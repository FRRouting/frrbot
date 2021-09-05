#!/usr/bin/env python3

from collections import defaultdict
from subprocess import CalledProcessError, PIPE, STDOUT
from logging.config import dictConfig
import subprocess
import datetime
import hmac
import os
import re
import time
import pprint

import yaml
import requests
import dateparser
import flask
from pylint import epylint as lint
from flask import Flask
from flask import Response
from flask import request
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from github import Github
from github import GithubException
from github import InputFileContent
from werkzeug.exceptions import BadRequest

# Global data ------------------------------------------------------------------
BAD_ISSUE_MSG = "When filing a bug report, please:\n\n- Describe the expected behavior\n- Describe the observed behavior\n\nPlease be sure to provide:\n\n- FRR version\n- OS distribution (e.g. Fedora, OpenBSD)\n- Kernel version (e.g. Linux 5.4)\n\nNeglecting to provide this information makes your issue difficult to address."
AUTO_CLOSE_MSG = "This issue will be automatically closed in one week unless there is further activity."
NO_AUTO_CLOSE_MSG = "This issue will no longer be automatically closed."
TRIGGER_LABEL = "autoclose"
BANNED_FUNCTIONS = [
    ("sprintf", "snprintf"),
    ("strcat", "strlcat"),
    ("strcpy", "strlcpy"),
    ("inet_ntoa", "inet_ntop"),
]

PR_GREETING_MSG = "Thanks for your contribution to FRR!\n\n"
PR_WARN_SIGNOFF_MSG = "* One of your commits has a missing or badly formatted `Signed-off-by` line; we can't accept your contribution until all of your commits have one\n"
PR_WARN_BLANKLN_MSG = "* One of your commits does not have a blank line between the summary and body; this will break `git log --oneline`\n"
PR_WARN_COMMIT_MSG = (
    "* One of your commits has an improperly formatted commit message\n"
)
PR_WARN_BANNED_FUNCTIONS = "* `{}` are banned; please use `{}`\n".format(
    ", ".join([x[0] for x in BANNED_FUNCTIONS]),
    ", ".join([x[1] for x in BANNED_FUNCTIONS]),
)
PR_GUIDELINES_REF_MSG = """
If you are a new contributor to FRR, please see our [contributing guidelines](http://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#coding-practices-style).

After making changes, you do not need to create a new PR. You should perform an [amend or interactive rebase](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History) followed by a [force push](https://git-scm.com/docs/git-push#Documentation/git-push.txt---force).
"""

# Scheduler functions ----------------------------------------------------------


def close_issue(repo_name, num):
    """
    Immediately close the named issue

    :param str: repository name
    :param int: issue number
    """
    LOG.warning("[+] Closing issue #%d", num)
    repo = g.get_repo(repo_name)
    issue = repo.get_issue(num)
    issue.edit(state="closed")
    try:
        issue.remove_from_labels(TRIGGER_LABEL)
    except GithubException:
        pass


def schedule_close_issue(issue, when):
    """
    Schedule an issue to be automatically closed on a certain date.

    :param github.Issue.Issue issue: issue to close
    :param datetime.datetime when: When to close the issue
    """
    reponame = issue.repository.full_name
    issuenum = issue.number
    issueid = "{}@@@{}".format(reponame, issuenum)
    LOG.warning("[-] Scheduling issue %d for autoclose (id: %d)", issuenum, issueid)
    scheduler.add_job(
        close_issue,
        run_date=when,
        args=[reponame, issuenum],
        id=issueid,
        replace_existing=True,
    )


def cancel_close_issue(issue):
    """
    Dechedule an issue to be automatically closed on a certain date.

    :param github.Issue.Issue issue: issue to cancel
    """
    reponame = issue.repository.full_name
    issuenum = issue.id
    issueid = "{}@@@{}".format(reponame, issuenum)
    LOG.warning("[-] Descheduling issue #%d for closing", issuenum)
    scheduler.remove_job(issueid)


# Module init ------------------------------------------------------------------

# configure logging
dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://flask.logging.wsgi_errors_stream",
                "formatter": "default",
            }
        },
        "root": {"level": "INFO", "handlers": ["wsgi"]},
    }
)

app = Flask(__name__)
LOG = flask.logging.create_logger(app)


class ConfigNotFoundError(Exception):
    pass


def load_config():
    """
    Load configuration.

    Configuration can be passed two ways:
    * By setting fields in config.yaml
    * Through environment variables

    Environment variables take precedence over config.yaml if both are present.

    Returns dictionary containing config.
    Raises ConfigNotFound if any of the required config items aren't found.
    """
    LOG.info("[+] Loading config")

    config = {
        "gh_webhook_secret": None,
        "gh_auth_token": None,
        "job_store_path": None,
    }

    # Load what we can from the config file first
    try:
        with open("config.yaml", "r") as conffile:
            file_conf = yaml.safe_load(conffile)
            for key in config.keys():
                try:
                    config[key] = file_conf[key]
                except KeyError:
                    pass
    except OSError:
        LOG.warning("[!] Can't open config.yaml (might not exist or bad permissions)")

    # Load what we can from the environment next
    for key in config.keys():
        config[key] = os.getenv(key.upper()) or config[key]

    # Verify all config is present
    for key, val in config.items():
        if not val:
            raise ConfigNotFoundError(
                "Missing required configuration for: {}".format(key)
            )

    return config


def initialize_github():
    """
    Initialize GitHub API

    Returns instance of Github
    """
    g = Github(config["gh_auth_token"])
    LOG.info("[+] Initialized GitHub API object")
    return g


def initialize_scheduler():
    """
    Initialize APScheduler, loading jobs database from disk if present

    Returns instance of BackgroundScheduler
    """
    if not os.path.exists(config["job_store_path"]):
        LOG.warning(
            "[!] Specified job store '%s' does not exist; creating one",
            config["job_store_path"],
        )
    jobstores = {
        "default": SQLAlchemyJobStore(
            url="sqlite:///{}".format(config["job_store_path"])
        )
    }
    scheduler = BackgroundScheduler(jobstores=jobstores)
    scheduler.start()
    jobs = scheduler.get_jobs()
    LOG.info("[+] Initialized scheduler")
    LOG.info("[+] Current jobs (%d):", len(jobs))
    for job in jobs:
        LOG.info("ID: %s", job.id)
        LOG.info("\tName: %s", job.name)
        LOG.info("\tFunc: %s", job.func)
        LOG.info("\tWhen: %s", job.next_run_time)
    return scheduler


# Load config
try:
    config = load_config()
    LOG.info("[+] Configuration:\n%s", pprint.pformat(config))
except ConfigNotFoundError as e:
    LOG.error("[!] Error while loading configuration: %s", e)
    exit(1)

# Initialize GitHub API
g = initialize_github()

# Initialize scheduler
scheduler = initialize_scheduler()


# Pull request management ------------------------------------------------------


class FrrPullRequest:
    """
    FRR pull request
    """

    def __init__(self, repo, pull_request):
        self.repo = repo
        self.pull_request = pull_request

    def check_pylint(self, repodir):
        """
        Run pylint over any changed python files, checking only for errors.

        :param repodir str: directory containing repository.
        """
        pyfiles = self.pull_request.get_files()
        pyfiles = [f for f in pyfiles if f.filename.endswith(".py")]

        result = ""

        for codefile in pyfiles:
            filename = "{}/{}".format(repodir, codefile.filename)
            LOG.warning("[+] Running pylint on: %s", filename)
            r = lint.py_run(
                "{} --persistent=n --disable=all --enable=E -E -r n --disable=import-error".format(
                    filename
                ),
                return_std=True,
            )
            pylint_stdout = r[0].read()
            pylint_stderr = r[1].read()
            LOG.warning("stdout: %s", pylint_stdout)
            LOG.warning("stderr: %s", pylint_stderr)
            if pylint_stdout:
                result += "Pylint report for {}:\n{}\n\n".format(
                    filename, pylint_stdout
                )

        return result

    def check_style(self, repodir):
        """
        Run clang-format and black and return the style diff.

        Modifies the repository.

        :param repodir str: directory containing repository.
        """
        LOG.warning("[+] Generating style diff")
        cmd = "git -C {} clang-format".format(repodir).split(" ")
        subprocess.run(cmd, check=False)

        pyfiles = self.pull_request.get_files()
        pyfiles = [f for f in pyfiles if f.filename.endswith(".py")]

        for codefile in pyfiles:
            filename = "{}/{}".format(repodir, codefile.filename)
            cmd = "python3 -m black {}".format(filename).split(" ")
            LOG.warning("[+] Running: %s", cmd)
            subprocess.run(cmd, check=False)

        cmd = "git -C {} diff".format(repodir).split(" ")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False).stdout or b""

        LOG.warning("[+] Result: %s", result)

        return result.decode("utf-8")

    def check_diff(self):
        """
        Run various checks on the code diff.
        Compute a clang-format diff for a pull request.

        Returns None if:
        - there are no issues
        - any of the git operations fail
        - git-clang-format isn't installed

        Otherwise returns a dictionary containing various reports on the diff.
        """
        repodir = "my_frr"

        ignore = ["ldpd", "babeld", "nhrpd", "eigrpd"]

        # get repo
        if not os.path.isdir(repodir):
            LOG.warning("[+] Cloning repository")
            cmd = "git clone {} {}".format(self.repo.git_url, repodir).split(" ")
            subprocess.run(cmd, check=True)

        # fetch pr diff
        resp = requests.get(self.pull_request.diff_url)
        if resp.status_code != 200:
            LOG.warning(
                "[-] GET '%s' failed with HTTP %d",
                self.pull_request.diff_url,
                resp.status_code,
            )
            return None
        if len(resp.text) == 0:
            LOG.warning("[-] diff at '%s' is empty", self.pull_request.diff_url)
            return None
        diff_filename = "/tmp/pr_{}.diff".format(self.pull_request.number)
        with open(diff_filename, "w") as change:
            change.write(resp.text)

        # Apply diff
        LOG.warning("[+] Fetching %s", self.pull_request.base.sha)
        cmd = "git -C {} fetch origin {}".format(
            repodir, self.pull_request.base.sha
        ).split(" ")
        LOG.warning("base SHA: %s\n", self.pull_request.base.sha)
        subprocess.run(cmd, check=False)
        LOG.warning("[+] Resetting to %s", self.pull_request.base.sha)
        cmd = "git -C {} reset --hard {}".format(
            repodir, self.pull_request.base.sha
        ).split(" ")
        subprocess.run(cmd, check=False)
        LOG.warning("[+] Cleaning")
        cmd = "git -C {} clean -fdx".format(
            repodir,
        ).split(" ")
        subprocess.run(cmd, check=False)
        LOG.warning("[+] Applying patch")
        # cmd = "git -C {} apply {}".format(repodir, diff_filename).split(" ")
        cmd = "git -C {} fetch {} {}".format(
            repodir, self.pull_request.head.repo.clone_url, self.pull_request.head.ref
        ).split(" ")
        subprocess.run(cmd, check=False)
        cmd = "git -C {} merge --no-ff --no-commit FETCH_HEAD".format(repodir).split(
            " "
        )

        try:
            subprocess.run(cmd, stdout=PIPE, stderr=STDOUT, check=True)
        except subprocess.CalledProcessError as error:
            LOG.error("[!] Issue applying PR diff: %s", error.output)
            LOG.warning("[+] Resetting to %s", self.pull_request.base.sha)
            cmd = "git -C {} reset --hard {}".format(
                repodir, self.pull_request.base.sha
            ).split(" ")
            return None

        # At this point the files are all staged; we need to unstage them, drop
        # the changes for directories we want to ignore, then re-stage them
        LOG.warning("[+] Unstaging all files")
        cmd = "git -C {} reset HEAD -- .".format(repodir).split(" ")
        subprocess.run(cmd, check=False)
        LOG.warning("[+] Applying ignore rules")
        cmd = "git -C {} checkout -- {}".format(repodir, " ".join(ignore)).split(" ")
        subprocess.run(cmd, check=False)
        LOG.warning("[+] Staging patch")
        cmd = "git -C {} add -u".format(repodir).split(" ")
        subprocess.run(cmd, check=False)

        result = {}
        result["pylint"] = self.check_pylint(repodir)
        result["style"] = self.check_style(repodir)

        cmd = "git -C {} reset --hard {}".format(
            repodir, self.pull_request.base.sha
        ).split(" ")
        subprocess.run(cmd, check=False)

        return result

    def check_commits(self):
        """
        For each commit in the PR, check for the following:

        - incorrect summary line formatting
        - missing DCOO / Signed-off-by line
        - missing blank line between summary line and message body

        Returns a dict indicating whether each of the above is true for any commit
        in the PR.
        """
        commits = self.pull_request.get_commits()

        warns = defaultdict(bool)

        for commit in commits:
            msg = commit.commit.message

            if len(msg) == 0:
                LOG.warning("[-] Zero length commit message; weird")
                continue

            if msg.startswith("Revert") or msg.startswith("Merge"):
                continue

            lines = msg.split("\n")

            if len(lines) < 2 or len(lines[1]) > 0:
                warns["blankln"] = True

            if ":" not in lines[0]:
                warns["bad_msg"] = True

            if not re.search(r"Signed-off-by: .* <.*@.*>", msg):
                warns["signoff"] = True

        return warns

    def check_functions(self):
        """
        Check for banned functions in the diff
        """
        resp = requests.get(self.pull_request.diff_url)
        if resp.status_code != 200:
            LOG.warning(
                "[-] GET '%s' failed with HTTP %d",
                self.pull_request.diff_url,
                resp.status_code,
            )
            return None
        if len(resp.text) == 0:
            LOG.warning("[-] diff at '%s' is empty", self.pull_request.diff_url)
            return None

        added = [x for x in resp.text.split("\n") if x.startswith("+")]
        banned_regexp = [r"\s{}\(".format(x[0]) for x in BANNED_FUNCTIONS]
        has_banned_functions = any(
            any((re.search(y, x) is not None) for y in banned_regexp) for x in added
        )

        return has_banned_functions

    def check(self):
        """
        Perform all checks on this PR
        """
        issues = defaultdict(lambda: None)

        issues["commits"] = self.check_commits()

        try:
            issues["diff"] = self.check_diff()
        except Exception as error:
            LOG.warning("[-] Style/lint checking failed:\n%s", str(error))

        try:
            issues["functions"] = self.check_functions()
        except Exception as error:
            LOG.warning("[-] Function checking failed:\n%s", str(error))

        return issues

    def review(self):
        """
        Perform all checks on this PR and leave a review if there are problems
        """
        issues = self.check()

        LOG.warning("[+] Reviewing #%d", self.pull_request.number)

        comment = ""
        nak = False

        if issues["commits"]:
            if issues["commits"]["bad_msg"]:
                comment += PR_WARN_COMMIT_MSG
                nak = True
            if issues["commits"]["signoff"]:
                comment += PR_WARN_SIGNOFF_MSG
                nak = True
            if issues["commits"]["blankln"]:
                comment += PR_WARN_BLANKLN_MSG
                nak = True
        if issues["functions"]:
            comment += PR_WARN_BANNED_FUNCTIONS
            nak = True
        if issues["diff"]:
            if issues["diff"]["pylint"]:
                comment += """
---

Pylint found errors in source files changed by this PR:

```
{pylint_report}
```

""".format(
                    pylint_report=issues["diff"]["pylint"]
                )

            if issues["diff"]["style"]:
                try:
                    gistname = "cr_{}_{}.diff".format(
                        self.pull_request.number, int(time.time())
                    )
                    files = {gistname: InputFileContent(issues["diff"]["style"])}
                    gist = g.get_user().create_gist(
                        True,
                        files,
                        "FRRouting/frr #{}".format(self.pull_request.number),
                    )
                    raw_url = gist.files[gistname].raw_url
                    comment += """
<details>
<summary><b>Click for style suggestions</b></summary>

To apply these suggestions:

<p>

```
curl -s {gisturl} | git apply
```

</p>

<p>

```diff
{stylediff}
```

</p>
</details>

""".format(
                        gisturl=raw_url, stylediff=issues["diff"]["style"]
                    )

                except KeyError as error:
                    LOG.warning("[-] Failed to create gist: %s", str(error))
        if not issues["diff"]:
            comment += "Style checking failed; check logs\n"

        # dismiss previous reviews if necessary
        if not nak:
            for review in self.pull_request.get_reviews():
                if (
                    review.user.id == g.get_user().id
                    and review.state == "CHANGES_REQUESTED"
                ):
                    review.dismiss("blocking comments addressed")

        # Post review
        if comment != "":
            comment = PR_GREETING_MSG + comment
            comment += PR_GUIDELINES_REF_MSG
            event = "COMMENT" if not nak else "REQUEST_CHANGES"
            self.pull_request.create_review(body=comment, event=event)

        try:
            state = "success" if not nak else "failure"
            description = "OK" if not nak else "Problems found"
            description = (
                "OK - but has style issues" if not nak and comment else description
            )
            commits = self.pull_request.get_commits()
            last_commit = None
            for last_commit in commits:
                pass
            LOG.warning(last_commit)
            last_commit.create_status(
                state=state,
                description=description,
                target_url="",
                context="polychaeta",
            )
        except Exception as error:
            LOG.warning("Error while making status: %s", str(error))

        return comment

    def add_labels(self):
        """
        Label a pull request using component directories present in the commit
        message subject lines.
        """
        # directory -> label
        label_map = {
            "alpine": "packaging",
            "babeld": "babel",
            "bfdd": "bfd",
            "bgpd": "bgp",
            "debian": "packaging",
            "doc": "documentation",
            "docker": "docker",
            "eigrpd": "eigrp",
            "fpm": "fpm",
            "isisd": "isis",
            "ldpd": "ldp",
            "lib": "libfrr",
            "nhrpd": "nhrp",
            "ospf6d": "ospfv3",
            "ospfd": "ospf",
            "pbrd": "pbr",
            "pimd": "pim",
            "pkgsrc": "packaging",
            "python": "clippy",
            "redhat": "packaging",
            "ripd": "rip",
            "ripngd": "ripng",
            "sharpd": "sharp",
            "snapcraft": "packaging",
            "solaris": "packaging",
            "staticd": "staticd",
            "tests": "tests",
            "tools": "tools",
            "vtysh": "vtysh",
            "vrrpd": "vrrp",
            "watchfrr": "watchfrr",
            "yang": "yang",
            "zebra": "zebra",
            # files
            "configure.ac": "build",
            "makefile.am": "build",
            "bootstrap.sh": "build",
        }

        commits = self.pull_request.get_commits()
        labels = set()

        for commit in commits:
            msg = commit.commit.message
            match = re.match(r"^([^:\n]+):", msg)
            if match:
                lbls = match.groups()[0].split(",")
                lbls = map(lambda x: x.strip(), lbls)
                lbls = map(lambda x: x.lower(), lbls)
                lbls = filter(lambda x: x in label_map, lbls)
                lbls = map(lambda x: label_map[x], lbls)
                labels = labels | set(lbls)

            lines = msg.split("\n")
            if lines[0].find("fix") != -1 or msg.find("Fixes:") != -1:
                labels.add("bugfix")

        if labels:
            self.pull_request.add_to_labels(*labels)


# Webhook handlers -------------------------------------------------------------


def issue_labeled(j):
    """
    Handle an issue getting a new label
    """
    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]
    issue = g.get_repo(reponame).get_issue(issuenum)

    def label_autoclose():
        closedate = datetime.datetime.now() + datetime.timedelta(weeks=1)
        schedule_close_issue(issue, closedate)
        issue.create_comment(AUTO_CLOSE_MSG)

    label_actions = {"autoclose": label_autoclose}

    try:
        labelname = j["label"]["name"]
        label_actions[labelname]()
    except KeyError:
        pass

    return Response("OK", 200)


def issue_comment_created(j):
    """
    Handle an issue comment being created.

    First we check if the comment contains a trigger phrase. If it does, and
    the user who made the comment has admin privileges on the repository, we
    then try to parse the trigger phrase and its arguments and take the
    specified action. If the action fails to parse nothing is done.

    If the comment doesn't contain a trigger phrase, and this issue is
    scheduled for autoclose, then we'll consider the comment to be activity on
    the issue and cancel the autoclose.

    Trigger phrases are of the form '@<botusername> <verb> <arguments>.

    Current verbs:

    autoclose <time period>
       Automatically close this issue in <time period>.

    rereview
       Re-run bot review on PR
    """

    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]

    repo = g.get_repo(reponame)
    issue = repo.get_issue(issuenum)

    body = j["comment"]["body"]
    sender = j["sender"]["login"]
    perm = repo.get_collaborator_permission(sender)

    def verb_autoclose(arg):
        """
        Verb to automatically close an issue after a certain period of time.

        :param tp str: trigger phrase
        :param arg str: automatically close this issue in <arg>, where <arg> is
        a time period in the future or a date. For instance, time period could
        be "in 1 day" to close the issue in 1 day, or "May 25th" to specify the
        next occurring May 15th.
        """
        if not perm in ("write", "admin"):
            LOG.warning(
                "[-] User '%s' (%s) isn't authorized to use this command", sender, perm
            )
            return

        closedate = dateparser.parse(arg.strip())
        if closedate is not None and closedate > datetime.datetime.now():
            schedule_close_issue(issue, closedate)
            issue.add_to_labels("autoclose")
            issue.get_comment(j["comment"]["id"]).create_reaction("+1")
        elif closedate is None:
            LOG.warning("[-] Couldn't parse '%s' as a datetime", arg)

    def verb_rereview(_):
        pull_request = FrrPullRequest(repo, repo.get_pull(j["issue"]["number"]))
        pull_request.review()

    def verb_badreport(_):
        issue.create_comment(BAD_ISSUE_MSG)
        issue.get_comment(j["comment"]["id"]).create_reaction("+1")

    verbs = {
        "autoclose": verb_autoclose,
        "rereview": verb_rereview,
        "bad-report": verb_badreport,
    }

    had_verb = False

    for verb, handler in verbs.items():
        trigger_me = "@{} {}".format(g.get_user().login, verb)
        if trigger_me.lower() in body.lower():
            LOG.warning("[+] Found trigger '%s'", verb)
            partition = body.lower().partition(trigger_me.lower())
            LOG.warning("[+] Trigger detected: %s %s", partition[1], partition[2])
            handler(partition[2])
            had_verb = True

    issueid = "{}@@@{}".format(reponame, issuenum)
    if not had_verb and scheduler.get_job(issueid) is not None:
        scheduler.remove_job(issueid)
        issue.remove_from_labels(TRIGGER_LABEL)
        issue.create_comment(NO_AUTO_CLOSE_MSG)

    return Response("OK", 200)


def pull_request_opened(j):
    """
    Handle a pull request being opened.

    - Add component labels
    - Review pull request for basic correctness

    If any issues are found, a review is submitted indicating the issues.
    """
    repo = g.get_repo(j["repository"]["full_name"])
    pull_request = repo.get_pull(j["number"])

    pull_request = FrrPullRequest(repo, pull_request)
    pull_request.add_labels()
    pull_request.review()

    return Response("OK", 200)


def pull_request_synchronize(j):
    """
    Handle a pull request being synchronized.

    Synchronized means new commits were pushed to the branch tracked by the PR.

    - Add component labels
    - Review pull request for basic correctness

    If any issues are found, a review is submitted indicating the issues.
    If prior issues have been resolved, the previous review is dismissed.
    """
    return pull_request_opened(j)


# API handler map
# {
#   'event1': {
#     'action1': ev1_action1_handler,
#     'action2': ev1_action2_handler,
#     ...
#   }
#   'event2': {
#     'action1': ev2_action1_handler,
#     'action2': ev2_action2_handler,
#     ...
#   }
# }
event_handlers = {
    "issues": {"labeled": issue_labeled},
    "issue_comment": {"created": issue_comment_created},
    "pull_request": {
        "opened": pull_request_opened,
        "synchronize": pull_request_synchronize,
    },
}


def handle_webhook(req):
    """
    Handle reception of a GitHub webhook
    """
    try:
        evtype = req.headers["X_GITHUB_EVENT"]
    except KeyError:
        LOG.warning("[-] No X-GitHub-Event header...")
        return Response("No X-GitHub-Event header", 400)

    LOG.warning("[+] Handling webhook '%s'", evtype)

    try:
        _ = event_handlers[evtype]
    except KeyError:
        LOG.warning("[+] Unknown event '%s'", evtype)
        return Response("OK", 200)

    try:
        j = req.get_json()
    except BadRequest:
        LOG.warning("[-] Could not parse payload as JSON")
        return Response("Bad JSON", 400)

    try:
        action = j["action"]
    except KeyError:
        LOG.warning("[+] No action for event '%s'", evtype)
        return Response("OK", 200)

    try:
        handler = event_handlers[evtype][action]
    except KeyError:
        LOG.warning("[+] No handler for action '%s'", action)
        return Response("OK", 200)

    try:
        sender = j["sender"]["login"]
        if sender == g.get_user().login:
            LOG.warning("[+] Ignoring event triggered by me")
            return Response("OK", 200)
    except KeyError:
        pass

    LOG.warning("[+] Handling action '%s' on event '%s'", action, evtype)
    return handler(j)


# Flask hooks ------------------------------------------------------------------


def gh_sig_valid(req):
    """
    Determine whether the signature in a request, ostensibly from GitHub, is
    valid

    :param req: The GitHub request
    """
    mydigest = (
        "sha1="
        + hmac.HMAC(
            bytes(config["gh_webhook_secret"], "utf8"), req.get_data(), "sha1"
        ).hexdigest()
    )
    ghdigest = req.headers["X_HUB_SIGNATURE"]
    comp = hmac.compare_digest(ghdigest, mydigest)
    LOG.warning("[+] Request: mine = %s, theirs = %s", mydigest, ghdigest)
    return comp


@app.route("/", methods=["GET", "POST"])
def parse_payload():
    """
    Validate and parse GitHub webhook request payload
    """
    try:
        if not gh_sig_valid(request):
            return Response("Unauthorized", 401)
    # No matter what the problem is with authentication, fail auth
    # pragma pylint: disable=W0702
    except:
        return Response("Unauthorized", 401)
    # pragma pylint: enable=W0702

    if request.method == "POST":
        return handle_webhook(request)

    return Response("OK", 200)
