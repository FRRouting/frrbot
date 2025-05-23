#!/usr/bin/env python3

from collections import defaultdict
from subprocess import PIPE, STDOUT
from logging.config import dictConfig
import subprocess
import datetime
import os
import re
import pprint
import sys

import yaml
import requests
import dateparser
import flask
from pylint import epylint as lint
from flask import Flask
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from ghapi.all import paged, GhApi
from flask_githubapplication import GitHubApp

# Global data ------------------------------------------------------------------
BAD_ISSUE_MSG = "When filing a bug report, please:\n\n- Describe the expected behavior\n- Describe the observed behavior\n\nPlease be sure to provide:\n\n- FRR version\n- OS distribution (e.g. Fedora, OpenBSD)\n- Kernel version (e.g. Linux 5.4)\n\nNeglecting to provide this information makes your issue difficult to address."
AUTO_CLOSE_MSG = "This issue will be automatically closed in the specified period unless there is further activity."
NO_AUTO_CLOSE_MSG = "This issue will no longer be automatically closed."
TRIGGER_LABEL = "autoclose"
BANNED_FUNCTIONS = [
    ("sprintf", "snprintf"),
    ("strcat", "strlcat"),
    ("strcpy", "strlcpy"),
    ("inet_ntoa", "inet_ntop"),
    ("ctime", "ctime_r"),
]
BANNED_CONTAINER_FUNCTIONS = [
    "hash_create",
    "hash_create_size",
    "list_new",
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
PR_WARN_BANNED_CONTAINER_FUNCTIONS = "* `{}` are banned for new uses; please use typesafe.h (DECLARE_HASH, DECLARE_DLIST, etc.)\n".format(
    ", ".join([x for x in BANNED_CONTAINER_FUNCTIONS]),
)
PR_GUIDELINES_REF_MSG = """
If you are a new contributor to FRR, please see our [contributing guidelines](http://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#coding-practices-style).

After making changes, you do not need to create a new PR. You should perform an [amend or interactive rebase](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History) followed by a [force push](https://git-scm.com/docs/git-push#Documentation/git-push.txt---force).
"""

# Scheduler functions ----------------------------------------------------------


def scheduler_make_id_issue(repo, issue):
    """
    Make database ID for issue

    :param dict repo: repository issue is in
    :param dict issue: issue to make id for
    """
    return "{}@@@{}".format(repo["full_name"], issue["id"])


def close_issue(repo, issue, installation_id):
    """
    Immediately close the named issue

    :param dict repo: repository issue is in
    :param dict issue: issue to close
    """
    LOG.info(
        "[+] Closing issue #%d, installation ID %s", issue["number"], installation_id
    )
    with app.app_context():
        client = ghapp.client(installation_id)
        client.issues.update(
            repo["owner"]["login"], repo["name"], issue["number"], state="closed"
        )
        client.issues.remove_label(
            repo["owner"]["login"], repo["name"], issue["number"], TRIGGER_LABEL
        )


def schedule_close_issue(installation_id, repo, issue, when):
    """
    Schedule an issue to be automatically closed on a certain date.

    :param dict repo: repository issue is in
    :param dict issue: issue to close
    :param datetime.datetime when: When to close the issue
    """
    issueid = scheduler_make_id_issue(repo, issue)
    LOG.warning(
        "[-] Scheduling issue %d for autoclose (id: %d)", issue["number"], issue["id"]
    )
    scheduler.add_job(
        close_issue,
        run_date=when,
        args=[repo, issue, installation_id],
        id=issueid,
        replace_existing=True,
    )


def cancel_close_issue(repo, issue):
    """
    Dechedule an issue to be automatically closed on a certain date.

    :param github.Issue.Issue issue: issue to cancel
    """
    issueid = scheduler_make_id_issue(repo, issue)
    LOG.warning("[-] Descheduling issue #%d for closing", issue["number"])
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
        "root": {"level": "DEBUG", "handlers": ["wsgi"]},
    }
)

app = Flask(__name__)
app.debug = True
LOG = flask.logging.create_logger(app)

import flask_githubapplication
flask_githubapplication.core.LOG = LOG


class ConfigNotFoundError(Exception):
    """
    Exception thrown when a configuration key cannot be found.
    """


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
        "gh_app_pkey_pem_path": None,
        "gh_webhook_secret": None,
        "gh_app_id": None,
        "gh_gist_user_token": None,
        "gh_app_route": None,
        "job_store_path": None,
    }

    # Load what we can from the config file first
    try:
        with open("config.yaml", "r", encoding="utf-8") as conffile:
            file_conf = yaml.safe_load(conffile)
            for key in config:
                try:
                    config[key] = file_conf[key]
                except KeyError:
                    pass
    except OSError:
        LOG.warning("[!] Can't open config.yaml (might not exist or bad permissions)")

    # Load what we can from the environment next
    for key in config:
        config[key] = os.getenv(key.upper()) or config[key]

    # Verify all config is present
    for key, val in config.items():
        if not val:
            raise ConfigNotFoundError(
                "Missing required configuration for: {}".format(key)
            )

    return config


def initialize_git():
    """
    Initialize Git settings
    """
    cmd = "git config --global user.name 'polychaeta'".split(" ")
    subprocess.run(cmd, check=False)
    cmd = "git config --global user.email 'frrbot@frrouting.org'".split(" ")
    subprocess.run(cmd, check=False)


def initialize_github(app, config):
    """
    Configure Flask settings to allow flask-githubapp to authorize itself
    """
    app.config["GITHUBAPP_ID"] = config["gh_app_id"]
    app.config["GITHUBAPP_SECRET"] = config["gh_webhook_secret"]
    app.config["GITHUBAPP_ROUTE"] = config["gh_app_route"]

    try:
        with open(config["gh_app_pkey_pem_path"], mode="rb") as keyfile:
            app.config["GITHUBAPP_KEY"] = keyfile.read()
    except FileNotFoundError:
        LOG.error(
            "Configured path to GitHub App PEM key file is inaccessible: '%s'",
            config["gh_app_pkey_pem_path"],
        )
        raise ConfigNotFoundError("Cannot access key file")

    return GitHubApp(app)


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
    jobs = scheduler.get_jobs()
    LOG.info("[+] Current jobs (%d):", len(jobs))
    for job in jobs:
        LOG.info("ID: %s", job.id)
        LOG.info("\tName: %s", job.name)
        LOG.info("\tFunc: %s", job.func)
        LOG.info("\tWhen: %s", job.next_run_time)
    scheduler.start()
    LOG.info("[+] Initialized scheduler")
    return scheduler


# Load config
try:
    config = load_config()
    LOG.info("[+] Configuration:\n%s", pprint.pformat(config))
except ConfigNotFoundError as e:
    LOG.error("[!] Error while loading configuration: %s", e)
    sys.exit(1)


# Initialize Git
initialize_git()

# Initialize scheduler
scheduler = initialize_scheduler()

# Initialize GitHub App
try:
    ghapp = initialize_github(app, config)
except ConfigNotFoundError as e:
    LOG.error("[!] Error while initializing GitHub App: %s", e)
    sys.exit(2)

# Initialize github gist user
gistclient = GhApi(token=config["gh_gist_user_token"])


# Pull request management ------------------------------------------------------


class FrrPullRequest:
    """
    FRR pull request
    """

    def __init__(self, client, repo, pull_request):
        self.client = client
        self.repo = repo
        self.pull_request = pull_request
        self.repo_tuple = (self.repo["owner"]["login"], self.repo["name"])

    def _get_pyfiles(self):
        pyfiles_pages = paged(
            self.client.pulls.list_files, *self.repo_tuple, self.pull_request["number"]
        )
        pyfiles = [
            [f for f in page if f["filename"].endswith(".py")] for page in pyfiles_pages
        ]
        pyfiles = [item for sublist in pyfiles for item in sublist]
        return pyfiles

    def check_pylint(self, repodir):
        """
        Run pylint over any changed python files, checking only for errors.

        :param repodir str: directory containing repository.
        """
        pyfiles = self._get_pyfiles()
        result = ""

        for codefile in pyfiles:
            filename = "{}/{}".format(repodir, codefile["filename"])
            if not os.path.exists(filename):
                LOG.warning(
                    "[+] Skipping pylint on '%s' as it appears removed", filename
                )
                continue
            LOG.warning("[+] Running pylint on: %s", filename)
            output = lint.py_run(
                "{} --persistent=n --disable=all --enable=E -E -r n --disable=import-error".format(
                    filename
                ),
                return_std=True,
            )
            pylint_stdout = output[0].read()
            pylint_stderr = output[1].read()
            LOG.debug("stdout: %s", pylint_stdout)
            LOG.debug("stderr: %s", pylint_stderr)
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

        pyfiles = self._get_pyfiles()

        for codefile in pyfiles:
            filename = "{}/{}".format(repodir, codefile["filename"])
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
        repodir = "my_frr-{}".format(os.getpid())

        ignore = ["ldpd", "babeld", "nhrpd", "eigrpd"]

        # get repo
        if not os.path.isdir(repodir):
            LOG.warning("[+] Cloning repository")
            cmd = "git clone {} {}".format(self.repo["clone_url"], repodir).split(" ")
            subprocess.run(cmd, check=True)

        # fetch pr diff
        resp = requests.get(self.pull_request["diff_url"])
        if resp.status_code != 200:
            LOG.warning(
                "[-] GET '%s' failed with HTTP %d",
                self.pull_request["diff_url"],
                resp.status_code,
            )
            return None
        if len(resp.text) == 0:
            LOG.warning("[-] diff at '%s' is empty", self.pull_request["diff_url"])
            return None
        diff_filename = "/tmp/pr_{}.diff".format(self.pull_request["number"])
        with open(diff_filename, "w", encoding="utf-8") as change:
            change.write(resp.text)

        # Apply diff
        LOG.warning("[+] Fetching %s", self.pull_request["base"]["sha"])
        cmd = "git -C {} fetch origin {}".format(
            repodir, self.pull_request["base"]["sha"]
        ).split(" ")
        LOG.warning("base SHA: %s\n", self.pull_request["base"]["sha"])
        subprocess.run(cmd, check=False)
        LOG.warning("[+] Resetting to %s", self.pull_request["base"]["sha"])
        cmd = "git -C {} reset --hard {}".format(
            repodir, self.pull_request["base"]["sha"]
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
            repodir,
            self.pull_request["head"]["repo"]["clone_url"],
            self.pull_request["head"]["ref"],
        ).split(" ")
        subprocess.run(cmd, check=False)
        cmd = "git -C {} merge --no-ff --no-commit FETCH_HEAD".format(repodir).split(
            " "
        )

        try:
            subprocess.run(cmd, stdout=PIPE, stderr=STDOUT, check=True)
        except subprocess.CalledProcessError as error:
            LOG.error("[!] Issue applying PR diff: %s", error.output)
            LOG.warning("[+] Resetting to %s", self.pull_request["base"]["sha"])
            cmd = "git -C {} reset --hard {}".format(
                repodir, self.pull_request["base"]["sha"]
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
            repodir, self.pull_request["base"]["sha"]
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
        warns = defaultdict(bool)

        commit_pages = paged(
            self.client.pulls.list_commits,
            *self.repo_tuple,
            self.pull_request["number"],
        )

        for page in commit_pages:
            for commit in page:
                msg = commit["commit"]["message"]

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
        resp = requests.get(self.pull_request["diff_url"])
        if resp.status_code != 200:
            LOG.warning(
                "[-] GET '%s' failed with HTTP %d",
                self.pull_request["diff_url"],
                resp.status_code,
            )
            return False
        if len(resp.text) == 0:
            LOG.warning("[-] diff at '%s' is empty", self.pull_request["diff_url"])
            return False

        added = [x for x in resp.text.split("\n") if x.startswith("+")]
        removed = [x for x in resp.text.split("\n") if x.startswith("-")]

        banned_regexp = [r"\s{}\(".format(x[0]) for x in BANNED_FUNCTIONS]
        has_banned_functions = any(
            any((re.search(y, x) is not None) for y in banned_regexp) for x in added
        )

        banned_container_regexp = [r"\s{}\(".format(x[0]) for x in BANNED_CONTAINER_FUNCTIONS]
        count_added = len([line for line in added if any((re.search(y, line) is not None) for y in banned_container_regexp)])
        count_removed = len([line for line in removed if any((re.search(y, line) is not None) for y in banned_container_regexp)])

        has_banned_container_functions = count_added > count_removed

        return (has_banned_functions, has_banned_container_functions)

    def check(self):
        """
        Perform check run on this PR
        """
        LOG.info("[+] Checking #%d", self.pull_request["number"])

        # Post check run start
        check = self.client.checks.create(
            *self.repo_tuple,
            name="frrbot",
            details_url=self.pull_request["html_url"] + "/checks",
            head_sha=self.pull_request["head"]["sha"],
            status="in_progress",
        )

        issues = defaultdict(lambda: None)
        issues["commits"] = self.check_commits()
        issues["diff"] = self.check_diff()
        issues["functions"], issues["containers"] = self.check_functions()

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
        if issues["containers"]:
            comment += PR_WARN_BANNED_CONTAINER_FUNCTIONS
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
                gist_filename = "style.diff"

                def sizeof_fmt(num, suffix="B"):
                    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
                        if abs(num) < 1024.0:
                            return f"{num:3.1f}{unit}{suffix}"
                        num /= 1024.0
                    return f"{num:.1f}Yi{suffix}"

                gist_size = sizeof_fmt(len(issues["diff"]["style"]))

                LOG.info(
                    "[+] Uploading gist with style diff (size: {}".format(gist_size)
                )
                try:
                    gist = gistclient.gists.create(
                        files={gist_filename: {"content": issues["diff"]["style"]}}
                    )
                    gist_raw_url = gist["files"][gist_filename]["raw_url"]
                    LOG.info("[+] Uploaded gist with style diff to: %s", gist_raw_url)
                    # I think the limit is 64kb, but the github docs don't really say
                    if len(issues["diff"]["style"].encode("utf-8")) > 60000:
                        comment += "[Style diff]({}) is too large to embed.\n".format(
                            gist_raw_url
                        )
                    else:
                        comment += """
<details>
<summary><b>Click for style suggestions</b></summary>

<p>


```diff
{stylediff}
```

</p>
</details>

""".format(
                            stylediff=issues["diff"]["style"]
                        )
                    comment += """
To apply the style suggestions:
```
curl {stylegist_url} | git apply -
```

""".format(
                        stylegist_url=gist_raw_url
                    )
                except Exception as e:
                    LOG.error("[!] Failed to upload gist:\n%s", str(e))
                    comment += "Error: Failed to upload style gist."

        if not issues["diff"]:
            comment += "Style checking failed; check logs\n"

        if comment != "":
            comment = PR_GREETING_MSG + comment
            comment += PR_GUIDELINES_REF_MSG

        state = "success"
        description = "OK"

        if nak:
            state = "failure"
            description = "Blocking issues found"
        elif comment:
            state = "neutral"
            description = "Style and/or linter errors found"

        output = {
            "title": description,
            "summary": description,
        }

        if comment != "":
            output["text"] = comment

        self.client.checks.update(
            *self.repo_tuple,
            check_run_id=check["id"],
            name="frrbot",
            details_url=self.pull_request["html_url"] + "/checks",
            conclusion=state,
            output=output,
        )

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
            "mgmtd": "mgmt",
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

        labels = set()
        commit_pages = paged(
            self.client.pulls.list_commits,
            *self.repo_tuple,
            self.pull_request["number"],
        )
        for page in commit_pages:
            for commit in page:
                msg = commit["commit"]["message"]
                match = re.match(r"^([^:\n]+):", msg)
                if match:
                    lbls = match.groups()[0].split(",")
                    lbls = map(lambda x: x.strip(), lbls)
                    lbls = map(lambda x: x.lower(), lbls)
                    lbls = filter(lambda x: x in label_map, lbls)
                    lbls = map(lambda x: label_map[x], lbls)
                    labels = labels | set(lbls)

                lines = msg.split("\n")
                if lines[0].find(" fix ") != -1 or msg.find("Fixes:") != -1:
                    labels.add("bugfix")

        if labels:
            self.client.issues.add_labels(
                *self.repo_tuple, self.pull_request["number"], list(labels)
            )


# Webhook handlers -------------------------------------------------------------


@ghapp.on("issues.labeled")
def issue_labeled():
    """
    Handle an issue getting a new label
    """
    j = ghapp.payload
    repo = j["repository"]
    issue = j["issue"]
    client = ghapp.client()

    issue = client.issues.get(repo["owner"]["login"], repo["name"], issue["number"])

    def label_autoclose():
        closedate = datetime.datetime.now() + datetime.timedelta(weeks=1)
        schedule_close_issue(j["installation"]["id"], repo, issue, closedate)
        client.issues.create_comment(
            repo["owner"]["login"], repo["name"], issue["number"], AUTO_CLOSE_MSG
        )

    label_actions = {"autoclose": label_autoclose}

    try:
        labelname = j["label"]["name"]
        label_actions[labelname]()
    except KeyError:
        pass

    return "Ok"


@ghapp.on("issue_comment.created")
def issue_comment_created():
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
    j = ghapp.payload
    client = ghapp.client()

    repo = j["repository"]
    issue = j["issue"]

    if j["comment"]["user"]["type"] == "Bot":
        return "Ok"

    body = j["comment"]["body"]
    sender = j["sender"]["login"]

    perm = client.repos.get_collaborator_permission_level(
        repo["owner"]["login"], repo["name"], sender
    )["permission"]

    LOG.info("Permission level for '%s': %s", sender, perm)

    def verb_autoclose(arg):
        """
        Verb to automatically close an issue after a certain period of time.

        :param tp str: trigger phrase
        :param arg str: automatically close this issue in <arg>, where <arg> is
        a time period in the future or a date. For instance, time period could
        be "in 1 day" to close the issue in 1 day, or "May 25th" to specify the
        next occurring May 25th.
        """
        if not perm in ("write", "admin"):
            LOG.warning(
                "[-] User '%s' (%s) isn't authorized to use this command", sender, perm
            )
            return

        closedate = dateparser.parse(arg.strip())
        if closedate is not None and closedate > datetime.datetime.now():
            schedule_close_issue(j["installation"]["id"], repo, issue, closedate)
            client.issues.add_labels(
                repo["owner"]["login"], repo["name"], issue["number"], ["autoclose"]
            )
            client.reactions.create_for_issue_comment(
                repo["owner"]["login"], repo["name"], j["comment"]["id"], "+1"
            )
        elif closedate is None:
            LOG.warning("[-] Couldn't parse '%s' as a datetime", arg)

    def verb_rereview(_):
        pull_request = FrrPullRequest(
            client,
            repo,
            client.pulls.get(repo["owner"]["login"], repo["name"], issue["number"]),
        )
        pull_request.check()

    def verb_badreport(_):
        client.issues.create_comment(
            repo["owner"]["login"], repo["name"], issue["number"], BAD_ISSUE_MSG
        )
        client.reactions.create_for_issue_comment(
            repo["owner"]["login"], repo["name"], j["comment"]["id"], "+1"
        )

    verbs = {
        "autoclose": verb_autoclose,
        "rereview": verb_rereview,
        "bad-report": verb_badreport,
    }

    had_verb = False

    for verb, handler in verbs.items():
        trigger_me = "@frrbot {}".format(verb)
        if trigger_me.lower() in body.lower():
            LOG.warning("[+] Found trigger '%s'", verb)
            partition = body.lower().partition(trigger_me.lower())
            LOG.warning("[+] Trigger detected: %s %s", partition[1], partition[2])
            handler(partition[2])
            had_verb = True

    issueid = scheduler_make_id_issue(repo, issue)
    if not had_verb and scheduler.get_job(issueid) is not None:
        scheduler.remove_job(issueid)
        client.issues.remove_label(
            repo["owner"]["login"], repo["name"], issue["number"], TRIGGER_LABEL
        )
        client.issues.create_comment(
            repo["owner"]["login"], repo["name"], issue["number"], NO_AUTO_CLOSE_MSG
        )

    return "Ok"


@ghapp.on("pull_request.synchronize")
@ghapp.on("pull_request.opened")
def pull_request_opened_or_synchronized():
    """
    Handle a pull request being opened or synchronized.
    Synchronized means new commits were pushed to the branch tracked by the PR.

    - Add component labels
    - Review pull request for basic correctness

    If any issues are found, a review is submitted indicating the issues.
    """
    j = ghapp.payload

    client = ghapp.client()
    repo = j["repository"]
    pr = client.pulls.get(repo["owner"]["login"], repo["name"], j["number"])

    pull_request = FrrPullRequest(client, repo, pr)
    pull_request.add_labels()
    pull_request.check()

    return "Ok"


# Flask hooks ------------------------------------------------------------------


@app.route("/health")
def index():
    """
    Health check endpoint
    """
    return "Ok"
