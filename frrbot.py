#!/usr/bin/env python3
#
# Deps:
# pip3 install flask PyGithub apscheduler sqlalchemy dateparser pygit2 requests
#
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from flask import Response
from flask import request
from github import Github
from github import GithubException
from github import InputFileContent
from hmac import HMAC
from werkzeug.exceptions import BadRequest
from collections import defaultdict
import dateparser
import datetime
import hmac
import json
import os
import re
import yaml
import subprocess
import pygit2
import requests
import time

# Global data ------------------------------------------------------------------
autoclosemsg = "This issue will be automatically closed in one week unless there is further activity."
noautoclosemsg = "This issue will no longer be automatically closed."
triggerlabel = "autoclose"
banned_functions = [("sprintf", "snprintf"), ("strcat", "strlcat"), ("strcpy", "strlcpy")]

pr_greeting_msg = "Thanks for your contribution to FRR!\n\n"
pr_warn_signoff_msg = "* One of your commits has a missing or badly formatted `Signed-off-by` line; we can't accept your contribution until all of your commits have one\n"
pr_warn_blankln_msg = "* One of your commits does not have a blank line between the summary and body; this will break `git log --oneline`\n"
pr_warn_commit_msg = (
    "* One of your commits has an improperly formatted commit message\n"
)
pr_warn_banned_functions = "* `{}` are banned; please use `{}`\n".format(', '.join([x[0] for x in banned_functions]), ', '.join([x[1] for x in banned_functions]))
pr_guidelines_ref_msg = "\nIf you are a new contributor to FRR, please see our [contributing guidelines](http://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#coding-practices-style).\n"

# Scheduler functions ----------------------------------------------------------


def close_issue(rn, num):
    app.logger.warning("[+] Closing issue #{}".format(num))
    repo = g.get_repo(rn)
    issue = repo.get_issue(num)
    issue.edit(state="closed")
    try:
        issue.remove_from_labels(triggerlabel)
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
    app.logger.warning(
        "[-] Scheduling issue #{} for autoclose (id: {})".format(issuenum, issueid)
    )
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
    app.logger.warning("[-] Descheduling issue #{} for closing".format(issuenum))
    scheduler.remove_job(issueid)


# Module init ------------------------------------------------------------------

print("[+] Loading config")

with open("config.yaml", "r") as conffile:
    conf = yaml.safe_load(conffile)
    whsec = conf["gh_webhook_secret"]
    auth = conf["gh_auth_token"]

print("[+] Github auth token: {}".format(auth))
print("[+] Github webhook secret: {}".format(whsec))

# Initialize GitHub API
g = Github(auth)
my_user = g.get_user()
print("[+] Initialized GitHub API object")

# Initialize scheduler
jobstores = {"default": SQLAlchemyJobStore(url="sqlite:///jobs.sqlite")}
scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()
print("[+] Initialized scheduler")
print("[+] Current jobs:")
scheduler.print_jobs()

# Initialize Flask app
app = Flask(__name__)
print("[+] Initialized Flask app")


# Pull request management ------------------------------------------------------

class FrrPullRequest(object):
    def __init__(self, repo, pr):
        self.repo = repo
        self.pr = pr


    def check_format(self):
        """
        Compute a clang-format diff for a pull request.

        Returns None if:
        - the diff is empty (no style issues)
        - any of the git operations fail
        - git-clang-format isn't installed

        Otherwise returns the style correction diff produced by clang-format.
        """
        repodir = "my_frr"

        ignore = [
            "ldpd",
            "babeld",
            "nhrpd",
            "eigrpd",
        ]

        # get repo
        if not os.path.isdir(repodir):
            pygit2.clone_repository(self.repo.git_url, repodir)

        # fetch pr diff
        resp = requests.get(self.pr.diff_url)
        if resp.status_code != 200:
            app.logger.warning(
                "[-] GET '{}' failed with HTTP {}".format(self.pr.diff_url, resp.status_code)
            )
            return None
        if len(resp.text) == 0:
            app.logger.warning("[-] diff at '{}' is empty".format(self.pr.diff_url))
            return None
        dn = "/tmp/pr_{}.diff".format(self.pr.number)
        with open(dn, "w") as change:
            change.write(resp.text)

        app.logger.warning("[+] Fetching {}".format(self.pr.base.sha))
        cmd = "git -C {} fetch origin {}".format(repodir, self.pr.base.sha).split(" ")
        subprocess.run(cmd)
        app.logger.warning("[+] Resetting to {}".format(self.pr.base.sha))
        cmd = "git -C {} reset --hard {}".format(repodir, self.pr.base.sha).split(" ")
        subprocess.run(cmd)
        app.logger.warning("[+] Applying patch")
        cmd = "git -C {} apply {}".format(repodir, dn).split(" ")
        subprocess.run(cmd)
        app.logger.warning("[+] Applying ignore rules")
        cmd = "git -C {} checkout -- {}".format(repodir, " ".join(ignore)).split(" ")
        subprocess.run(cmd)
        app.logger.warning("[+] Staging patch")
        cmd = "git -C {} add -u".format(repodir).split(" ")
        subprocess.run(cmd)
        app.logger.warning("[+] Generating style diff")
        cmd = "git -C {} clang-format --diff".format(repodir).split(" ")
        result = subprocess.run(cmd, stdout=subprocess.PIPE).stdout

        app.logger.warning("[+] Result: {}".format(result))
        result = result.decode("utf-8") if result is not None else result
        if result and "did not modify" not in result and "no modified files" not in result:
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
        commits = self.pr.get_commits()

        warns = defaultdict(bool)

        for commit in commits:
            msg = commit.commit.message

            if len(msg) == 0:
                app.logger.warning("[-] Zero length commit message; weird")
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
        resp = requests.get(self.pr.diff_url)
        if resp.status_code != 200:
            app.logger.warning(
                "[-] GET '{}' failed with HTTP {}".format(self.pr.diff_url, resp.status_code)
            )
            return None
        if len(resp.text) == 0:
            app.logger.warning("[-] diff at '{}' is empty".format(self.pr.diff_url))
            return None

        added = [x for x in resp.text.split("\n") if x.startswith("+")]
        banned = [x[0] for x in banned_functions]
        has_banned_functions = any([any([y in x for y in banned]) for x in added])

        return has_banned_functions


    def check(self):
        issues = defaultdict(lambda: None)

        issues["commits"] = self.check_commits()

        try:
            issues["style"] = self.check_format()
        except Exception as e:
            app.logger.warning("[-] Style checking failed:\n" + str(e))

        try:
            issues["functions"] = self.check_functions()
        except Exception as e:
            app.logger.warning("[-] Function checking failed:\n" + str(e))

        return issues


    def review(self):
        issues = self.check()

        app.logger.warning("[+] Reviewing {}".format(self.pr.number))

        comment = ""
        nak = False

        if issues["commits"]:
            if issues["commits"]["bad_msg"]:
                comment += pr_warn_commit_msg
                nak = True
            if issues["commits"]["signoff"]:
                comment += pr_warn_signoff_msg
                nak = True
            if issues["commits"]["blankln"]:
                comment += pr_warn_blankln_msg
                nak = True
        if issues["functions"]:
            comment += pr_warn_banned_functions
            nak = True
        if issues["style"]:
            try:
                gistname = "cr_{}_{}.diff".format(self.pr.number, int(time.time()))
                files = {gistname: InputFileContent(issues["style"])}
                gist = my_user.create_gist(True, files, "FRRouting/frr #{}".format(self.pr.number))
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

            """.format(gisturl=raw_url, stylediff=issues["style"])

            except Exception as e:
                app.logger.warning("[-] Failed to create gist: ")
                app.logger.warning(e)

        # dismiss previous reviews if necessary
        if not nak:
            for r in self.pr.get_reviews():
                if r.user.id == my_user.id and r.state == "CHANGES_REQUESTED":
                    r.dismiss("blocking comments addressed")

        # Post review
        if comment != "":
            comment = pr_greeting_msg + comment
            comment += pr_guidelines_ref_msg
            event = "COMMENT" if not nak else "REQUEST_CHANGES"
            self.pr.create_review(body=comment, event=event)

        return comment


    def add_labels(self):
        """
        Label a pull request using component directories present in the commit
        message subject lines.
        """
        # directory -> label
        label_map = {
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

        commits = self.pr.get_commits()
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

        if labels:
            self.pr.add_to_labels(*labels)



# Webhook handlers -------------------------------------------------------------


def issue_labeled(j):
    reponame = j["repository"]["full_name"]
    issuenum = j["issue"]["number"]
    issue = g.get_repo(reponame).get_issue(issuenum)

    def label_autoclose():
        closedate = datetime.datetime.now() + datetime.timedelta(weeks=1)
        schedule_close_issue(issue, closedate)
        issue.create_comment(autoclosemsg)

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
        if not (perm == "write" or perm == "admin"):
            app.logger.warning(
                "[-] User '{}' ({}) isn't authorized to use this command".format(
                    sender, perm
                )
            )
            return

        closedate = dateparser.parse(arg)
        if closedate is not None and closedate > datetime.datetime.now():
            schedule_close_issue(issue, closedate)
            issue.add_to_labels("autoclose")
            issue.get_comment(j["comment"]["id"]).create_reaction("+1")
        elif closedate is None:
            app.logger.warning("[-] Couldn't parse '{}' as a datetime".format(arg))

    verbs = {"autoclose": verb_autoclose}

    had_verb = False

    for verb in verbs.keys():
        tp = "@{} {} ".format(my_user.login, verb)
        if tp.lower() in body.lower():
            partition = body.lower().partition(tp.lower())
            app.logger.warning(
                "[+] Trigger detected: {} {}".format(partition[1], partition[2])
            )
            verbs[verb](partition[2])
            had_verb = True

    issueid = "{}@@@{}".format(reponame, issuenum)
    if not had_verb and scheduler.get_job(issueid) is not None:
        scheduler.remove_job(issueid)
        issue.remove_from_labels(triggerlabel)
        issue.create_comment(noautoclosemsg)

    return Response("OK", 200)



def pull_request_opened(j):
    """
    Handle a pull request being opened.

    - Add component labels
    - Review pull request for basic correctness

    If any issues are found, a review is submitted indicating the issues.
    """
    repo = g.get_repo(j["repository"]["full_name"])
    pr = repo.get_pull(j["number"])

    pr = FrrPullRequest(repo, pr)
    pr.add_labels()
    pr.review()

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


def handle_webhook(request):
    try:
        evtype = request.headers["X_GITHUB_EVENT"]
    except KeyError as e:
        app.logger.warning("[-] No X-GitHub-Event header...")
        return Response("No X-GitHub-Event header", 400)

    app.logger.warning("[+] Handling webhook '{}'".format(evtype))

    try:
        event = event_handlers[evtype]
    except KeyError as e:
        app.logger.warning("[+] Unknown event '{}'".format(evtype))
        return Response("OK", 200)

    try:
        j = request.get_json()
    except BadRequest as e:
        app.logger.warning("[-] Could not parse payload as JSON")
        return Response("Bad JSON", 400)

    try:
        action = j["action"]
    except KeyError as e:
        app.logger.warning("[+] No action for event '{}'".format(evtype))
        return Response("OK", 200)

    try:
        handler = event_handlers[evtype][action]
    except KeyError as e:
        app.logger.warning("[+] No handler for action '{}'".format(action))
        return Response("OK", 200)

    try:
        sender = j["sender"]["login"]
        if sender == my_user.login:
            app.logger.warning("[+] Ignoring event triggered by me")
            return Response("OK", 200)
    except KeyError as e:
        pass

    app.logger.warning("[+] Handling action '{}' on event '{}'".format(action, evtype))
    return handler(j)


# Flask hooks ------------------------------------------------------------------


def gh_sig_valid(req):
    mydigest = "sha1=" + HMAC(bytes(whsec, "utf8"), req.get_data(), "sha1").hexdigest()
    ghdigest = req.headers["X_HUB_SIGNATURE"]
    comp = hmac.compare_digest(ghdigest, mydigest)
    app.logger.warning("[+] Request: mine = {}, theirs = {}".format(mydigest, ghdigest))
    return comp


@app.route("/", methods=["GET", "POST"])
def parse_payload():
    try:
        if not gh_sig_valid(request):
            return Response("Unauthorized", 401)
    except:
        return Response("Unauthorized", 401)

    if request.method == "POST":
        return handle_webhook(request)
    else:
        return Response("OK", 200)
