frrbot
======

A GitHub bot for managing the FRRouting/frr repo.

Setup
-----
1. Install Python 3
2. Clone repo & `cd frrbot`
3. Install [poetry](https://python-poetry.org/docs/#osx-linux-bashonwindows-install-instructions)
4. `poetry install`
5. Copy `config.yaml.example` to `config.yaml`
6. Set up your webhooks on GitHub, generate a webhook secret and put it in the
   `gh_webhook_secret` field in `config.yaml`
7. Generate an auth token for the account you want the bot to use and put it in
   the `gh_auth_token field` in `config.yaml`
8. Set `job_store_path` to the desired path to write the sqlite job store.

Running
-------

**Option 1: `flask run`**

1. Set environment variable `FLASK_APP=frrbot.py`
2. Execute `flask run`
3. Configure your web server of choice to proxy your payload URL to
   `http://localhost:5000/` and reload it

**Option 2: WSGI**

1. Install [uwsgi](https://uwsgi-docs.readthedocs.io/en/latest/)
2. Use `./run.sh` to create and mount a WSGI endpoint on `/frrbot` and configure
   your web server to WSGI proxy your payload URL to it
