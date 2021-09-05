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

**Option 3: Docker**

1. `docker build .`
2. `docker run -e GH_WEBHOOK_SECRET=<secret> -e GH_AUTH_TOKEN=<token> -e JOB_STORE_PATH=<path> --port 80:80 <image>`
3. frrbot will be listening on `0.0.0.0:80/frrbot`

Since the job store should outlive the container, you should mount a volume
where the job store should live from the host into the container before running
and set `JOB_STORE_PATH` appropriately. For example:

```
docker run --mount type=bind,source=/opt/frrbot,target=/frrbot -e GH_WEBHOOK_SECRET=<secret> -e GH_AUTH_TOKEN=<token> -e JOB_STORE_PATH=/frrbot/jobstore.sqlite <image>
```

uWSGI options within the container can be modified by changing `uwsgi.ini` in
this repository root and rebuilding the container.
