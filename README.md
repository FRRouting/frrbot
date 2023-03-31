frrbot
======

A GitHub bot for managing the FRRouting/frr repo.

## Quickstart

```
git clone https://github.com/frrouting/frrbot.git
cd frrbot
mkdir data
cp .env.sample .env
# Edit .env and fill in all values
docker compose up -d
```

The app will now be listening on 127.0.0.1:9091. You can either:

- change the port in `docker-compose.yml` to `80`, or
- set up a reverse proxy from 80 to 9091

The latter is recommended; this way you can set up TLS in the reverse proxy.

* `GH_WEBHOOK_SECRET` should be the webhook secret used to authenticate requests from GitHub
* `GH_APP_ID` should be the ID of your GitHub App
* `GP_APP_ROUTE` should be the URL you want to listen for webhooks on
  *relative to the uWSGI mountpoint*
* `GH_APP_PKEY_PEM_PATH` should be the absolute path to the PEM format private
  key associated with your GitHub App; you should mount the key into the
  container at that path
* `GH_GIST_USER_TOKEN` should be a personal access token for a real user. This
  user will be used to host gists, since GitHub apps can't use gists.


Miscellaneous notes:

* uWSGI options within the container can be modified by changing `uwsgi.ini` in
  this repository root and rebuilding the container.
* The job store sqlite database will be in `data/jobstore.sqlite`


## Development

### Running manually 
1. `docker build --tag frrbot:latest .`
2. `docker run -e GH_WEBHOOK_SECRET=<secret> GH_APP_ROUTE="/gh" GH_APP_ID=<ID> -e GH_APP_PKEY_PEM_PATH=<path> -e JOB_STORE_PATH=<path> --port 80:80 frrbot:latest`
3. frrbot will be listening on `0.0.0.0:80/frrbot/gh`
