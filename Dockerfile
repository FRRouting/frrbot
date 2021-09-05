FROM tiangolo/uwsgi-nginx-flask:python3.8
RUN apt-get update \
	&& apt-get install -yy ca-certificates curl \
	&& curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python - \
	&& export PATH="/root/.local/bin:$PATH" \
	&& poetry config virtualenvs.create false
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN export PATH="/root/.local/bin:$PATH" && poetry install
COPY . .
RUN mkdir /frrbot
