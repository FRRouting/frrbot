FROM tiangolo/uwsgi-nginx-flask:python3.8
RUN apt-get update \
	&& apt-get install -yy ca-certificates curl clang-format \
	&& pip install --upgrade pip
RUN curl -sSL https://install.python-poetry.org | python3 - --version 1.4.2 \
    && export PATH="/root/.local/bin:$PATH" \
    && poetry config virtualenvs.create false
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN export PATH="/root/.local/bin:$PATH" && poetry install
COPY . .
RUN mkdir /frrbot
