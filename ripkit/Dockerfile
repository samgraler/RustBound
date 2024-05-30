FROM python:3.10-bullseye as builder

RUN pip install poetry==1.8.3

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

RUN mkdir -p ~/.crates.io/cloned_crates
RUN mkdir -p ~/.ripbin/ripped_bins

COPY pyproject.toml poetry.lock ./
RUN touch README.md

RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --no-root

FROM python:3.10-slim-bullseye as runtime

COPY ripkit ripkit/

ENTRYPOINT ["poetry", "run", "python",  "ripkit/main.py"]
