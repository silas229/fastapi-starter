# Overview

This is a template for FastAPI projects with a SQLite database. It is expected to run with Python 3.11-3.13

## Development setup

The repository are using *poetry* for dependency management. You can get it [here](https://python-poetry.org/docs/#installing-with-the-official-installer).

For setup, run the following commands:

```sh
poetry install
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
poetry run app.main:app --reload
```
