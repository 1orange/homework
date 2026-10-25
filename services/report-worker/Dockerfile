# syntax=docker/dockerfile:1.7

FROM python:3.11.9-bookworm AS dependencies

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.lock ./requirements.lock

# PyYAML 5.3.1 predates Python 3.11 wheels.  Cython is a build-only helper
# for the unchanged vulnerable lock entry; it is not part of the application
# runtime dependency set.
RUN python -m pip install --no-cache-dir Cython==0.29.36 \
    && python -m pip install --no-cache-dir --no-build-isolation --prefix=/install \
       -r requirements.lock pytest==8.3.5

FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY --from=dependencies /install /usr/local

COPY pyproject.toml ./pyproject.toml
COPY conftest.py ./conftest.py
COPY report_worker ./report_worker
COPY tests ./tests

RUN groupadd --system worker && useradd --system --gid worker --create-home worker \
    && chown -R worker:worker /app
USER worker

CMD ["pytest", "-q"]
