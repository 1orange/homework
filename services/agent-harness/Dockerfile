# syntax=docker/dockerfile:1.7

FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# The repository-root build context is intentional: the image embeds the
# supplied findings fixture, while the harness itself remains a standalone
# package and has no access to the host filesystem at runtime.
COPY services/agent-harness/ /app/
COPY findings/findings.json /app/findings/findings.json

# This is a source-tree developer image: install the pinned dependencies,
# but do not install a second copy of the project into site-packages.  Running
# the module from /app keeps code, policies, and fixture catalogs on one path.
RUN python -m pip install --no-cache-dir -r requirements.lock \
    && python -m pip install --no-cache-dir -r requirements-dev.lock

RUN groupadd --system harness && useradd --system --gid harness --create-home harness \
    && mkdir -p /evidence \
    && chown -R harness:harness /app /evidence
USER harness

# Compose overrides this with explicit test/evaluation tasks.  Keeping a
# harmless default makes the image useful with `docker run` as well.
CMD ["python", "-m", "agent_harness", "--help"]
