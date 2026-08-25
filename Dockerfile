FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10001 mcp \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --shell /usr/sbin/nologin \
        mcp

COPY pyproject.toml .
COPY src/ ./src/

RUN pip install --no-cache-dir .

USER mcp:mcp

EXPOSE 8000

CMD ["python", "-m", "peek_mcp"]
