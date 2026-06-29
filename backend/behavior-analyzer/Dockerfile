FROM python:3.12-slim
WORKDIR /app

# Install CodeQL CLI
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip && \
    wget -q https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz && \
    tar xzf codeql-bundle-linux64.tar.gz -C /opt && \
    rm codeql-bundle-linux64.tar.gz && \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql && \
    apt-get remove -y wget unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

ENTRYPOINT ["python", "-m", "behavior_analyzer"]
