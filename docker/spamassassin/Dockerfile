FROM debian:13-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends spamassassin && \
    rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
