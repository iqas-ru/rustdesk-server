# iQAS: glibc build (hbb_common pulls native-tls/openssl, static musl via cross fails without vendored openssl)
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY hbbs hbbr rustdesk-utils /usr/bin/
WORKDIR /root
ENV HOME=/root
