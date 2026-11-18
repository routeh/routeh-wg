# What the OpenWrt SDK needs on its host. linux/amd64: the SDK's tools are
# x86_64 binaries.
FROM debian:bookworm
RUN apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
      build-essential ca-certificates curl file gawk git gettext libncurses-dev \
      python3 python3-setuptools rsync unzip wget xz-utils zstd kmod \
    && rm -rf /var/lib/apt/lists/*
