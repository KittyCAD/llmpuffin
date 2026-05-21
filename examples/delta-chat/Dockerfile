FROM node:22-slim AS base
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/chatmail/core.git /src
WORKDIR /src
