FROM node:22-slim AS base
RUN apt-get update && apt-get install -y git
RUN git clone --depth 1 https://github.com/curl/curl /src
WORKDIR /src
