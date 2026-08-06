FROM node@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

WORKDIR /workspace
COPY package.json package-lock.json ./

RUN npm install --global --ignore-scripts --no-audit --no-fund npm@12.0.2

ARG NPM_CONFIG_MIN_RELEASE_AGE
ARG NPM_CONFIG_ALLOW_GIT
ARG NPM_CONFIG_ALLOW_REMOTE
ARG NPM_CONFIG_SAVE_EXACT

RUN npm config set allow-git none --location=user \
    && npm config set allow-remote none --location=user \
    && npm config set min-release-age "$NPM_CONFIG_MIN_RELEASE_AGE" --location=user \
    && npm config set save-exact "$NPM_CONFIG_SAVE_EXACT" --location=user \
    && npm ci --no-audit --no-fund \
    && rm -rf /root/.npm /tmp/*

RUN mkdir /capsule-tmp && chown 65532:65532 /capsule-tmp
ENV NODE_ENV=test
