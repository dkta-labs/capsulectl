FROM node@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

ARG NPM_CONFIG_MIN_RELEASE_AGE
ARG NPM_CONFIG_ALLOW_GIT
ARG NPM_CONFIG_ALLOW_REMOTE
ARG NPM_CONFIG_SAVE_EXACT
RUN test "$NPM_CONFIG_MIN_RELEASE_AGE" = "3" \
    && test "$NPM_CONFIG_ALLOW_GIT" = "none" \
    && test "$NPM_CONFIG_ALLOW_REMOTE" = "none" \
    && test "$NPM_CONFIG_SAVE_EXACT" = "true"
RUN node --input-type=module --eval \
      "import { writeFile } from 'node:fs/promises'; const response = await fetch('https://registry.npmjs.org/npm/-/npm-12.0.2.tgz'); if (!response.ok) throw new Error('npm download failed: ' + response.status); await writeFile('/tmp/npm-12.0.2.tgz', Buffer.from(await response.arrayBuffer()));" \
    && printf '%s  %s\n' \
      b885e890b9418fa1693544d05f53e64f9a73ec194837d4258b15fecdd692347b1dd2a517b1b0cbaf9d31cd8e92c3b70956bd2ecc72833a57b4b3098f5bfa7943 \
      /tmp/npm-12.0.2.tgz \
      | sha512sum --check --strict \
    && rm -rf /usr/local/lib/node_modules/npm \
    && mkdir -p /usr/local/lib/node_modules/npm \
    && tar --extract --gzip --file /tmp/npm-12.0.2.tgz \
      --strip-components=1 --directory /usr/local/lib/node_modules/npm \
    && ln -sfn ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -sfn ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && test "$(npm --version)" = "12.0.2" \
    && rm -f /tmp/npm-12.0.2.tgz

WORKDIR /workspace
