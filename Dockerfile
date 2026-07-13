FROM oven/bun:1.3.13 AS dependencies

WORKDIR /app

COPY package.json bun.lock ./

RUN bun install --frozen-lockfile --production

FROM oven/bun:1.3.13

WORKDIR /app
ENV NODE_ENV=production

COPY --from=dependencies /app/node_modules ./node_modules
COPY --chown=bun:bun package.json ./
COPY --chown=bun:bun src ./src

EXPOSE 3000

USER bun

CMD ["bun", "run", "start"]
