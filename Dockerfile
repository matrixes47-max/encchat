# enc.chat v4.2 - Docker build
FROM node:20-alpine AS base

# Production build (default)
FROM base AS production
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

COPY server.js ./
COPY public ./public/

RUN addgroup -g 1001 -S encchat && \
    adduser -S encchat -u 1001 && \
    chown -R encchat:encchat /app

USER encchat

ENV NODE_ENV=production \
    PORT=3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) })"

EXPOSE 3000
CMD ["node", "server.js"]
