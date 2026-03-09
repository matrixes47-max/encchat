# enc.chat v4.1 Enhanced - Multi-stage Docker build
FROM node:20-alpine AS base

# Install Tor (optional, for integrated deployment)
FROM base AS tor-base
RUN apk add --no-cache tor

# Production build
FROM base AS production
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application files
COPY server.js ./
COPY public ./public/

# Create non-root user for security
RUN addgroup -g 1001 -S encchat && \
    adduser -S encchat -u 1001 && \
    chown -R encchat:encchat /app

USER encchat

# Environment
ENV NODE_ENV=production \
    PORT=3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) })"

EXPOSE 3000

CMD ["node", "server.js"]

# Tor-integrated variant (larger image)
FROM tor-base AS tor-integrated
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY server.js ./
COPY public ./public/
COPY tor/torrc.example /etc/tor/torrc

RUN addgroup -g 1001 -S encchat && \
    adduser -S encchat -u 1001 && \
    mkdir -p /var/lib/tor/encchat && \
    chown -R tor:tor /var/lib/tor/encchat && \
    chown -R encchat:encchat /app

# Startup script to run both Tor and Node
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV NODE_ENV=production \
    PORT=3000 \
    TOR_ENABLED=true \
    TRUST_PROXY=true

EXPOSE 3000

ENTRYPOINT ["/entrypoint.sh"]
