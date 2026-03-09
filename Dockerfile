# enc.chat v4.2 - Docker build
FROM node:20-alpine AS base

# Production build (default)
FROM base AS production
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev && \
    npm cache clean --force

COPY server.js ./
COPY public ./public/

# ბიბლიოთეკები CDN-ის გარეშე — ლოკალურად
# argon2 JS + WASM
RUN cp $(find node_modules/argon2-browser/dist -name "argon2.min.js" | head -1) public/argon2.min.js 2>/dev/null || \
    cp $(find node_modules/argon2-browser -name "*.min.js" | head -1) public/argon2.min.js && \
    find node_modules/argon2-browser -name "*.wasm" -exec cp {} public/ \; && \
    find node_modules/argon2-browser -name "argon2-simd.wasm" -exec cp {} public/ \; || true

# kyber JS — ML-KEM-768
RUN node -e " \
  const k = require('crystals-kyber-js'); \
  const fs = require('fs'); \
  const src = 'const Kyber768 = (' + k.Kyber768.toString() + ')(); if(typeof module!==\"undefined\") module.exports={Kyber768};'; \
  fs.writeFileSync('public/kyber.min.js', src); \
" 2>/dev/null || \
    find node_modules/crystals-kyber-js -name "*.js" ! -path "*/node_modules/*/node_modules/*" | head -1 | xargs -I{} cp {} public/kyber.min.js || true

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
