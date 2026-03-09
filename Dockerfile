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
# kyber JS
RUN npm install -g esbuild --silent && \
    echo "const k=require('crystals-kyber-js');globalThis.Kyber768=k.Kyber768;globalThis.Kyber512=k.Kyber512;globalThis.Kyber1024=k.Kyber1024;" > /tmp/ke.js && \
    esbuild /tmp/ke.js --bundle --outfile=public/kyber.min.js --platform=browser --minify

# argon2 JS + WASM (FIX: .wasm ფაილები სავალდებულოა runtime-ზე)
RUN cp $(find node_modules/argon2-browser/dist -name "argon2.min.js" | head -1) public/argon2.min.js 2>/dev/null || \
    cp $(find node_modules/argon2-browser -name "*.min.js" | head -1) public/argon2.min.js && \
    find node_modules/argon2-browser -name "*.wasm" -exec cp {} public/ \; && \
    find node_modules/argon2-browser -name "argon2-simd.wasm" -exec cp {} public/ \; || true

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
