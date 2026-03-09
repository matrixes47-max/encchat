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
# kyber JS — node-ით პირდაპირ bundle
RUN node -e "\
const k=require('crystals-kyber-js');\
const fs=require('fs');\
const src=fs.readFileSync(require.resolve('crystals-kyber-js'),{encoding:'utf8'});\
const wrap='(function(global){'+src+'\nglobal.Kyber768=module.exports.Kyber768;global.Kyber512=module.exports.Kyber512;global.Kyber1024=module.exports.Kyber1024;})(globalThis);';\
fs.writeFileSync('public/kyber.min.js',wrap);\
" 2>/dev/null || \
    find node_modules/crystals-kyber-js -name "*.js" ! -name "*.test.js" | head -1 | xargs -I{} cp {} public/kyber.min.js

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
