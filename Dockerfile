# enc.chat v4.2 - Docker build
FROM node:20-alpine
WORKDIR /app

# პირველ dependency-ები
COPY package*.json ./
COPY build-kyber.js ./
RUN npm install --ignore-scripts && \
    npm cache clean --force

# შემდეგ source ფაილები
COPY server.js ./
COPY public ./public/

# ახლა ვაწყობთ kyber + argon2 — public/ უკვე ადგილზეა
RUN node build-kyber.js

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
