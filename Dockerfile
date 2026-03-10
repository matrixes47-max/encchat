FROM node:20-alpine
WORKDIR /app

COPY package*.json ./
COPY build-kyber.js ./
RUN npm install --ignore-scripts && npm cache clean --force

COPY server.js ./
COPY public ./public/

RUN node build-kyber.js

RUN addgroup -g 1001 -S encchat && adduser -S encchat -u 1001 && chown -R encchat:encchat /app
USER encchat
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
