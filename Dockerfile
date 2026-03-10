FROM node:20-alpine
WORKDIR /app

COPY package*.json ./
COPY build-kyber.js ./
RUN npm install --ignore-scripts && npm cache clean --force

COPY server.js ./
COPY public ./public/

# API-ს ვამოწმებთ და kyber.min.js-ს ვაწყობთ
RUN node -e "
(async () => {
  const lib = await import('./node_modules/crystals-kyber-js/dist/index.js');
  console.log('KEYS:', Object.keys(lib));
  const inst = new lib.Kyber768();
  const own = Object.getOwnPropertyNames(inst).filter(k => typeof inst[k] === 'function');
  let p = Object.getPrototypeOf(inst), proto = [];
  while(p && p !== Object.prototype){ proto.push(...Object.getOwnPropertyNames(p)); p = Object.getPrototypeOf(p); }
  console.log('OWN:', own);
  console.log('PROTO:', proto.filter(m => m !== 'constructor'));
})().catch(e => { console.error(e.message); });
"

RUN node build-kyber.js

RUN addgroup -g 1001 -S encchat && adduser -S encchat -u 1001 && chown -R encchat:encchat /app
USER encchat
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
