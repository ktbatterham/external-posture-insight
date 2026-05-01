FROM node:22.13.1-bookworm-slim

WORKDIR /app

COPY . .

RUN npm ci
RUN npm run build
RUN npm prune --omit=dev

ENV NODE_ENV=production

CMD ["npm", "run", "start"]
