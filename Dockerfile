# Multi-stage lightweight production container
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

COPY package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY server.js ./
COPY public ./public

EXPOSE 8080

# Run unprivileged
USER node

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "server.js"]
