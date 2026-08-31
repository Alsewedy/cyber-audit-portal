FROM node:22-alpine

WORKDIR /app

RUN apk add --no-cache curl jq

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

EXPOSE 3050
EXPOSE 4500

CMD ["node", "server.js"]
