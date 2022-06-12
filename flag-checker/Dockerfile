FROM node:18-alpine3.14

ENV flag "we{e5514bc336e94c74ae6cff66dccee4a5acc389c34d65fd62}"

COPY certs app/certs

WORKDIR /app
COPY package.json /app
RUN npm i

COPY flag_server.js /app

COPY index_server.js /app

COPY proxy.js /app

COPY start.sh /app
RUN chmod +x start.sh

CMD ./start.sh