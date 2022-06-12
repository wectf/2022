FROM node:18

WORKDIR /app

RUN wget https://artifacts.elastic.co/downloads/logstash/logstash-7.15.0-linux-x86_64.tar.gz

RUN tar xzvf logstash-7.15.0-linux-x86_64.tar.gz && mv logstash-7.15.0 logstash

COPY log.conf .
COPY package.json .
RUN npm i
COPY server.js .
COPY views/ ./views

COPY start.sh .
RUN chmod +x start.sh

RUN echo "we{88b93d4b-0fb0-423a-8971-bdb9cfaa04ef@L0g4Sh311.1n.1nt3rna1.Netw0rk}" > /flag

CMD ./start.sh
