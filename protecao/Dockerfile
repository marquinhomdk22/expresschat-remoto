FROM node:20-alpine
WORKDIR /app
ADD https://raw.githubusercontent.com/marquinhomdk22/expresschat-remoto/8d0874a/protecao/api.tar.gz /tmp/api.tar.gz
RUN tar xzf /tmp/api.tar.gz -C /app && rm /tmp/api.tar.gz && npm ci --omit=dev
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
