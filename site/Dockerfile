FROM nginx:alpine
ARG REV=master
ADD https://raw.githubusercontent.com/marquinhomdk22/expresschat-remoto/${REV}/painel/site.tar.gz /tmp/site.tar.gz
RUN tar xzf /tmp/site.tar.gz -C /usr/share/nginx/html && rm /tmp/site.tar.gz
