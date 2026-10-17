FROM lejianwen/rustdesk-api:latest
ADD https://raw.githubusercontent.com/marquinhomdk22/expresschat-remoto/1f41cfc/painel/admin.tar.gz /tmp/admin.tar.gz
RUN rm -rf /app/resources/admin && mkdir -p /app/resources/admin && tar xzf /tmp/admin.tar.gz -C /app/resources/admin && rm /tmp/admin.tar.gz
