FROM nginx:1.28-alpine
RUN apk add --no-cache bash openssl
COPY docker/nginx.conf /etc/nginx/templates/default.conf.template
COPY scripts/start-attacker.sh /lab/start-attacker.sh
ENTRYPOINT ["bash", "/lab/start-attacker.sh"]
