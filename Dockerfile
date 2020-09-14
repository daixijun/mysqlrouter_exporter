FROM alpine:3.12
LABEL MAINTAINER="Xijun Dai <daixijun1990@gmail.com>"

ENV TZ=Asia/Shanghai

RUN apk add --no-cache ca-certificates tzdata && \
    ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo "${TZ}" > /etc/timezone

COPY mysqlrouter_exporter /usr/local/bin/
COPY docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "/usr/local/bin/mysqlrouter_exporter", "-h" ]