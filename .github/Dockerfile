FROM golang:alpine

WORKDIR /app

ADD https://github.com/swoiow/ftw-ci/raw/main/vendors/golang/bin/gr /usr/bin

RUN chmod +x /usr/bin/gr && \
    apk add git wget curl make upx zip

RUN stableTag=$(gr "coredns/coredns") && \
    echo $stableTag && \
    git clone --depth 1 --branch $stableTag https://github.com/coredns/coredns.git /app

COPY .github/plugin.cfg /app/plugin.cfg
COPY Makefile /app/Makefile
CMD ["sh"]