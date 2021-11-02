FROM golang:alpine

WORKDIR /app

ADD https://github.com/swoiow/ftw-ci/raw/main/vendors/golang/bin/gr /usr/bin

RUN chmod +x /usr/bin/gr && \
    apk add git wget curl make upx zip

RUN git clone https://github.com/coredns/coredns.git /app && \
    git fetch --tags && \
    stableTag=$(gr "coredns/coredns") && \
    git checkout $stableTag

COPY .github/plugin.cfg /app/plugin.cfg
COPY Makefile /app/Makefile
CMD ["sh"]