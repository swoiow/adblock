CURRENT_DATE?=$(shell date +%Y_%m_%d)
GITHUB_SHA?=main

clean:
	rm -rf ./.github/*.txt ./.github/rules/*.* ./.github/raw/*.*

generate:
	go get github.com/swoiow/blocked@$(GITHUB_SHA) && \
    go get github.com/leiless/dnsredir && \
	go generate

build-rules:
	go run .github/etl.go

build-image:
	docker build -t runtime \
		-f .github/Dockerfile .

build-bin:
	docker run -i --rm \
		-e GITHUB_SHA=$(GITHUB_SHA) \
		-v ${PWD}/dist:/dist \
		runtime \
		make build_arm build_amd build_win_x64


build_osx: generate
	GO111MODULE=auto \
	CGO_ENABLED=1 \
	GOOS=darwin \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o ./coredns_osx

build_arm: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=arm64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_arm

build_amd: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_amd

build_win_x64: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=windows \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_x64.exe
