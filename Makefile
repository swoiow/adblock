CURRENT_DATE?=$(shell date +%Y.%m.%d)
GITHUB_SHA?=main
DIST_PATH?=.

SHORT_SHA=$(shell git rev-parse --short $(GITHUB_SHA))
WORKSHOP?=edition-
PREFIX?=$(WORKSHOP)$(SHORT_SHA)
SUFFIX?=,$(CURRENT_DATE)

version:
	echo $(SHORT_SHA)
	echo $(GITHUB_SHA)
	echo $(PREFIX)$(SUFFIX)

clean:
	rm -rf .github/*.txt .github/rules/*.* .github/raw/*.* .build_space dist

generate:
	go get github.com/swoiow/blocked@$(GITHUB_SHA) && \
	go get github.com/swoiow/turned@main && \
	go generate

build-rules:
	go run .github/etl.go
	echo `date +%F`

build-inside-rules:
	go run .github/inside/etl.go

build-image:
	docker build -t runtime \
		-f .github/Dockerfile .

build-bin:
	docker run -i --rm \
		-e GITHUB_SHA=$(GITHUB_SHA) \
		-v ${PWD}/dist:/dist \
		runtime \
		make build_arm build_amd build_win_x64


build-local-osx: clean build-image
	docker run -it --rm -v `pwd`/.build_space:/build_space runtime cp -arf /app/ /build_space
	cd .build_space/app && \
		go get github.com/swoiow/blocked@$(GITHUB_SHA) && \
		go get github.com/swoiow/turned@main && \
		go generate && \
		GO111MODULE=auto \
		CGO_ENABLED=0 \
		GOOS=darwin \
		GOARCH=amd64 \
		go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(PREFIX)$(SUFFIX)" -o $(DIST_PATH)/coredns_osx

build_arm: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=arm64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(PREFIX)$(SUFFIX)" -o $(DIST_PATH)/coredns_arm

build_amd: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(PREFIX)$(SUFFIX)" -o $(DIST_PATH)/coredns_amd

build_win_x64: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=windows \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(PREFIX)$(SUFFIX)" -o $(DIST_PATH)/coredns_x64.exe
