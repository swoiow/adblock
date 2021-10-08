CURRENT_DATE:=$(shell date +%Y_%m_%d)


clean:
	rm -rf ./.github/*.txt ./.github/rules/*.* ./.github/raw/*.*

generate:
	go get github.com/swoiow/blocked@$(GITHUB_SHA) && \
    go get github.com/leiless/dnsredir && \
	go generate

build-image:
	docker build -t runtime \
		-f .github/Dockerfile .

build-bin:
	docker run -i --rm \
		-e GITHUB_SHA=$(GITHUB_SHA) \
		-v ${PWD}/dist:/dist \
		runtime \
		make build_arm build_amd build_amd_win


build_osx: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=darwin \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_osx
	upx -9 -o /dist/coredns_osx coredns_osx
	zip /dist/coredns_osx.zip /dist/coredns_osx

build_arm: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=arm64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_arm
	upx -9 -o /dist/coredns_arm coredns_arm
	zip /dist/coredns_arm.zip /dist/coredns_arm

build_amd: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_amd
	upx -9 -o /dist/coredns_amd coredns_amd
	zip /dist/coredns_amd.zip /dist/coredns_amd

build_amd_win: generate
	GO111MODULE=auto \
	CGO_ENABLED=0 \
	GOOS=windows \
	GOARCH=amd64 \
	go build -ldflags "-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(CURRENT_DATE)" -o coredns_x64.exe
	upx -9 -o /dist/coredns_x64.exe coredns_x64.exe
	zip /dist/coredns_x64.zip /dist/coredns_x64.exe
