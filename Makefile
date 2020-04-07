BIN            = jwtis
BUILD         ?= $(shell git rev-parse --short HEAD)
BUILD_DATE    ?= $(shell git log -1 --format=%ai)
BUILD_BRANCH  ?= $(shell git rev-parse --abbrev-ref HEAD)
BUILD_VERSION ?= $(shell git describe --always --tags)
BUILD_TAGS    ?=
GOPATH        ?= $(shell go env GOPATH)

export GO111MODULE := off

# Build-time Go variables
appVersion     = github.com/karantin2020/jwtis/cmdz/cmd.appVersion
gitBranch      = github.com/karantin2020/jwtis/cmdz/cmd.gitBranch
lastCommitSHA  = github.com/karantin2020/jwtis/cmdz/cmd.lastCommitSHA
lastCommitTime = github.com/karantin2020/jwtis/cmdz/cmd.lastCommitTime

BUILD_FLAGS   ?= -ldflags '-s -w -X ${lastCommitSHA}=${BUILD} -X "${lastCommitTime}=${BUILD_DATE}" -X "${appVersion}=${BUILD_VERSION}" -X ${gitBranch}=${BUILD_BRANCH}'

all: proto openapi

proto:
	@ if ! which protoc > /dev/null; then \
		echo "error: protoc not installed" >&2; \
		exit 1; \
	fi
	protoc -I/usr/local/include -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway \
		-I${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
		--gogofaster_out=plugins=grpc,import_path=jwtispb:. api/jwtispb/*.proto

goclay:
	@ if ! which protoc > /dev/null; then \
		echo "error: protoc not installed" >&2; \
		exit 1; \
	fi
	protoc -I/usr/local/include -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway \
		-I${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
		--gogofaster_out=plugins=grpc,import_path=jwtispb:. \
		--goclay_out=force=true:. api/pb/*.proto

openapi:
	@ if ! which protoc > /dev/null; then \
		echo "error: protoc not installed" >&2; \
		exit 1; \
	fi
	protoc -I/usr/local/include -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway \
		-I${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
		--swagger_out=logtostderr=true:. http/pb/*.proto

clear:
	rm http/pb/svc.pb.go; \
	rm cmd/jwtis; \
	rm http/swagger/*

cleardb:
	rm cmd/data/keys.db

build:
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -v -o cmdz/jwtis ./cmdz