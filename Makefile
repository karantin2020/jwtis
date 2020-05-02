BIN            = jwtis
CLIENT_BIN     = jcli
BUILD         ?= $(shell git rev-parse --short HEAD)
BUILD_DATE    ?= $(shell git log -1 --format=%cI --date=iso-strict)
BUILD_BRANCH  ?= $(shell git rev-parse --abbrev-ref HEAD)
BUILD_VERSION ?= $(shell git describe --always --tags)
BUILD_TIME    ?= $(shell date --iso-8601=seconds)
BUILD_TAGS    ?=
GOPATH        ?= $(shell go env GOPATH)

BASEPATH = github.com/karantin2020/jwtis
CLIENTPATH = github.com/karantin2020/jwtis/client
# BUILDPATH = ./cmd

export GO111MODULE := off

# Build-time Go variables - server
appVersion     = ${BASEPATH}/version.AppVersion
gitBranch      = ${BASEPATH}/version.GitBranch
lastCommitSHA  = ${BASEPATH}/version.LastCommitSHA
lastCommitTime = ${BASEPATH}/version.LastCommitTime
buildTime      = ${BASEPATH}/version.BuildTime

# Build-time Go variables - client
clientAppVersion     = ${CLIENTPATH}/pkg/version.AppVersion
clientGitBranch      = ${CLIENTPATH}/pkg/version.GitBranch
clientLastCommitSHA  = ${CLIENTPATH}/pkg/version.LastCommitSHA
clientLastCommitTime = ${CLIENTPATH}/pkg/version.LastCommitTime
clientBuildTime      = ${CLIENTPATH}/pkg/version.BuildTime

BUILD_FLAGS   ?= -ldflags '-s -w -X ${lastCommitSHA}=${BUILD} -X "${lastCommitTime}=${BUILD_DATE}" -X "${appVersion}=${BUILD_VERSION}" -X ${gitBranch}=${BUILD_BRANCH} -X ${buildTime}=${BUILD_TIME}'

CLIENT_BUILD_FLAGS   ?= -ldflags '-s -w -X ${clientLastCommitSHA}=${BUILD} -X "${clientLastCommitTime}=${BUILD_DATE}" -X "${clientAppVersion}=${BUILD_VERSION}" -X ${clientGitBranch}=${BUILD_BRANCH} -X ${clientBuildTime}=${BUILD_TIME}'

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

protoapi:
	@ if ! which protoc > /dev/null; then \
		echo "error: protoc not installed" >&2; \
		exit 1; \
	fi
	for x in api/*/*/*.proto; \
	do protoc -I/usr/local/include -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway \
		-I${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
		--gogofaster_out=plugins=grpc,paths=source_relative:. \
		$$x; done


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
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -v -o cmd/${BIN} ./cmd

clientbuild:
	CGO_ENABLED=0 go build $(CLIENT_BUILD_FLAGS) -v -o client/${CLIENT_BIN} ./client