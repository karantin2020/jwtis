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
		--gogofaster_out=plugins=grpc,import_path=jwtispb:. http/pb/*.proto

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
		--goclay_out=. http/pb/*.proto

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
	CGO_ENABLED=0 go build -ldflags="-s -w" -v -o cmd/jwtis ./cmd