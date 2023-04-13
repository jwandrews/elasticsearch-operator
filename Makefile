# Makefile for the Docker image upmcenterprises/elasticsearch-operator
# MAINTAINER: Steve Sloka <steve@stevesloka.com>

.PHONY: all build container push clean test

TAG ?= 0.4.0
PREFIX ?= upmcenterprises
pkgs = $(shell go list ./... | grep -v /vendor/ | grep -v /test/)

all: container

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -o _output/bin/elasticsearch-operator --ldflags '-w' ./cmd/operator/main.go

container: build
	docker build \
		--platform=linux/amd64 \
		-t $(PREFIX)/elasticsearch-operator:$(TAG) \
		.

push:
	docker push $(PREFIX)/elasticsearch-operator:$(TAG)

clean:
	rm -f elasticsearch-operator

format:
	go fmt $(pkgs)

check:
	@go vet ./...

helm-package:
	helm package charts/{elasticsearch,elasticsearch-operator} -d charts
	helm repo index --merge charts/index.yaml charts

test: clean
	go test $$(go list ./... | grep -v /vendor/)

devpreq:
	mkdir -p /tmp/certs/config && mkdir -p /tmp/certs/certs
	go get -u github.com/cloudflare/cfssl/cmd/cfssl
	go get -u github.com/cloudflare/cfssl/cmd/cfssljson
