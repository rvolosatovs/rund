.PHONY: all
all: assets/rootfs api

DOCKER ?= docker
PROTOC_OUT ?= /out
PROTOC ?= $(DOCKER) run --user `id -u` --rm \
                    	--mount type=bind,src=$(PWD)/api,dst=$(PWD)/api \
                     	--mount type=bind,src=$(PWD)/pkg/pb,dst=$(PROTOC_OUT)/github.com/rvolosatovs/rund/pkg/pb \
                     	-w $(PWD) \
						thethingsindustries/protoc:3.1.33 -I$(PWD)

pkg/pb/api.pb: api/api.proto
	$(PROTOC) \
		--go-grpc_out $(PROTOC_OUT) \
		--go_out $(PROTOC_OUT) \
 		$<

assets/rootfs:
	mkdir -p $@
	curl -sL https://dl-cdn.alpinelinux.org/alpine/v3.13/releases/x86_64/alpine-minirootfs-3.13.4-x86_64.tar.gz | tar xz --strip 1 -C $@

.PHONY: api
api: pkg/pb/api.pb
