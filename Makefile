.PHONY: all
all: api

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

.PHONY: api
api: pkg/pb/api.pb
