#
# Tools
#

GO = go
GOFMT = gofmt
GOCI = golangci-lint
ZLMEXPORTER_IMAGE = zlm_exporter
IMAGE_TAG = latest
#
# Format
#

.PHONY: fmt lint lintfix test test-cover test-file build build-docker run

# check code style in these directories
FMT_DIRS = .

fmt:
	$(GOFMT) -d -s -w $(FMT_DIRS)

lint:
	$(GOCI) run --timeout=10m

lintfix:
	$(GOCI) run --skip-dirs=gen --fix


TEST_FLAGS := \
	-v -race -failfast -p=1 \
	-covermode=atomic \

test:
	$(GO) test -v ./... -failfast

test_cover:
	$(GO) test -v $(TEST_FLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

test_file:
	$(GO) test -v $(FILE)

build:
	$(GO) build -ldflags="-s -w" -o zlm_exporter .

build-docker:
	docker build -t $(ZLMEXPORTER_IMAGE):$(IMAGE_TAG) .

run:
	$(GO) run .
