#
# Tools
#

GO = go
GOFMT = gofmt
GOCI = golangci-lint
GIT = git

#
# Format
#

.PHONY: fmt lint lintfix test test-cover test-file

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
# 运行所有测试
test:
	$(GO) test -v ./... -failfast

# 运行测试并生成覆盖率报告
test_cover:
	$(GO) test -v $(TEST_FLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# 运行指定的测试文件，使用方法：make test_file FILE=path/to/test/file
test_file:
	$(GO) test -v $(FILE)
