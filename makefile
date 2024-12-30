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

# 运行所有测试
test:
	$(GO) test -v ./... -failfast

# 运行测试并生成覆盖率报告
test-cover:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# 运行指定的测试文件，使用方法：make test-file FILE=path/to/test/file
test-file:
	$(GO) test -v $(FILE)