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

.PHONY: fmt lint lintfix

# check code style in these directories
FMT_DIRS = .

fmt:
	$(GOFMT) -d -s -w $(FMT_DIRS)

lint:
	$(GOCI) run --timeout=10m

lintfix:
	$(GOCI) run --skip-dirs=gen --fix