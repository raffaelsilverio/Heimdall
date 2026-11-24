GO ?= go
PYTHON ?= python3

.PHONY: check fmt-check modules-check architecture-check file-size-check vet lint staticcheck govulncheck browser-test test test-quality build

check: fmt-check modules-check architecture-check file-size-check vet lint staticcheck govulncheck browser-test test-quality build

fmt-check:
	@files="$$(find . -name '*.go' -not -path './.git/*' -print0 | xargs -0 gofmt -l)"; \
	if [ -n "$$files" ]; then \
		printf 'Go files need gofmt:\n%s\n' "$$files"; \
		exit 1; \
	fi

modules-check:
	$(GO) mod tidy -diff

architecture-check:
	$(PYTHON) scripts/check_architecture.py

file-size-check:
	$(PYTHON) scripts/check_go_file_size.py

browser-test:
	$(PYTHON) -m unittest discover -s browser/tests -t browser

vet:
	$(GO) vet ./...

lint:
	$(PYTHON) scripts/check_lint.py

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.2.0 ./...

test-quality:
	$(PYTHON) scripts/check_test_quality.py

test: test-quality

build:
	$(GO) build ./...
