BIN := valky
PKG := ./cmd/valky

# Optional author credit, baked in only when AUTHOR is set:
#   make build AUTHOR=@spearh34d
#   make release AUTHOR=@spearh34d
# A plain build shows no credit.
AUTHOR ?=
LDFLAGS :=
ifneq ($(AUTHOR),)
LDFLAGS := -ldflags "-X 'main.author=$(AUTHOR)'"
endif

# OS/arch matrix for the single binary.
PLATFORMS := \
	linux/amd64 linux/arm64 linux/arm linux/386 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/386 \
	freebsd/amd64 openbsd/amd64 netbsd/amd64

.PHONY: all build release clean $(PLATFORMS)

all: build

# Binary for the current machine
build:
	go build $(LDFLAGS) -o bin/$(BIN) $(PKG)

# Build for every OS into dist/
release: $(PLATFORMS)

$(PLATFORMS):
	@os=$(word 1,$(subst /, ,$@)); arch=$(word 2,$(subst /, ,$@)); \
	ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	out="dist/$(BIN)-$$os-$$arch$$ext"; \
	echo "build $$out"; \
	GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(LDFLAGS) -o $$out $(PKG)

clean:
	rm -rf bin dist
