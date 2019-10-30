.PHONY: info clean lib

all: lib

clean:
	go clean .

lib: info
	go install .

ifneq ($(MSYSTEM),)
info:
	@echo "Building for Windows (MSYS)"
else
info:
	@echo "Building for Linux"
endif
