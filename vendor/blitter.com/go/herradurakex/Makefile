.PHONY: info clean all lib

all: lib

clean:
	go clean .

lib: info
	go install .

ifneq ($(MSYSTEM),)
info:
	@echo "building for Windows (MSYS)"
else
info:
	@echo "building for Linux"
endif
