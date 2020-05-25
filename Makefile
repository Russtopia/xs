VERSION := 0.8.22
.PHONY: lint vis clean common client server subpkgs install uninstall reinstall

## Tag version of binaries with build info wrt.
## GO111MODULE(=on) and vendor/ setup vs. $GOPATH pkg builds
############################################################
ifeq ($(shell go env GOMOD),)
MTAG=
else
MTAG="-m"
endif

ifneq ($(VENDOR),)
GOBUILDOPTS :=-v -mod vendor
VTAG = "-v"
else
GOBUILDOPTS=
VTAG =
endif
############################################################

GIT_COMMIT := $(shell git rev-list -1 HEAD)

#ifeq ($(BUILDOPTS),)
BUILDOPTS :=$(BUILDOPTS)"$(GOBUILDOPTS) -ldflags \"-X main.version=$(VERSION)$(MTAG)$(VTAG) -X main.gitCommit=$(GIT_COMMIT)\""
#endif

SUBPKGS = logger spinsult xsnet
TOOLS = xs xsd
SUBDIRS = $(LIBS) $(TOOLS)

ifeq ($(GOOS),)
	GOOS=$(shell go env GOOS)
endif

ifeq ($(GOOS),windows)
ifeq ($(MSYSTEM),MSYS)
WIN_MSYS=1
endif
endif


INSTPREFIX = /usr/local

all: common client server

clean:
	@echo "Make: $(MAKE)"
	go clean .
	for d in $(SUBDIRS); do\
	  $(MAKE) -C $$d clean;\
	done

subpkgs:
	for d in $(SUBPKGS); do\
	  $(MAKE) BUILDOPTS=$(BUILDOPTS) -C $$d all;\
	done

tools:
	for d in $(TOOLS); do\
	  $(MAKE) BUILDOPTS=$(BUILDOPTS) -C $$d all;\
	done


common:
	go build .
	go install .


client: common
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C xs


server: common
ifdef WIN_MSYS
	echo "Build of xsd server for Windows not yet supported"
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C xsd
endif

vis:
	@which go-callvis >/dev/null 2>&1; \
	stat=$$?; if [ $$stat -ne "0" ]; then \
	  /bin/echo "go-callvis not found. Run go get https://github.com/TrueFurby/go-callvis to install."; \
	else \
	  $(MAKE) -C xs vis;\
	  $(MAKE) -C xsd vis;\
	fi

lint:
	$(MAKE) -C xsd lint
	$(MAKE) -C xs lint

reinstall: uninstall install

install:
	echo "WIN_MSYS:" $(WIN_MSYS)
ifdef WIN_MSYS
	cp xs/mintty_wrapper.sh $(INSTPREFIX)/bin/xs
	cp xs/mintty_wrapper.sh $(INSTPREFIX)/bin/xc
	cp xs/xs $(INSTPREFIX)/bin/_xs
	cp xs/xs $(INSTPREFIX)/bin/_xc
	echo "Install of xsd server for Windows not yet supported"
else
	cp xs/xs $(INSTPREFIX)/bin
	cd $(INSTPREFIX)/bin && ln -s xs xc && cd -
endif

uninstall:
	rm -f $(INSTPREFIX)/bin/xs $(INSTPREFIX)/bin/xc \
	$(INSTPREFIX)/bin/_xs $(INSTPREFIX)/bin/_xc
ifndef $(WIN_MSYS)
	rm -f $(INSTPREFIX)/sbin/xsd
endif
