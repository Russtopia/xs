VERSION := 0.8.23
.PHONY: lint vis clean common client server passwd subpkgs install uninstall reinstall

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
TOOLS = xspasswd xs xsd
SUBDIRS = $(LIBS) $(TOOLS)

INSTPREFIX = /usr/local

all: common client server passwd

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


ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
server: common
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C xsd
else
	echo "Cross-build of xsd server for Windows not yet supported"
endif
else
server: common
	echo "xsd server not (yet) supported on Windows"
endif


passwd: common
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C xspasswd

vis:
	@which go-callvis >/dev/null 2>&1; \
	stat=$$?; if [ $$stat -ne "0" ]; then \
	  /bin/echo "go-callvis not found. Run go get https://github.com/TrueFurby/go-callvis to install."; \
	else \
	  $(MAKE) -C xs vis;\
	  $(MAKE) -C xsd vis;\
	  $(MAKE) -C xspasswd vis; \
	fi

lint:
	$(MAKE) -C xspasswd lint
	$(MAKE) -C xsd lint
	$(MAKE) -C xs lint

reinstall: uninstall install

install:
	cp xs/xs $(INSTPREFIX)/bin
ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
	cp xsd/xsd xspasswd/xspasswd $(INSTPREFIX)/sbin
else
	mv $(INSTPREFIX)/bin/xs $(INSTPREFIX)/bin/_xs
	cp xs/mintty_wrapper.sh $(INSTPREFIX)/bin/xs
	echo "Cross-build of xsd server for Windows not yet supported"
endif
else
	echo "Cross-build of xsd server for Windows not yet supported"
endif
	cd $(INSTPREFIX)/bin && ln -s xs xc && cd -


uninstall:
	rm -f $(INSTPREFIX)/bin/xs $(INSTPREFIX)/bin/xc $(INSTPREFIX)/bin/_xs
ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
	rm -f $(INSTPREFIX)/sbin/xsd $(INSTPREFIX)/sbin/xspasswd
else
endif
else
endif
