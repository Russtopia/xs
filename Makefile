.PHONY: lint vis clean common client server passwd subpkgs install uninstall reinstall

#ifeq ($(MAKEOPTS),)
  MAKEOPTS = $(MAKEOPTS)
#endif

GIT_COMMIT := $(shell git rev-list -1 HEAD)
VERSION := 0.8.7-kcp
#ifeq ($(BUILDOPTS),)
BUILDOPTS :=$(BUILDOPTS)" -ldflags \"-X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT)\""
#endif

SUBPKGS = logger spinsult hkexnet
TOOLS = hkexpasswd hkexsh hkexshd
SUBDIRS = $(LIBS) $(TOOLS)

INSTPREFIX = /usr/local

all: common client server passwd

clean:
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
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C hkexsh


ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
server: common
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C hkexshd
else
	echo "Cross-build of hkexshd server for Windows not yet supported"
endif
else
server: common
	echo "hkexshd server not (yet) supported on Windows"
endif


passwd: common
	$(MAKE) BUILDOPTS=$(BUILDOPTS) -C hkexpasswd

vis:
	@which go-callvis >/dev/null 2>&1; \
	stat=$$?; if [ $$stat -ne "0" ]; then \
	  /bin/echo "go-callvis not found. Run go get github.com/Russtopia/go-callvis to install."; \
	else \
	  make -C hkexsh vis;\
	  make -C hkexshd vis;\
	  make -C hkexpasswd vis; \
	fi

lint:
	make -C hkexpasswd lint
	make -C hkexshd lint
	make -C hkexsh lint

reinstall: uninstall install

install:
	cp hkexsh/hkexsh $(INSTPREFIX)/bin
ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
	cp hkexshd/hkexshd hkexpasswd/hkexpasswd $(INSTPREFIX)/sbin
else
	mv $(INSTPREFIX)/bin/hkexsh $(INSTPREFIX)/bin/_hkexsh
	cp hkexsh/mintty_wrapper.sh $(INSTPREFIX)/bin/hkexsh
	echo "Cross-build of hkexshd server for Windows not yet supported"
endif
else
	echo "Cross-build of hkexshd server for Windows not yet supported"
endif
	cd $(INSTPREFIX)/bin && ln -s hkexsh hkexcp && cd -


uninstall:
	rm -f $(INSTPREFIX)/bin/hkexsh $(INSTPREFIX)/bin/hkexcp $(INSTPREFIX)/bin/_hkexsh
ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
	rm -f $(INSTPREFIX)/sbin/hkexshd $(INSTPREFIX)/sbin/hkexpasswd
else
endif
else
endif
