.PHONY: clean all vis lint

EXTPKGS = bytes,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall,binary,encoding
EXE = $(notdir $(shell pwd))

all:
	go build $(BUILDOPTS) .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -format png -file xspasswd-vis -ignore $(EXTPKGS) -group pkg,type .

lint:
	-golangci-lint run
