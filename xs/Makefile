.PHONY: clean all vis lint

EXTPKGS = bytes,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall,binary,encoding
EXE = $(notdir $(shell pwd))

all:
	echo "BUILDOPTS:" $(BUILDOPTS)
	go build $(BUILDOPTS) .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -file xs-vis -format png -ignore $(EXTPKGS) -group pkg,type .
	../fixup-gv.sh xs.go && cat xs-vis.gv | dot -Tpng -oxs-vis-fixedup.png

lint:
	-golangci-lint run
