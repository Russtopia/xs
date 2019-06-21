.PHONY: clean all vis lint

EXTPKGS = binary,bytes,crypto,encoding,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall
EXE = $(notdir $(shell pwd))

all:
	go build $(BUILDOPTS) .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -file hkexshd-vis -format png -ignore $(EXTPKGS) -group pkg,type .
	../fixup-gv.sh hkexshd.go && cat hkexshd-vis.gv | dot -Tpng -ohkexshd-vis-fixedup.png

lint:
	-gometalinter --deadline=60s | sort

