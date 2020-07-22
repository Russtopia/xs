#!/bin/bash
#
## This wrapper may be used within the MSYS/mintty Windows
## shell environment to have a functioning hkexsh client with
## working 'raw' mode and hidden password entry.
##
## mintty uses named pipes and ptys to get a more POSIX-like
## terminal (incl. VT/ANSI codes) rather than the dumb Windows
## console interface; however Go on Windows does not have functioning
## MSYS/mintty code to set raw, echo etc. modes.
##
## Someday it would be preferable to put native Windows term mode
## code into the client build, but this is 'good enough' for now
## (with the exception of tty rows/cols not being set based on
##  info from the server).
##
## INSTALLATION
## --
## Build the client, put it somewhere in your $PATH with this
## wrapper and edit the name of the client binary
## eg.,
## $ cp hkexsh.exe /usr/bin/.hkexsh.exe
## $ cp mintty_wrapper.sh /usr/bin/hkexsh
####
trap cleanup EXIT ERR

cleanup() {
  stty sane
}

me="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"

if [ ${1}x == "-hx" ]; then
  _${me} -h
else
  stty -echo raw icrnl
  _${me} $@
fi

