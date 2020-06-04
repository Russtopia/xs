// xs client

//
// Copyright (c) 2017-2019 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"net/http"
	_ "net/http/pprof"

	xs "blitter.com/go/xs"
	"blitter.com/go/xs/logger"
	"blitter.com/go/xs/spinsult"
	"blitter.com/go/xs/xsnet"
	isatty "github.com/mattn/go-isatty"
)

var (
	version   string
	gitCommit string // set in -ldflags by build

	// wg controls when the goroutines handling client I/O complete
	wg sync.WaitGroup

	kcpMode string // set to a valid KCP BlockCrypt alg tag to use rather than TCP

	// Log defaults to regular syslog output (no -d)
	Log *logger.Writer

	cpuprofile string
	memprofile string
)

////////////////////////////////////////////////////

// Praise Bob. Do not remove, lest ye lose Slack.
const bob = string("\r\n\r\n" +
	"@@@@@@@^^~~~~~~~~~~~~~~~~~~~~^@@@@@@@@@\r\n" +
	"@@@@@@^     ~^  @  @@ @ @ @ I  ~^@@@@@@\r\n" +
	"@@@@@            ~ ~~ ~I          @@@@@\r\n" +
	"@@@@'                  '  _,w@<    @@@@\r\n" +
	"@@@@     @@@@@@@@w___,w@@@@@@@@  @  @@@\r\n" +
	"@@@@     @@@@@@@@@@@@@@@@@@@@@@  I  @@@\r\n" +
	"@@@@     @@@@@@@@@@@@@@@@@@@@*@[ i  @@@\r\n" +
	"@@@@     @@@@@@@@@@@@@@@@@@@@[][ | ]@@@\r\n" +
	"@@@@     ~_,,_ ~@@@@@@@~ ____~ @    @@@\r\n" +
	"@@@@    _~ ,  ,  `@@@~  _  _`@ ]L  J@@@\r\n" +
	"@@@@  , @@w@ww+   @@@ww``,,@w@ ][  @@@@\r\n" +
	"@@@@,  @@@@www@@@ @@@@@@@ww@@@@@[  @@@@\r\n" +
	"@@@@@_|| @@@@@@P' @@P@@@@@@@@@@@[|c@@@@\r\n" +
	"@@@@@@w| '@@P~  P]@@@-~, ~Y@@^'],@@@@@@\r\n" +
	"@@@@@@@[   _        _J@@Tk     ]]@@@@@@\r\n" +
	"@@@@@@@@,@ @@, c,,,,,,,y ,w@@[ ,@@@@@@@\r\n" +
	"@@@@@@@@@ i @w   ====--_@@@@@  @@@@@@@@\r\n" +
	"@@@@@@@@@@`,P~ _ ~^^^^Y@@@@@  @@@@@@@@@\r\n" +
	"@@@@^^=^@@^   ^' ,ww,w@@@@@ _@@@@@@@@@@\r\n" +
	"@@@_xJ~ ~   ,    @@@@@@@P~_@@@@@@@@@@@@\r\n" +
	"@@   @,   ,@@@,_____   _,J@@@@@@@@@@@@@\r\n" +
	"@@L  `' ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n" +
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n" +
	"\r\n")

type (
	// Handler for special functions invoked by escSeqs
	escHandler func(io.Writer)
	// escSeqs is a map of special keystroke sequences to trigger escHandlers
	escSeqs map[byte]escHandler
)

// Copy copies from src to dst until either EOF is reached
// on src or an error occurs. It returns the number of bytes
// copied and the first error encountered while copying, if any.
//
// A successful Copy returns err == nil, not err == EOF.
// Because Copy is defined to read from src until EOF, it does
// not treat an EOF from Read as an error to be reported.
//
// If src implements the WriterTo interface,
// the copy is implemented by calling src.WriteTo(dst).
// Otherwise, if dst implements the ReaderFrom interface,
// the copy is implemented by calling dst.ReadFrom(src).
//
// This is identical to stdlib pkg/io.Copy save that it
// calls a client-custom version of copyBuffer(), which allows
// some client escape sequences to trigger special actions during
// interactive sessions.
//
// (See go doc xs/xs.{escSeqs,escHandler})
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	written, err = copyBuffer(dst, src, nil)
	return
}

// copyBuffer is the actual implementation of Copy and CopyBuffer.
// if buf is nil, one is allocated.
//
// This private version of copyBuffer is derived from the
// go stdlib pkg/io, with escape sequence interpretation to trigger
// some special client-side actions.
//
// (See go doc xs/xs.{escSeqs,escHandler})
func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	// NOTE: using dst.Write() in these esc funcs will cause the output
	// to function as a 'macro', outputting as if user typed the sequence
	// (that is, the client 'sees' the user type it, and the server 'sees'
	// it as well).
	//
	// Using os.Stdout outputs to the client's term w/o it or the server
	// 'seeing' the output.
	//
	// TODO: Devise a way to signal to main client thread that
	// a goroutine should be spawned to do long-lived tasks for
	// some esc sequences (eg., a time ticker in the corner of terminal,
	// or tunnel traffic indicator - note we cannot just spawn a goroutine
	// here, as copyBuffer() returns after each burst of data. Scope must
	// outlive individual copyBuffer calls).
	escs := escSeqs{
		'i': func(io.Writer) { os.Stdout.Write([]byte("\x1b[s\x1b[2;1H\x1b[1;31m[HKEXSH]\x1b[39;49m\x1b[u")) },
		't': func(io.Writer) { os.Stdout.Write([]byte("\x1b[1;32m[HKEXSH]\x1b[39;49m")) },
		'B': func(io.Writer) { os.Stdout.Write([]byte("\x1b[1;32m" + bob + "\x1b[39;49m")) },
	}

	/*
		// If the reader has a WriteTo method, use it to do the copy.
		// Avoids an allocation and a copy.
		if wt, ok := src.(io.WriterTo); ok {
			return wt.WriteTo(dst)
		}
		// Similarly, if the writer has a ReadFrom method, use it to do the copy.
		if rt, ok := dst.(io.ReaderFrom); ok {
			return rt.ReadFrom(src)
		}
	*/
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}

	var seqPos int
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// Look for sequences to trigger client-side diags
			// A repeat of 4 keys (conveniently 'dead' chars for most
			// interactive shells; here CTRL-]) shall introduce
			// some special responses or actions on the client side.
			if seqPos < 4 {
				if buf[0] == 0x1d {
					seqPos++
				}
			} else {
				if v, ok := escs[buf[0]]; ok {
					v(dst)
					nr--
					buf = buf[1:]
				}
				seqPos = 0
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

////////////////////////////////////////////////////

// GetSize gets the terminal size using 'stty' command
//
// TODO: do in code someday instead of using external 'stty'
func GetSize() (cols, rows int, err error) {
	cmd := exec.Command("stty", "size") // #nosec
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()

	if err != nil {
		log.Println(err)
		cols, rows = 80, 24 //failsafe
	} else {
		n, err := fmt.Sscanf(string(out), "%d %d\n", &rows, &cols)
		if n < 2 ||
			rows < 0 ||
			cols < 0 ||
			rows > 9000 ||
			cols > 9000 ||
			err != nil {
			log.Printf("GetSize error: rows:%d cols:%d; %v\n",
				rows, cols, err)
		}
	}
	return
}

func buildCmdRemoteToLocal(copyQuiet bool, copyLimitBPS uint, destPath, files string) (captureStderr bool, cmd string, args []string) {
	// Detect if we have 'pv'
	// pipeview http://www.ivarch.com/programs/pv.shtml
	// and use it for nice client progress display.
	_, pverr := os.Stat("/usr/bin/pv")
	if pverr != nil {
		_, pverr = os.Stat("/usr/local/bin/pv")
	}

	if copyQuiet || pverr != nil {
		// copyQuiet and copyLimitBPS are not applicable in dumb copy mode
		captureStderr = true
		cmd = xs.GetTool("tar")

		args = []string{"-xz", "-C", destPath}
	} else {
		// TODO: Query remote side for total file/dir size
		bandwidthInBytesPerSec := " -L " + fmt.Sprintf("%d ", copyLimitBPS)
		displayOpts := " -pre "
		cmd = xs.GetTool("bash")
		args = []string{"-c", "pv " + displayOpts + bandwidthInBytesPerSec + "| tar -xz -C " + destPath}
	}
	log.Printf("[%v %v]\n", cmd, args)
	return
}

func buildCmdLocalToRemote(copyQuiet bool, copyLimitBPS uint, files string) (captureStderr bool, cmd string, args []string) {
	// Detect if we have 'pv'
	// pipeview http://www.ivarch.com/programs/pv.shtml
	// and use it for nice client progress display.
	_, pverr := os.Stat("/usr/bin/pv")
	if pverr != nil {
		_, pverr = os.Stat("/usr/local/bin/pv")
	}

	if pverr != nil {
		// copyQuiet and copyLimitBPS are not applicable in dumb copy mode

		captureStderr = true
		cmd = xs.GetTool("tar")
		args = []string{"-cz", "-f", "/dev/stdout"}
		files = strings.TrimSpace(files)
		// Awesome fact: tar actually can take multiple -C args, and
		// changes to the dest dir *as it sees each one*. This enables
		// its use below, where clients can send scattered sets of source
		// files and dirs to be extracted to a single dest dir server-side,
		// whilst preserving the subtrees of dirs on the other side.
		// Eg., tar -c -f /dev/stdout -C /dirA fileInA -C /some/where/dirB fileInB /foo/dirC
		// packages fileInA, fileInB, and dirC at a single toplevel in the tar.
		// The tar authors are/were real smarties :)
		//
		// This is the 'scatter/gather' logic to allow specification of
		// files and dirs in different trees to be deposited in a single
		// remote destDir.
		for _, v := range strings.Split(files, " ") {
			v, _ = filepath.Abs(v) // #nosec
			dirTmp, fileTmp := path.Split(v)
			if dirTmp == "" {
				args = append(args, fileTmp)
			} else {
				args = append(args, "-C", dirTmp, fileTmp)
			}
		}
	} else {
		captureStderr = copyQuiet
		bandwidthInBytesPerSec := " -L " + fmt.Sprintf("%d", copyLimitBPS)
		displayOpts := " -pre "
		cmd = xs.GetTool("bash")
		args = []string{"-c", xs.GetTool("tar") + " -cz -f /dev/stdout "}
		files = strings.TrimSpace(files)
		// Awesome fact: tar actually can take multiple -C args, and
		// changes to the dest dir *as it sees each one*. This enables
		// its use below, where clients can send scattered sets of source
		// files and dirs to be extracted to a single dest dir server-side,
		// whilst preserving the subtrees of dirs on the other side.
		// Eg., tar -c -f /dev/stdout -C /dirA fileInA -C /some/where/dirB fileInB /foo/dirC
		// packages fileInA, fileInB, and dirC at a single toplevel in the tar.
		// The tar authors are/were real smarties :)
		//
		// This is the 'scatter/gather' logic to allow specification of
		// files and dirs in different trees to be deposited in a single
		// remote destDir.
		for _, v := range strings.Split(files, " ") {
			v, _ = filepath.Abs(v) // #nosec
			dirTmp, fileTmp := path.Split(v)
			if dirTmp == "" {
				args[1] = args[1] + fileTmp + " "
			} else {
				args[1] = args[1] + " -C " + dirTmp + " " + fileTmp + " "
			}
		}
		args[1] = args[1] + "| pv" + displayOpts + bandwidthInBytesPerSec + " -s " + getTreeSizeSubCmd(files) + " -c"
	}

	log.Printf("[%v %v]\n", cmd, args)
	return
}

func getTreeSizeSubCmd(paths string) (c string) {
	if runtime.GOOS == "linux" {
		c = " $(du -cb " + paths + " | tail -1 | cut -f 1) "
	} else {
		c = " $(expr $(du -c " + paths + ` | tail -1 | cut -f 1) \* 1024) `
	}
	return c
}

// doCopyMode begins a secure xs local<->remote file copy operation.
//
// TODO: reduce gocyclo
func doCopyMode(conn *xsnet.Conn, remoteDest bool, files string, copyQuiet bool, copyLimitBPS uint, rec *xs.Session) (exitStatus uint32, err error) {
	if remoteDest {
		log.Println("local files:", files, "remote filepath:", string(rec.Cmd()))

		var c *exec.Cmd

		//os.Clearenv()
		//os.Setenv("HOME", u.HomeDir)
		//os.Setenv("TERM", "vt102") // TODO: server or client option?

		captureStderr, cmdName, cmdArgs := buildCmdLocalToRemote(copyQuiet, copyLimitBPS, strings.TrimSpace(files))
		c = exec.Command(cmdName, cmdArgs...) // #nosec
		c.Dir, _ = os.Getwd()                 // #nosec
		log.Println("[wd:", c.Dir, "]")
		c.Stdout = conn
		stdErrBuffer := new(bytes.Buffer)
		if captureStderr {
			c.Stderr = stdErrBuffer
		} else {
			c.Stderr = os.Stderr
		}

		// Start the command (no pty)
		err = c.Start() // returns immediately
		/////////////
		// NOTE: There is, apparently, a bug in Go stdlib here. Start()
		// can actually return immediately, on a command which *does*
		// start but exits quickly, with c.Wait() error
		// "c.Wait status: exec: not started".
		// As in this example, attempting a client->server copy to
		// a nonexistent remote dir (it's tar exiting right away, exitStatus
		// 2, stderr
		// /bin/tar -xz -C /home/someuser/nosuchdir
		// stderr: fork/exec /bin/tar: no such file or directory
		//
		// In this case, c.Wait() won't give us the real
		// exit status (is it lost?).
		/////////////
		if err != nil {
			fmt.Println("cmd exited immediately. Cannot get cmd.Wait().ExitStatus()")
			err = errors.New("cmd exited prematurely")
			exitStatus = uint32(2)
		} else {
			if err = c.Wait(); err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok {
					// The program has exited with an exit code != 0

					// This works on both Unix and Windows. Although package
					// syscall is generally platform dependent, WaitStatus is
					// defined for both Unix and Windows and in both cases has
					// an ExitStatus() method with the same signature.
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						exitStatus = uint32(status.ExitStatus())
						if captureStderr {
							fmt.Print(stdErrBuffer)
						}
					}
				}
			}
			// send CSOExitStatus to inform remote (server) end cp is done
			log.Println("Sending local exitStatus:", exitStatus)
			r := make([]byte, 4)
			binary.BigEndian.PutUint32(r, exitStatus)
			_, we := conn.WritePacket(r, xsnet.CSOExitStatus)
			if we != nil {
				fmt.Println("Error:", we)
			}

			// Do a final read for remote's exit status
			s := make([]byte, 4)
			_, remErr := conn.Read(s)
			if remErr != io.EOF &&
				!strings.Contains(remErr.Error(), "use of closed network") &&
				!strings.Contains(remErr.Error(), "connection reset by peer") {
				fmt.Printf("*** remote status Read() failed: %v\n", remErr)
			} else {
				conn.SetStatus(0) // cp finished OK
			}

			// If local side status was OK, use remote side's status
			if exitStatus == 0 {
				exitStatus = uint32(conn.GetStatus())
				log.Println("Received remote exitStatus:", exitStatus)
			}
			log.Printf("*** client->server cp finished , status %d ***\n", conn.GetStatus())
		}
	} else {
		log.Println("remote filepath:", string(rec.Cmd()), "local files:", files)
		destPath := files

		_, cmdName, cmdArgs := buildCmdRemoteToLocal(copyQuiet, copyLimitBPS, destPath, strings.TrimSpace(files))

		var c *exec.Cmd
		c = exec.Command(cmdName, cmdArgs...) // #nosec
		c.Stdin = conn
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		// Start the command (no pty)
		err = c.Start() // returns immediately
		if err != nil {
			fmt.Println(err)
		} else {
			if err = c.Wait(); err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok {
					// The program has exited with an exit code != 0

					// This works on both Unix and Windows. Although package
					// syscall is generally platform dependent, WaitStatus is
					// defined for both Unix and Windows and in both cases has
					// an ExitStatus() method with the same signature.
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						exitStatus = uint32(status.ExitStatus())
					}
				}
			}
			// return local status, if nonzero;
			// otherwise, return remote status if nonzero
			if exitStatus == 0 {
				exitStatus = uint32(conn.GetStatus())
			}
			log.Printf("*** server->client cp finished, status %d ***\n", conn.GetStatus())
		}
	}
	return
}

// doShellMode begins an xs shell session (one-shot command or
// interactive).
func doShellMode(isInteractive bool, conn *xsnet.Conn, oldState *xs.State, rec *xs.Session) {
	//client reader (from server) goroutine
	//Read remote end's stdout

	wg.Add(1)
	// #gv:s/label=\"doShellMode\$1\"/label=\"shellRemoteToStdin\"/
	// TODO:.gv:doShellMode:1:shellRemoteToStdin
	shellRemoteToStdin := func() {
		defer func() {
			wg.Done()
		}()

		// By deferring a call to wg.Done(),
		// each goroutine guarantees that it marks
		// its direction's stream as finished.

		// pkg io/Copy expects EOF so normally this will
		// exit with inerr == nil
		_, inerr := io.Copy(os.Stdout, conn)
		if inerr != nil {
			restoreTermState(oldState)
			// Copy operations and user logging off will cause
			// a "use of closed network connection" so handle that
			// gracefully here
			if !strings.HasSuffix(inerr.Error(), "use of closed network connection") {
				log.Println(inerr)
				exitWithStatus(1)
			}
		}

		rec.SetStatus(uint32(conn.GetStatus()))
		log.Println("rec.status:", rec.Status())

		if isInteractive {
			log.Println("[* Got EOF *]")
			restoreTermState(oldState)
			exitWithStatus(int(rec.Status()))
		}
	}
	go shellRemoteToStdin()

	// Only look for data from stdin to send to remote end
	// for interactive sessions.
	if isInteractive {
		handleTermResizes(conn)

		// client writer (to server) goroutine
		// Write local stdin to remote end
		wg.Add(1)
		// #gv:s/label=\"doShellMode\$2\"/label=\"shellStdinToRemote\"/
		// TODO:.gv:doShellMode:2:shellStdinToRemote
		shellStdinToRemote := func() {
			defer wg.Done()
			_, outerr := func(conn *xsnet.Conn, r io.Reader) (w int64, e error) {
				// Copy() expects EOF so this will
				// exit with outerr == nil
				w, e = Copy(conn, r)
				return w, e
			}(conn, os.Stdin)

			if outerr != nil {
				log.Println(outerr)
				fmt.Println(outerr)
				restoreTermState(oldState)
				log.Println("[Hanging up]")
				exitWithStatus(0)
			}
		}
		go shellStdinToRemote()
	}

	// Wait until both stdin and stdout goroutines finish before returning
	// (ensure client gets all data from server before closing)
	wg.Wait()
}

func usageShell() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])            // nolint: errcheck
	fmt.Fprintf(os.Stderr, "%s [opts] [user]@server\n", os.Args[0]) // nolint: errcheck
	flag.PrintDefaults()
}

func usageCp() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])                                         // nolint: errcheck
	fmt.Fprintf(os.Stderr, "%s [opts] srcFileOrDir [...] [user]@server[:dstpath]\n", os.Args[0]) // nolint: errcheck
	fmt.Fprintf(os.Stderr, "%s [opts] [user]@server[:srcFileOrDir] dstPath\n", os.Args[0])       // nolint: errcheck
	flag.PrintDefaults()
}

// rejectUserMsg snarkily rebukes users giving incorrect
// credentials.
//
// TODO: do this from the server side and have client just emit that
func rejectUserMsg() string {
	return "Begone, " + spinsult.GetSentence() + "\r\n"
}

// Transmit request to server for it to set up the remote end of a tunnel
//
// Server responds with [CSOTunAck:rport] or [CSOTunRefused:rport]
// (handled in xsnet.Read())
func reqTunnel(hc *xsnet.Conn, lp uint16, p string /*net.Addr*/, rp uint16) {
	// Write request to server so it can attempt to set up its end
	var bTmp bytes.Buffer
	if e := binary.Write(&bTmp, binary.BigEndian, lp); e != nil {
		fmt.Fprintln(os.Stderr, "reqTunnel:", e) // nolint: errcheck
	}
	if e := binary.Write(&bTmp, binary.BigEndian, rp); e != nil {
		fmt.Fprintln(os.Stderr, "reqTunnel:", e) // nolint: errcheck
	}
	_ = logger.LogDebug(fmt.Sprintln("[Client sending CSOTunSetup]")) // nolint: gosec
	if n, e := hc.WritePacket(bTmp.Bytes(), xsnet.CSOTunSetup); e != nil || n != len(bTmp.Bytes()) {
		fmt.Fprintln(os.Stderr, "reqTunnel:", e) // nolint: errcheck
	}
}

func parseNonSwitchArgs(a []string) (user, host, path string, isDest bool, otherArgs []string) {
	// Whether fancyArg is src or dst file depends on flag.Args() index;
	//  fancyArg as last flag.Args() element denotes dstFile
	//  fancyArg as not-last flag.Args() element denotes srcFile
	var fancyUser, fancyHost, fancyPath string
	for i, arg := range a {
		if strings.Contains(arg, ":") || strings.Contains(arg, "@") {
			fancyArg := strings.Split(flag.Arg(i), "@")
			var fancyHostPath []string
			if len(fancyArg) < 2 {
				//TODO: no user specified, use current
				fancyUser = "[default:getUser]"
				fancyHostPath = strings.Split(fancyArg[0], ":")
			} else {
				// user@....
				fancyUser = fancyArg[0]
				fancyHostPath = strings.Split(fancyArg[1], ":")
			}

			// [...@]host[:path]
			if len(fancyHostPath) > 1 {
				fancyPath = fancyHostPath[1]
			}
			fancyHost = fancyHostPath[0]

			if i == len(a)-1 {
				isDest = true
			}
		} else {
			otherArgs = append(otherArgs, a[i])
		}
	}
	return fancyUser, fancyHost, fancyPath, isDest, otherArgs
}

func launchTuns(conn *xsnet.Conn, remoteHost string, tuns string) {
	remAddrs, _ := net.LookupHost(remoteHost) // nolint: gosec

	if tuns == "" {
		return
	}

	tunSpecs := strings.Split(tuns, ",")
	for _, tunItem := range tunSpecs {
		var lPort, rPort uint16
		_, _ = fmt.Sscanf(tunItem, "%d:%d", &lPort, &rPort) // nolint: gosec
		reqTunnel(conn, lPort, remAddrs[0], rPort)
	}
}

func sendSessionParams(conn io.Writer /* *xsnet.Conn*/, rec *xs.Session) (e error) {
	_, e = fmt.Fprintf(conn, "%d %d %d %d %d %d\n",
		len(rec.Op()), len(rec.Who()), len(rec.ConnHost()), len(rec.TermType()), len(rec.Cmd()), len(rec.AuthCookie(true)))
	if e != nil {
		return
	}
	_, e = conn.Write(rec.Op())
	if e != nil {
		return
	}
	_, e = conn.Write(rec.Who())
	if e != nil {
		return
	}
	_, e = conn.Write(rec.ConnHost())
	if e != nil {
		return
	}
	_, e = conn.Write(rec.TermType())
	if e != nil {
		return
	}
	_, e = conn.Write(rec.Cmd())
	if e != nil {
		return
	}
	_, e = conn.Write(rec.AuthCookie(true))
	return e
}

// TODO: reduce gocyclo
func main() {
	var vopt bool
	var gopt bool //login via password, asking server to generate authToken
	var dbg bool
	var shellMode bool   // if true act as shell, else file copier
	var cipherAlg string //cipher alg
	var hmacAlg string   //hmac alg
	var kexAlg string    //KEX/KEM alg
	var server string
	var port uint
	var cmdStr string
	var tunSpecStr string // lport1:rport1[,lport2:rport2,...]

	var copySrc []byte
	var copyDst string
	var copyQuiet bool
	var copyLimitBPS uint

	var authCookie string
	var chaffEnabled bool
	var chaffFreqMin uint
	var chaffFreqMax uint
	var chaffBytesMax uint

	var op []byte
	isInteractive := false

	flag.BoolVar(&vopt, "v", false, "show version")
	flag.BoolVar(&dbg, "d", false, "debug logging")
	flag.StringVar(&cipherAlg, "c", "C_AES_256", "session `cipher` [C_AES_256 | C_TWOFISH_128 | C_BLOWFISH_64 | C_CRYPTMT1 | C_CHACHA20_12]")
	flag.StringVar(&hmacAlg, "m", "H_SHA256", "session `HMAC` [H_SHA256 | H_SHA512]")
	flag.StringVar(&kexAlg, "k", "KEX_HERRADURA512", "KEx `alg` [KEX_HERRADURA{256/512/1024/2048} | KEX_KYBER{512/768/1024} | KEX_NEWHOPE | KEX_NEWHOPE_SIMPLE]")
	flag.StringVar(&kcpMode, "K", "unused", "KCP `alg`, one of [KCP_NONE | KCP_AES | KCP_BLOWFISH | KCP_CAST5 | KCP_SM4 | KCP_SALSA20 | KCP_SIMPLEXOR | KCP_TEA | KCP_3DES | KCP_TWOFISH | KCP_XTEA] to use KCP (github.com/xtaci/kcp-go) reliable UDP instead of TCP")
	flag.UintVar(&port, "p", 2000, "``port")
	//flag.StringVar(&authCookie, "a", "", "auth cookie")
	flag.BoolVar(&chaffEnabled, "e", true, "enable chaff pkts")
	flag.UintVar(&chaffFreqMin, "f", 100, "chaff pkt freq min `msecs`")
	flag.UintVar(&chaffFreqMax, "F", 5000, "chaff pkt freq max `msecs`")
	flag.UintVar(&chaffBytesMax, "B", 64, "chaff pkt size max `bytes`")

	flag.StringVar(&cpuprofile, "cpuprofile", "", "write cpu profile to <`file`>")
	flag.StringVar(&memprofile, "memprofile", "", "write memory profile to <`file`>")

	// Find out what program we are (shell or copier)
	myPath := strings.Split(os.Args[0], string(os.PathSeparator))
	if myPath[len(myPath)-1] != "xc" &&
		myPath[len(myPath)-1] != "_xc" &&
		myPath[len(myPath)-1] != "xc.exe" &&
		myPath[len(myPath)-1] != "_xc.exe" {
		// xs accepts a command (-x) but not
		// a srcpath (-r) or dstpath (-t)
		flag.StringVar(&cmdStr, "x", "", "run <`command`> (if not specified, run interactive shell)")
		flag.StringVar(&tunSpecStr, "T", "", "``tunnelspec - localPort:remotePort[,localPort:remotePort,...]")
		flag.BoolVar(&gopt, "g", false, "ask server to generate authtoken")
		shellMode = true
		flag.Usage = usageShell
	} else {
		flag.BoolVar(&copyQuiet, "q", false, "do not output progress bar during copy")
		flag.UintVar(&copyLimitBPS, "L", 8589934592, "copy max rate in bytes per sec")
		flag.Usage = usageCp
	}
	flag.Parse()

	if vopt {
		fmt.Printf("version %s (%s)\n", version, gitCommit)
		exitWithStatus(0)
	}

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		fmt.Println("StartCPUProfile()")
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		} else {
			defer pprof.StopCPUProfile()
		}

		go func() { http.ListenAndServe("localhost:6060", nil) }()
	}

	remoteUser, remoteHost, tmpPath, pathIsDest, otherArgs :=
		parseNonSwitchArgs(flag.Args())
	//fmt.Println("otherArgs:", otherArgs)

	// Set defaults if user doesn't specify user, path or port
	var uname string
	if remoteUser == "" {
		u, _ := user.Current() // nolint: gosec
		uname = localUserName(u)
	} else {
		uname = remoteUser
	}

	if remoteHost != "" {
		server = remoteHost + ":" + fmt.Sprintf("%d", port)
	}
	if tmpPath == "" {
		tmpPath = "."
	}

	var fileArgs string
	if !shellMode /*&& tmpPath != ""*/ {
		// -if pathIsSrc && len(otherArgs) > 1 ERROR
		// -else flatten otherArgs into space-delim list => copySrc
		if pathIsDest {
			if len(otherArgs) == 0 {
				log.Fatal("ERROR: Must specify at least one dest path for copy")
			} else {
				for _, v := range otherArgs {
					copySrc = append(copySrc, ' ')
					copySrc = append(copySrc, v...)
				}
				copyDst = tmpPath
				fileArgs = string(copySrc)
			}
		} else {
			if len(otherArgs) == 0 {
				log.Fatal("ERROR: Must specify src path for copy")
			} else if len(otherArgs) == 1 {
				copyDst = otherArgs[0]
				if strings.Contains(copyDst, "*") || strings.Contains(copyDst, "?") {
					log.Fatal("ERROR: wildcards not allowed in dest path for copy")
				}
			} else {
				log.Fatal("ERROR: cannot specify more than one dest path for copy")
			}
			copySrc = []byte(tmpPath)
			fileArgs = copyDst
		}
	}

	// Do some more option consistency checks

	//fmt.Println("server finally is:", server)
	if flag.NFlag() == 0 && server == "" {
		flag.Usage()
		exitWithStatus(0)
	}

	if len(cmdStr) != 0 && (len(copySrc) != 0 || len(copyDst) != 0) {
		log.Fatal("incompatible options -- either cmd (-x) or copy ops but not both")
	}

	//-------------------------------------------------------------------
	// Here we have parsed all options and can now carry out
	// either the shell session or copy operation.
	_ = shellMode

	Log, _ = logger.New(logger.LOG_USER|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR, "xs") // nolint: errcheck,gosec
	xsnet.Init(dbg, "xs", logger.LOG_USER|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR)
	if dbg {
		log.SetOutput(Log)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	if !gopt {
		// See if we can log in via an auth token
		u, _ := user.Current() // nolint: gosec
		ab, aerr := ioutil.ReadFile(fmt.Sprintf("%s/.xs_id", u.HomeDir))
		if aerr == nil {
			idx := strings.Index(string(ab), remoteHost)
			if idx >= 0 {
				ab = ab[idx:]
				entries := strings.SplitN(string(ab), "\n", -1)
				authCookie = strings.TrimSpace(entries[0])
				// Security scrub
				ab = nil
				runtime.GC()
			} else {
				_, _ = fmt.Fprintln(os.Stderr, "[no authtoken, use -g to request one from server]")
			}
		} else {
			log.Printf("[cannot read %s/.xs_id]\n", u.HomeDir)
		}
	}

	// Enforce some sane min/max vals on chaff flags
	if chaffFreqMin < 2 {
		chaffFreqMin = 2
	}
	if chaffFreqMax == 0 {
		chaffFreqMax = chaffFreqMin + 1
	}
	if chaffBytesMax == 0 || chaffBytesMax > 4096 {
		chaffBytesMax = 64
	}

	if shellMode {
		// We must make the decision about interactivity before Dial()
		// as it affects chaffing behaviour. 20180805
		if gopt {
			fmt.Fprintln(os.Stderr, "[requesting authtoken from server]") // nolint: errcheck
			op = []byte{'A'}
			chaffFreqMin = 2
			chaffFreqMax = 10
		} else if len(cmdStr) == 0 {
			op = []byte{'s'}
			isInteractive = true
		} else {
			op = []byte{'c'}
			// non-interactive cmds may complete quickly, so chaff earlier/faster
			// to help ensure there's some cover to the brief traffic.
			// (ignoring cmdline values)
			chaffFreqMin = 2
			chaffFreqMax = 10
		}
	} else {
		// as copy mode is also non-interactive, set up chaffing
		// just like the 'c' mode above
		chaffFreqMin = 2
		chaffFreqMax = 10

		if pathIsDest {
			// client->server file copy
			// src file list is in copySrc
			op = []byte{'D'}
			//fmt.Println("client->server copy:", string(copySrc), "->", copyDst)
			cmdStr = copyDst
		} else {
			// server->client file copy
			// remote src file(s) in copyDsr
			op = []byte{'S'}
			//fmt.Println("server->client copy:", string(copySrc), "->", copyDst)
			cmdStr = string(copySrc)
		}
	}

	proto := "tcp"
	if kcpMode != "unused" {
		proto = "kcp"
	}
	conn, err := xsnet.Dial(proto, server, cipherAlg, hmacAlg, kexAlg, kcpMode)
	if err != nil {
		fmt.Println(err)
		exitWithStatus(3)
	}

	// Set stdin in raw mode if it's an interactive session
	// TODO: send flag to server side indicating this
	//  affects shell command used
	var oldState *xs.State
	defer conn.Close() // nolint: errcheck

	// From this point on, conn is a secure encrypted channel

	if shellMode {
		if isatty.IsTerminal(os.Stdin.Fd()) {
			oldState, err = xs.MakeRaw(os.Stdin.Fd())
			if err != nil {
				panic(err)
			}
			// #gv:s/label=\"main\$1\"/label=\"deferRestore\"/
			// TODO:.gv:main:1:deferRestore
			defer restoreTermState(oldState)
		} else {
			log.Println("NOT A TTY")
		}
	}

	// Start login timeout here and disconnect if user/pass phase stalls
	loginTimeout := time.AfterFunc(30*time.Second, func() {
		fmt.Printf(" .. [login timeout]")
	})

	if len(authCookie) == 0 {
		//No auth token, prompt for password
		fmt.Printf("Gimme cookie:")
		ab, e := xs.ReadPassword(os.Stdin.Fd())
		fmt.Printf("\r\n")
		if e != nil {
			panic(e)
		}
		authCookie = string(ab)
	}

	_ = loginTimeout.Stop()
	// Security scrub
	runtime.GC()

	// Set up session params and send over to server
	rec := xs.NewSession(op, []byte(uname), []byte(remoteHost), []byte(os.Getenv("TERM")), []byte(cmdStr), []byte(authCookie), 0)
	sendErr := sendSessionParams(&conn, rec)
	if sendErr != nil {
		restoreTermState(oldState)
		rec.SetStatus(254)
		fmt.Fprintln(os.Stderr, "Error: server rejected secure proposal params or login timed out") // nolint: errcheck
		exitWithStatus(int(rec.Status()))
		//log.Fatal(sendErr)
	}

	//Security scrub
	authCookie = "" // nolint: ineffassign
	runtime.GC()

	// Read auth reply from server
	authReply := make([]byte, 1) // bool: 0 = fail, 1 = pass
	_, err = conn.Read(authReply)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading auth reply") // nolint: errcheck
		rec.SetStatus(255)
	} else if authReply[0] == 0 {
		fmt.Fprintln(os.Stderr, rejectUserMsg()) // nolint: errcheck
		rec.SetStatus(255)
	} else {
		// Set up chaffing to server
		conn.SetupChaff(chaffFreqMin, chaffFreqMax, chaffBytesMax) // enable client->server chaffing
		if chaffEnabled {
			// #gv:s/label=\"main\$2\"/label=\"deferCloseChaff\"/
			// TODO:.gv:main:2:deferCloseChaff
			conn.EnableChaff() // goroutine, returns immediately
			defer conn.DisableChaff()
			defer conn.ShutdownChaff()
		}

		// Keepalive for any tunnels that may exist
		// #gv:s/label=\"main\$1\"/label=\"tunKeepAlive\"/
		// TODO:.gv:main:1:tunKeepAlive
		//[1]: better to always send tunnel keepAlives even if client didn't specify
		//     any, to prevent listeners from knowing this.
		//[1] if tunSpecStr != "" {
		keepAliveWorker := func() {
			for {
				// Add a bit of jitter to keepAlive so it doesn't stand out quite as much
				time.Sleep(time.Duration(2000-rand.Intn(200)) * time.Millisecond)
				// FIXME: keepAlives should probably have small random packet len/data as well
				// to further obscure them vs. interactive or tunnel data
				// keepAlives must be  >=2 bytes, due to processing elsewhere
				conn.WritePacket([]byte{0, 0}, xsnet.CSOTunKeepAlive) // nolint: errcheck,gosec
			}
		}
		go keepAliveWorker()
		//[1]}

		if shellMode {
			launchTuns(&conn, remoteHost, tunSpecStr)
			doShellMode(isInteractive, &conn, oldState, rec)
		} else { // copyMode
			s, _ := doCopyMode(&conn, pathIsDest, fileArgs, copyQuiet, copyLimitBPS, rec) // nolint: errcheck,gosec
			rec.SetStatus(s)
		}

		if rec.Status() != 0 {
			restoreTermState(oldState)
			fmt.Fprintln(os.Stderr, "Session exited with status:", rec.Status()) // nolint: errcheck
		}
	}

	if oldState != nil {
		restoreTermState(oldState)
		oldState = nil
	}

	exitWithStatus(int(rec.Status()))
}

// currentUser returns the current username minus any OS-specific prefixes
// such as MS Windows workgroup prefixes (eg. workgroup\user).
func localUserName(u *user.User) string {
	if u == nil {
		log.Fatal("null User?!")
	}

	// WinAPI: username may have CIFS prefix %USERDOMAIN%\
	userspec := strings.Split(u.Username, `\`)
	username := userspec[len(userspec)-1]
	return username
}

func restoreTermState(oldState *xs.State) {
	_ = xs.Restore(os.Stdin.Fd(), oldState) // nolint: errcheck,gosec
}

// exitWithStatus wraps os.Exit() plus does any required pprof housekeeping
func exitWithStatus(status int) {
	if cpuprofile != "" {
		pprof.StopCPUProfile()
	}

	if memprofile != "" {
		f, err := os.Create(memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}

	os.Exit(status)
}
