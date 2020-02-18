// xsd server
//
// Copyright (c) 2017-2019 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"blitter.com/go/goutmp"
	xs "blitter.com/go/xs"
	"blitter.com/go/xs/logger"
	"blitter.com/go/xs/xsnet"
	"github.com/kr/pty"
)

var (
	version   string
	gitCommit string // set in -ldflags by build

	useSysLogin bool
	kcpMode     string // set to a valid KCP BlockCrypt alg tag to use rather than TCP

	// Log - syslog output (with no -d)
	Log *logger.Writer
)

func ioctl(fd, request, argp uintptr) error {
	if _, _, e := syscall.Syscall6(syscall.SYS_IOCTL, fd, request, argp, 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

func ptsName(fd uintptr) (string, error) {
	var n uintptr
	err := ioctl(fd, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}

/* -------------------------------------------------------------- */
// Perform a client->server copy
func runClientToServerCopyAs(who, ttype string, conn *xsnet.Conn, fpath string, chaffing bool) (exitStatus uint32, err error) {
	u, _ := user.Lookup(who) // nolint: gosec
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid) // nolint: gosec,errcheck
	fmt.Sscanf(u.Gid, "%d", &gid) // nolint: gosec,errcheck
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	os.Setenv("HOME", u.HomeDir) // nolint: gosec,errcheck
	os.Setenv("TERM", ttype)     // nolint: gosec,errcheck
	os.Setenv("HKEXSH", "1")     // nolint: gosec,errcheck

	var c *exec.Cmd
	cmdName := "/bin/tar"

	var destDir string
	if path.IsAbs(fpath) {
		destDir = fpath
	} else {
		destDir = path.Join(u.HomeDir, fpath)
	}

	cmdArgs := []string{"-xz", "-C", destDir}

	// NOTE the lack of quotes around --xform option's sed expression.
	// When args are passed in exec() format, no quoting is required
	// (as this isn't input from a shell) (right? -rlm 20180823)
	//cmdArgs := []string{"-x", "-C", destDir, `--xform=s#.*/\(.*\)#\1#`}
	c = exec.Command(cmdName, cmdArgs...) // nolint: gosec

	c.Dir = destDir

	//If os.Clearenv() isn't called by server above these will be seen in the
	//client's session env.
	//c.Env = []string{"HOME=" + u.HomeDir, "SUDO_GID=", "SUDO_UID=", "SUDO_USER=", "SUDO_COMMAND=", "MAIL=", "LOGNAME="+who}
	//c.Dir = u.HomeDir
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	c.Stdin = conn
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if chaffing {
		conn.EnableChaff()
	}
	defer conn.DisableChaff()
	defer conn.ShutdownChaff()

	// Start the command (no pty)
	log.Printf("[%v %v]\n", cmdName, cmdArgs)
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
		log.Println("cmd exited immediately. Cannot get cmd.Wait().ExitStatus()")
		err = errors.New("cmd exited prematurely")
		//exitStatus = uint32(254)
		exitStatus = xsnet.CSEExecFail
	} else {
		if err := c.Wait(); err != nil {
			//fmt.Println("*** c.Wait() done ***")
			if exiterr, ok := err.(*exec.ExitError); ok {
				// The program has exited with an exit code != 0

				// This works on both Unix and Windows. Although package
				// syscall is generally platform dependent, WaitStatus is
				// defined for both Unix and Windows and in both cases has
				// an ExitStatus() method with the same signature.
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					exitStatus = uint32(status.ExitStatus())
					//err = errors.New("cmd returned nonzero status")
					log.Printf("Exit Status: %d\n", exitStatus)
				}
			}
		}
		log.Println("*** client->server cp finished ***")
	}
	return
}

// Perform a server->client copy
func runServerToClientCopyAs(who, ttype string, conn *xsnet.Conn, srcPath string, chaffing bool) (exitStatus uint32, err error) {
	u, err := user.Lookup(who)
	if err != nil {
		exitStatus = 1
		return
	}
	var uid, gid uint32
	_, _ = fmt.Sscanf(u.Uid, "%d", &uid) // nolint: gosec
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid) // nolint: gosec
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	_ = os.Setenv("HOME", u.HomeDir) // nolint: gosec
	_ = os.Setenv("TERM", ttype)     // nolint: gosec
	_ = os.Setenv("HKEXSH", "1")     // nolint: gosec

	var c *exec.Cmd
	cmdName := "/bin/tar"
	if !path.IsAbs(srcPath) {
		srcPath = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, srcPath)
	}

	srcDir, srcBase := path.Split(srcPath)
	cmdArgs := []string{"-cz", "-C", srcDir, "-f", "-", srcBase}

	c = exec.Command(cmdName, cmdArgs...) // nolint: gosec

	//If os.Clearenv() isn't called by server above these will be seen in the
	//client's session env.
	//c.Env = []string{"HOME=" + u.HomeDir, "SUDO_GID=", "SUDO_UID=", "SUDO_USER=", "SUDO_COMMAND=", "MAIL=", "LOGNAME="+who}
	c.Dir = u.HomeDir
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	c.Stdout = conn
	// Stderr sinkholing (or buffering to something other than stdout)
	// is important. Any extraneous output to tarpipe messes up remote
	// side as it's expecting pure tar data.
	// (For example, if user specifies abs paths, tar outputs
	// "Removing leading '/' from path names")
	stdErrBuffer := new(bytes.Buffer)
	c.Stderr = stdErrBuffer
	//c.Stderr = nil

	if chaffing {
		conn.EnableChaff()
	}
	//defer conn.Close()
	defer conn.DisableChaff()
	defer conn.ShutdownChaff()

	// Start the command (no pty)
	log.Printf("[%v %v]\n", cmdName, cmdArgs)
	err = c.Start() // returns immediately
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		return xsnet.CSEExecFail, err // !?
	}
	if err := c.Wait(); err != nil {
		//fmt.Println("*** c.Wait() done ***")
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitStatus = uint32(status.ExitStatus())
				if len(stdErrBuffer.Bytes()) > 0 {
					log.Print(stdErrBuffer)
				}
				log.Printf("Exit Status: %d", exitStatus)
			}
		}
	}
	//fmt.Println("*** server->client cp finished ***")
	return
}

// Run a command (via default shell) as a specific user
//
// Uses ptys to support commands which expect a terminal.
// nolint: gocyclo
func runShellAs(who, hname, ttype, cmd string, interactive bool, conn *xsnet.Conn, chaffing bool) (exitStatus uint32, err error) {
	var wg sync.WaitGroup
	u, err := user.Lookup(who)
	if err != nil {
		exitStatus = 1
		return
	}
	var uid, gid uint32
	_, _ = fmt.Sscanf(u.Uid, "%d", &uid) // nolint: gosec
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid) // nolint: gosec
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	_ = os.Setenv("HOME", u.HomeDir) // nolint: gosec
	_ = os.Setenv("TERM", ttype)     // nolint: gosec
	_ = os.Setenv("HKEXSH", "1")     // nolint: gosec

	var c *exec.Cmd
	if interactive {
		if useSysLogin {
			// Use the server's login binary (post-auth
			// which is still done via our own bcrypt file)
			// Things UNIX login does, like print the 'motd',
			// and use the shell specified by /etc/passwd, will be done
			// automagically, at the cost of another external tool
			// dependency.
			//
			c = exec.Command("/bin/login", "-f", "-p", who) // nolint: gosec
		} else {
			c = exec.Command("/bin/bash", "-i", "-l") // nolint: gosec
		}
	} else {
		c = exec.Command("/bin/bash", "-c", cmd) // nolint: gosec
	}
	//If os.Clearenv() isn't called by server above these will be seen in the
	//client's session env.
	//c.Env = []string{"HOME=" + u.HomeDir, "SUDO_GID=", "SUDO_UID=", "SUDO_USER=", "SUDO_COMMAND=", "MAIL=", "LOGNAME="+who}
	c.Dir = u.HomeDir
	c.SysProcAttr = &syscall.SysProcAttr{}
	if useSysLogin {
		// If using server's login binary, drop to user creds
		// is taken care of by it.
		c.SysProcAttr.Credential = &syscall.Credential{}
	} else {
		c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	}

	// Start the command with a pty.
	ptmx, err := pty.Start(c) // returns immediately with ptmx file
	if err != nil {
		log.Println(err)
		return xsnet.CSEPtyExecFail, err
	}
	// Make sure to close the pty at the end.
	// #gv:s/label=\"runShellAs\$1\"/label=\"deferPtmxClose\"/
	defer func() {
		//logger.LogDebug(fmt.Sprintf("[Exited process was %d]", c.Process.Pid))
		_ = ptmx.Close()
	}() // nolint: gosec

	// get pty info for system accounting (who, lastlog)
	pts, pe := ptsName(ptmx.Fd())
	if pe != nil {
		return xsnet.CSEPtyGetNameFail, err
	}
	utmpx := goutmp.Put_utmp(who, pts, hname)
	defer func() { goutmp.Unput_utmp(utmpx) }()
	goutmp.Put_lastlog_entry("xs", who, pts, hname)

	log.Printf("[%s]\n", cmd)
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	} else {
		// Watch for term resizes
		// #gv:s/label=\"runShellAs\$2\"/label=\"termResizeWatcher\"/
		go func() {
			for sz := range conn.WinCh {
				log.Printf("[Setting term size to: %v %v]\n", sz.Rows, sz.Cols)
				pty.Setsize(ptmx, &pty.Winsize{Rows: sz.Rows, Cols: sz.Cols}) // nolint: gosec,errcheck
			}
			log.Println("*** WinCh goroutine done ***")
		}()

		// Copy stdin to the pty.. (bgnd goroutine)
		// #gv:s/label=\"runShellAs\$3\"/label=\"stdinToPtyWorker\"/
		go func() {
			_, e := io.Copy(ptmx, conn)
			if e != nil {
				log.Println("** stdin->pty ended **:", e.Error())
			} else {
				log.Println("*** stdin->pty goroutine done ***")
			}
		}()

		if chaffing {
			conn.EnableChaff()
		}
		// #gv:s/label=\"runShellAs\$4\"/label=\"deferChaffShutdown\"/
		defer func() {
			conn.DisableChaff()
			conn.ShutdownChaff()
		}()

		// ..and the pty to stdout.
		// This may take some time exceeding that of the
		// actual command's lifetime, so the c.Wait() below
		// must synchronize with the completion of this goroutine
		// to ensure all stdout data gets to the client before
		// connection is closed.
		wg.Add(1)
		// #gv:s/label=\"runShellAs\$5\"/label=\"ptyToStdoutWorker\"/
		go func() {
			defer wg.Done()
			_, e := io.Copy(conn, ptmx)
			if e != nil {
				log.Println("** pty->stdout ended **:", e.Error())
			} else {
				// The above io.Copy() will exit when the command attached
				// to the pty exits
				log.Println("*** pty->stdout goroutine done ***")
			}
		}()

		if err := c.Wait(); err != nil {
			//fmt.Println("*** c.Wait() done ***")
			if exiterr, ok := err.(*exec.ExitError); ok {
				// The program has exited with an exit code != 0

				// This works on both Unix and Windows. Although package
				// syscall is generally platform dependent, WaitStatus is
				// defined for both Unix and Windows and in both cases has
				// an ExitStatus() method with the same signature.
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					exitStatus = uint32(status.ExitStatus())
					log.Printf("Exit Status: %d", exitStatus)
				}
			}
			conn.SetStatus(xsnet.CSOType(exitStatus))
		} else {
			logger.LogDebug("*** Main proc has exited. ***")
			// Background jobs still may be running; close the
			// pty anyway, so the client can return before
			// wg.Wait() below completes (Issue #18)
			if interactive {
				_ = ptmx.Close()
			}
		}
		wg.Wait() // Wait on pty->stdout completion to client
	}
	return
}

// GenAuthToken generates a pseudorandom auth token for a specific
// user from a specific host to allow non-interactive logins.
func GenAuthToken(who string, connhost string) string {
	//tokenA, e := os.Hostname()
	//if e != nil {
	//	tokenA = "badhost"
	//}
	tokenA := connhost

	tokenB := make([]byte, 64)
	_, _ = rand.Read(tokenB) // nolint: gosec
	return fmt.Sprintf("%s:%s", tokenA, hex.EncodeToString(tokenB))
}

var (
	aKEXAlgs    allowedKEXAlgs
	aCipherAlgs allowedCipherAlgs
	aHMACAlgs   allowedHMACAlgs
)

type allowedKEXAlgs []string    // TODO
type allowedCipherAlgs []string // TODO
type allowedHMACAlgs []string   // TODO

func (a allowedKEXAlgs) allowed(k xsnet.KEXAlg) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == "KEX_all" || a[i] == k.String() {
			return true
		}
	}
	return false
}

func (a *allowedKEXAlgs) String() string {
	return fmt.Sprintf("allowedKEXAlgs: %v", *a)
}

func (a *allowedKEXAlgs) Set(value string) error {
	*a = append(*a, strings.TrimSpace(value))
	return nil
}

func (a allowedCipherAlgs) allowed(c xsnet.CSCipherAlg) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == "C_all" || a[i] == c.String() {
			return true
		}
	}
	return false
}

func (a *allowedCipherAlgs) String() string {
	return fmt.Sprintf("allowedCipherAlgs: %v", *a)
}

func (a *allowedCipherAlgs) Set(value string) error {
	*a = append(*a, strings.TrimSpace(value))
	return nil
}

func (a allowedHMACAlgs) allowed(h xsnet.CSHmacAlg) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == "H_all" || a[i] == h.String() {
			return true
		}
	}
	return false
}

func (a *allowedHMACAlgs) String() string {
	return fmt.Sprintf("allowedHMACAlgs: %v", *a)
}

func (a *allowedHMACAlgs) Set(value string) error {
	*a = append(*a, strings.TrimSpace(value))
	return nil
}

// Main server that listens and spawns goroutines for each
// connecting client to serve interactive or file copy sessions
// and any requested tunnels.
// Note that this server does not do UNIX forks of itself to give
// each client its own separate manager process, so if the main
// daemon dies, all clients will be rudely disconnected.
// Consider this when planning to restart or upgrade in-place an installation.
// TODO: reduce gocyclo
func main() {
	var vopt bool
	var chaffEnabled bool
	var chaffFreqMin uint
	var chaffFreqMax uint
	var chaffBytesMax uint
	var dbg bool
	var laddr string

	var useSystemPasswd bool

	flag.BoolVar(&vopt, "v", false, "show version")
	flag.StringVar(&laddr, "l", ":2000", "interface[:port] to listen")
	flag.StringVar(&kcpMode, "K", "unused", `set to one of ["KCP_NONE","KCP_AES", "KCP_BLOWFISH", "KCP_CAST5", "KCP_SM4", "KCP_SALSA20", "KCP_SIMPLEXOR", "KCP_TEA", "KCP_3DES", "KCP_TWOFISH", "KCP_XTEA"] to use KCP (github.com/xtaci/kcp-go) reliable UDP instead of TCP`)
	flag.BoolVar(&useSysLogin, "L", false, "use system login")
	flag.BoolVar(&chaffEnabled, "e", true, "enable chaff pkts")
	flag.UintVar(&chaffFreqMin, "f", 100, "chaff pkt freq min (msecs)")
	flag.UintVar(&chaffFreqMax, "F", 5000, "chaff pkt freq max (msecs)")
	flag.UintVar(&chaffBytesMax, "B", 64, "chaff pkt size max (bytes)")
	flag.BoolVar(&useSystemPasswd, "s", true, "use system shadow passwds")
	flag.BoolVar(&dbg, "d", false, "debug logging")

	flag.Var(&aKEXAlgs, "aK", `List of allowed KEX algs (eg. 'KEXAlgA KEXAlgB ... KEXAlgN') (default allow all)`)
	flag.Var(&aCipherAlgs, "aC", `List of allowed ciphers (eg. 'CipherAlgA CipherAlgB ... CipherAlgN') (default allow all)`)
	flag.Var(&aHMACAlgs, "aH", `List of allowed HMACs (eg. 'HMACAlgA HMACAlgB ... HMACAlgN') (default allow all)`)

	flag.Parse()

	if vopt {
		fmt.Printf("version %s (%s)\n", version, gitCommit)
		os.Exit(0)
	}

	{
		me, e := user.Current()
		if e != nil || me.Uid != "0" {
			log.Fatal("Must run as root.")
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

	Log, _ = logger.New(logger.LOG_DAEMON|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR, "xsd") // nolint: gosec
	xsnet.Init(dbg, "xsd", logger.LOG_DAEMON|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR)
	if dbg {
		log.SetOutput(Log)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// Set up allowed algs, if specified (default allow all)
	if len(aKEXAlgs) == 0 {
		aKEXAlgs = []string{"KEX_all"}
	}
	logger.LogNotice(fmt.Sprintf("Allowed KEXAlgs: %v\n", aKEXAlgs)) // nolint: gosec,errcheck

	if len(aCipherAlgs) == 0 {
		aCipherAlgs = []string{"C_all"}
	}
	logger.LogNotice(fmt.Sprintf("Allowed CipherAlgs: %v\n", aCipherAlgs)) // nolint: gosec,errcheck

	if len(aHMACAlgs) == 0 {
		aHMACAlgs = []string{"H_all"}
	}
	logger.LogNotice(fmt.Sprintf("Allowed HMACAlgs: %v\n", aHMACAlgs)) // nolint: gosec,errcheck

	// Set up handler for daemon signalling
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, os.Signal(syscall.SIGTERM), os.Signal(syscall.SIGINT), os.Signal(syscall.SIGHUP), os.Signal(syscall.SIGUSR1), os.Signal(syscall.SIGUSR2))
	go func() {
		for {
			sig := <-exitCh
			switch sig.String() {
			case "terminated":
				logger.LogNotice(fmt.Sprintf("[Got signal: %s]", sig)) // nolint: gosec,errcheck
				signal.Reset()
				syscall.Kill(0, syscall.SIGTERM) // nolint: gosec,errcheck
			case "interrupt":
				logger.LogNotice(fmt.Sprintf("[Got signal: %s]", sig)) // nolint: gosec,errcheck
				signal.Reset()
				syscall.Kill(0, syscall.SIGINT) // nolint: gosec,errcheck
			case "hangup":
				logger.LogNotice(fmt.Sprintf("[Got signal: %s - nop]", sig)) // nolint:gosec,errcheck
			default:
				logger.LogNotice(fmt.Sprintf("[Got signal: %s - ignored]", sig)) // nolint: gosec,errcheck
			}
		}
	}()

	proto := "tcp"
	if kcpMode != "unused" {
		proto = "kcp"
	}
	l, err := xsnet.Listen(proto, laddr, kcpMode)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close() // nolint: errcheck

	log.Println("Serving on", laddr)
	for {
		// Wait for a connection.
		// Then check if client-proposed algs are allowed
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept() got error(%v), hanging up.\n", err)
		} else if !aKEXAlgs.allowed(conn.KEX()) {
			log.Printf("Accept() rejected for banned KEX alg %d, hanging up.\n", conn.KEX())
			conn.SetStatus(xsnet.CSEKEXAlgDenied)
			conn.Close()
		} else if !aCipherAlgs.allowed(conn.CAlg()) {
			log.Printf("Accept() rejected for banned Cipher alg %d, hanging up.\n", conn.CAlg())
			conn.SetStatus(xsnet.CSECipherAlgDenied)
			conn.Close()
		} else if !aHMACAlgs.allowed(conn.HAlg()) {
			log.Printf("Accept() rejected for banned HMAC alg %d, hanging up.\n", conn.HAlg())
			conn.SetStatus(xsnet.CSEHMACAlgDenied)
			conn.Close()
		} else {
			log.Println("Accepted client")

			// Set up chaffing to client
			// Will only start when runShellAs() is called
			// after stdin/stdout are hooked up
			conn.SetupChaff(chaffFreqMin, chaffFreqMax, chaffBytesMax) // configure server->client chaffing

			// Handle the connection in a new goroutine.
			// The loop then returns to accepting, so that
			// multiple connections may be served concurrently.
			go func(hc *xsnet.Conn) (e error) {
				defer hc.Close() // nolint: errcheck

				//We use io.ReadFull() here to guarantee we consume
				//just the data we want for the xs.Session, and no more.
				//Otherwise data will be sitting in the channel that isn't
				//passed down to the command handlers.
				var rec xs.Session
				var len1, len2, len3, len4, len5, len6 uint32

				n, err := fmt.Fscanf(hc, "%d %d %d %d %d %d\n", &len1, &len2, &len3, &len4, &len5, &len6)
				log.Printf("xs.Session read:%d %d %d %d %d %d\n", len1, len2, len3, len4, len5, len6)

				if err != nil || n < 6 {
					log.Println("[Bad xs.Session fmt]")
					return err
				}

				tmp := make([]byte, len1)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad xs.Session.Op]")
					return err
				}
				rec.SetOp(tmp)

				tmp = make([]byte, len2)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad xs.Session.Who]")
					return err
				}
				rec.SetWho(tmp)

				tmp = make([]byte, len3)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad xs.Session.ConnHost]")
					return err
				}
				rec.SetConnHost(tmp)

				tmp = make([]byte, len4)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad xs.Session.TermType]")
					return err
				}
				rec.SetTermType(tmp)

				tmp = make([]byte, len5)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad xs.Session.Cmd]")
					return err
				}
				rec.SetCmd(tmp)

				tmp = make([]byte, len6)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad xs.Session.AuthCookie]")
					return err
				}
				rec.SetAuthCookie(tmp)

				log.Printf("[xs.Session: op:%c who:%s connhost:%s cmd:%s auth:****]\n",
					rec.Op()[0], string(rec.Who()), string(rec.ConnHost()), string(rec.Cmd()))

				var valid bool
				var allowedCmds string // Currently unused
				if xs.AuthUserByToken(xs.NewAuthCtx(), string(rec.Who()), string(rec.ConnHost()), string(rec.AuthCookie(true))) {
					valid = true
				} else {
					if useSystemPasswd {
						//var passErr error
						valid, _ /*passErr*/ = xs.VerifyPass(xs.NewAuthCtx(), string(rec.Who()), string(rec.AuthCookie(true)))
					} else {
						valid, allowedCmds = xs.AuthUserByPasswd(xs.NewAuthCtx(), string(rec.Who()), string(rec.AuthCookie(true)), "/etc/xs.passwd")
					}
				}

				// Security scrub
				rec.ClearAuthCookie()

				// Tell client if auth was valid
				if valid {
					hc.Write([]byte{1}) // nolint: gosec,errcheck
				} else {
					logger.LogNotice(fmt.Sprintln("Invalid user", string(rec.Who()))) // nolint: errcheck,gosec
					hc.Write([]byte{0})                                               // nolint: gosec,errcheck
					return
				}

				log.Printf("[allowedCmds:%s]\n", allowedCmds)

				if rec.Op()[0] == 'A' {
					// Generate automated login token
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Generating autologin token for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					token := GenAuthToken(string(rec.Who()), string(rec.ConnHost()))
					tokenCmd := fmt.Sprintf("echo \"%s\" | tee -a ~/.xs_id", token)
					cmdStatus, runErr := runShellAs(string(rec.Who()), hname, string(rec.TermType()), tokenCmd, false, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error generating autologin token for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						log.Printf("[Autologin token generation completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)
						hc.SetStatus(xsnet.CSOType(cmdStatus))
					}
				} else if rec.Op()[0] == 'c' {
					// Non-interactive command
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running command for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					cmdStatus, runErr := runShellAs(string(rec.Who()), hname, string(rec.TermType()), string(rec.Cmd()), false, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error spawning cmd for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						logger.LogNotice(fmt.Sprintf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
						hc.SetStatus(xsnet.CSOType(cmdStatus))
					}
				} else if rec.Op()[0] == 's' {
					// Interactive session
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running shell for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck

					cmdStatus, runErr := runShellAs(string(rec.Who()), hname, string(rec.TermType()), string(rec.Cmd()), true, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						Log.Err(fmt.Sprintf("[Error spawning shell for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						logger.LogNotice(fmt.Sprintf("[Shell completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
						hc.SetStatus(xsnet.CSOType(cmdStatus))
					}
				} else if rec.Op()[0] == 'D' {
					// File copy (destination) operation - client copy to server
					log.Printf("[Client->Server copy]\n")
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running copy for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					cmdStatus, runErr := runClientToServerCopyAs(string(rec.Who()), string(rec.TermType()), hc, string(rec.Cmd()), chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error running cp for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						logger.LogNotice(fmt.Sprintf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
					}
					hc.SetStatus(xsnet.CSOType(cmdStatus))

					// Send CSOExitStatus *before* client closes channel
					s := make([]byte, 4)
					binary.BigEndian.PutUint32(s, cmdStatus)
					log.Printf("** cp writing closeStat %d at Close()\n", cmdStatus)
					hc.WritePacket(s, xsnet.CSOExitStatus) // nolint: gosec,errcheck
				} else if rec.Op()[0] == 'S' {
					// File copy (src) operation - server copy to client
					log.Printf("[Server->Client copy]\n")
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running copy for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					cmdStatus, runErr := runServerToClientCopyAs(string(rec.Who()), string(rec.TermType()), hc, string(rec.Cmd()), chaffEnabled)
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error spawning cp for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						// Returned hopefully via an EOF or exit/logout;
						logger.LogNotice(fmt.Sprintf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
					}
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					hc.SetStatus(xsnet.CSOType(cmdStatus))
					//fmt.Println("Waiting for EOF from other end.")
					//_, _ = hc.Read(nil /*ackByte*/)
					//fmt.Println("Got remote end ack.")
				} else {
					logger.LogErr(fmt.Sprintln("[Bad xs.Session]")) // nolint: gosec,errcheck
				}
				return
			}(&conn) // nolint: errcheck
		} // Accept() success
	} //endfor
	//logger.LogNotice(fmt.Sprintln("[Exiting]")) // nolint: gosec,errcheck
}
