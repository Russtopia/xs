// +build windows
//
// Note the terminal manipulation functions herein are mostly stubs. They
// don't really do anything and the xs demo client depends on a wrapper
// script using the 'stty' tool to actually set the proper mode for
// password login and raw mode required, then restoring it upon logout/exit.
//
// mintty uses named pipes and ptys rather than Windows 'console'
// mode, and Go's x/crypto/ssh/terminal libs only work for the latter, so
// until some truly cross-platform terminal mode handling makes it into the
// go std lib I'm not going to jump through hoops trying to be cross-platform
// here; the wrapper does the bare minimum to make the client workable
// under MSYS+mintty which is what I use.

package xs

import (
	"io"
	"os/exec"

	"golang.org/x/sys/windows"
)

type State struct {
}

// MakeRaw put the terminal connected to the given file descriptor into raw
// mode and returns the previous state of the terminal so that it can be
// restored.
func MakeRaw(fd int) (*State, error) {
	// This doesn't really work. The exec.Command() runs a sub-shell
	// so the stty mods don't affect the client process.
	cmd := exec.Command("stty", "-echo raw")
	cmd.Run()
	return &State{}, nil
}

// GetState returns the current state of a terminal which may be useful to
// restore the terminal after a signal.
func GetState(fd int) (*State, error) {
	return &State{}, nil
}

// Restore restores the terminal connected to the given file descriptor to a
// previous state.
func Restore(fd int, state *State) error {
	cmd := exec.Command("stty", "echo cooked")
	cmd.Run()
	return nil
}

// ReadPassword reads a line of input from a terminal without local echo.  This
// is commonly used for inputting passwords and other sensitive data. The slice
// returned does not include the \n.
func ReadPassword(fd int) ([]byte, error) {
	return readPasswordLine(passwordReader(fd))
}

// passwordReader is an io.Reader that reads from a specific file descriptor.
type passwordReader windows.Handle

func (r passwordReader) Read(buf []byte) (int, error) {
	return windows.Read(windows.Handle(r), buf)
}

// readPasswordLine reads from reader until it finds \n or io.EOF.
// The slice returned does not include the \n.
// readPasswordLine also ignores any \r it finds.
func readPasswordLine(reader io.Reader) ([]byte, error) {
	var buf [1]byte
	var ret []byte

	for {
		n, err := reader.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\n':
				return ret, nil
			case '\r':
				// remove \r from passwords on Windows
			default:
				ret = append(ret, buf[0])
			}
			continue
		}
		if err != nil {
			if err == io.EOF && len(ret) > 0 {
				return ret, nil
			}
			return ret, err
		}
	}
}
