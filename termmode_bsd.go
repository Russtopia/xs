// +build freebsd
package xs

import (
	"errors"
	"io"
	"unsafe"

	unix "golang.org/x/sys/unix"
)

/* -------------
 * minimal terminal APIs brought in from ssh/terminal
 * (they have no real business being there as they aren't specific to
 * ssh, but as of Go v1.10, late 2019, core go stdlib hasn't yet done
 * the planned terminal lib reorgs.)
 * ------------- */

// From github.com/golang/crypto/blob/master/ssh/terminal/util_linux.go
const getTermios = unix.TIOCGETA
const setTermios = unix.TIOCSETA

// From github.com/golang/crypto/blob/master/ssh/terminal/util.go

// State contains the state of a terminal.
type State struct {
	termios unix.Termios
}

// MakeRaw put the terminal connected to the given file descriptor into raw
// mode and returns the previous state of the terminal so that it can be
// restored.
func MakeRaw(fd uintptr) (*State, error) {
	var oldState State
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, fd, getTermios, uintptr(unsafe.Pointer(&oldState.termios))); err != 0 {
		return nil, err
	}

	newState := oldState.termios
	newState.Iflag &^= (unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON)
	newState.Oflag &^= unix.OPOST
	newState.Lflag &^= (unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN)
	newState.Cflag &^= (unix.CSIZE | unix.PARENB)
	newState.Cflag |= unix.CS8
	newState.Cc[unix.VMIN] = 1
	newState.Cc[unix.VTIME] = 0

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, fd, setTermios, uintptr(unsafe.Pointer(&newState))); err != 0 {
		return nil, err
	}

	return &oldState, nil
}

// Restore restores the terminal connected to the given file descriptor to a
// previous state.
func Restore(fd uintptr, state *State) error {
	if state != nil {
		if _, _, err := unix.Syscall(unix.SYS_IOCTL, fd, setTermios, uintptr(unsafe.Pointer(state))); err != 0 {
			return err
		} else {
			return nil
		}
	} else {
		return errors.New("nil State")
	}
}

// ReadPassword reads a line of input from a terminal without local echo.  This
// is commonly used for inputting passwords and other sensitive data. The slice
// returned does not include the \n.
func ReadPassword(fd uintptr) ([]byte, error) {
	var oldState State
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, fd, getTermios, uintptr(unsafe.Pointer(&oldState.termios))); err != 0 {
		return nil, err
	}

	newState := oldState.termios
	newState.Lflag &^= unix.ECHO
	newState.Lflag |= unix.ICANON | unix.ISIG
	newState.Iflag |= unix.ICRNL
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, fd, setTermios, uintptr(unsafe.Pointer(&newState))); err != 0 {
		return nil, err
	}

	defer func() {
		unix.Syscall(unix.SYS_IOCTL, fd, setTermios, uintptr(unsafe.Pointer(&oldState.termios)))
	}()

	return readPasswordLine(passwordReader(fd))
}

// passwordReader is an io.Reader that reads from a specific file descriptor.
type passwordReader int

func (r passwordReader) Read(buf []byte) (int, error) {
	return unix.Read(int(r), buf)
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
