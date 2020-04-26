// +build windows

// Wrapper around UNIX syslog, so that it also may be wrapped
// with something else for Windows.
package logger

import (
	"os"
)

type Priority = int
type Writer = os.File


const (
	// Severity.

	// From /usr/include/sys/syslog.h.
	// These are the same on Linux, BSD, and OS X.
	LOG_EMERG Priority = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

const (
	// Facility.

	// From /usr/include/sys/syslog.h.
	// These are the same up to LOG_FTP on Linux, BSD, and OS X.
	LOG_KERN Priority = iota << 3
	LOG_USER
	LOG_MAIL
	LOG_DAEMON
	LOG_AUTH
	LOG_SYSLOG
	LOG_LPR
	LOG_NEWS
	LOG_UUCP
	LOG_CRON
	LOG_AUTHPRIV
	LOG_FTP
	_ // unused
	_ // unused
	_ // unused
	_ // unused
	LOG_LOCAL0
	LOG_LOCAL1
	LOG_LOCAL2
	LOG_LOCAL3
	LOG_LOCAL4
	LOG_LOCAL5
	LOG_LOCAL6
	LOG_LOCAL7
)

func New(flags Priority, tag string) (w *Writer, e error) {
	return os.Stderr, nil
}

func Alert(s string) error {
		return nil
}
func LogClose() error {
		return nil
}
func LogCrit(s string) error {
		return nil
}
func LogDebug(s string) error {
		return nil
}
func LogEmerg(s string) error {
		return nil
}
func LogErr(s string) error {
		return nil
}
func LogInfo(s string) error {
		return nil
}
func LogNotice(s string) error {
		return nil
}
func LogWarning(s string) error {
		return nil
}
func LogWrite(b []byte) (int, error) {
		return len(b), nil
}
