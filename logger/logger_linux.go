// +build linux

// Package logger is a wrapper around UNIX syslog, so that it also may
// be wrapped with something else for Windows (Sadly, the stdlib log/syslog
// is frozen, and there is no Windows implementation.)
package logger

import (
	sl "log/syslog"
)

// Priority is the logger priority
type Priority = sl.Priority

// Writer is a syslog Writer
type Writer = sl.Writer

// nolint: golint
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

// nolint: golint
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

var (
	l *sl.Writer
)

// New returns a new log Writer.
func New(flags Priority, tag string) (w *Writer, e error) {
	w, e = sl.New(flags, tag)
	l = w
	return w, e
}

// Alert returns a log Alert error
func Alert(s string) error {
	if l != nil {
		return l.Alert(s)
	}
	return nil

}

// LogClose closes the log Writer.
func LogClose() error {
	if l != nil {
		return l.Close()
	}
	return nil
}

// LogCrit returns a log Alert error
func LogCrit(s string) error {
	if l != nil {
		return l.Crit(s)
	}
	return nil
}

// LogDebug returns a log Debug error
func LogDebug(s string) error {
	if l != nil {
		return l.Debug(s)
	}
	return nil
}

// LogEmerg returns a log Emerg error
func LogEmerg(s string) error {
	if l != nil {
		return l.Emerg(s)
	}
	return nil
}

// LogErr returns a log Err error
func LogErr(s string) error {
	if l != nil {
		return l.Err(s)
	}
	return nil
}

// LogInfo returns a log Info error
func LogInfo(s string) error {
	if l != nil {
		return l.Info(s)
	}
	return nil
}

// LogNotice returns a log Notice error
func LogNotice(s string) error {
	if l != nil {
		return l.Notice(s)
	}
	return nil
}

// LogWarning returns a log Warning error
func LogWarning(s string) error {
	if l != nil {
		return l.Warning(s)
	}
	return nil
}

// LogWrite writes to the logger at default level
func LogWrite(b []byte) (int, error) {
	if l != nil {
		return l.Write(b)
	}
	return len(b),nil
}
