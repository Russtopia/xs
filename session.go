package xs

// Package xs - a secure terminal client/server written from scratch in Go
//
// Copyright (c) 2017-2019 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

// Session info/routines for the HKExSh

import (
	"fmt"
	"runtime"
)

// Session holds essential bookkeeping info about an active session.
type Session struct {
	op         []byte
	who        []byte
	connhost   []byte
	termtype   []byte // client initial $TERM
	cmd        []byte
	authCookie []byte
	status     uint32 // exit status (0-255 is std UNIX status)
}

// Output Session record as a string. Implements Stringer interface.
func (h *Session) String() string {
	return fmt.Sprintf("xs.Session:\nOp:%v\nWho:%v\nCmd:%v\nAuthCookie:%v\nStatus:%v",
		h.op, h.who, h.cmd, h.AuthCookie(false), h.status)
}

// Op returns the op code of the Session (interactive shell, cmd, ...)
func (h Session) Op() []byte {
	return h.op
}

// SetOp stores the op code desired for a Session.
func (h *Session) SetOp(o []byte) {
	h.op = o
}

// Who returns the user associated with a Session.
func (h Session) Who() []byte {
	return h.who
}

// SetWho sets the username associated with a Session.
func (h *Session) SetWho(w []byte) {
	h.who = w
}

// ConnHost returns the connecting hostname/IP string for a Session.
func (h Session) ConnHost() []byte {
	return h.connhost
}

// SetConnHost stores the connecting hostname/IP string for a Session.
func (h *Session) SetConnHost(n []byte) {
	h.connhost = n
}

// TermType returns the TERM env variable reported by the client initiating
// a Session.
func (h Session) TermType() []byte {
	return h.termtype
}

// SetTermType stores the TERM env variable supplied by the client initiating
// a Session.
func (h *Session) SetTermType(t []byte) {
	h.termtype = t
}

// Cmd returns the command requested for execution by a client initiating
// the Session.
func (h Session) Cmd() []byte {
	return h.cmd
}

// SetCmd stores the command request by the client for execution when initiating
// the Session.
func (h *Session) SetCmd(c []byte) {
	h.cmd = c
}

// AuthCookie returns the authcookie (essentially the password) used for
// authorization of the Session. This return value is censored unless
// reallyShow is true (so dumps of Session Info do not accidentally leak it).
func (h Session) AuthCookie(reallyShow bool) []byte {
	if reallyShow {
		return h.authCookie
	}
	return []byte("**REDACTED**")
}

// SetAuthCookie stores the authcookie (essentially the password) used to
// authenticate the Session.
func (h *Session) SetAuthCookie(a []byte) {
	h.authCookie = a
}

// ClearAuthCookie attempts to scrub the Session's stored authcookie.
//
// This should of course be called as soon as possible after authentication
// and it is no longer required.
func (h *Session) ClearAuthCookie() {
	for i := range h.authCookie {
		h.authCookie[i] = 0
	}
	runtime.GC()
}

// Status returns the (current) Session status code.
//
// This usually corresponds to a UNIX shell exit code, but
// extended codes are returns at times to indicate internal errors.
func (h Session) Status() uint32 {
	return h.status
}

// SetStatus stores the current Session status code.
func (h *Session) SetStatus(s uint32) {
	h.status = s
}

// NewSession returns a new Session record.
func NewSession(op, who, connhost, ttype, cmd, authcookie []byte, status uint32) *Session {
	return &Session{
		op:         op,
		who:        who,
		connhost:   connhost,
		termtype:   ttype,
		cmd:        cmd,
		authCookie: authcookie,
		status:     status}
}
