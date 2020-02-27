package xs

import (
	"testing"
)

func _newMockSession() (s *Session) {
	s = &Session{op: []byte("A"),
		who:        []byte("johndoe"),
		connhost:   []byte("host"),
		termtype:   []byte("vt100"),
		cmd:        []byte("/bin/false"),
		authCookie: []byte("authcookie"),
		status:     0}
	return s
}

func TestSessionAuthCookieShowTrue(t *testing.T) {
	sess := _newMockSession()
	if string(sess.AuthCookie(true)) != string(sess.authCookie) {
		t.Fatal("Failed to return unredacted authcookie on request")
	}
}

func TestSessionAuthCookieShowFalse(t *testing.T) {
	sess := _newMockSession()
	if string(sess.AuthCookie(false)) != string("**REDACTED**") {
		t.Fatal("Failed to return redacted authcookie on request")
	}
}
