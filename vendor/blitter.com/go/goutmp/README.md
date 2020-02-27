goutmp - Minimal bindings to C stdlib pututmpx(), getutmpx() (/var/log/wtmp) and /var/log/lastlog

Any Go program which allows user shell access should update the standard UNIX files which track user sessions: /var/log/wtmp (for the 'w' and 'who' commands), and /var/log/lastlog (the 'last' and 'lastlog' commands).

```
go doc
package goutmp // import "blitter.com/go/goutmp"

Golang bindings for basic login/utmp accounting

type UtmpEntry struct{ ... }

func Put_lastlog_entry(app, usr, ptsname, host string)
func Unput_utmp(entry UtmpEntry)
func Put_utmp(user, ptsname, host string) UtmpEntry
```

