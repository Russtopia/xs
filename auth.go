package xs

// Package xs - a secure terminal client/server written from scratch in Go
//
// Copyright (c) 2017-2019 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

// Authentication routines for the HKExSh

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/jameskeane/bcrypt"
	passlib "gopkg.in/hlandau/passlib.v1"
)

type AuthCtx struct {
	reader     func(string) ([]byte, error)     // eg. ioutil.ReadFile()
	userlookup func(string) (*user.User, error) // eg. os/user.Lookup()
}

func NewAuthCtx( /*reader func(string) ([]byte, error), userlookup func(string) (*user.User, error)*/ ) (ret *AuthCtx) {
	ret = &AuthCtx{ioutil.ReadFile, user.Lookup}
	return
}

// --------- System passwd/shadow auth routine(s) --------------

// VerifyPass verifies a password against system standard shadow file
// Note auxilliary fields for expiry policy are *not* inspected.
func VerifyPass(ctx *AuthCtx, user, password string) (bool, error) {
	if ctx.reader == nil {
		ctx.reader = ioutil.ReadFile // dependency injection hides that this is required
	}
	passlib.UseDefaults(passlib.Defaults20180601)
	var pwFileName string
	if runtime.GOOS == "linux" {
		pwFileName = "/etc/shadow"
	} else if runtime.GOOS == "freebsd" {
		pwFileName = "/etc/master.passwd"
	} else {
		pwFileName = "unsupported"
	}
	pwFileData, e := ctx.reader(pwFileName)
	if e != nil {
		return false, e
	}
	pwLines := strings.Split(string(pwFileData), "\n")
	if len(pwLines) < 1 {
		return false, errors.New("Empty shadow file!")
	} else {
		var line string
		var hash string
		var idx int
		for idx = range pwLines {
			line = pwLines[idx]
			lFields := strings.Split(line, ":")
			if lFields[0] == user {
				hash = lFields[1]
				break
			}
		}
		if len(hash) == 0 {
			return false, errors.New("nil hash!")
		} else {
			pe := passlib.VerifyNoUpgrade(password, hash)
			if pe != nil {
				return false, pe
			}
		}
	}
	return true, nil
}

// --------- End System passwd/shadow auth routine(s) ----------

// ------------- xs-local passwd auth routine(s) ---------------

// AuthUserByPasswd checks user login information using a password.
// This checks /etc/xs.passwd for auth info, and system /etc/passwd
// to cross-check the user actually exists.
// nolint: gocyclo
func AuthUserByPasswd(ctx *AuthCtx, username string, auth string, fname string) (valid bool, allowedCmds string) {
	if ctx.reader == nil {
		ctx.reader = ioutil.ReadFile // dependency injection hides that this is required
	}
	if ctx.userlookup == nil {
		ctx.userlookup = user.Lookup // again for dependency injection as dep is now hidden
	}
	b, e := ctx.reader(fname) // nolint: gosec
	if e != nil {
		valid = false
		log.Printf("ERROR: Cannot read %s!\n", fname)
	}
	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 3 // username:salt:authCookie [TODO:disallowedCmdList (a,b,...)]
	for {
		record, err := r.Read()
		if err == io.EOF {
			// Use dummy entry if user not found
			// (prevent user enumeration attack via obvious timing diff;
			// ie., not attempting any auth at all)
			record = []string{"$nosuchuser$",
				"$2a$12$l0coBlRDNEJeQVl6GdEPbU",
				"$2a$12$l0coBlRDNEJeQVl6GdEPbUC/xmuOANvqgmrMVum6S4i.EXPgnTXy6"}
			username = "$nosuchuser$"
			err = nil
		}
		if err != nil {
			log.Fatal(err)
		}

		if username == record[0] {
			tmp, err := bcrypt.Hash(auth, record[1])
			if err != nil {
				break
			}
			if tmp == record[2] && username != "$nosuchuser$" {
				valid = true
			}
			break
		}
	}
	// Security scrub
	for i := range b {
		b[i] = 0
	}
	r = nil
	runtime.GC()

	_, userErr := ctx.userlookup(username)
	if userErr != nil {
		valid = false
	}
	return
}

// ------------- End xs-local passwd auth routine(s) -----------

// AuthUserByToken checks user login information against an auth token.
// Auth tokens are stored in each user's $HOME/.xs_id and are requested
// via the -g option.
// The function also check system /etc/passwd to cross-check the user
// actually exists.
func AuthUserByToken(ctx *AuthCtx, username string, connhostname string, auth string) (valid bool) {
	if ctx.reader == nil {
		ctx.reader = ioutil.ReadFile // dependency injection hides that this is required
	}
	if ctx.userlookup == nil {
		ctx.userlookup = user.Lookup // again for dependency injection as dep is now hidden
	}

	auth = strings.TrimSpace(auth)
	u, ue := ctx.userlookup(username)
	if ue != nil {
		return false
	}

	b, e := ctx.reader(fmt.Sprintf("%s/.xs_id", u.HomeDir))
	if e != nil {
		log.Printf("INFO: Cannot read %s/.xs_id\n", u.HomeDir)
		return false
	}

	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 2 // connhost:authtoken
	for {
		record, err := r.Read()
		if err == io.EOF {
			return false
		}
		record[0] = strings.TrimSpace(record[0])
		record[1] = strings.TrimSpace(record[1])
		//fmt.Println("auth:", auth, "record:",
		//	strings.Join([]string{record[0], record[1]}, ":"))

		if (connhostname == record[0]) &&
			(auth == strings.Join([]string{record[0], record[1]}, ":")) {
			valid = true
			break
		}
	}
	_, userErr := ctx.userlookup(username)
	if userErr != nil {
		valid = false
	}
	return
}

func GetTool(tool string) (ret string) {
	ret = "/bin/"+tool
	_, err := os.Stat(ret)
	if err == nil {
		return ret
	}
	ret = "/usr/bin/"+tool
	_, err = os.Stat(ret)
	if err == nil {
		return ret
	}
	ret = "/usr/local/bin/"+tool
	_, err = os.Stat(ret)
	if err == nil {
		return ret
	}
	return ""
}

