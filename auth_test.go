package xs

import (
	"errors"
	"fmt"
	"os/user"
	"strings"
	"testing"
)

type userVerifs struct {
	user   string
	passwd string
	good   bool
}

var (
	dummyShadowA = `johndoe:$6$EeQlTtn/KXdSh6CW$UHbFuEw3UA0Jg9/GoPHxgWk6Ws31x3IjqsP22a9pVMOte0yQwX1.K34oI4FACu8GRg9DArJ5RyWUE9m98qwzZ1:18310:0:99999:7:::
joebloggs:$6$F.0IXOrb0w0VJHG1$3O4PYyng7F3hlh42mbroEdQZvslybY5etPPiLMQJ1xosjABY.Q4xqAfyIfe03Du61ZjGQIt3nL0j12P9k1fsK/:18310:0:99999:7:::
disableduser:!:18310::::::`

	dummyAuthTokenFile = "hostA:abcdefg\nhostB:wxyz\n"

	dummyXsPasswdFile = `#username:salt:authCookie
bobdobbs:$2a$12$9vqGkFqikspe/2dTARqu1O:$2a$12$9vqGkFqikspe/2dTARqu1OuDKCQ/RYWsnaFjmi.HtmECRkxcZ.kBK
notbob:$2a$12$cZpiYaq5U998cOkXzRKdyu:$2a$12$cZpiYaq5U998cOkXzRKdyuJ2FoEQyVLa3QkYdPQk74VXMoAzhvuP6
`

	testGoodUsers = []userVerifs{
		{"johndoe", "testpass", true},
		{"joebloggs", "testpass2", true},
		{"johndoe", "badpass", false},
	}

	testXsPasswdUsers = []userVerifs{
		{"bobdobbs", "praisebob", true},
		{"notbob", "imposter", false},
	}

	userlookup_arg_u string
	readfile_arg_f   string
)

func newMockAuthCtx(reader func(string) ([]byte, error), userlookup func(string) (*user.User, error)) (ret *AuthCtx) {
	ret = &AuthCtx{reader, userlookup}
	return
}

func _mock_user_Lookup(username string) (*user.User, error) {
	username = userlookup_arg_u
	if username == "baduser" {
		return &user.User{}, errors.New("bad user")
	}
	urec := &user.User{Uid: "1000", Gid: "1000", Username: username, Name: "Full Name", HomeDir: "/home/user"}
	fmt.Printf("  [mock user rec:%v]\n", urec)
	return urec, nil
}

func _mock_ioutil_ReadFile(f string) ([]byte, error) {
	f = readfile_arg_f
	if f == "/etc/shadow" {
		fmt.Println("  [mocking ReadFile(\"/etc/shadow\")]")
		return []byte(dummyShadowA), nil
	}
	if f == "/etc/xs.passwd" {
		fmt.Println("  [mocking ReadFile(\"/etc/xs.passwd\")]")
		return []byte(dummyXsPasswdFile), nil
	}
	if strings.Contains(f, "/.xs_id") {
		fmt.Println("  [mocking ReadFile(\".xs_id\")]")
		return []byte(dummyAuthTokenFile), nil
	}
	return []byte{}, errors.New("no readfile_arg_f supplied")
}

func _mock_ioutil_ReadFileEmpty(f string) ([]byte, error) {
	return []byte{}, nil
}

func _mock_ioutil_ReadFileHasError(f string) ([]byte, error) {
	return []byte{}, errors.New("IO Error")
}

func TestVerifyPass(t *testing.T) {
	readfile_arg_f = "/etc/shadow"
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, nil)
	for idx, rec := range testGoodUsers {
		stat, e := VerifyPass(ctx, rec.user, rec.passwd)
		if rec.good && (!stat || e != nil) {
			t.Fatalf("failed %d\n", idx)
		}
	}
}

func TestVerifyPassFailsOnEmptyFile(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFileEmpty, nil)
	stat, e := VerifyPass(ctx, "johndoe", "somepass")
	if stat || (e == nil) {
		t.Fatal("failed to fail w/empty file")
	}
}

func TestVerifyPassFailsOnFileError(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFileEmpty, nil)
	stat, e := VerifyPass(ctx, "johndoe", "somepass")
	if stat || (e == nil) {
		t.Fatal("failed to fail on ioutil.ReadFile error")
	}
}

func TestVerifyPassFailsOnDisabledEntry(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFileEmpty, nil)
	stat, e := VerifyPass(ctx, "disableduser", "!")
	if stat || (e == nil) {
		t.Fatal("failed to fail on disabled user entry")
	}
}

////

func TestAuthUserByTokenFailsOnMissingEntryForHost(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	stat := AuthUserByToken(ctx, "johndoe", "hostZ", "abcdefg")
	if stat {
		t.Fatal("failed to fail on missing/mismatched host entry")
	}
}

func TestAuthUserByTokenFailsOnMissingEntryForUser(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	stat := AuthUserByToken(ctx, "unkuser", "hostA", "abcdefg")
	if stat {
		t.Fatal("failed to fail on wrong user")
	}
}

func TestAuthUserByTokenFailsOnUserLookupFailure(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	userlookup_arg_u = "baduser"
	stat := AuthUserByToken(ctx, "johndoe", "hostA", "abcdefg")
	if stat {
		t.Fatal("failed to fail with bad return from user.Lookup()")
	}
}

func TestAuthUserByTokenFailsOnMismatchedTokenForUser(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	stat := AuthUserByToken(ctx, "johndoe", "hostA", "badtoken")
	if stat {
		t.Fatal("failed to fail with valid user, bad token")
	}
}

func TestAuthUserByTokenSucceedsWithMatchedUserAndToken(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	userlookup_arg_u = "johndoe"
	readfile_arg_f = "/.xs_id"
	stat := AuthUserByToken(ctx, userlookup_arg_u, "hostA", "hostA:abcdefg")
	if !stat {
		t.Fatal("failed with valid user and token")
	}
}

func TestAuthUserByPasswdFailsOnEmptyFile(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFileEmpty, _mock_user_Lookup)
	userlookup_arg_u = "bobdobbs"
	readfile_arg_f = "/etc/xs.passwd"
	stat, _ := AuthUserByPasswd(ctx, userlookup_arg_u, "praisebob", readfile_arg_f)
	if stat {
		t.Fatal("failed to fail with missing xs.passwd file")
	}
}

func TestAuthUserByPasswdFailsOnBadAuth(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	userlookup_arg_u = "bobdobbs"
	readfile_arg_f = "/etc/xs.passwd"
	stat, _ := AuthUserByPasswd(ctx, userlookup_arg_u, "wrongpass", readfile_arg_f)
	if stat {
		t.Fatal("failed to fail with valid user, incorrect passwd in xs.passwd file")
	}
}

func TestAuthUserByPasswdFailsOnBadUser(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	userlookup_arg_u = "bobdobbs"
	readfile_arg_f = "/etc/xs.passwd"
	stat, _ := AuthUserByPasswd(ctx, userlookup_arg_u, "theotherbob", readfile_arg_f)
	if stat {
		t.Fatal("failed to fail on invalid user vs. xs.passwd file")
	}
}

func TestAuthUserByPasswdPassesOnGoodAuth(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	userlookup_arg_u = "bobdobbs"
	readfile_arg_f = "/etc/xs.passwd"
	stat, _ := AuthUserByPasswd(ctx, userlookup_arg_u, "praisebob", readfile_arg_f)
	if !stat {
		t.Fatal("failed on valid user w/correct passwd in xs.passwd file")
	}
}

func TestAuthUserByPasswdPassesOnOtherGoodAuth(t *testing.T) {
	ctx := newMockAuthCtx(_mock_ioutil_ReadFile, _mock_user_Lookup)
	userlookup_arg_u = "notbob"
	readfile_arg_f = "/etc/xs.passwd"
	stat, _ := AuthUserByPasswd(ctx, userlookup_arg_u, "imposter", readfile_arg_f)
	if !stat {
		t.Fatal("failed on valid user 2nd entry w/correct passwd in xs.passwd file")
	}
}
