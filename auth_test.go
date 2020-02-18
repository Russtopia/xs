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

	testGoodUsers = []userVerifs{
		{"johndoe", "testpass", true},
		{"joebloggs", "testpass2", true},
		{"johndoe", "badpass", false},
	}

	userlookup_arg_u string
	readfile_arg_f   string
)

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
	for idx, rec := range testGoodUsers {
		stat, e := VerifyPass(_mock_ioutil_ReadFile, rec.user, rec.passwd)
		if rec.good && (!stat || e != nil) {
			t.Fatalf("failed %d\n", idx)
		}
	}
}

func TestVerifyPassFailsOnEmptyFile(t *testing.T) {
	stat, e := VerifyPass(_mock_ioutil_ReadFileEmpty, "johndoe", "sompass")
	if stat || (e == nil) {
		t.Fatal("failed to fail w/empty file")
	}
}

func TestVerifyPassFailsOnFileError(t *testing.T) {
	stat, e := VerifyPass(_mock_ioutil_ReadFileEmpty, "johndoe", "somepass")
	if stat || (e == nil) {
		t.Fatal("failed to fail on ioutil.ReadFile error")
	}
}

func TestVerifyPassFailsOnDisabledEntry(t *testing.T) {
	stat, e := VerifyPass(_mock_ioutil_ReadFileEmpty, "disableduser", "!")
	if stat || (e == nil) {
		t.Fatal("failed to fail on disabled user entry")
	}
}

////

func TestAuthUserByTokenFailsOnMissingEntryForHost(t *testing.T) {
	stat := AuthUserByToken(_mock_ioutil_ReadFile, _mock_user_Lookup, "johndoe", "hostZ", "abcdefg")
	if stat {
		t.Fatal("failed to fail on missing/mismatched host entry")
	}
}

func TestAuthUserByTokenFailsOnMissingEntryForUser(t *testing.T) {
	stat := AuthUserByToken(_mock_ioutil_ReadFile, _mock_user_Lookup, "unkuser", "hostA", "abcdefg")
	if stat {
		t.Fatal("failed to fail on wrong user")
	}
}

func TestAuthUserByTokenFailsOnUserLookupFailure(t *testing.T) {
	userlookup_arg_u = "baduser"
	stat := AuthUserByToken(_mock_ioutil_ReadFile, _mock_user_Lookup, "johndoe", "hostA", "abcdefg")
	if stat {
		t.Fatal("failed to fail with bad return from user.Lookup()")
	}
}

func TestAuthUserByTokenFailsOnMismatchedTokenForUser(t *testing.T) {
	stat := AuthUserByToken(_mock_ioutil_ReadFile, _mock_user_Lookup, "johndoe", "hostA", "badtoken")
	if stat {
		t.Fatal("failed to fail with valid user, bad token")
	}
}

func TestAuthUserByTokenSucceedsWithMatchedUserAndToken(t *testing.T) {
	userlookup_arg_u = "johndoe"
	readfile_arg_f = "/.xs_id"
	stat := AuthUserByToken(_mock_ioutil_ReadFile, _mock_user_Lookup, userlookup_arg_u, "hostA", "hostA:abcdefg")
	if !stat {
		t.Fatal("failed with valid user and token")
	}
}
