package xs

import (
	"errors"
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

	testGoodUsers = []userVerifs{
		{"johndoe", "testpass", true},
		{"joebloggs", "testpass2", true},
		{"johndoe", "badpass", false},
	}
)

func _mock_ioutil_ReadFile(f string) ([]byte, error) {
	return []byte(dummyShadowA), nil
}

func _mock_ioutil_ReadFileEmpty(f string) ([]byte, error) {
	return []byte{}, nil
}

func _mock_ioutil_ReadFileHasError(f string) ([]byte, error) {
	return []byte{}, errors.New("IO Error")
}

func TestVerifyPass(t *testing.T) {
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
