package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.

	u, err = InitUser("alice", "pingpong")
	if err == nil {
		// t.Error says the test fails
		t.Error("Failed to recognize a taken username", err)
		return
	}

	u, err = InitUser("", "pingpong")
	if err == nil {
		// t.Error says the test fails
		t.Error("Failed to recognize an invalid empty username", err)
		return
	}

	u, err = InitUser("bob", "pingpong")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to successfully create new user", err)
		return
	}
}

func TestGet(t *testing.T) {
	clear()
	t.Log("GetUser test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, e := GetUser("alice", "fubar")

	if e != nil {
		t.Error("Failed to get user", e)
		return
	}

	_, e = GetUser("alice", "kkkk")

	if e == nil {
		t.Error("Failed to recognize wrong password.", e)
		return
	}

	_, e = GetUser("alicea", "fubar")

	if e == nil {
		t.Error("Failed to recognize wrong username.", e)
		return
	}

	_, e = GetUser("alisce", "kkkk")

	if e == nil {
		t.Error("Failed to recognize wrong username and password.", e)
		return
	}

}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	err1 := u.StoreFile("file1", v)
	if err1 != nil {
		t.Error("Failed to store.", err1)
		return
	}

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	u1, _ := InitUser("bob", "password")
	_, err3 := u1.LoadFile("file1")
	if err3 == nil {
		t.Error("Did not detect invalid load.", err3)
		return
	}

	_, err4 := u.LoadFile("file2")
	if err4 == nil {
		t.Error("Did not detect file DNE.", err4)
		return
	}

	v = []byte("This is a test")
	err5 := u.StoreFile("file1", v)
	if err5 == nil {
		t.Error("Did not detect duplicate filename.", err5)
		return
	}
}

func TestPad(t *testing.T) {
	clear()
	msg := []byte("test padding")
	padded := Padding(msg)
	unpadded := Unpad(padded)
	if string(unpadded) != string(msg) {
		t.Error("padding didn't work", unpadded)
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	stored_v, _ := u.LoadFile("file1")
	if !reflect.DeepEqual(v, stored_v) {
		t.Error("not matching: ", string(stored_v))
		return
	}

	err1 := u.AppendFile("file1", []byte(" appended data"))
	if err1 != nil {
		t.Error("Failed to append", err1)
		return
	}
	
	expected := []byte("This is a test appended data")
	loaded, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to load appended file", err2)
		return
	}
	if !reflect.DeepEqual(expected, loaded) {
		t.Error("Failed to correctly append ", string(loaded))
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// share a file, go to that UUID and print out
}
