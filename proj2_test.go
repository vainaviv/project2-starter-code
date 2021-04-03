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

	v3 := []byte("This better overwrite")
	err5 := u.StoreFile("file1", v3)
	if err5 != nil {
		t.Error("Failed to overwrite.", err5)
		return
	}

	v4, err5 := u.LoadFile("file1")
	if err5 != nil {
		t.Error("Failed to upload and download", err5)
		return
	}
	if !reflect.DeepEqual(v3, v4) {
		t.Error("Downloaded file is not the same", v3, v4)
		return
	}
}

func TestPad(t *testing.T) {
	clear()
	msg := []byte("multiplejfbdjgkd") // multiple of 16
	padded := Padding(msg)
	unpadded := Unpad(padded)
	if string(unpadded) != string(msg) {
		t.Error("padding didn't work", padded, unpadded)
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
}

func TestRevoke_1(t *testing.T) {
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

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after share", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after revoke", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Bob still has access after revocation", err)
		return
	}
}

func TestRevoke_2(t *testing.T) {
	//alice shares with bob & charlie, revoke from charlie, bob should still be able to load
	clear()

	// initalize users
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
	u3, err3 := InitUser("charlie", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize bob", err3)
		return
	}
	/////////////////

	//alice create file
	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
	//////////////////

	// alice shares with bob
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
	///////////////////

	// alice shares with charlie
	accessToken, err = u.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file3", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v3)
		return
	}
	//////////////////

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after share", err)
		return
	}

	// Alice revokes from Bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}
	////////////

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after revoke", err)
		return
	}
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file from charlie after alice revoked bob", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Bob still has access after revocation", err)
		return
	}
}
func TestRevoke_3(t *testing.T) {
	//alice shares with bob, bob shares with charlie, revoke from bob - neither should be able to load
	clear()

	// initalize users
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
	u3, err3 := InitUser("charlie", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize bob", err3)
		return
	}
	/////////////////

	//alice create file
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	//////////////////

	// alice shares with bob
	accessToken, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	///////////////////

	// bob shares with charlie
	accessToken, err = u2.ShareFile("file2", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file3", "bob", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v3)
		return
	}
	//////////////////

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after share", err)
		return
	}

	// Alice revokes from Bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}
	////////////

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after revoke", err)
		return
	}
	v3, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Charlie still has access after revocation", err)
		return
	}

	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Bob still has access after revocation", err)
		return
	}
}

func TestRevoke_4(t *testing.T) {
	// test error check: share when user does not have acces to file
	clear()

	// initalize users
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
	u3, err3 := InitUser("charlie", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize bob", err3)
		return
	}
	/////////////////

	//alice create file
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	//////////////////

	// bob shares with charlie
	_, err = u2.ShareFile("file1", "charlie")
	if err == nil {
		t.Error("Failed to recognize that Bob does not have access to file and cannot share the file", err)
		return
	}

	// Alice revokes from Bob w/o sharing with Bob
	err = u.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("Failed to recognize alice cannot revoke from bob", err)
		return
	}
	////////////

	// test error check: alice share Bob, bob share charlie, but he cannot revoke charlie
	accessToken, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	accessToken, err = u2.ShareFile("file2", "charlie")
	if err != nil {
		t.Error("Failed to allow participant (not owner) to share the file", err)
		return
	}

	err = u3.ReceiveFile("file3", "bob", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	err = u2.RevokeFile("file1", "charlie")
	if err == nil {
		t.Error("Failed to recognize bob (who is not the owner) cannot revoke from charlie", err)
		return
	}

}

// THINGS WE NEED TO DO
// 2. Implement append
// 3. test non-owners trying to append
// 5. make a test  to share, revoke, then share again different users sharing file again
// 6. how to test revoking access of an offline user
// 8. how to test multiple user session with same user?
// 9. check each public key is used for a single purpose
// 10. cannot:
// reusing the same key for multiple purposes (e.g. encryption, authentication, key- derivation, etc); and
// authenticate-then-encrypt; and
// decrypt-then-verify.

func TestRemoveSubtree(t *testing.T) {
	var participants Tree
	var root Node
	root.Username = "alice"
	root.User_invite_loc = nil

	var child1 Node
	child1.Username = "bob"
	child1.User_invite_loc = nil

	var child2 Node
	child2.Username = "charlie"
	child2.User_invite_loc = nil
	child2.Children = nil

	child1.Children = []*Node{&child2}

	root.Children = []*Node{&child1}

	participants.Root = &root

	ok := removeSubtree(&participants, "bob")
	if !ok {
		t.Error("Subtree not removed")
		return
	}

	var participants_check Tree
	var root_check Node
	root_check.Username = "alice"
	root_check.User_invite_loc = nil
	root_check.Children = nil

	participants_check.Root = &root_check

	if !reflect.DeepEqual(participants_check, participants) {
		t.Error("Tree is not the same", participants_check, participants)
		return
	}

}
