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

func TestGetUserErrors(t *testing.T) {
	clear()

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

	// tamper with datastore
	// datastore := userlib.DatastoreGetMap()
	hash := userlib.Hash([]byte("alice"))
	slicehash := hash[:]
	garbage := userlib.RandomBytes(64)
	uuid_hash, _ := uuid.FromBytes(slicehash)
	userlib.DatastoreSet(uuid_hash, garbage)

	_, e = GetUser("alice", "fubar")

	if e == nil {
		t.Error("Failed to recognize user can't be retrieved.", e)
		return
	}

	//////////////
	clear()

	_, err = InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, e = GetUser("alice", "fubar")

	if e != nil {
		t.Error("Failed to get user", e)
		return
	}

	// tamper with datastore
	// datastore := userlib.DatastoreGetMap()
	hash = userlib.Hash([]byte("alice" + "HMAC"))
	slicehash = hash[:]
	garbage = userlib.RandomBytes(64)
	uuid_hash, _ = uuid.FromBytes(slicehash)
	userlib.DatastoreSet(uuid_hash, garbage)

	_, e = GetUser("alice", "fubar")

	if e == nil {
		t.Error("Failed to recognize user can't be retrieved.", e)
		return
	}
}

func TestRetrieveHashmapErrors(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("Test storage")
	e := u.StoreFile("file1", v)

	if e != nil {
		t.Error("Failed to store file", e)
		return
	}

	hash := userlib.Hash([]byte("alice" + "files"))
	slicehash := hash[:]
	garbage := userlib.RandomBytes(64)
	uuid_hash, _ := uuid.FromBytes(slicehash)
	userlib.DatastoreSet(uuid_hash, garbage)

	v = []byte("Test overwriting with storage")
	e = u.StoreFile("file1", v)

	if e == nil {
		t.Error("Failed to store file", e)
		return
	}

	//////////////
	clear()

	u, err = InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	v = []byte("Test storage")
	e = u.StoreFile("file1", v)

	if e != nil {
		t.Error("Failed to store file", e)
		return
	}

	hash = userlib.Hash([]byte("alice" + "files HMAC"))
	slicehash = hash[:]
	garbage = userlib.RandomBytes(64)
	uuid_hash, _ = uuid.FromBytes(slicehash)
	userlib.DatastoreSet(uuid_hash, garbage)

	v = []byte("Test overwriting with storage")
	e = u.StoreFile("file1", v)

	if e == nil {
		t.Error("Failed to store file", e)
		return
	}
}

func TestMultipleUserSessions(t *testing.T) {
	clear()

	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	alice1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	alice2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	if !reflect.DeepEqual(alice1, alice2) {
		t.Error("Alice1 and Alice2 don't point to the same thing", alice1, alice2)
		return
	}

	// alice1 creates a file
	v := []byte("This is a test")
	err1 := alice1.StoreFile("file1", v)
	if err1 != nil {
		t.Error("Alice1 failed to store.", err1)
		return
	}

	v2, err2 := alice1.LoadFile("file1")
	if err2 != nil {
		t.Error("Alice1 failed to download", err2)
		return
	}

	// alice2 can load the file
	v2, err2 = alice2.LoadFile("file1")
	if err2 != nil {
		t.Error("Alice2 failed to download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Alice2's downloaded file is not the same", v, v2)
		return
	}

	// alice2 appends to the file
	err = alice2.AppendFile("file1", []byte("Appending to file."))
	if err != nil {
		t.Error("Alice2 failed to append", err)
	}

	// alice1 can load the appended file
	v1, err1 := alice1.LoadFile("file1")
	if err1 != nil {
		t.Error("Alice1 failed to download", err1)
		return
	}
	expected_v := []byte("This is a testAppending to file.")
	if !reflect.DeepEqual(expected_v, v1) {
		t.Error("Alice1's downloaded file is not the same", expected_v, v1)
		return
	}

	// alice1 shares file to bob
	bob, _ := InitUser("bob", "password")

	accessToken, err := alice1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Alice1 failed to share file1 with bob", err)
		return
	}

	err = bob.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Bob failed to receive file1 from Alice", err)
		return
	}

	// bob appends to file
	err = bob.AppendFile("file1", []byte("Bob appending here."))
	if err != nil {
		t.Error("Bob failed to append to file1", err)
		return
	}

	bob_v, err1 := bob.LoadFile("file1")
	if err1 != nil {
		t.Error("Bob failed to download", err1)
		return
	}

	expected_v = []byte("This is a testAppending to file.Bob appending here.")
	if !reflect.DeepEqual(expected_v, bob_v) {
		t.Error("Bob's downloaded file is not the same", expected_v, bob_v)
		return
	}

	// alice1 and alice 2 can load the appended file

	alice1_v, err1 := alice1.LoadFile("file1")
	if err1 != nil {
		t.Error("Alice1 failed to download", err1)
		return
	}

	if !reflect.DeepEqual(expected_v, alice1_v) {
		t.Error("Alice1's downloaded file is not the same", expected_v, alice1_v)
		return
	}

	alice2_v, err1 := alice2.LoadFile("file1")
	if err1 != nil {
		t.Error("Alice2 failed to download", err1)
		return
	}

	if !reflect.DeepEqual(expected_v, alice2_v) {
		t.Error("Alice2's downloaded file is not the same", expected_v, alice2_v)
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

/*func TestPad(t *testing.T) {
	clear()
	msg := []byte("multiplejfbdjgkd") // multiple of 16
	padded := Padding(msg)
	unpadded := Unpad(padded)
	if string(unpadded) != string(msg) {
		t.Error("padding didn't work", padded, unpadded)
	}
}
*/
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

func TestAppend_NonOwners(t *testing.T) {
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

	u3, err3 := InitUser("charlie", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize bob", err3)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

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

	err = u2.AppendFile("file2", []byte("Appending this data."))
	if err != nil {
		t.Error("Failed to allow non-owner to append", err)
		return
	}

	v2, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Bob failed to download the file after non-owner appended", err)
		return
	}

	expected_v := []byte("This is a testAppending this data.")
	if !reflect.DeepEqual(expected_v, v2) {
		t.Error("The file bob loaded after appending is incorrect.", expected_v, v2)
		return
	}

	alice_v, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Alice failed to download the file after non-owner appended", err)
		return
	}
	if !reflect.DeepEqual(expected_v, alice_v) {
		t.Error("The file alice loaded after bob (non-owner) appended is incorrect.", expected_v, alice_v)
		return
	}

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

	err = u3.AppendFile("file3", []byte("Appending more data."))
	if err != nil {
		t.Error("Failed to allow non-owner (charlie) to append", err)
		return
	}

	err = u3.AppendFile("file3", []byte("AND more data."))
	if err != nil {
		t.Error("Failed to allow non-owner (charlie) to append", err)
		return
	}

	err = u.AppendFile("file1", []byte("AND even more data."))
	if err != nil {
		t.Error("Failed to allow owner Alice to append", err)
		return
	}

	expected_v = []byte("This is a testAppending this data.Appending more data.AND more data.AND even more data.")
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(expected_v, v3) {
		t.Error("Shared file is not the same", v, v3)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Bob failed to download the file after charlie appended", err)
		return
	}

	if !reflect.DeepEqual(expected_v, v2) {
		t.Error("Bob's shared file is not the same", v, v2)
		return
	}

	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Alice failed to download the file after charlie appended", err)
		return
	}

	if !reflect.DeepEqual(expected_v, v1) {
		t.Error("Alice's shared file is not the same", v, v1)
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

func TestOverwrite(t *testing.T) {
	clear()
	// alice stores
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	bob, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	var accessToken uuid.UUID

	// alice loads
	v, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	// overwrite
	v = []byte("This is overwriting")
	alice.StoreFile("file1", v)

	// alice loads -- check correctly overwritten
	var v2 []byte
	v2, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after overwrite", err)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("overwritten file is not the same", v, v2)
		return
	}

	// alice share with Bob
	accessToken, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Alice failed to share file with bob", err)
		return
	}

	err = bob.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Bob failed to receive the share message", err)
		return
	}

	// bob storess
	v = []byte("Bob is overwriting")
	bob.StoreFile("file2", v)

	// alice load -- check correctly overwritten
	v2, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice after bob overwrites", err)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// bob load -- check correctly overwritten
	v2, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob after he overwrites", err)
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

	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file1")
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

	v2, err = u2.LoadFile("file1")
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

func TestRevokeShare(t *testing.T) {
	// test error check: share, revoke, reshare
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

	bob_v, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Bob failed to load after receiving from Alice", err)
		return
	}

	if !reflect.DeepEqual(v, bob_v) {
		t.Error("Shared file is not the same", v, bob_v)
		return
	}

	///////////////////

	// Alice revokes from Bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}

	bob_v, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to correctly revoke from Bob.", err)
		return
	}

	////////////

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

	bob_v, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to reshare to Bob.", err)
		return
	}
	///////////////////

}

func TestRevokeShare_2(t *testing.T) {
	// test error check: share, revoke, reshare
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

	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	// alice shares with charlie
	accessToken, err = u.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	charlie_v, err := u3.LoadFile("file1")
	if err != nil {
		t.Error("Charlie failed to load after receiving from Alice", err)
		return
	}

	if !reflect.DeepEqual(v, charlie_v) {
		t.Error("Shared file is not the same", v, charlie_v)
		return
	}

	///////////////////

	// Alice revokes from Bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}

	_, err = u2.LoadFile("file1")
	if err == nil {
		t.Error("Failed to correctly revoke from Bob.", err)
		return
	}

	////////////

	// charlie shares with bob
	accessToken, err = u3.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file1", "charlie", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	bob_v, err := u2.LoadFile("file1")
	if err != nil {
		t.Error("Failed to reshare to Bob.", err)
		return
	}

	if !reflect.DeepEqual(v, bob_v) {
		t.Error("Shared file is not the same", v, bob_v)
		return
	}
	///////////////////
}

func TestRevokeAppend(t *testing.T) {
	// test error check: share, revoke, reshare
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

	// Bob append
	err = u2.AppendFile("file2", []byte("Appending to file."))
	if err != nil {
		t.Error("Bob failed to append", err)
	}

	// Alice revokes from Bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}

	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to correctly revoke from Bob.", err)
		return
	}

	////////////

	// Alice load and the appended data should still be there
	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to correctly load after revoking Bob.", err)
		return
	}

	expected_v := []byte("This is a testAppending to file.")
	if !reflect.DeepEqual(expected_v, v1) {
		t.Error("Shared file is not the same", expected_v, v1)
		return
	}
}

func TestRevokeStore(t *testing.T) {
	// test error check: share, revoke, reshare
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

	// Bob append
	err = u2.AppendFile("file2", []byte("Appending to file."))
	if err != nil {
		t.Error("Bob failed to append", err)
	}

	// Alice revokes from Bob
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from bob", err)
		return
	}

	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to correctly revoke from Bob.", err)
		return
	}

	////////////

	err = u2.StoreFile("file2", []byte("Bob trying to overwrite without access"))
	if err == nil {
		t.Error("Failed to correctly revoke from Bob. He's still storing!", err)
		return
	}
}

func TestRevokeMultChildren(t *testing.T) {
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
	u3, err := InitUser("charlie", "fubar")
	if err != nil {
		t.Error("Failed to initialize charlie", err)
		return
	}
	u4, err2 := InitUser("david", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize david", err2)
		return
	}
	u5, err := InitUser("eric", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u6, err2 := InitUser("fred", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u7, err2 := InitUser("greg", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	//alice create file
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	//////////////////

	//alice shares with bob & charlie
	// alice shares with bob
	accessToken, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Bob failed to receive the share message", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the file with charlie", err)
		return
	}

	err = u3.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Charlie failed to receive the share message", err)
		return
	}

	//Bob shares with greg
	accessToken, err = u2.ShareFile("file2", "greg")
	if err != nil {
		t.Error("Bob failed to share the file with greg", err)
		return
	}

	err = u7.ReceiveFile("file1", "bob", accessToken)
	if err != nil {
		t.Error("Greg failed to receive the share message", err)
		return
	}

	//Charlie shares with david & eric
	accessToken, err = u3.ShareFile("file2", "david")
	if err != nil {
		t.Error("Charlie failed to share the file with david", err)
		return
	}

	err = u4.ReceiveFile("file1", "charlie", accessToken)
	if err != nil {
		t.Error("David failed to receive the share message", err)
		return
	}

	accessToken, err = u3.ShareFile("file2", "eric")
	if err != nil {
		t.Error("Charlie failed to share the file with eric", err)
		return
	}

	err = u5.ReceiveFile("file1", "charlie", accessToken)
	if err != nil {
		t.Error("Eric failed to receive the share message", err)
		return
	}

	//Eric shares with fred
	accessToken, err = u5.ShareFile("file1", "fred")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u6.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("Fred failed to receive the share message", err)
		return
	}

	//Alice revokes from charlie
	err = u.RevokeFile("file1", "charlie")
	if err != nil {
		t.Error("Alice failed to revoke from charlie", err)
		return
	}

	//Check that only alice, bob, greg can load
	_, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Alice failed to load", err)
		return
	}

	_, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Bob failed to load", err)
		return
	}

	_, err = u3.LoadFile("file2")
	if err == nil {
		t.Error("Charlie still has access", err)
		return
	}

	_, err = u4.LoadFile("file1")
	if err == nil {
		t.Error("David still has access", err)
		return
	}

	_, err = u5.LoadFile("file1")
	if err == nil {
		t.Error("Eric still has access", err)
		return
	}

	_, err = u6.LoadFile("file1")
	if err == nil {
		t.Error("Fred still has access", err)
		return
	}

	_, err = u7.LoadFile("file1")
	if err != nil {
		t.Error("Greg failed to load", err)
		return
	}

}

func TestShareALot(t *testing.T) {
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
	u3, err := InitUser("charlie", "fubar")
	if err != nil {
		t.Error("Failed to initialize charlie", err)
		return
	}
	u4, err2 := InitUser("david", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize david", err2)
		return
	}
	u5, err := InitUser("eric", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u6, err2 := InitUser("fred", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u7, err2 := InitUser("greg", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u8, err2 := InitUser("harry", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize harry", err2)
		return
	}

	u9, err2 := InitUser("izzy", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize izzy", err2)
		return
	}

	u10, err2 := InitUser("john", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize john", err2)
		return
	}

	u11, err2 := InitUser("kevin", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize kevin", err2)
		return
	}

	u12, err2 := InitUser("lisa", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize lisa", err2)
		return
	}

	u13, err2 := InitUser("monica", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize monica", err2)
		return
	}

	u14, err2 := InitUser("nancy", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize nancy", err2)
		return
	}

	u15, err2 := InitUser("olaf", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize olaf", err2)
		return
	}

	u16, err2 := InitUser("pat", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize pat", err2)
		return
	}

	//alice create file
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	//////////////////

	//alice shares with bob & charlie
	// alice shares with bob
	accessToken, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Bob failed to receive the share message", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the file with charlie", err)
		return
	}

	err = u3.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Charlie failed to receive the share message", err)
		return
	}

	//Bob shares with greg
	accessToken, err = u2.ShareFile("file2", "greg")
	if err != nil {
		t.Error("Bob failed to share the file with greg", err)
		return
	}

	err = u7.ReceiveFile("file1", "bob", accessToken)
	if err != nil {
		t.Error("Greg failed to receive the share message", err)
		return
	}

	//Charlie shares with david & eric
	accessToken, err = u3.ShareFile("file2", "david")
	if err != nil {
		t.Error("Charlie failed to share the file with david", err)
		return
	}

	err = u4.ReceiveFile("file1", "charlie", accessToken)
	if err != nil {
		t.Error("David failed to receive the share message", err)
		return
	}

	accessToken, err = u3.ShareFile("file2", "eric")
	if err != nil {
		t.Error("Charlie failed to share the file with eric", err)
		return
	}

	err = u5.ReceiveFile("file1", "charlie", accessToken)
	if err != nil {
		t.Error("Eric failed to receive the share message", err)
		return
	}

	//Eric shares with fred
	accessToken, err = u5.ShareFile("file1", "fred")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u6.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("Fred failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "harry")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u8.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("harry failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "izzy")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u9.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("izzy failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "john")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u10.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("john failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "kevin")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u11.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("kevin failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "lisa")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u12.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("lisa failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "monica")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u13.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("monica failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "nancy")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u14.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("nancy failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "olaf")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u15.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("olaf failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "pat")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u16.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("pat failed to receive the share message", err)
		return
	}

}

func TestShareTreeSearch(t *testing.T) {
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
	u3, err := InitUser("charlie", "fubar")
	if err != nil {
		t.Error("Failed to initialize charlie", err)
		return
	}
	u4, err2 := InitUser("david", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize david", err2)
		return
	}
	u5, err := InitUser("eric", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u6, err2 := InitUser("fred", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u7, err2 := InitUser("greg", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u8, err2 := InitUser("harry", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize harry", err2)
		return
	}

	u9, err2 := InitUser("izzy", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize izzy", err2)
		return
	}

	u10, err2 := InitUser("john", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize john", err2)
		return
	}

	_, err2 = InitUser("kevin", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize kevin", err2)
		return
	}

	//alice create file
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	//////////////////

	//alice shares with bob & charlie
	// alice shares with bob
	accessToken, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Bob failed to receive the share message", err)
		return
	}

	accessToken, err = u2.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the file with charlie", err)
		return
	}

	err = u3.ReceiveFile("file1", "bob", accessToken)
	if err != nil {
		t.Error("Charlie failed to receive the share message", err)
		return
	}

	//Bob shares with greg
	accessToken, err = u3.ShareFile("file1", "david")
	if err != nil {
		t.Error("Bob failed to share the file with greg", err)
		return
	}

	err = u4.ReceiveFile("file1", "charlie", accessToken)
	if err != nil {
		t.Error("Greg failed to receive the share message", err)
		return
	}

	accessToken, err = u4.ShareFile("file1", "eric")
	if err != nil {
		t.Error("Charlie failed to share the file with david", err)
		return
	}

	err = u5.ReceiveFile("file1", "david", accessToken)
	if err != nil {
		t.Error("David failed to receive the share message", err)
		return
	}

	accessToken, err = u5.ShareFile("file1", "fred")
	if err != nil {
		t.Error("Charlie failed to share the file with eric", err)
		return
	}

	err = u6.ReceiveFile("file1", "eric", accessToken)
	if err != nil {
		t.Error("Eric failed to receive the share message", err)
		return
	}

	accessToken, err = u6.ShareFile("file1", "greg")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u7.ReceiveFile("file1", "fred", accessToken)
	if err != nil {
		t.Error("Fred failed to receive the share message", err)
		return
	}

	accessToken, err = u7.ShareFile("file1", "harry")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u8.ReceiveFile("file1", "greg", accessToken)
	if err != nil {
		t.Error("harry failed to receive the share message", err)
		return
	}

	accessToken, err = u8.ShareFile("file1", "izzy")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u9.ReceiveFile("file1", "harry", accessToken)
	if err != nil {
		t.Error("izzy failed to receive the share message", err)
		return
	}

	accessToken, err = u9.ShareFile("file1", "john")
	if err != nil {
		t.Error("Eric failed to share the file with eric", err)
		return
	}

	err = u10.ReceiveFile("file1", "izzy", accessToken)
	if err != nil {
		t.Error("john failed to receive the share message", err)
		return
	}

	err = u.RevokeFile("file1", "john")
	if err != nil {
		t.Error("Failed to revoke from john", err)
		return
	}

	err = u.RevokeFile("file1", "kevin")
	if err == nil {
		t.Error("Should have errored")
		return
	}
}

// there is a datastoredelete function
// write tests for threat models?

// THINGS WE NEED TO DO
// 11. test all possible combinations of functions
/*
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

}*/

func TestRetrieveAccessTokenError(t *testing.T) {
	clear()
	u, err := InitUser("alice", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	_, _, _, _, err = RetrieveAccessToken(u2, "file1")
	if err == nil {
		t.Error("Should have errored", err)
		return
	}

	//alice share with bob
	v := []byte("Alice's file")
	err = u.StoreFile("file1", v)
	if err != nil {
		t.Error("Failed to store", err)
		return
	}

	accessToken, _ := u.ShareFile("file1", "bob")

	//bob receive accessToken
	u2.ReceiveFile("file1", "alice", accessToken)

	//delete the accessToken from datastore
	userlib.DatastoreDelete(accessToken)

	//expect error when bob tries to load
	_, err = u2.LoadFile("file1")
	if err == nil {
		t.Error("Did not recognize accessToken is missing from datastores", err)
		return
	}
}

/*func TestRetrieveFileError(t *testing.T) {
	clear()
	u, err := InitUser("alice", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	//alice stores file
	v := []byte("Alice's file")
	err = u.StoreFile("file1", v)
	if err != nil {
		t.Error("Failed to store", err)
		return
	}

	_, file_id, file_owner_hash, _, err1 := RetrieveAccessToken(u, "file1")
	if err1 != nil {
		t.Error("Failed to store", err1)
		return
	}

	key_hash := userlib.Hash(append(file_id, file_owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	userlib.DatastoreDelete(storageKey)

	_, err = u.LoadFile("file1")
	if err == nil {
		t.Error("Did not recognize file is missing from datastores", err)
		return
	}

	// HMAC not in datastore
	hmac := []byte("HMAC")
	key_HMAC := append(hmac, file_owner_hash...)
	key_HMAC = append(file_id, key_HMAC...)
	key_hash_HMAC := userlib.Hash(key_HMAC)
	storageKey_HMAC, _ := uuid.FromBytes(key_hash_HMAC[:16])
	userlib.DatastoreDelete(storageKey_HMAC)

	_, err = u.LoadFile("file1")
	if err == nil {
		t.Error("Did not recognize file HMAC is missing from datastores", err)
		return
	}

	// HMACS don't match
	userlib.DatastoreSet(storageKey_HMAC, userlib.RandomBytes(64))
	_, err = u.LoadFile("file1")
	if err == nil {
		t.Error("Did not recognize file HMACs don't match", err)
		return
	}

}*/

func TestAppendError(t *testing.T) {
	clear()
	u, err := InitUser("alice", "foobar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}

	v := []byte("Alice's file")
	err = u.StoreFile("file1", v)
	if err != nil {
		t.Error("Failed to store", err)
		return
	}

	err = u.AppendFile("file1", []byte(""))
	if err == nil {
		t.Error("Failed to recognize no bytes to append", err)
		return
	}

	u2, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	err = u2.AppendFile("file1", []byte("bob can't do this"))
	if err == nil {
		t.Error("Failed to recognize bob can't append", err)
		return
	}

	//Alice appends a bunch of stuff serially
	u.AppendFile("file1", []byte("Append1"))
	u.AppendFile("file1", []byte("Append2"))
	u.AppendFile("file1", []byte("Append3"))
	u.AppendFile("file1", []byte("Append4"))
	u.AppendFile("file1", []byte("Append5"))
	u.AppendFile("file1", []byte("Append6"))
	u.AppendFile("file1", []byte("Append7"))
	u.AppendFile("file1", []byte("Append8"))
	u.AppendFile("file1", []byte("Append9"))
	u.AppendFile("file1", []byte("Append10"))
	u.AppendFile("file1", []byte("Append11"))
	u.AppendFile("file1", []byte("Append12"))

	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load after multiple appends", err)
		return
	}
	expected_v := []byte("Alice's fileAppend1Append2Append3Append4Append5Append6" +
		"Append7Append8Append9Append10Append11Append12")

	if !reflect.DeepEqual(expected_v, v1) {
		t.Error("appended file is not correc", expected_v, v1)
		return
	}

	accessToken, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Alice failed to share the file with bob", err)
		return
	}

	err = u2.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("bob failed to receive the share message", err)
		return
	}

	err = u2.StoreFile("file1", []byte("Overwriting everything"))
	if err != nil {
		t.Error("bob failed to overwrite", err)
		return
	}

	v2, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Alice failed to load after bob overwrite", err)
		return
	}

	expected_v = []byte("Overwriting everything")
	if !reflect.DeepEqual(expected_v, v2) {
		t.Error("overwritten file is not correct", expected_v, v2)
		return
	}

}

//delete old data after overwriting
