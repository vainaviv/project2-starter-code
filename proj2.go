package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//Add helper function to generate padding

// User is the structure definition for a user record.
type User struct {
	Username string
	Secret_key []byte
	HMAC_sk []byte
	Signing_sk []byte
	HMAC_sign_sk []byte
	File_loc_sk []byte //secret key for HMACing file location to check if pointer switch
	HMAC_file []byte	//HMAC of above
	Files map[string][]byte //Hashmap of files: filename → accesstoken|HMAC(file_location)


	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	user_enckey := username + "_enckey"
	//Check if username already exists
	_, ok := userlib.KeystoreGet(user_enckey)
	if ok {
		return nil, errors.New(strings.ToTitle("Username already exists."))
	}

	if len(username) <= 0 {
		return nil, errors.New(strings.ToTitle("Username length is not valid."))
	}

	userdata.Username = username
	pwd_bytes := []byte(password)

	public_key, secret_key, _ := userlib.PKEKeyGen()

	IV_enc := userlib.RandomBytes(16)
	pk, _ := json.Marshal(public_key)
	salt, _ := userlib.HMACEval(pk[0:16], []byte(username))
	//TODO: Check keylen later if necessary - secret keys using keylen = 32, hmacs using keylen = 16
	userlib.KeystoreSet(user_enckey, public_key)
	sk_1, err := json.Marshal(secret_key)
	//userdata.Secret_key
	userdata.Secret_key = userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, sk_1)
	//sk_2, _ := json.Marshal(userdata.Secret_key)
	userdata.HMAC_sk, _ = userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata.Secret_key)

	signing_sk, signing_verk, _ := userlib.DSKeyGen()

	user_verkey := username + "_verkey"
	IV_sign := userlib.RandomBytes(16)
	userlib.KeystoreSet(user_verkey, signing_verk)
	sk_3, _ := json.Marshal(signing_sk)


	userdata.Signing_sk = userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_sign, sk_3)
  userdata.HMAC_sign_sk, _ = userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata.Signing_sk)

	userdata.File_loc_sk = userlib.RandomBytes(16)
	userdata.HMAC_file, _ = userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata.File_loc_sk)

	userbytes, _ := json.Marshal(userdata)
	hash := userlib.Hash([]byte(username + password))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userbytes) //store user struct (or address?) in datastore

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	user_enckey := username + "_enckey"
	user_verkey := username + "_verkey"

	public_key, ok_enc := userlib.KeystoreGet(user_enckey)
	_, ok_sign := userlib.KeystoreGet(user_verkey)

	if ok_enc && ok_sign {
	//user has been initialized
	//do we need to check both enckey and verkey? what are security implications if one exists and other doesn’t?
		hash := userlib.Hash([]byte(username + password))
		slicehash := hash[:]
		user, ok := userlib.DatastoreGet(bytesToUUID(slicehash))

		if !ok {
			//username & pwd don’t match (or this combo not in datastore -- which should mean they don’t match)
			return nil, errors.New(strings.ToTitle("Username and password don't match."))
		}

		_ = json.Unmarshal(user, userdataptr)
//check integrity of user struct & malicious action?
	//check that:
		pk, _ := json.Marshal(public_key)
		salt, _ := userlib.HMACEval(pk, []byte(username))

		sec_key, _ := json.Marshal(userdata.Secret_key)
		sign_key, _ := json.Marshal(userdata.Signing_sk)
		loc_key, _ := json.Marshal(userdata.File_loc_sk)

		HMAC_enc, _ := userlib.HMACEval(userlib.Argon2Key([]byte(password), salt, 16), sec_key)
		HMAC_sign, _ := userlib.HMACEval(userlib.Argon2Key([]byte(password), salt, 16), sign_key)
		HMAC_file, _ := userlib.HMACEval(userlib.Argon2Key([]byte(password), salt, 16), loc_key)

		if ! userlib.HMACEqual(HMAC_enc, userdata.HMAC_sk) {
			return nil, errors.New(strings.ToTitle("HMAC of encryption keys don't match."))
		}
		if ! userlib.HMACEqual(HMAC_sign, userdata.HMAC_sign_sk) {
			return nil, errors.New(strings.ToTitle("HMAC of signing keys don't match."))
		}
		if ! userlib.HMACEqual(HMAC_file, userdata.HMAC_file) {
			return nil, errors.New(strings.ToTitle("HMAC of file location encryption keys don't match."))
		}

		//userdataptr = &user
		return userdataptr, nil

	} else {
		return nil, errors.New(strings.ToTitle("User has not been initialized."))
	}

}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
