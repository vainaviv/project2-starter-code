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

type Node struct {
	Username        string
	User_invite_loc []byte //encrypted with the root/owner's public key
	Children        []*Node
}

type LL_node struct {
	Data      []byte
	HMAC_Data []byte
	Next      userlib.UUID
}

type Tree struct {
	Root *Node
}

// User is the structure definition for a user record.
type User struct {
	password    string
	Username    string
	Tree_sk			userlib.PKEDecKey
	Secret_key  userlib.PKEDecKey
	Signing_sk  userlib.DSSignKey
	Files_key 	[]byte
	//Files       userlib.UUID // pointer to Hashmap of files: filename → accesstoken|HMAC(file_location)
}

type File struct {
	//Data         []byte
	// End_pointer  int  //encrypted int len of file
	Head         userlib.UUID
	Tail         userlib.UUID
	Participants Tree
	File_ID      []byte
}

type AccessToken struct {
	Enc_file_symm []byte
	Enc_file_id []byte
	Enc_file_owner []byte
	Signed_file_symm []byte
	Signed_file_id []byte
	Signed_file_owner []byte
	// Enc_keys    []byte
	// Signed_keys []byte
}

func Padding(msg []byte) (padded_msg []byte) {
	msg_len := len(msg)
	padding := 16 - msg_len%16
	for i := 0; i < padding; i += 1 {
		msg = append(msg, byte(padding))
	}
	return msg
}

func Unpad(ciphertext []byte) (unpadded_msg []byte) {
	padding := int(ciphertext[len(ciphertext)-1])
	unpadded_msg = ciphertext[0 : len(ciphertext)-padding]
	return unpadded_msg
}

func TreeSearch(participants *Tree, username string) (node *Node) {
	queue := make([]*Node, 0)
	queue = append(queue, participants.Root)

	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if next.Username == username {
			return next
		}
		if len(next.Children) > 0 {
			for _, child := range next.Children {
				queue = append(queue, child)
			}
		}
	}

	return nil
}

func RetrieveHashmap(username string, files_key []byte) (files map[string]userlib.UUID, err error) {

	hash := userlib.Hash([]byte(username + "files"))
	slicehash := hash[:]
	enc_marshalled_files, _ := userlib.DatastoreGet(bytesToUUID(slicehash))

	hash_HMAC := userlib.Hash([]byte(username + "files HMAC"))
	slicehash_HMAC := hash_HMAC[:]
	enc_marshalled_files_HMAC, _ := userlib.DatastoreGet(bytesToUUID(slicehash_HMAC))


	HMAC_key, _ := userlib.HashKDF(files_key, []byte("HMAC files"))
	HMAC_calc, _ := userlib.HMACEval(HMAC_key[:16], enc_marshalled_files)
	if !userlib.HMACEqual(HMAC_calc, enc_marshalled_files_HMAC) {
		return nil, errors.New(strings.ToTitle("Files HMAC doesn't match."))
	}

	dec_key, _ := userlib.HashKDF(files_key, []byte("encryption files"))
	marshalled_files := userlib.SymDec(dec_key[:16], enc_marshalled_files)
	marshalled_files = Unpad(marshalled_files)
	json.Unmarshal(marshalled_files, &files)
	return files, nil
}

func SetHashmap(filename string, accessToken userlib.UUID, username string, files_key []byte) error {
	files, err := RetrieveHashmap(username, files_key)
	if err != nil {
		return err
	}
	files[filename] = accessToken
	files_marshalled, _ := json.Marshal(files)
	files_marshalled = Padding(files_marshalled)
	enc_key, _ := userlib.HashKDF(files_key, []byte("encryption files"))
	files_marshalled_enc := userlib.SymEnc(enc_key[:16], userlib.RandomBytes(16), files_marshalled)
	hash := userlib.Hash([]byte(username + "files"))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), files_marshalled_enc)

	HMAC_key, _ := userlib.HashKDF(files_key, []byte("HMAC files"))
	files_marshalled_enc_HMAC, _ := userlib.HMACEval(HMAC_key[:16], files_marshalled_enc)
	hash_HMAC := userlib.Hash([]byte(username + "files HMAC"))
	slicehash_HMAC := hash_HMAC[:]
	userlib.DatastoreSet(bytesToUUID(slicehash_HMAC), files_marshalled_enc_HMAC)
	return nil
}

func RetrieveFile(owner_hash []byte, file_symm []byte, file_id []byte) (filedataptr *File, err error) {
	key_hash := userlib.Hash(append(file_id, owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not in Datastore!"))
	}
	file_symm_struct, _ := userlib.HashKDF(file_symm, []byte("encrypt struct"))
	file_symm_struct = file_symm_struct[:16]
	dataJSON_dec := userlib.SymDec(file_symm_struct, dataJSON) // check why this is slice out of range error
	dataJSON_dec = Unpad(dataJSON_dec)
	var filedata File
	filedataptr = &filedata
	json.Unmarshal(dataJSON_dec, filedataptr)

	hmac := []byte("HMAC")
	key_HMAC := append(hmac, owner_hash...)
	key_HMAC = append(file_id, key_HMAC...)
	key_hash_HMAC := userlib.Hash(key_HMAC)
	storageKey_HMAC, _ := uuid.FromBytes(key_hash_HMAC[:16])
	filedata_HMAC, ok := userlib.DatastoreGet(storageKey_HMAC)
	if !ok {
		return nil, errors.New(strings.ToTitle("File HMAC not in Datastore!"))
	}
	file_symm_struct_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC struct"))
	file_symm_struct_HMAC = file_symm_struct_HMAC[:16]
	filedata_HMAC_datastore, _ := userlib.HMACEval(file_symm_struct_HMAC, dataJSON)
	if !userlib.HMACEqual(filedata_HMAC, filedata_HMAC_datastore) {
		return nil, errors.New(strings.ToTitle("File HMACs don't match!"))
	}

	return filedataptr, nil
}

func RetrieveAccessToken(userdata *User, filename string) (file_symm []byte, file_id []byte, file_owner_hash []byte,
	owner []byte, err error) {
	files, err := RetrieveHashmap(userdata.Username, userdata.Files_key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	uuid_accessToken, ok := files[filename]
	if !ok {
		return nil, nil, nil, nil, errors.New(strings.ToTitle("Access token not in hashmap!"))
	}
	accessToken_marshaled, ok := userlib.DatastoreGet(uuid_accessToken)

	if !ok {
		return nil, nil, nil, nil, errors.New(strings.ToTitle("Access Token not in Datastore"))
	}

	secret_key := userdata.Secret_key
	var AT AccessToken
	_ = json.Unmarshal(accessToken_marshaled, &AT)

	file_symm, _ = userlib.PKEDec(secret_key, AT.Enc_file_symm)
	invalid := []byte("This is an invalid accessToken.")
	if string(file_symm) == string(invalid) {
		return nil, nil, nil, nil, errors.New(strings.ToTitle("This user does not have a valid accessToken."))
	}
	file_id, _ = userlib.PKEDec(secret_key, AT.Enc_file_id)
	owner, _ = userlib.PKEDec(secret_key, AT.Enc_file_owner)
	file_owner := userlib.Hash(owner)
	file_owner_hash = file_owner[:]

	return file_symm, file_id, file_owner_hash, owner, nil
}

func DatastoreFile(file_id []byte, owner_hash []byte, file_symm []byte, filedata *File) {
	//Storing encrypted file struct in datastore
	key_hash := userlib.Hash(append(file_id, owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	jsonData, _ := json.Marshal(filedata)
	jsonData_enc := Padding(jsonData)
	iv := userlib.RandomBytes(16)
	file_symm_struct, _ := userlib.HashKDF(file_symm, []byte("encrypt struct"))
	file_symm_struct = file_symm_struct[:16]
	jsonData_enc = userlib.SymEnc(file_symm_struct, iv, jsonData_enc)
	userlib.DatastoreSet(storageKey, jsonData_enc)

	//Storing encrypted file struct HMAC in datastore
	hmac := []byte("HMAC")
	key_HMAC := append(hmac, owner_hash[:]...)
	key_HMAC = append(file_id, key_HMAC...)
	key_hash_HMAC := userlib.Hash(key_HMAC)
	storageKey_HMAC, _ := uuid.FromBytes(key_hash_HMAC[:16])
	file_symm_struct_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC struct"))
	file_symm_struct_HMAC = file_symm_struct_HMAC[:16]
	jsonData_enc_HMAC, _ := userlib.HMACEval(file_symm_struct_HMAC, jsonData_enc) //maybe don't use file_symm
	userlib.DatastoreSet(storageKey_HMAC, jsonData_enc_HMAC)
}

func DatastoreUser(userdata *User, pk userlib.PKEEncKey) {
	userbytes, _ := json.Marshal(userdata)
	pwd_bytes := []byte(userdata.password)

	//Storing encrypted user struct in datastore
	IV_enc := userlib.RandomBytes(16)
	userbytes = Padding(userbytes)

	pk_salt, _ := userlib.KeystoreGet(userdata.Username + "_salt")
	salt_marshalled, _ := json.Marshal(pk_salt)
	salt, _ := userlib.HMACEval(salt_marshalled[:16], []byte(userdata.Username))

	userdata_enc := userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, userbytes)
	hash := userlib.Hash([]byte(userdata.Username))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userdata_enc)

	//Storing HMAC of encrypted user struct in datastore
	userdata_HMAC, _ := userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata_enc)
	hash_HMAC := userlib.Hash([]byte(userdata.Username + "HMAC"))
	slicehash_HMAC := hash_HMAC[:]
	userlib.DatastoreSet(bytesToUUID(slicehash_HMAC), userdata_HMAC)
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

	//TODO: Check keylen later if necessary - secret keys using keylen = 32, hmacs using keylen = 16
	userlib.KeystoreSet(user_enckey, public_key)

	userdata.Secret_key = secret_key
	pk_salt, _, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(username + "_salt", pk_salt)
	salt_marshalled, _ := json.Marshal(pk_salt)
	salt, _ := userlib.HMACEval(salt_marshalled[:16], []byte(username))

	Tree_pk, Tree_sk, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(username + "_treekey", Tree_pk)
	userdata.Tree_sk = Tree_sk

	signing_sk, signing_verk, _ := userlib.DSKeyGen()

	user_verkey := username + "_verkey"
	userlib.KeystoreSet(user_verkey, signing_verk)

	userdata.Signing_sk = signing_sk
	userdata.Files_key = userlib.RandomBytes(16)

	//initialize empty files hashmap and store in datastore
	files := make(map[string]userlib.UUID)
	files_marshalled, _ := json.Marshal(files)
	files_marshalled = Padding(files_marshalled)
	enc_key, _ := userlib.HashKDF(userdata.Files_key, []byte("encryption files"))
	files_marshalled_enc := userlib.SymEnc(enc_key[:16], userlib.RandomBytes(16), files_marshalled)
	hash := userlib.Hash([]byte(username + "files"))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), files_marshalled_enc)

	HMAC_key, _ := userlib.HashKDF(userdata.Files_key, []byte("HMAC files"))
	files_marshalled_enc_HMAC, _ := userlib.HMACEval(HMAC_key[:16], files_marshalled_enc)
	hash_HMAC := userlib.Hash([]byte(username + "files HMAC"))
	slicehash_HMAC := hash_HMAC[:]
	userlib.DatastoreSet(bytesToUUID(slicehash_HMAC), files_marshalled_enc_HMAC)

	userbytes, _ := json.Marshal(userdata)
	//Storing encrypted user struct in datastore
	IV_enc := userlib.RandomBytes(16)
	userbytes = Padding(userbytes)
	userdata_enc := userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, userbytes)
	hash = userlib.Hash([]byte(username))
	slicehash = hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userdata_enc)

	//Storing HMAC of encrypted user struct in datastore
	userdata_HMAC, _ := userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata_enc)
	hash_HMAC = userlib.Hash([]byte(username + "HMAC"))
	slicehash_HMAC = hash_HMAC[:]
	userlib.DatastoreSet(bytesToUUID(slicehash_HMAC), userdata_HMAC)

	userdata.password = password

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	user_enckey := username + "_enckey"
	user_verkey := username + "_verkey"

	_, ok_enc := userlib.KeystoreGet(user_enckey)
	_, ok_sign := userlib.KeystoreGet(user_verkey)

	if ok_enc && ok_sign {
		hash := userlib.Hash([]byte(username))
		slicehash := hash[:]
		user, ok := userlib.DatastoreGet(bytesToUUID(slicehash))

		if !ok {
			return nil, errors.New(strings.ToTitle("Username does not exist."))
		}

		hash_HMAC := userlib.Hash([]byte(username + "HMAC"))
		slicehash_HMAC := hash_HMAC[:]
		user_HMAC_datastore, _ := userlib.DatastoreGet(bytesToUUID(slicehash_HMAC))

		pk_salt, _ := userlib.KeystoreGet(username + "_salt")
		salt_marshalled, _ := json.Marshal(pk_salt)
		salt, _ := userlib.HMACEval(salt_marshalled[:16], []byte(username))

		pwd_bytes := []byte(password)
		user_HMAC, _ := userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), user)

		if !userlib.HMACEqual(user_HMAC, user_HMAC_datastore) {
			return nil, errors.New(strings.ToTitle("HMAC of user structs don't match."))
		}
		user = userlib.SymDec(userlib.Argon2Key(pwd_bytes, salt, 32), user)
		user = Unpad(user)
		_ = json.Unmarshal(user, userdataptr)

		userdata.password = password

		return userdataptr, nil

	} else {
		return nil, errors.New(strings.ToTitle("User has not been initialized."))
	}

}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	// file_symm: HMAC data, encrypt data, HMAC file struct, encrypt file struct
	var filedata File

	data = Padding(data)

	// case where file exists and someone else may be owner and we are overwriting
	files, err := RetrieveHashmap(userdata.Username, userdata.Files_key)
	if err != nil {
		return err
	}
	_, ok := files[filename]
	if ok {
		file_symm, file_id, file_owner_hash, _, _ := RetrieveAccessToken(userdata, filename)
		filedata, _ := RetrieveFile(file_owner_hash, file_symm, file_id)

		var data_node LL_node
		iv := userlib.RandomBytes(16)
		file_symm_data, _ := userlib.HashKDF(file_symm, []byte("encrypt data"))
		file_symm_data = file_symm_data[:16]
		data_node.Data = userlib.SymEnc(file_symm_data, iv, data)
		file_symm_data_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC data"))
		file_symm_data_HMAC = file_symm_data_HMAC[:16]
		data_node.HMAC_Data, _ = userlib.HMACEval(file_symm_data_HMAC, data_node.Data)
		data_node.Next = uuid.Nil

		random := userlib.RandomBytes(16)
		data_loc := bytesToUUID(random)

		data_node_marshal, _ := json.Marshal(data_node)
		userlib.DatastoreSet(data_loc, data_node_marshal)

		filedata.Head = data_loc
		filedata.Tail = data_node.Next

		DatastoreFile(file_id, file_owner_hash, file_symm, filedata)
		return
	}

	file_symm := userlib.RandomBytes(16)

	var data_node LL_node //needs to go onto datastore
	iv := userlib.RandomBytes(16)
	file_symm_data, _ := userlib.HashKDF(file_symm, []byte("encrypt data"))
	file_symm_data = file_symm_data[:16]
	data_node.Data = userlib.SymEnc(file_symm_data, iv, data)
	file_symm_data_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC data"))
	file_symm_data_HMAC = file_symm_data_HMAC[:16]
	data_node.HMAC_Data, _ = userlib.HMACEval(file_symm_data_HMAC, data_node.Data)
	data_node.Next = uuid.Nil

	random := userlib.RandomBytes(16)
	data_loc := bytesToUUID(random)

	data_node_marshal, _ := json.Marshal(data_node)
	userlib.DatastoreSet(data_loc, data_node_marshal)

	filedata.Head = data_loc
	filedata.Tail = data_loc

	pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	file_id := userlib.RandomBytes(16)
	filedata.File_ID = file_id

	owner_hash := userlib.Hash([]byte(userdata.Username))

	// AT := append(file_symm, file_id...)
	// AT = append(AT, []byte(userdata.Username)...)

	signing_sk := userdata.Signing_sk

	user_hash := userlib.Hash(append([]byte(userdata.Username), []byte("accessToken")...))
	key_hash := userlib.Hash(append(file_id, user_hash[:]...))

	accessToken, _ := uuid.FromBytes(key_hash[:16])
	encrypted_file_symm, _ := userlib.PKEEnc(pk, file_symm)
	encrypted_file_id, _ := userlib.PKEEnc(pk, file_id)
	encrypted_file_owner, _ := userlib.PKEEnc(pk, []byte(userdata.Username))

	signed_enc_file_symm, _ := userlib.DSSign(signing_sk, encrypted_file_symm)
	signed_enc_file_id, _ := userlib.DSSign(signing_sk, encrypted_file_id)
	signed_enc_file_owner, _ := userlib.DSSign(signing_sk, encrypted_file_owner)

	var encrypted_AT_struct AccessToken
	encrypted_AT_struct.Enc_file_symm = encrypted_file_symm
	encrypted_AT_struct.Enc_file_id = encrypted_file_id
	encrypted_AT_struct.Enc_file_owner = encrypted_file_owner
	encrypted_AT_struct.Signed_file_symm = signed_enc_file_symm
	encrypted_AT_struct.Signed_file_id = signed_enc_file_id
	encrypted_AT_struct.Signed_file_owner = signed_enc_file_owner
	encrypted_AT_marshaled, _ := json.Marshal(encrypted_AT_struct)

	userlib.DatastoreSet(accessToken, encrypted_AT_marshaled)

	// Encrypting file with Tree_pk
	Tree_pk, _ := userlib.KeystoreGet(userdata.Username + "_treekey")
	SetHashmap(filename, accessToken, userdata.Username, userdata.Files_key)
	//userdata.Files[filename] = accessToken
	invite_AT, _ := json.Marshal(accessToken)
	invite_AT_enc, _ := userlib.PKEEnc(Tree_pk, invite_AT)

	var usernode Node
	usernodeptr := &usernode
	usernode.Username = userdata.Username
	usernode.User_invite_loc = invite_AT_enc
	usernode.Children = nil

	var participants Tree
	participants.Root = usernodeptr
	filedata.Participants = participants

	DatastoreFile(file_id, owner_hash[:], file_symm, &filedata)
	DatastoreUser(userdata, pk)
	return
}

//AppendFile is documented at:
//https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	if data == nil || len(data) < 1 {
		return errors.New(strings.ToTitle("No data to append."))
	}

	file_symm, file_id, file_owner_hash, _, _ := RetrieveAccessToken(userdata, filename)
	if file_symm == nil {
		return errors.New(strings.ToTitle("File not found."))
	}
	filedata, err := RetrieveFile(file_owner_hash, file_symm, file_id)
	if err != nil {
		return err
	}

	participants := filedata.Participants
	if TreeSearch(&participants, userdata.Username) == nil {
		return errors.New(strings.ToTitle("User does not have access to this file."))
	}

	// Create new node for new Data and place in Datstore at data_loc
	var data_node LL_node
	iv := userlib.RandomBytes(16)
	data = Padding(data)

	file_symm_data, _ := userlib.HashKDF(file_symm, []byte("encrypt data"))
	file_symm_data = file_symm_data[:16]
	file_symm_data_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC data"))
	file_symm_data_HMAC = file_symm_data_HMAC[:16]

	data_node.Data = userlib.SymEnc(file_symm_data, iv, data)
	data_node.HMAC_Data, _ = userlib.HMACEval(file_symm_data_HMAC, data_node.Data)
	data_node.Next = uuid.Nil

	random := userlib.RandomBytes(16)
	data_loc := bytesToUUID(random)

	data_node_marshal, _ := json.Marshal(data_node)
	userlib.DatastoreSet(data_loc, data_node_marshal)
	///////////////////

	//old tail Next should point to new data node
	tail, _ := userlib.DatastoreGet(filedata.Tail)
	var tail_ll LL_node
	json.Unmarshal(tail, &tail_ll)
	tail_ll.Next = data_loc
	tail_marshal, _ := json.Marshal(tail_ll)
	userlib.DatastoreSet(filedata.Tail, tail_marshal)
	//////////////

	filedata.Tail = data_loc
	DatastoreFile(file_id, file_owner_hash, file_symm, filedata)
	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	file_symm, file_id, file_owner_hash, _, err := RetrieveAccessToken(userdata, filename)
	if err != nil {
		return nil, err
	}

	filedata, err := RetrieveFile(file_owner_hash, file_symm, file_id)
	if err != nil {
		return nil, err
	}

	participants := filedata.Participants

	if TreeSearch(&participants, userdata.Username) == nil {
		return nil, errors.New(strings.ToTitle("User does not have access to this file."))
	}

	file_id_str := string(file_id)

	if file_id_str != string(filedata.File_ID) {
		return nil, errors.New(strings.ToTitle("Did not retrieve the correct file."))
	}

	head, _ := userlib.DatastoreGet(filedata.Head)
	var linked_list LL_node
	json.Unmarshal(head, &linked_list)
	dataBytes = []byte{}

	file_symm_data, _ := userlib.HashKDF(file_symm, []byte("encrypt data"))
	file_symm_data = file_symm_data[:16]
	file_symm_data_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC data"))
	file_symm_data_HMAC = file_symm_data_HMAC[:16]

	for linked_list.Next != uuid.Nil {
		calc_HMAC, _ := userlib.HMACEval(file_symm_data_HMAC, linked_list.Data)
		if string(calc_HMAC) != string(linked_list.HMAC_Data) {
			return nil, errors.New(strings.ToTitle("File contents have been corrupted."))
		}
		data := userlib.SymDec(file_symm_data, linked_list.Data)
		data = Unpad(data)
		dataBytes = append(dataBytes, data...)
		next, _ := userlib.DatastoreGet(linked_list.Next)
		json.Unmarshal(next, &linked_list)
	}
	// calc_HMAC, _ := userlib.HMACEval(file_symm_data_HMAC, linked_list.Data)
	// if string(calc_HMAC) != string(linked_list.HMAC_Data) {
	// 	return nil, errors.New(strings.ToTitle("File contents have been corrupted end."))
	// }
	data := userlib.SymDec(file_symm_data, linked_list.Data)
	data = Unpad(data)
	dataBytes = append(dataBytes, data...)

	return dataBytes, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	file_symm, file_id, file_owner_hash, owner, err := RetrieveAccessToken(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}
	filedata, err := RetrieveFile(file_owner_hash, file_symm, file_id)
	if err != nil {
		return uuid.Nil, err
	}
	participants := filedata.Participants

	if TreeSearch(&participants, userdata.Username) == nil {
		return uuid.Nil, errors.New(strings.ToTitle("This user does not have access to the file."))
	}
	recipient_pk, ok := userlib.KeystoreGet(recipient + "_enckey")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("Recipient username is incorrect."))
	}

	signing_sk := userdata.Signing_sk
	// AT := append(file_symm, file_id...)
	// AT = append(AT, owner...)
	encrypted_file_symm, _ := userlib.PKEEnc(recipient_pk, file_symm)
	encrypted_file_id, _ := userlib.PKEEnc(recipient_pk, file_id)
	encrypted_file_owner, _ := userlib.PKEEnc(recipient_pk, owner)
	signed_enc_file_symm, _ := userlib.DSSign(signing_sk, encrypted_file_symm)
	signed_enc_file_id, _ := userlib.DSSign(signing_sk, encrypted_file_id)
	signed_enc_file_owner, _ := userlib.DSSign(signing_sk, encrypted_file_owner)

	var encrypted_AT_struct AccessToken
	encrypted_AT_struct.Enc_file_symm = encrypted_file_symm
	encrypted_AT_struct.Enc_file_id = encrypted_file_id
	encrypted_AT_struct.Enc_file_owner = encrypted_file_owner
	encrypted_AT_struct.Signed_file_symm = signed_enc_file_symm
	encrypted_AT_struct.Signed_file_id = signed_enc_file_id
	encrypted_AT_struct.Signed_file_owner = signed_enc_file_owner
	encrypted_AT_marshaled, _ := json.Marshal(encrypted_AT_struct)

	recipient_key := append([]byte(recipient), []byte("accessToken")...)
	recipient_key = append(recipient_key, file_id...)
	key_hash := userlib.Hash(recipient_key) //changes file_owner_hash

	accessToken, _ = uuid.FromBytes(key_hash[:16])

	userlib.DatastoreSet(accessToken, encrypted_AT_marshaled)

	return accessToken, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {

	files, err := RetrieveHashmap(userdata.Username, userdata.Files_key)
	if err != nil {
			return err
	}
	_, ok := files[filename]
	if ok {
		_, _, _, _, err := RetrieveAccessToken(userdata, filename)
		if err != nil {
			return err
		}
	}

	accessToken_enc, _ := userlib.DatastoreGet(accessToken)

	// secret_key := userdata.Secret_key
	var AT AccessToken
	_ = json.Unmarshal(accessToken_enc, &AT)

	sender_verkey, _ := userlib.KeystoreGet(sender + "_verkey")
	err = userlib.DSVerify(sender_verkey, AT.Enc_file_symm, AT.Signed_file_symm)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(sender_verkey, AT.Enc_file_id, AT.Signed_file_id)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(sender_verkey, AT.Enc_file_owner, AT.Signed_file_owner)
	if err != nil {
		return err
	}
	SetHashmap(filename, accessToken, userdata.Username, userdata.Files_key)
	//userdata.Files[filename] = accessToken

	file_symm, file_id, file_owner_hash, owner, err := RetrieveAccessToken(userdata, filename)
	if err != nil {
		return err
	}

	filedata, err := RetrieveFile(file_owner_hash, file_symm, file_id)
	if err != nil {
		return err
	}
	Tree_pk, _ := userlib.KeystoreGet(string(owner) + "_treekey")
	participants := filedata.Participants
	invite_AT, _ := json.Marshal(accessToken)
	invite_AT_enc, _ := userlib.PKEEnc(Tree_pk, invite_AT)

	var usernode Node
	usernode.Username = userdata.Username
	usernode.User_invite_loc = invite_AT_enc
	usernode.Children = nil

	// set this user to be child of sender
	sender_node := TreeSearch(&participants, sender)
	if sender_node == nil {
		return errors.New(strings.ToTitle("Sender does not have access to the file."))
	}
	sender_node.Children = append(sender_node.Children, &usernode)

	pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")

	DatastoreFile(file_id, file_owner_hash, file_symm, filedata)
	DatastoreUser(userdata, pk)
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	file_symm, file_id, file_owner_hash, owner, err := RetrieveAccessToken(userdata, filename)
	if err != nil {
		return err
	}
	filedata, err := RetrieveFile(file_owner_hash, file_symm, file_id)
	if err != nil {
		return err
	}
	participants := filedata.Participants
	if (participants.Root).Username != userdata.Username {
		return errors.New(strings.ToTitle("User does not have revoke access."))
	}
	targetNode := TreeSearch(&participants, targetUsername)
	if targetNode == nil {
		return errors.New(strings.ToTitle("Target does not currently have access to this file."))
	}

	Tree_sk := userdata.Tree_sk

	// for the for subtree of target user, change accessTokens to garbage
	// garbage := userlib.RandomBytes(16 + 16 + 64)
	// updateAccessTokens(targetNode, garbage, root_sk)
	invalid := []byte("This is an invalid accessToken.")
	updateAccessTokens(targetNode, invalid, userlib.RandomBytes(16), userlib.RandomBytes(10), Tree_sk)

	// remove subtree for this node in participants (probably create this helper)
	removeSubtree(&participants, targetNode.Username)

	// go through pariticipants and replace file_symm
	file_symm_new := userlib.RandomBytes(16)
	// AT := append(file_symm_new, file_id...)
	// AT = append(AT, owner...)
	updateAccessTokens(participants.Root, file_symm_new, file_id, owner, Tree_sk)

	//affected by  file_symm: encryption of data, HMAC of data, encryption of filestruct, HMAC of filestruct

	head, _ := userlib.DatastoreGet(filedata.Head)
	var linked_list LL_node
	json.Unmarshal(head, &linked_list)

	file_symm_data, _ := userlib.HashKDF(file_symm, []byte("encrypt data"))
	file_symm_data = file_symm_data[:16]
	file_symm_data_HMAC, _ := userlib.HashKDF(file_symm, []byte("HMAC data"))
	file_symm_data_HMAC = file_symm_data_HMAC[:16]

	file_symm_new_data, _ := userlib.HashKDF(file_symm_new, []byte("encrypt data"))
	file_symm_new_data = file_symm_new_data[:16]
	file_symm_new_data_HMAC, _ := userlib.HashKDF(file_symm_new, []byte("HMAC data"))
	file_symm_new_data_HMAC = file_symm_new_data_HMAC[:16]

	location := filedata.Head
	for linked_list.Next != uuid.Nil {
		calc_HMAC, _ := userlib.HMACEval(file_symm_data_HMAC, linked_list.Data)
		if string(calc_HMAC) != string(linked_list.HMAC_Data) {
			return errors.New(strings.ToTitle("File contents have been corrupted in revoke."))
		}
		data := userlib.SymDec(file_symm_data, linked_list.Data)
		iv := userlib.RandomBytes(16)
		data = userlib.SymEnc(file_symm_new_data, iv, data)
		data_HMAC, _ := userlib.HMACEval(file_symm_new_data_HMAC, data)
		linked_list.Data = data
		linked_list.HMAC_Data = data_HMAC
		ll_marshalled, _ := json.Marshal(linked_list)
		userlib.DatastoreSet(location, ll_marshalled)
		next, _ := userlib.DatastoreGet(linked_list.Next)
		location = linked_list.Next
		json.Unmarshal(next, &linked_list)
	}
	calc_HMAC, _ := userlib.HMACEval(file_symm_data_HMAC, linked_list.Data)
	if string(calc_HMAC) != string(linked_list.HMAC_Data) {
		return errors.New(strings.ToTitle("File contents have been corrupted in revoke end."))
	}
	data := userlib.SymDec(file_symm_data, linked_list.Data)
	iv := userlib.RandomBytes(16)
	data = userlib.SymEnc(file_symm_new_data, iv, data)
	data_HMAC, _ := userlib.HMACEval(file_symm_new_data_HMAC, data)
	linked_list.Data = data
	linked_list.HMAC_Data = data_HMAC
	ll_marshalled, _ := json.Marshal(linked_list)
	userlib.DatastoreSet(location, ll_marshalled)

	DatastoreFile(file_id, file_owner_hash, file_symm_new, filedata)
	return
}

// iterates through node and all it's children and updates their accessTokens with given udpate_val
// encrypts the update_val according to who the node belongs to
func updateAccessTokens(node *Node, file_symm []byte, file_id []byte, file_owner []byte, owner_sk userlib.PKEDecKey) (err error) {
	if node == nil {
		return nil
	}
	node_pk, _ := userlib.KeystoreGet(node.Username + "_enckey")

	encrypted_file_symm, _ := userlib.PKEEnc(node_pk, file_symm)
	encrypted_file_id, _ := userlib.PKEEnc(node_pk, file_id)
	encrypted_file_owner, _ := userlib.PKEEnc(node_pk, file_owner)
	signed_enc_file_symm := userlib.RandomBytes(256)
	signed_enc_file_id := userlib.RandomBytes(256)
	signed_enc_file_owner := userlib.RandomBytes(256)

	var encrypted_AT_struct AccessToken
	encrypted_AT_struct.Enc_file_symm = encrypted_file_symm
	encrypted_AT_struct.Enc_file_id = encrypted_file_id
	encrypted_AT_struct.Enc_file_owner = encrypted_file_owner
	encrypted_AT_struct.Signed_file_symm = signed_enc_file_symm
	encrypted_AT_struct.Signed_file_id = signed_enc_file_id
	encrypted_AT_struct.Signed_file_owner = signed_enc_file_owner
	encrypted_AT_marshaled, _ := json.Marshal(encrypted_AT_struct)

	AT, _ := userlib.PKEDec(owner_sk, node.User_invite_loc)
	var AT_uuid uuid.UUID
	json.Unmarshal(AT, &AT_uuid)
	userlib.DatastoreSet(AT_uuid, encrypted_AT_marshaled)

	for _, child := range node.Children {
		updateAccessTokens(child, file_symm, file_id, file_owner, owner_sk)
	}
	return nil
}

func removeSubtree(participants *Tree, targetUser string) (found bool) {
	queue := make([]*Node, 0)
	queue = append(queue, participants.Root)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if len(next.Children) > 0 {
			for idx, child := range next.Children {
				if child.Username == targetUser {
					if len(next.Children) == 1 {
						next.Children = nil
					} else {
						next.Children = append(next.Children[:idx], next.Children[idx+1:]...)

					}
					return true
				}
				queue = append(queue, child)
			}
		}
	}

	return false
}
