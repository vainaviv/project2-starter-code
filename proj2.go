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

type Tree struct {
	Root *Node
}

// User is the structure definition for a user record.
type User struct {
	password   string
	Username   string
	Secret_key userlib.PKEDecKey
	//HMAC_sk []byte
	Signing_sk userlib.DSSignKey
	Files      map[string]userlib.UUID //Hashmap of files: filename → accesstoken|HMAC(file_location)
}

type File struct {
	Data         []byte
	End_pointer  int  //encrypted int len of file
	Participants Tree //marshaled version of Tree
	File_ID      []byte
}

type AccessToken struct {
	Enc_keys    []byte
	Signed_keys []byte
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

func TreeSearch(participants* Tree, username string) (node *Node) {
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

func RetrieveFile(owner_hash []byte, file_symm []byte, file_id []byte) (filedataptr *File, err error) {
	key_hash := userlib.Hash(append(file_id, owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not in Datastore!"))
	}
	dataJSON_dec := userlib.SymDec(file_symm, dataJSON)
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
	filedata_HMAC_datastore, _ := userlib.HMACEval(file_symm, dataJSON)
	if !userlib.HMACEqual(filedata_HMAC, filedata_HMAC_datastore) {
		return nil, errors.New(strings.ToTitle("File HMACs don't match!"))
	}

	return filedataptr, nil
}

func RetrieveAccessToken(userdata *User, filename string) (file_symm []byte, file_id []byte, file_owner_hash []byte,
	owner []byte, err error) {
	uuid_accessToken, ok := userdata.Files[filename]
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

	decrypted_keys, _ := userlib.PKEDec(secret_key, AT.Enc_keys)
	file_symm, file_id, owner = decrypted_keys[:16], decrypted_keys[16:32], decrypted_keys[32:]
	file_owner := userlib.Hash(owner)
	file_owner_hash = file_owner[:]
	//owner_pk, _ = userlib.KeystoreGet(string(owner))
	// file_symm, file_id, file_owner_hash = decrypted_keys[:16], decrypted_keys[16:32], decrypted_keys[32:96]
	// owner_pk = decrypted_keys[96:]

	return file_symm, file_id, file_owner_hash, owner, nil
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

	//
	pk, _ := json.Marshal(public_key)
	// //TODO: Check keylen later if necessary - secret keys using keylen = 32, hmacs using keylen = 16
	userlib.KeystoreSet(user_enckey, public_key)

	userdata.Secret_key = secret_key

	signing_sk, signing_verk, _ := userlib.DSKeyGen()

	user_verkey := username + "_verkey"
	userlib.KeystoreSet(user_verkey, signing_verk)

	userdata.Signing_sk = signing_sk
	userdata.Files = make(map[string]userlib.UUID)

	userbytes, _ := json.Marshal(userdata)

	//Storing encrypted user struct in datastore
	IV_enc := userlib.RandomBytes(16)
	salt, _ := userlib.HMACEval(pk[0:16], []byte(username))
	userbytes = Padding(userbytes)
	userdata_enc := userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, userbytes)
	hash := userlib.Hash([]byte(username))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userdata_enc)

	//Storing HMAC of encrypted user struct in datastore
	userdata_HMAC, _ := userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata_enc)
	hash_HMAC := userlib.Hash([]byte(username + "HMAC"))
	slicehash_HMAC := hash_HMAC[:]
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

	public_key, ok_enc := userlib.KeystoreGet(user_enckey)
	_, ok_sign := userlib.KeystoreGet(user_verkey)

	if ok_enc && ok_sign {
		//do we need to check both enckey and verkey? what are security implications if one exists and other doesn’t?
		hash := userlib.Hash([]byte(username))
		slicehash := hash[:]
		user, ok := userlib.DatastoreGet(bytesToUUID(slicehash))

		if !ok {
			return nil, errors.New(strings.ToTitle("Username does not exist."))
		}

		hash_HMAC := userlib.Hash([]byte(username + "HMAC"))
		slicehash_HMAC := hash_HMAC[:]
		user_HMAC_datastore, _ := userlib.DatastoreGet(bytesToUUID(slicehash_HMAC))

		pk, _ := json.Marshal(public_key)
		salt, _ := userlib.HMACEval(pk[0:16], []byte(username))
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
	var filedata File

	_, ok := userdata.Files[filename]
	if ok {
		return errors.New(strings.ToTitle("This user already has a file with this name."))
	}

	file_symm := userlib.RandomBytes(16)
	filedata.Data = data
	filedata.End_pointer = len(filedata.Data)

	pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	file_id := userlib.RandomBytes(16)
	filedata.File_ID = file_id

	owner_hash := userlib.Hash([]byte(userdata.Username))

	// AT := append(file_symm, file_id...)
	// AT = append(AT, owner_hash[:]...)
	// owner_pk, _ := json.Marshal(pk)
	// AT = append(AT, owner_pk...)

	AT := append(file_symm, file_id...)
	AT = append(AT, []byte(userdata.Username)...)

	signing_sk := userdata.Signing_sk

	user_hash := userlib.Hash(append([]byte(userdata.Username), []byte("accessToken")...))
	key_hash := userlib.Hash(append(file_id, user_hash[:]...))

	accessToken, _ := uuid.FromBytes(key_hash[:16])
	encrypted_AT, err := userlib.PKEEnc(pk, AT)
	if err != nil {
		return err
	}
	signed_enc_AT, _ := userlib.DSSign(signing_sk, encrypted_AT)

	var encrypted_AT_struct AccessToken
	encrypted_AT_struct.Enc_keys = encrypted_AT
	encrypted_AT_struct.Signed_keys = signed_enc_AT
	encrypted_AT_marshaled, _ := json.Marshal(encrypted_AT_struct)

	userlib.DatastoreSet(accessToken, encrypted_AT_marshaled)

	userdata.Files[filename] = accessToken
	invite_AT, _ := json.Marshal(accessToken)
	invite_AT_enc, _ := userlib.PKEEnc(pk, invite_AT)

	var usernode Node
	usernodeptr := &usernode
	usernode.Username = userdata.Username
	usernode.User_invite_loc = invite_AT_enc
	usernode.Children = nil

	var participants Tree
	participants.Root = usernodeptr
	filedata.Participants = participants

	//Storing encrypted file struct in datastore
	key_hash = userlib.Hash(append(file_id, owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	jsonData, _ := json.Marshal(filedata)
	jsonData_enc := Padding(jsonData)
	iv := userlib.RandomBytes(16)
	jsonData_enc = userlib.SymEnc(file_symm, iv, jsonData_enc)
	userlib.DatastoreSet(storageKey, jsonData_enc)

	//Storing encrypted file struct HMAC in datastore
	hmac := []byte("HMAC")
	key_HMAC := append(hmac, owner_hash[:]...)
	key_HMAC = append(file_id, key_HMAC...)
	key_hash_HMAC := userlib.Hash(key_HMAC)
	storageKey_HMAC, _ := uuid.FromBytes(key_hash_HMAC[:16])
	jsonData_enc_HMAC, _ := userlib.HMACEval(file_symm, jsonData_enc)
	userlib.DatastoreSet(storageKey_HMAC, jsonData_enc_HMAC)

	userbytes, _ := json.Marshal(userdata)
	pwd_bytes := []byte(userdata.password)
	pub_k, _ := json.Marshal(pk)

	//Storing encrypted user struct in datastore
	IV_enc := userlib.RandomBytes(16)
	salt, _ := userlib.HMACEval(pub_k[0:16], []byte(userdata.Username))
	userbytes = Padding(userbytes)
	userdata_enc := userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, userbytes)
	hash := userlib.Hash([]byte(userdata.Username))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userdata_enc)

	//Storing HMAC of encrypted user struct in datastore
	userdata_HMAC, _ := userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata_enc)
	hash_HMAC := userlib.Hash([]byte(userdata.Username + "HMAC"))
	slicehash_HMAC := hash_HMAC[:]
	userlib.DatastoreSet(bytesToUUID(slicehash_HMAC), userdata_HMAC)

	return
}

//AppendFile is documented at:
//https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

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

	end_ptr_num := filedata.End_pointer

	var dataBytes []byte
	if end_ptr_num <= 32 {
		dataBytes = filedata.Data
		dataBytes = append(dataBytes, data...)
		filedata.Data = dataBytes
	} else {
		encrypted_end_data := filedata.Data[end_ptr_num-32:]
		iv := encrypted_end_data[:16]
		tail := encrypted_end_data[16:]
		tail = userlib.SymDec(file_symm, tail)
		tail = Unpad(tail)
		tail = append(tail, data...)
		tail = Padding(tail)
		filedata.Data = append(filedata.Data[:end_ptr_num-16], userlib.SymEnc(file_symm, iv, tail)...)
	}

	filedata.End_pointer = len(filedata.Data) //userlib.SymEnc(file_symm, iv, ep)
	//filedata.Ep_HMAC, _ = userlib.HMACEval(file_symm, filedata.End_pointer)

	key_hash := userlib.Hash(append(file_id, file_owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])

	jsonData, _ := json.Marshal(filedata)
	userlib.DatastoreSet(storageKey, jsonData)

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

	dataBytes = filedata.Data

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

	AT := append(file_symm, file_id...)
	AT = append(AT, owner...)

	signing_sk := userdata.Signing_sk

	recipient_key := append([]byte(recipient), []byte("accessToken")...)
	recipient_key = append(recipient_key, file_id...)
	key_hash := userlib.Hash(recipient_key) //changes file_owner_hash

	accessToken, _ = uuid.FromBytes(key_hash[:16])
	encrypted_AT, _ := userlib.PKEEnc(recipient_pk, AT)
	signed_enc_AT, _ := userlib.DSSign(signing_sk, encrypted_AT)

	var encrypted_AT_struct AccessToken
	encrypted_AT_struct.Enc_keys = encrypted_AT
	encrypted_AT_struct.Signed_keys = signed_enc_AT
	encrypted_AT_marshaled, _ := json.Marshal(encrypted_AT_struct)

	userlib.DatastoreSet(accessToken, encrypted_AT_marshaled)

	return accessToken, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {

	_, ok := userdata.Files[filename]
	if ok {
		return errors.New(strings.ToTitle("This user already has a file with this name."))
	}

	accessToken_enc, _ := userlib.DatastoreGet(accessToken)

	// secret_key := userdata.Secret_key
	var AT AccessToken
	_ = json.Unmarshal(accessToken_enc, &AT)

	secret_key := userdata.Secret_key

	decrypted_keys, _ := userlib.PKEDec(secret_key, AT.Enc_keys)
	_ = append(decrypted_keys, []byte("hello")...)

	sender_verkey, _ := userlib.KeystoreGet(sender + "_verkey")
	err := userlib.DSVerify(sender_verkey, AT.Enc_keys, AT.Signed_keys) //erroring here
	if err != nil {
		return err
	}

	//pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	userdata.Files[filename] = accessToken

	file_symm, file_id, file_owner_hash, owner, err := RetrieveAccessToken(userdata, filename)
	if err != nil {
		return err
	}

	owner_pk, _ := userlib.KeystoreGet(string(owner) + "_enckey")

	filedata, err := RetrieveFile(file_owner_hash, file_symm, file_id)
	if err != nil {
		return err
	}

	participants := filedata.Participants
	invite_AT, _ := json.Marshal(accessToken)
	invite_AT_enc, _ := userlib.PKEEnc(owner_pk, invite_AT)

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

	//Storing encrypted file struct in datastore
	key_hash := userlib.Hash(append(file_id, file_owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	jsonData, _ := json.Marshal(filedata)
	jsonData_enc := Padding(jsonData)
	iv := userlib.RandomBytes(16)
	jsonData_enc = userlib.SymEnc(file_symm, iv, jsonData_enc)
	userlib.DatastoreSet(storageKey, jsonData_enc)

	//Storing encrypted file struct HMAC in datastore

	hmac := []byte("HMAC")
	key_HMAC := append(hmac, file_owner_hash...)
	key_HMAC = append(file_id, key_HMAC...)
	key_hash_HMAC := userlib.Hash(key_HMAC)
	storageKey_HMAC, _ := uuid.FromBytes(key_hash_HMAC[:16])
	jsonData_enc_HMAC, _ := userlib.HMACEval(file_symm, jsonData_enc)
	userlib.DatastoreSet(storageKey_HMAC, jsonData_enc_HMAC)

	pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	userbytes, _ := json.Marshal(userdata)
	pwd_bytes := []byte(userdata.password)
	pub_k, _ := json.Marshal(pk)

	//Storing encrypted user struct in datastore
	IV_enc := userlib.RandomBytes(16)
	salt, _ := userlib.HMACEval(pub_k[0:16], []byte(userdata.Username))
	userbytes = Padding(userbytes)
	userdata_enc := userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, userbytes)
	hash := userlib.Hash([]byte(userdata.Username))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userdata_enc)

	//Storing HMAC of encrypted user struct in datastore
	userdata_HMAC, _ := userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata_enc)
	hash_HMAC := userlib.Hash([]byte(userdata.Username + "HMAC"))
	slicehash_HMAC := hash_HMAC[:]
	userlib.DatastoreSet(bytesToUUID(slicehash_HMAC), userdata_HMAC)

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
	root_sk := userdata.Secret_key

	// for the for subtree of target user, change accessTokens to nil
	garbage := userlib.RandomBytes(16 + 16 + 64)
	updateAccessTokens(targetNode, garbage, root_sk)

	// remove subtree for this node in participants (probably create this helper)
	removeSubtree(&participants, targetNode.Username)

	// go through pariticipants and replace file_symm
	file_symm_new := userlib.RandomBytes(16)
	AT := append(file_symm_new, file_id...)
	AT = append(AT, owner...)
	updateAccessTokens(participants.Root, AT, root_sk)

	//Storing encrypted file struct in datastore
	key_hash := userlib.Hash(append(file_id, file_owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	jsonData, _ := json.Marshal(filedata)
	jsonData_enc := Padding(jsonData)
	iv := userlib.RandomBytes(16)
	jsonData_enc = userlib.SymEnc(file_symm, iv, jsonData_enc)
	userlib.DatastoreSet(storageKey, jsonData_enc)

	//Storing encrypted file struct HMAC in datastore
	hmac := []byte("HMAC")
	key_HMAC := append(hmac, file_owner_hash...)
	key_HMAC = append(file_id, key_HMAC...)
	key_hash_HMAC := userlib.Hash(key_HMAC)
	storageKey_HMAC, _ := uuid.FromBytes(key_hash_HMAC[:16])
	jsonData_enc_HMAC, _ := userlib.HMACEval(file_symm, jsonData_enc)
	userlib.DatastoreSet(storageKey_HMAC, jsonData_enc_HMAC)

	return
}

// iterates through node and all it's children and updates their accessTokens with given udpate_val
// encrypts the update_val according to who the node belongs to
func updateAccessTokens(node *Node, update_val []byte, owner_sk userlib.PKEDecKey) (err error) {
	if node == nil {
		return nil
	}
	node_pk, _ := userlib.KeystoreGet(node.Username + "_enckey")

	encrypted_AT, _ := userlib.PKEEnc(node_pk, update_val)
	signed_enc_AT := userlib.RandomBytes(256)

	var encrypted_AT_struct AccessToken
	encrypted_AT_struct.Enc_keys = encrypted_AT
	encrypted_AT_struct.Signed_keys = signed_enc_AT
	encrypted_AT_marshaled, _ := json.Marshal(encrypted_AT_struct)

	AT, _ := userlib.PKEDec(owner_sk, node.User_invite_loc)
	var AT_uuid uuid.UUID
	json.Unmarshal(AT, &AT_uuid)
	userlib.DatastoreSet(AT_uuid, encrypted_AT_marshaled)

	for _, child := range node.Children {
		updateAccessTokens(child, update_val, owner_sk)
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
