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
	Username string
	User_invite_loc []byte //encrypted with the root/owner's public key
	Children []*Node
}

type Tree struct {
	Root *Node
}

// User is the structure definition for a user record.
type User struct {
	password string
	Username string
	Secret_key []byte
	HMAC_sk []byte
	Signing_sk []byte
	HMAC_sign_sk []byte
	//File_loc_sk []byte //secret key for HMACing file location to check if pointer switch
	//HMAC_loc []byte	//HMAC of above
	Files map[string] userlib.UUID //Hashmap of files: filename → accesstoken|HMAC(file_location)
	//accessToken = file_symm, file_id, owner_hash
	HMAC_files []byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	Data []byte
	End_pointer []byte //encrypted int len of file
	Participants []byte //marshaled version of Tree
	Data_HMAC []byte
	Participants_HMAC []byte
	Ep_HMAC []byte
	File_ID []byte
}

func Padding(msg []byte) (padded_msg []byte) {
	msg_len := len(msg)
	padding := 16 - msg_len % 16
	for i := 0; i < padding; i+=1 {
		msg = append(msg, byte(padding))
	}
	return msg
}

func Unpad(ciphertext []byte) (unpadded_msg []byte) {
	padding := int(ciphertext[len(ciphertext)-1])
	unpadded_msg = ciphertext[0:len(ciphertext) - padding]
	return unpadded_msg
}

func TreeSearch(participants Tree, username string) (node *Node) {
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

func RetrieveFile(owner_hash []byte, filename string) (filedataptr *File, err error){
	key_hash := userlib.Hash(append([]byte(filename), owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not in Datastore!"))
	}
	var filedata File
	filedataptr = &filedata
	json.Unmarshal(dataJSON, filedataptr)

	return filedataptr, nil
}

func RetrieveAccessToken(userdata *User, filename string) (file_symm []byte, file_id []byte, file_owner_hash []byte, err error) {
	uuid_accessToken, ok := userdata.Files[filename]
	if !ok {
		return nil, nil, nil, errors.New(strings.ToTitle("Access token not in hashmap!"))
	}
	keys, ok := userlib.DatastoreGet(uuid_accessToken)

	if !ok {
		return nil, nil, nil, errors.New(strings.ToTitle("Access Token not in Datastore"))
	}
	secret_key := GetPKESecretKey(userdata)
	decrypted_keys, _ := userlib.PKEDec(secret_key, keys)
	if len(decrypted_keys) == 0 {
		return nil, nil, nil, errors.New(strings.ToTitle("decrypted_keys is empty" + string(keys)))
	}

	file_symm, file_id, file_owner_hash = decrypted_keys[:16], decrypted_keys[16:32], decrypted_keys[32:96]
	return file_symm, file_id, file_owner_hash, nil
}

func GetPKESecretKey(userdata *User) (secret_key userlib.PrivateKeyType) {
	public_key, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	pk, _ := json.Marshal(public_key)
	salt, _ := userlib.HMACEval(pk[0:16], []byte(userdata.Username))
	secret_key_byte := userlib.SymDec(userlib.Argon2Key([]byte(userdata.password), salt, 32), userdata.Secret_key)
	secret_key_byte = Unpad(secret_key_byte)
	json.Unmarshal(secret_key_byte, &secret_key)

	return secret_key
}

func GetSecretSignKey(userdata *User) (signing_sk userlib.DSSignKey) {
	public_key, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	pk, _ := json.Marshal(public_key)
	salt, _ := userlib.HMACEval(pk[0:16], []byte(userdata.Username))
	signing_sk_byte := userlib.SymDec(userlib.Argon2Key([]byte(userdata.password), salt, 32), userdata.Signing_sk)

	signing_sk_byte = Unpad(signing_sk_byte)
	json.Unmarshal(signing_sk_byte, &signing_sk)
	return signing_sk
}

//func (filedata *File) ParticipantCheck(target *User) {
	//file_symm = RetrieveAccessTok
//}

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
	sk_1 = Padding(sk_1)
	userdata.Secret_key = userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_enc, sk_1)
	//sk_2, _ := json.Marshal(userdata.Secret_key)
	userdata.HMAC_sk, _ = userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata.Secret_key)

	signing_sk, signing_verk, _ := userlib.DSKeyGen()

	user_verkey := username + "_verkey"
	IV_sign := userlib.RandomBytes(16)
	userlib.KeystoreSet(user_verkey, signing_verk)
	sk_3, _ := json.Marshal(signing_sk)

	sk_3 = Padding(sk_3)
	userdata.Signing_sk = userlib.SymEnc(userlib.Argon2Key(pwd_bytes, salt, 32), IV_sign, sk_3)
  userdata.HMAC_sign_sk, _ = userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), userdata.Signing_sk)

	userdata.Files = make(map[string]userlib.UUID)
	files_marshal, _ := json.Marshal(userdata.Files)
	userdata.HMAC_files, _ = userlib.HMACEval(userlib.Argon2Key(pwd_bytes, salt, 16), files_marshal)

	userbytes, _ := json.Marshal(userdata)
	hash := userlib.Hash([]byte(username + password))
	slicehash := hash[:]
	userlib.DatastoreSet(bytesToUUID(slicehash), userbytes)
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
		hash := userlib.Hash([]byte(username + password))
		slicehash := hash[:]
		user, ok := userlib.DatastoreGet(bytesToUUID(slicehash))

		if !ok {
			return nil, errors.New(strings.ToTitle("Username and password don't match."))
		}

		_ = json.Unmarshal(user, userdataptr)
//check integrity of user struct & malicious action?
	//check that:
		pk, _ := json.Marshal(public_key)
		salt, _ := userlib.HMACEval(pk[0:16], []byte(username))

		HMAC_enc, _ := userlib.HMACEval(userlib.Argon2Key([]byte(password), salt, 16), userdata.Secret_key)
		HMAC_sign, _ := userlib.HMACEval(userlib.Argon2Key([]byte(password), salt, 16), userdata.Signing_sk)

		if ! userlib.HMACEqual(HMAC_enc, userdata.HMAC_sk) {
			return nil, errors.New(strings.ToTitle("HMAC of encryption keys don't match."))
		}
		if ! userlib.HMACEqual(HMAC_sign, userdata.HMAC_sign_sk) {
			return nil, errors.New(strings.ToTitle("HMAC of signing keys don't match."))
		}
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
	data = Padding(data)
	iv := userlib.RandomBytes(16)
	filedata.Data = userlib.SymEnc(file_symm, iv, data)
	iv = userlib.RandomBytes(16)
	ep := []byte{byte(len(filedata.Data))}
	ep = Padding(ep)
	filedata.End_pointer = userlib.SymEnc(file_symm, iv, ep)

	filedata.Ep_HMAC, _ = userlib.HMACEval(file_symm, filedata.End_pointer)
	filedata.Data_HMAC, _ = userlib.HMACEval(file_symm, filedata.Data)
	pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")

	//
	file_id := userlib.RandomBytes(16)

	iv = userlib.RandomBytes(16)
	filedata.File_ID = userlib.SymEnc(file_symm, iv, file_id)
	//
	owner_hash := userlib.Hash([]byte(userdata.Username))


	accessToken := append(file_symm, file_id...)
	accessToken = append(accessToken, owner_hash[:]...)

	signing_sk := GetSecretSignKey(userdata)
	signed_accessToken, _ := userlib.DSSign(signing_sk, accessToken)
	user_hash := userlib.Hash(append([]byte(userdata.Username), []byte("accessToken")...))
	key_hash := userlib.Hash(append([]byte(filename), user_hash[:]...))

	accessToken_uuid , _ := uuid.FromBytes(key_hash[:16])
	userdata.Files[filename] = accessToken_uuid
	pk_byte, _ := json.Marshal(pk)
	salt, _ := userlib.HMACEval(pk_byte[0:16], []byte(userdata.Username))
	files_marshal, _ := json.Marshal(userdata.Files)
	userdata.HMAC_files, _ = userlib.HMACEval(userlib.Argon2Key([]byte(userdata.password), salt, 16), files_marshal)
	
	encrypted_AT, _ := userlib.PKEEnc(pk, accessToken)
	encrypted_sign, _ := userlib.PKEEnc(pk, signed_accessToken)
	encrypted_AT = append(encrypted_AT, encrypted_sign...)

	userlib.DatastoreSet(accessToken_uuid, encrypted_AT)

	AT_uuid_marshal, _ := json.Marshal(accessToken_uuid)
	encrypted_AT_uuid, _ := userlib.PKEEnc(pk, AT_uuid_marshal)

	var usernode Node
	usernodeptr := &usernode
	usernode.Username = userdata.Username
	usernode.User_invite_loc = encrypted_AT_uuid
	usernode.Children = nil

	var participants Tree
	participants.Root = usernodeptr

	participants_marshal, _ := json.Marshal(participants)
	participants_marshal = Padding(participants_marshal)
	iv = userlib.RandomBytes(16)
	filedata.Participants = userlib.SymEnc(file_symm, iv, participants_marshal)
	filedata.Participants_HMAC, _ = userlib.HMACEval(file_symm, filedata.Participants)

	user_hash = userlib.Hash([]byte(userdata.Username)) // ok because current user is the owner
	key_hash = userlib.Hash(append([]byte(filename), user_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])
	jsonData, _ := json.Marshal(filedata)
	userlib.DatastoreSet(storageKey, jsonData)

	_, ok = userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New(strings.ToTitle("Data not correctly stored in Datastore."))
	}

	hash := userlib.Hash([]byte(userdata.Username + userdata.password))
	slicehash := hash[:]
	userbytes, _ := json.Marshal(userdata)
	userlib.DatastoreSet(bytesToUUID(slicehash), userbytes)

	return
}

//AppendFile is documented at:
//https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	file_symm, _, file_owner_hash, _ := RetrieveAccessToken(userdata, filename)
	if file_symm == nil {
		return errors.New(strings.ToTitle("File not found."))
	}
	filedata, err := RetrieveFile(file_owner_hash, filename)
	if err != nil {
		return err
	}

	calc_participants_HMAC, _ := userlib.HMACEval(file_symm, filedata.Participants)
	if ! userlib.HMACEqual(calc_participants_HMAC, filedata.Participants_HMAC) {
		return errors.New(strings.ToTitle("HMAC of file participants tree don't match."))
	}

	var participants Tree
	participants_decrypted := userlib.SymDec(file_symm, filedata.Participants)
	participants_decrypted = Unpad(participants_decrypted)
	json.Unmarshal(participants_decrypted, &participants)

	if TreeSearch(participants, userdata.Username) == nil {
		return errors.New(strings.ToTitle("User does not have access to this file."))
	}

	end_ptr := userlib.SymDec(file_symm, filedata.End_pointer)
	end_ptr = Unpad(end_ptr)
	end_ptr_num := int(end_ptr[0])

	var dataBytes []byte
	if end_ptr_num <= 32 {
		dataBytes = userlib.SymDec(file_symm, filedata.Data)
		dataBytes = Unpad(dataBytes)
		dataBytes = append(dataBytes, data...)
		dataBytes = Padding(dataBytes)
		iv := userlib.RandomBytes(16)
		filedata.Data = userlib.SymEnc(file_symm, iv, dataBytes)
	} else {
		encrypted_end_data := filedata.Data[end_ptr_num - 32:]
		iv := encrypted_end_data[:16]
		tail := encrypted_end_data[16:]
		tail = userlib.SymDec(file_symm, tail)
		tail = Unpad(tail)
		tail = append(tail, data...)
		tail = Padding(tail)
		filedata.Data = append(filedata.Data[:end_ptr_num - 16], userlib.SymEnc(file_symm, iv, tail)...)
	}

	filedata.Data_HMAC, _ = userlib.HMACEval(file_symm, filedata.Data)
	ep := []byte{byte(len(filedata.Data))}
	ep = Padding(ep)
	iv := userlib.RandomBytes(16)
	filedata.End_pointer = userlib.SymEnc(file_symm, iv, ep)
	filedata.Ep_HMAC, _ = userlib.HMACEval(file_symm, filedata.End_pointer)

	//user_hash := userlib.Hash([]byte(file_owner))
	key_hash := userlib.Hash(append([]byte(filename), file_owner_hash[:]...))
	storageKey, _ := uuid.FromBytes(key_hash[:16])

	jsonData, _ := json.Marshal(filedata)
	userlib.DatastoreSet(storageKey, jsonData)

	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	file_symm, file_id, file_owner_hash, err := RetrieveAccessToken(userdata, filename)
	if err != nil {
		return nil, err
	}
	filedata, err := RetrieveFile(file_owner_hash, filename)
	if err != nil {
		return nil, err
	}

	calc_participants_HMAC, _ := userlib.HMACEval(file_symm, filedata.Participants)
	if ! userlib.HMACEqual(calc_participants_HMAC, filedata.Participants_HMAC) {
		return nil, errors.New(strings.ToTitle("HMAC of file participants tree don't match."))
	}

	var participants Tree
	participants_decrypted := userlib.SymDec(file_symm, filedata.Participants)
	participants_decrypted = Unpad(participants_decrypted)
	json.Unmarshal(participants_decrypted, &participants)

	if TreeSearch(participants, userdata.Username) == nil {
		return nil, errors.New(strings.ToTitle("User does not have access to this file."))
	}

	stored_file_id := userlib.SymDec(file_symm, filedata.File_ID)
	file_id_str := string(file_id)
	stored_file_id_str := string(stored_file_id)

	if file_id_str != stored_file_id_str {
		return nil, errors.New(strings.ToTitle("Did not retrieve the correct file."))
	}
	calc_data_HMAC, _ := userlib.HMACEval(file_symm, filedata.Data)
	if ! userlib.HMACEqual(calc_data_HMAC, filedata.Data_HMAC) {
		return nil, errors.New(strings.ToTitle("HMAC of file data don't match."))
	}
	calc_ep_HMAC, _ := userlib.HMACEval(file_symm, filedata.End_pointer)
	if ! userlib.HMACEqual(calc_ep_HMAC, filedata.Ep_HMAC) {
		return nil, errors.New(strings.ToTitle("HMAC of file end pointers don't match."))
	}

	dataBytes = userlib.SymDec(file_symm, filedata.Data)
	dataBytes = Unpad(dataBytes)
	return dataBytes, nil

	return
}


// Rethink
// 1. In hashmap, we accessToken (store file_id and file_symm) directly. Instead, they should be in datastore safely
//stored and the hashmap should have a pointer to it.
// 1. RESOLVED
// 2. When we share, we add the person to participants tree along with the location of the accessToken encrypted with the owners PK.
// 3. How are we storing files in Datastore? What is storagekey? Maybe make file_id storagekey?
// 3. accessToken - append "accessToken", regular files - add file owner hash to distinguish RESOLVED

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	file_symm, file_id, file_owner_hash, err := RetrieveAccessToken(userdata, filename)
	if err != nil{
		return uuid.Nil, err
	}
	filedata, err := RetrieveFile(file_owner_hash, filename)
	if err != nil {
		return uuid.Nil, err
	}
	var participants Tree
	participants_decrypted := userlib.SymDec(file_symm, filedata.Participants)
	participants_decrypted = Unpad(participants_decrypted)
	err = json.Unmarshal(participants_decrypted, &participants)
	if err != nil {
		return uuid.Nil, err
	}

	if TreeSearch(participants, userdata.Username) == nil{
		return uuid.Nil, errors.New(strings.ToTitle("This user does not have access to the file."))
	}
	recipient_pk, ok := userlib.KeystoreGet(recipient + "_enckey")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("Recipient username is incorrect."))
	}

	AT := append(file_symm, file_id...)
	AT = append(AT, file_owner_hash...)

	signing_sk := GetSecretSignKey(userdata)
	signed_accessToken, _ := userlib.DSSign(signing_sk, AT)
	
	user_hash := userlib.Hash(append([]byte(recipient), []byte("accessToken")...))
	key_hash := userlib.Hash(append([]byte(filename), user_hash[:]...))

	accessToken, _ = uuid.FromBytes(key_hash[:16])
	encrypted_AT, _ := userlib.PKEEnc(recipient_pk, AT)
	encrypted_sign, _ := userlib.PKEEnc(recipient_pk, signed_accessToken)
	encrypted_AT = append(encrypted_AT, encrypted_sign...)

	userlib.DatastoreSet(accessToken, encrypted_AT)

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

	secret_key := GetPKESecretKey(userdata)
	accessToken_enc, _ := userlib.DatastoreGet(accessToken)

	sender_verkey, _ := userlib.KeystoreGet(sender + "_verkey")
	accessToken_msg, _ := userlib.PKEDec(secret_key, accessToken_enc[:256])
	accessToken_sig, _ := userlib.PKEDec(secret_key, accessToken_enc[256:])
	err := userlib.DSVerify(sender_verkey, accessToken_msg, accessToken_sig) //erroring here
	if err != nil {
		return err
	}

	pk, _ := userlib.KeystoreGet(userdata.Username + "_enckey")
	userdata.Files[filename] = accessToken 
	pk_byte, _ := json.Marshal(pk)
	salt, _ := userlib.HMACEval(pk_byte[0:16], []byte(userdata.Username))
	files_marshal, _ := json.Marshal(userdata.Files)
	userdata.HMAC_files, _ = userlib.HMACEval(userlib.Argon2Key([]byte(userdata.password), salt, 16), files_marshal)

	file_symm, _, file_owner_hash, err := RetrieveAccessToken(userdata, filename)
	if err != nil{
		return err
	}
	filedata, err := RetrieveFile(file_owner_hash, filename)
	if err != nil {
		return err
	}

	var participants Tree
	participants_decrypted := userlib.SymDec(file_symm, filedata.Participants)
	participants_decrypted = Unpad(participants_decrypted)
	err = json.Unmarshal(participants_decrypted, &participants)
	if err != nil {
		return err
	}

	AT_uuid_marshal, _ := json.Marshal(accessToken)
	owner_username_enc := participants.Root.Username + "_enckey"
	owner_pk, _ := userlib.KeystoreGet(owner_username_enc)
	encrypted_AT_uuid, _ := userlib.PKEEnc(owner_pk, AT_uuid_marshal)

	var usernode Node
	usernode.Username = userdata.Username
	usernode.User_invite_loc = encrypted_AT_uuid
	usernode.Children = nil

	// set this user to be child of sender
	sender_node := TreeSearch(participants, sender)
	if sender_node == nil {
		return errors.New(strings.ToTitle("Sender does not have access to the file."))
	}
	sender_node.Children = append(sender_node.Children, &usernode)

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
