package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"bytes"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username   string
	RSAPrivkey userlib.PKEDecKey
	DSSignkey  userlib.DSSignKey
	SymEncKey1 []byte
	SymEncKey2 []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type TreeNode struct {
	NodeUserName string
	Children     []TreeNode
}

func Padding(ciphertext []byte) []byte {
	padding_size := 64 - len(ciphertext)%64

	for i := 0; i < padding_size; i++ {
		ciphertext = append(ciphertext, byte(padding_size))
	}

	return ciphertext
}

func UnPadding(ciphertext []byte) []byte {

	padding_size := int(ciphertext[len(ciphertext)-1])

	ciphertext = ciphertext[:len(ciphertext)-padding_size]
	return ciphertext
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if the username is not empty, or return an error
	if username == "" {
		err = errors.New("the input username is empty")
		return
	}
	var userdata User
	userdata.Username = username
	// create a pair of public and  private rsa key.
	public1, private1, _ := userlib.PKEKeyGen()
	userdata.RSAPrivkey = private1
	err = userlib.KeystoreSet(userdata.Username+"1", public1)
	if err != nil {
		// err is not nil means user already exist and we return err
		err = errors.New("user with the username already exists")
		return
	}
	private2, public2, _ := userlib.DSKeyGen()
	err = userlib.KeystoreSet(userdata.Username+"2", public2)
	userdata.DSSignkey = private2
	if err != nil {
		// err is not nil means user already exist and we return err
		err = errors.New("user with the username already exists")
		return
	}
	userdataptr = &userdata

	userdata.SymEncKey1 = userlib.RandomBytes(16)
	userdata.SymEncKey2 = userlib.RandomBytes(16)
	// var credential []byte
	// credential = []byte(username + "password" + password)
	hmacKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	user_json, _ := json.Marshal(userdata)
	user_json = Padding(user_json)
	datastoreUUID, err := uuid.FromBytes(userlib.Hash(hmacKey)[:16])
	if err != nil {
		err = errors.New("unable to create datastore UUID")
		return
	}
	hmac_tag, _ := userlib.HMACEval(hmacKey, user_json)
	//combine encryption + tag to make ciphertext
	ciphertext := append(user_json, hmac_tag...)
	//store ciphertext to Datastore
	userlib.DatastoreSet(datastoreUUID, ciphertext)

	// generate auth manager key from username
	hashedRepicientName := userlib.Hash([]byte(username + "Auth Manager"))[:16]
	authKeyHash, hasherr := userlib.HashKDF(hashedRepicientName, []byte("forSavingKey!"))
	if hasherr != nil {
		err = errors.New("unable to hash auth manager storage key")
		return
	}
	authStorageKey, uuiderr := uuid.FromBytes(authKeyHash[:16])
	if uuiderr != nil {
		err = errors.New("unable to create auth storage key UUID")
		return
	}

	keyMap := make(map[string][]byte)
	keyMapJSON, newmaperr := json.Marshal(keyMap)
	if newmaperr != nil {
		err = errors.New("new map marshal error")
		return
	}
	userlib.DatastoreSet(authStorageKey, keyMapJSON)

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	// userdataptr = &userdata
	_, ok := userlib.KeystoreGet(username + "1")
	if !ok {
		err = errors.New("invalid username")
		return
	}
	verifyKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	// hmacKey, err := userlib.HashKDF([]byte(username+"password"+password), []byte("for Hmac purposes"))
	useruuid, err := uuid.FromBytes(userlib.Hash(verifyKey)[:16])
	if err != nil {
		err = errors.New("the user credentials are invalid")
		return
	}

	downloadedData, ok := userlib.DatastoreGet(useruuid)
	if !ok {
		err = errors.New("the User struct cannot be obtained due to malicious action")
		return
	}

	datalen := len(downloadedData)
	if datalen < 64 {
		err = errors.New("the integrity of the user struct has been compromised")
		return
	}

	content, old_tag := downloadedData[:datalen-64], downloadedData[datalen-64:]
	verifytag, _ := userlib.HMACEval(verifyKey, content)
	if !userlib.HMACEqual(verifytag, old_tag) {
		err = errors.New("the integrity of the user struct has been compromised")
		return
	}

	user_json := UnPadding(content)

	if err = json.Unmarshal(user_json, &userdata); err != nil {
		err = errors.New("unable to Unmarshal User Struct")
		return
	}

	userdataptr = &userdata

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])

	_, spliterr := splitAndStore(0, content, userdata.SymEncKey2)
	if spliterr != nil {
		return spliterr
	}

	// Initialize the Auth Manager
	keyMapKey, keyMap, getkeymaperr := getKeyMap(userdata.Username)
	if getkeymaperr != nil {
		return getkeymaperr
	}

	keyMap[filename] = append([]byte("root"), userdata.SymEncKey2...)

	keyMapJSON, marshalerr := json.Marshal(keyMap)
	if marshalerr != nil {
		err = errors.New("unable to unmarshal key map in auth manager")
		return
	}
	userlib.DatastoreSet(keyMapKey, keyMapJSON)

	// Creating a new Tree
	// hashedSymmKey = userlib.Hash(userdata.SymEncKey2)
	treeKeyHash, hasherr2 := userlib.HashKDF(userdata.SymEncKey2, []byte("forPlantingTree!"))
	if hasherr2 != nil {
		err = errors.New("unable to hash tree manager storage key")
		return
	}
	treeKey, uuiderr2 := uuid.FromBytes(treeKeyHash[:16])
	if uuiderr2 != nil {
		err = errors.New("unable to create tree storage key UUID")
		return
	}

	newNode := new(TreeNode)
	newNode.Children = make([]TreeNode, 0)
	newNode.NodeUserName = userdata.Username
	treeJSON, marshallerr := json.Marshal(newNode)
	if marshallerr != nil {
		err = errors.New("unable to marshall the tree")
		return
	}
	userlib.DatastoreSet(treeKey, treeJSON)

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	symmkey, getkeyerr, _ := userdata.getKey(filename)
	if getkeyerr != nil {
		return getkeyerr
	}

	length, segmentKeys, lengthKey, getkeyerr2 := getfileAccessKeys(symmkey)
	if getkeyerr2 != nil {
		return getkeyerr2
	}

	tailSegment, ok := userlib.DatastoreGet(segmentKeys[length-1])
	if !ok {
		return errors.New("unable to retrieve file segment")
	}
	tailUnpad := UnPadding(tailSegment)
	// fmt.Println(string(tailUnpad))

	newTail := append(tailUnpad, content...)
	newLength, spliterr := splitAndStore(length-1, newTail, symmkey)
	if spliterr != nil {
		return spliterr
	}

	newLength = newLength + length - 1
	userlib.DatastoreSet(lengthKey, []byte(strconv.Itoa(newLength)))

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	symmkey, getkeyerr, _ := userdata.getKey(filename)
	if getkeyerr != nil {
		err = getkeyerr
		return
	}

	length, segmentKeys, _, getkeyerr2 := getfileAccessKeys(symmkey)
	if getkeyerr2 != nil {
		err = getkeyerr2
		return
	}

	content = make([]byte, 0)
	for i, indexKey := range segmentKeys {
		segment, ok := userlib.DatastoreGet(indexKey)
		if !ok {
			err = errors.New("unable to retrieve file segment")
			return
		}
		if i == length-1 {
			segment = UnPadding(segment)
		}
		content = append(content, segment...)
	}

	return content, err

	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// if err != nil {
	// 	return nil, err
	// }
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	// }
	// err = json.Unmarshal(dataJSON, &content)
	// return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// get the key to invitation
	hashedRepicientName := userlib.Hash([]byte(recipientUsername + "Killua" + filename + "goat"))[:16]
	storageKeyHash, hasherr := userlib.HashKDF(hashedRepicientName, []byte("forInvite!"))
	if hasherr != nil {
		err = errors.New("unable to hash invitation storagekey")
		return
	}
	storageKey, uuiderr := uuid.FromBytes(storageKeyHash[:16])
	if uuiderr != nil {
		err = errors.New("unable to create invitation key UUID")
		return
	}

	// get symmKey
	symkey2, getkeyerr, _ := userdata.getKey(filename)
	if getkeyerr != nil {
		err = getkeyerr
		return
	}

	// get the encrypt public key
	recipientRSAPublicKey, keystoregetok := userlib.KeystoreGet(recipientUsername + "1")
	if !keystoregetok {
		err = errors.New("unable to get invitation recipient's public key from keystore")
		return
	}

	// sign and encrypt symmkey2
	signedEncryptedInvite, encrypterr := encrypt_sign(symkey2, userdata.DSSignkey, recipientRSAPublicKey)
	if encrypterr != nil {
		err = encrypterr
		return
	}

	//put the invitation into DataStore
	userlib.DatastoreSet(storageKey, signedEncryptedInvite)

	return storageKey, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	//put the received key in the auth manager

	//retrieve invitationKey
	signedEncryptedInvite, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("unable to get Invitation from invitationPtr")
	}

	//load & verify & decrypt key
	senderVerifyKey, ok2 := userlib.KeystoreGet(senderUsername + "2")
	if !ok2 {
		return errors.New("unable to get public verify Key")
	}

	invitationKey, decrypterr := verify_decrypt(signedEncryptedInvite[256:], signedEncryptedInvite[0:256], senderVerifyKey, userdata.RSAPrivkey)
	if decrypterr != nil {
		return decrypterr
	}

	//save key
	hashedRepicientName := userlib.Hash([]byte(userdata.Username + "Auth Manager"))[:16]
	authKeyHash, hasherr := userlib.HashKDF(hashedRepicientName, []byte("forSavingKey!"))
	if hasherr != nil {
		return errors.New("unable to hash auth manager storage key")
	}
	authStorageKey, uuiderr := uuid.FromBytes(authKeyHash[:16])
	if uuiderr != nil {
		return errors.New("unable to create auth storage key UUID")
	}

	var invitationMap map[string][]byte
	existedInvitationMapJSON, existed := userlib.DatastoreGet(authStorageKey)
	if existed {
		unmarshalerr := json.Unmarshal(existedInvitationMapJSON, &invitationMap)
		if unmarshalerr != nil {
			return errors.New("unable to Unmarshal existing InvitationMap in auth manager")
		}
	} else {
		invitationMap = make(map[string][]byte)
	}

	invitationMap[filename] = append([]byte("Light Up"), invitationKey...)
	invitationMapJSON, marshalerr := json.Marshal(invitationMap)
	if marshalerr != nil {
		return errors.New("unable to marshal InvitationMap in auth manager")
	}

	userlib.DatastoreSet(authStorageKey, invitationMapJSON)

	//delete the invitation entry
	userlib.DatastoreDelete(invitationPtr)

	//retrieve tree
	treeKey, tree, gettreeerr := getTree(invitationKey)
	if gettreeerr != nil {
		return gettreeerr
	}

	//update tree
	newNode := new(TreeNode)
	newNode.Children = make([]TreeNode, 0)
	newNode.NodeUserName = userdata.Username
	var queue []TreeNode
	queue = append(queue, tree)
	for len(queue) > 0 {
		curNode := queue[0]
		if curNode.NodeUserName == senderUsername {
			curNode.Children = append(curNode.Children, *newNode)
			break
		}
		for _, child := range curNode.Children {
			queue = append(queue, child)
		}
		queue = queue[1:]
	}

	//put tree back
	newTreeJSON, marshalerr3 := json.Marshal(tree)
	if marshalerr3 != nil {
		return errors.New("unable to marshal the tree JSON when putting it back")
	}

	userlib.DatastoreSet(treeKey, newTreeJSON)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// generate new symmkey2
	newSymmkey := userlib.RandomBytes(16)

	// get the original symmkey2
	oldSymmkey2, getkeyerr, isOwner := userdata.getKey(filename)
	if getkeyerr != nil {
		return getkeyerr
	}
	if !isOwner {
		return errors.New("the caller is not the owner of the file")
	}

	// update userdata symmkey2
	userdata.SymEncKey2 = newSymmkey

	// Part I: tree
	// get tree
	treeKey, tree, gettreeerr := getTree(oldSymmkey2)
	if gettreeerr != nil {
		return gettreeerr
	}

	// update all siblings' auth manager in the tree & delete revoked user from the tree
	var queue []TreeNode
	queue = append(queue, tree)
	for len(queue) > 0 {
		curNode := queue[0]
		fmt.Println(curNode.NodeUserName)
		fmt.Println(len(curNode.Children))
		if curNode.NodeUserName != recipientUsername {
			datastoreKey, authKeyMap, getmaperr := getKeyMap(userdata.Username)
			if getmaperr != nil {
				return getmaperr //not sure should exit the program here
			}
			var childUserFilename string
			nodeIsOwner := curNode.NodeUserName == userdata.Username // if the user is the root user
			for k, value := range authKeyMap {
				var valueKey []byte
				if nodeIsOwner {
					valueKey = append([]byte("root"), oldSymmkey2...)
				} else {
					valueKey = append([]byte("Light Up"), oldSymmkey2...)
				}
				fmt.Println("old key =")
				fmt.Println(valueKey)
				if bytes.Equal(value, valueKey) { // import bytes here
					childUserFilename = k
					break
				}
			}
			if nodeIsOwner {
				authKeyMap[childUserFilename] = append([]byte("root"), newSymmkey...)
			} else {
				authKeyMap[childUserFilename] = append([]byte("Light Up"), newSymmkey...)
			}
			fmt.Println("new sym key =")
			fmt.Println(authKeyMap[childUserFilename])

			// put back map
			authKeyMapJSON, marshalerr := json.Marshal(authKeyMap)
			if marshalerr != nil {
				return errors.New("unable to marshal keyMap in auth manager")
			}

			userlib.DatastoreSet(datastoreKey, authKeyMapJSON)

		}

		// find the revoked recipient and delete it, else append to queue
		var to_delete int
		children := curNode.Children
		if len(children) != 0 {
			for i, child := range curNode.Children {
				if child.NodeUserName == recipientUsername {
					to_delete = i
					continue
				}
				queue = append(queue, child)
			}
			if to_delete == len(children)-1 {
				curNode.Children = children[:to_delete]
			} else {
				curNode.Children = append(children[:to_delete], children[(to_delete+1):]...)
			}
		}

		queue = queue[1:]
	}

	// marshal the tree
	newTreeJSON, marshalerr3 := json.Marshal(tree)
	if marshalerr3 != nil {
		return errors.New("unable to marshal the tree JSON when putting it back")
	}

	// delete the original tree
	userlib.DatastoreDelete(treeKey)

	// get new Tree key from the newSymmkey
	// newhashedSymmKey := userlib.Hash(newSymmkey)
	treeKeyHash, hasherr2 := userlib.HashKDF(newSymmkey, []byte("forPlantingTree!"))
	if hasherr2 != nil {
		return errors.New("unable to hash tree manager storage key")
	}
	newTreeKey, uuiderr2 := uuid.FromBytes(treeKeyHash[:16])
	if uuiderr2 != nil {
		return errors.New("unable to create tree storage key UUID")
	}

	// put the new tree back
	userlib.DatastoreSet(newTreeKey, newTreeJSON)

	// Part II: file manager
	// *** generate new file meta uuid
	newfileKeyHash, hasherr3 := userlib.HashKDF(newSymmkey, []byte("length"))
	if hasherr3 != nil {
		return errors.New("unable to hash file manager storage key")
	}
	newFileLengthKey, uuiderr3 := uuid.FromBytes(newfileKeyHash[:16])
	if uuiderr3 != nil {
		return errors.New("unable to create tree storage key UUID")
	}

	// get the old file uuids
	length, oldSegmentKeys, oldFileLengthKey, getfilekeyerr := getfileAccessKeys(oldSymmkey2)
	if getfilekeyerr != nil {
		return getfilekeyerr
	}

	// replace old segment uuids
	for i, oldindexKey := range oldSegmentKeys {
		segment, ok := userlib.DatastoreGet(oldindexKey)
		if !ok {
			return errors.New("unable to retrieve file segment")
		}

		// *** generate new index key
		newindexKeyHash, hasherr4 := userlib.HashKDF(newSymmkey, []byte("indexIs"+strconv.Itoa(i)))
		if hasherr4 != nil {
			return errors.New("unable to hash file manager index key")
		}
		newindexKey, uuiderr4 := uuid.FromBytes(newindexKeyHash[:16])
		if uuiderr4 != nil {
			return errors.New("unable to create file index key UUID")
		}

		userlib.DatastoreSet(newindexKey, segment)
		userlib.DatastoreDelete(oldindexKey)
	}

	// put the file length back with new length uuid
	userlib.DatastoreSet(newFileLengthKey, []byte(strconv.Itoa(length)))
	userlib.DatastoreDelete(oldFileLengthKey)

	return nil
}

// get the lengthkey and segmentkeys(list of keys) from a symkey
func getfileAccessKeys(symkey []byte) (length int, segmentKeys []uuid.UUID, lengthKey userlib.UUID, err error) {
	// hashedSymmKey := userlib.Hash(symkey)
	lengthfileKeyHash, hasherr1 := userlib.HashKDF(symkey, []byte("length"))
	if hasherr1 != nil {
		err = errors.New("unable to hash file manager length key")
		return
	}
	lengthfileKey, uuiderr1 := uuid.FromBytes(lengthfileKeyHash[:16])
	if uuiderr1 != nil {
		err = errors.New("unable to create file length key UUID")
		return
	}

	fmt.Println("length key = ")
	fmt.Println(lengthfileKey)
	fmt.Println(symkey)
	// get length
	lengtharray, ok := userlib.DatastoreGet(lengthfileKey)
	if !ok {
		err = errors.New("unable retrieve the file length")
		return
	}
	length, converterr := strconv.Atoi(string(lengtharray))
	if converterr != nil {
		err = errors.New("unable to convert length string to int")
		return
	}

	// get segment keys
	segmentKeys = make([]uuid.UUID, length)
	for i := 0; i < length; i++ {
		indexKeyHash, hasherr2 := userlib.HashKDF(symkey, []byte("indexIs"+strconv.Itoa(i)))
		if hasherr2 != nil {
			err = errors.New("unable to hash file manager index key")
			return
		}
		indexKey, uuiderr2 := uuid.FromBytes(indexKeyHash[:16])
		if uuiderr2 != nil {
			err = errors.New("unable to create file index key UUID")
			return
		}

		segmentKeys[i] = indexKey
	}

	return length, segmentKeys, lengthfileKey, err
}

// get the symmkey from auth manager.
func (userdata *User) getKey(filename string) (key []byte, err error, isOwner bool) {
	err = nil
	_, keyMap, getmaperr := getKeyMap(userdata.Username)
	if getmaperr != nil {
		err = getmaperr
		return
	}

	retKey := keyMap[filename]
	if retKey == nil {
		err = errors.New("key not existed in Map given filename")
		return
	}

	// check the format of the key
	if len(retKey) == 20 && bytes.Equal(retKey[:4], []byte("root")) { //need to import bytes here
		return retKey[4:], err, true
	} else if len(retKey) == 24 && bytes.Equal(retKey[:8], []byte("Light Up")) {
		return retKey[8:], err, false
	} else {
		err = errors.New("key retrieved from auth manager has incorrect format")
		return
	}
}

// get the keyMap stored in Auth Manager. KeyMap entry: filename -> symmkey
func getKeyMap(username string) (mapKey uuid.UUID, KeyMap map[string][]byte, err error) {
	err = nil
	// generate auth manager key from username
	hashedRepicientName := userlib.Hash([]byte(username + "Auth Manager"))[:16]
	authKeyHash, hasherr := userlib.HashKDF(hashedRepicientName, []byte("forSavingKey!"))
	if hasherr != nil {
		err = errors.New("unable to hash auth manager storage key")
		return
	}
	authStorageKey, uuiderr := uuid.FromBytes(authKeyHash[:16])
	if uuiderr != nil {
		err = errors.New("unable to create auth storage key UUID")
		return
	}

	// get the marshaled keymap from Datastore
	keyMapJSON, ok := userlib.DatastoreGet(authStorageKey)
	if !ok {
		err = errors.New("auth key map not found")
		return
	}

	// unmarshal keymap
	var keyMap map[string][]byte
	marshalerr := json.Unmarshal(keyMapJSON, &keyMap)
	if marshalerr != nil {
		err = errors.New("unable to unmarshal key map in auth manager")
		return
	}

	return authStorageKey, keyMap, err
}

// first verify. then decrypt
func verify_decrypt(cryptext []byte, sig []byte, verifyKey userlib.DSVerifyKey, decryptKey userlib.PKEDecKey) (text []byte, err error) {
	signerr := userlib.DSVerify(verifyKey, cryptext, sig)
	if signerr != nil {
		err = errors.New("unable to verify the invitation's signature")
		return
	}
	plaintext, decrypterr := userlib.PKEDec(decryptKey, cryptext)
	if decrypterr != nil {
		err = errors.New("unable to decrypt the invitation")
		return
	}
	return plaintext, decrypterr
}

// first encrypt. then sign. reverse function of verify_decrypt
func encrypt_sign(plaintext []byte, signKey userlib.DSSignKey, encryptKey userlib.PublicKeyType) (text []byte, err error) {
	encrytedInvite, encrypterr := userlib.PKEEnc(encryptKey, plaintext)
	if encrypterr != nil {
		err = errors.New("unable to encrypt invitation with recipient's public key")
		return
	}

	// sign the symmKey
	signature, signerr := userlib.DSSign(signKey, encrytedInvite)
	if signerr != nil {
		err = errors.New("unable to sign invitation with sender's private key")
		return
	}

	// merge signature and encrypted text
	retText := append(signature, encrytedInvite...)
	return retText, err
}

// get the root node(TreeNode type) from input symmkey
func getTree(symmkey []byte) (treeKey uuid.UUID, tree TreeNode, err error) {
	// hashedSymmKey := userlib.Hash(symmkey)
	treeKeyHash, hasherr2 := userlib.HashKDF(symmkey, []byte("forPlantingTree!"))
	if hasherr2 != nil {
		err = errors.New("unable to hash tree manager storage key")
		return
	}
	treeKey, uuiderr2 := uuid.FromBytes(treeKeyHash[:16])
	if uuiderr2 != nil {
		err = errors.New("unable to create tree storage key UUID")
		return
	}
	treeJSON, oktree := userlib.DatastoreGet(treeKey)
	if !oktree {
		err = errors.New("unable to retrieve tree JSON")
		return
	}
	marshalerr2 := json.Unmarshal(treeJSON, &tree)
	if marshalerr2 != nil {
		err = errors.New("unable to unmarshal tree JSON")
		return
	}
	return treeKey, tree, err
}

func splitAndStore(startindex int, content []byte, symmkey []byte) (length int, err error) {
	fileKeyHash, hasherr3 := userlib.HashKDF(symmkey, []byte("length"))
	if hasherr3 != nil {
		err = errors.New("unable to hash file manager length key")
		return
	}
	fileKey, uuiderr3 := uuid.FromBytes(fileKeyHash[:16])
	if uuiderr3 != nil {
		err = errors.New("unable to create file length key UUID")
		return
	}

	if len(content)%64 == 0 {
		length = len(content) / 64
	} else {
		length = len(content)/64 + 1
	}
	// creating segmentKeys to store the segments of the content
	segmentKeys := make([]uuid.UUID, length)
	for i := 0; i < length; i++ {
		index := i + startindex
		indexKeyHash, hasherr2 := userlib.HashKDF(symmkey, []byte("indexIs"+strconv.Itoa(index)))
		if hasherr2 != nil {
			err = errors.New("unable to hash file manager index key")
			return
		}
		indexKey, uuiderr2 := uuid.FromBytes(indexKeyHash[:16])
		if uuiderr2 != nil {
			err = errors.New("unable to create file index key UUID")
			return
		}

		segmentKeys[i] = indexKey
	}
	//put the content slices into the segmentkey map
	for i, indexKey := range segmentKeys {
		var segment []byte
		if i == length-1 {
			segment = content[i*64:]
			segment = Padding(segment)
		} else {
			segment = content[i*64 : (i+1)*64]
		}
		userlib.DatastoreSet(indexKey, segment)
	}
	userlib.DatastoreSet(fileKey, []byte(strconv.Itoa(length)))

	return length, nil
}
