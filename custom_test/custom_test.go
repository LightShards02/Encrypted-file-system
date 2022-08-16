package client_test

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

	userlib "github.com/cs161-staff/project2-userlib"
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
}

func TestInitFail(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("alice", "fubar222")
	if err == nil {
		// t.Error says the test fails
		t.Error("Didn't fail to initilize same username user", err)
		return
	}

	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestGetUser(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	u_temp, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	if u.Username != u_temp.Username {
		t.Error("Different username", err)
		return
	}
}

func TestMultipleSessions(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	u_1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	u_2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	v := []byte("This is a test")
	u_1.StoreFile("file1", v)

	v1, err := u_1.LoadFile("file1")
	v2, err := u_2.LoadFile("file1")

	if !reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is not the same", v1, v2)
		return
	}

	u_2.AppendFile("file1", v)

	v3, err := u_1.LoadFile("file1")
	v4, err := u_2.LoadFile("file1")

	if !reflect.DeepEqual(v3, v4) {
		t.Error("Downloaded file is not the same", v3, v4)
		return
	}

	jeff, err := InitUser("jeffrey", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	jeff.StoreFile("file2", v)

	accessToken, err := jeff.ShareFile("file2", "alice")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	u_2.ReceiveFile("file3", "jeffrey", accessToken)

	v5, err := u_1.LoadFile("file3")
	v6, err := u_2.LoadFile("file3")

	if !reflect.DeepEqual(v5, v6) {
		t.Error("Downloaded file is not the same", v5, v6)
		return
	}
}

func TestLoadFail(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err = u.LoadFile("file does not exist")
	if err == nil {
		t.Error("Loaded a file that doesn't exist")
		return
	}

}

func TestAppedFail(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	err = u.AppendFile("file does not exist", v)

	if err == nil {
		t.Error("Appended to a file that doesn't exist")
		return
	}

}

func TestShareRevokeFail(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("joanna", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err = u.ShareFile("file doesn't exist", "joanna")
	if err == nil {
		t.Error("Shared a file that doesn't exist")
		return
	}

	_, err = u.ShareFile("file1", "jeffrey")
	if err == nil {
		t.Error("Shared to a recipient that doesn't exist")
		return
	}

	err = u.RevokeFile("file1", "joanna")
	if err == nil {
		t.Error("Revoked before even shared")
		return
	}

	accessToken, _ := u.ShareFile("file1", "joanna")

	u2.ReceiveFile("file1", "alice", accessToken)

	err = u.RevokeFile("file100", "joanna")
	if err == nil {
		t.Error("Revoked a file that doesn't exist")
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
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestStorageAdvance(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	u2, err := InitUser("joanna", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	accessToken, _ := u.ShareFile("file1", "joanna")

	u2.ReceiveFile("file1", "alice", accessToken)

	v2 := []byte("kfajewoifjlskadafsdfasdfa")
	u.StoreFile("file1", v2)

	v3, err := u2.LoadFile("file1")
	if err != nil {
		t.Error("Shared users failed to load after owner stored again")
	}

	v4, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Shared users failed to load after owner stored again")
	}

	if !reflect.DeepEqual(v2, v3) {
		t.Error("Downloaded file is not the same", string(v2), string(v3))
		return
	}

	if !reflect.DeepEqual(v2, v4) {
		t.Error("Downloaded file is not the same", string(v2), string(v4))
		return
	}

	v4 = []byte("3333333333333333")
	u2.StoreFile("file1", v4)
	u2.AppendFile("file1", v4)

	v100, err := u.LoadFile("file1")

	if !reflect.DeepEqual(v100, []byte("33333333333333333333333333333333")) {
		t.Error("Downloaded file is not the same", string(v100), string(v4))
		return
	}

}

func TestRevokeAdvance(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	u2, _ := InitUser("jeffrey", "fubar")

	u3, _ := InitUser("joanna", "fubar")

	token1, err := u.ShareFile("file1", "jeffrey")
	if err != nil {
		t.Error("Filed to share")
		return
	}

	token2, err := u.ShareFile("file1", "joanna")
	if err != nil {
		t.Error("Filed to share")
		return
	}

	u2.ReceiveFile("file1", "alice", token1)
	u3.ReceiveFile("file1", "alice", token2)

	err = u.RevokeFile("file1", "jeffrey")
	if err != nil {
		t.Error("Failed to revoke", err)
		return
	}

	err = u.AppendFile("file1", v)
	if err != nil {
		t.Error("Failed to append post revoking", err)
		return
	}
}

func TestAppend1(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	//userlib.DebugMsg("halo")

	err100 := u.AppendFile("file1", v)
	u.AppendFile("file1", v)
	u.AppendFile("file1", v)
	u.AppendFile("file1", v)
	u.AppendFile("file1", v)

	//userlib.DebugMsg("halo")
	if err100 != nil {
		t.Error("erorrrrrrrrrrrrr", err100)
		return
	}
	//userlib.DebugMsg("halo")

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	//userlib.DebugMsg("halo")
	if !reflect.DeepEqual([]byte("This is a testThis is a testThis is a testThis is a testThis is a testThis is a test"), v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestAppend2(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

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

	u3, err3 := InitUser("joanna", "pigpigpig")
	if err3 != nil {
		t.Error("Failed to initialize joanna", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	accessToken1, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	u.AppendFile("file1", v)

	err = u2.ReceiveFile("file2", "alice", accessToken1)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	accessToken2, err := u.ShareFile("file1", "joanna")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file1", "alice", accessToken2)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, _ := u2.LoadFile("file2")

	v3, _ := u3.LoadFile("file1")

	v_ori, _ := u.LoadFile("file1")

	if !reflect.DeepEqual(v_ori, v2) {
		t.Error("Downloaded file is not the same", v_ori, v2)
		return
	}

	if !reflect.DeepEqual(v2, v3) {
		t.Error("Downloaded file is not the same", v2, v3)
		return
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

func TestShare(t *testing.T) {
	userlib.SetDebugStatus(true)
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

func TestReceive(t *testing.T) {
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
	u2.StoreFile("file1", v)

	token, err := u.ShareFile("file1", "bob")

	err = u2.ReceiveFile("file1", "alice", token)
	if err == nil {
		t.Error("received a file with an existing filename")
		return
	}

	u.RevokeFile("file1", "bob")

	err = u2.ReceiveFile("file2", "alice", token)
	if err == nil {
		t.Error("received a file after it is revoked")
		return
	}

}

func TestBasicRevoke(t *testing.T) {
	userlib.SetDebugStatus(true)
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

	u3, err3 := InitUser("joanna", "pigpigpig")
	if err3 != nil {
		t.Error("Failed to initialize joanna", err)
		return
	}

	u4, err4 := InitUser("jeffrey", "fan")
	if err4 != nil {
		t.Error("Failed to initialize jeffrey", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	//var v2 []byte
	var accessToken1 uuid.UUID

	accessToken1, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", accessToken1)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	accessToken11, err := u.ShareFile("file1", "jeffrey")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u4.ReceiveFile("file1", "alice", accessToken11)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	accessToken2, err := u2.ShareFile("file2", "joanna")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file2", "bob", accessToken2)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke", err)
		return
	}

	v, err99 := u2.LoadFile("file2")
	if err99 == nil {
		t.Error("failed revoke", err)
		return
	}

	err = u2.AppendFile("file2", v)
	if err99 == nil {
		t.Error("can still append after being revoked", err)
		return
	}

	// err = u2.StoreFile("file2", v)
	// if err99 == nil {
	// 	t.Error("can still share file after being revoked", err)
	// 	return
	// }

	// userlib.DebugMsg("empty file:%v", v)

	v, err100 := u3.LoadFile("file2")
	if err100 == nil {
		t.Error("failed revoke", err)
		return
	}

	v, err1000 := u4.LoadFile("file1")
	if err1000 != nil {
		t.Error("failed access but should not", err)
		return
	}

	// userlib.DebugMsg("empty file:%v", string(v))
}
