package hashpass

import (
	"fmt"
	"strings"
	"testing"
)

func TestKeyCheckWithCorrectPassword(t *testing.T) {
	mypass := Key("my password")
	ret := Check("my password", mypass)
	if !ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}

func TestKeyCheckWithWrongPassword(t *testing.T) {
	mypass := Key("my password")
	ret := Check("bad password", mypass)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}

func TestKeyReturnsRandomly(t *testing.T) {
	mypass := Key("my password")
	mypass2 := Key("my password")
	if mypass == mypass2 {
		t.Error(fmt.Errorf("Key returns wrong value."))
	}
}

func TestKeyManuplatingName(t *testing.T) {
	mypass := Key("my password")
	params := strings.Split(mypass, "$")
	params[0] = "sha224"
	alter := strings.Join(params, "$")
	ret := Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}

func TestKeyManuplatingStretch(t *testing.T) {
	mypass := Key("my password")
	params := strings.Split(mypass, "$")
	params[1] = "9999"
	alter := strings.Join(params, "$")
	ret := Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}

func TestKeyManuplatingSalt(t *testing.T) {
	mypass := Key("my password")
	params := strings.Split(mypass, "$")
	params[2] = encode([]byte("bad salt"))
	alter := strings.Join(params, "$")
	ret := Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}

func TestKeyManuplatingKey(t *testing.T) {
	mypass := Key("my password")
	params := strings.Split(mypass, "$")
	params[3] = encode([]byte("bad key"))
	alter := strings.Join(params, "$")
	ret := Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}

func BenchmarkKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Key("my password")
	}
}
