package hashpass

import (
	"fmt"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	mypass := Key("my password")

	ret := Check("my password", mypass)
	if !ret {
		t.Error(fmt.Errorf("Check failed."))
	}

	ret = Check("bad password", mypass)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}

	params := strings.Split(mypass, "$")
	params[0] = "sha224"
	alter := strings.Join(params, "$")
	ret = Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}

	params = strings.Split(mypass, "$")
	params[1] = "9999"
	alter = strings.Join(params, "$")
	ret = Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}

	params = strings.Split(mypass, "$")
	params[2] = encode([]byte("bad salt"))
	alter = strings.Join(params, "$")
	ret = Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}

	params = strings.Split(mypass, "$")
	params[3] = encode([]byte("bad key"))
	alter = strings.Join(params, "$")
	ret = Check("my password", alter)
	if ret {
		t.Error(fmt.Errorf("Check failed."))
	}
}
