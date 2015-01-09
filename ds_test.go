package ldap

import (
	"fmt"
	"testing"
)

func TestConnectApacheDS(t *testing.T) {
	l, err := Dial("tcp", "192.168.1.141:10389")
	if err != nil {
		t.Error(err)
		return
	}
	defer l.Close()

	err = l.Bind("uid=admin,ou=system", "secret")
	if err != nil {
		t.Error(err)
		return
	}

	search_request := NewSearchRequest(
		"",
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		"(ou=system)",
		attributes,
		nil)
	sr, err := l.SearchWithPaging(search_request, 5)
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Printf("TestSearchWithPaging: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}
