package app

import (
	"reflect"
	"testing"
)

func TestValidRolePermissions(t *testing.T) {
	got, ok := validRolePermissions([]string{"compute.view", "account.view", "compute.view"})
	want := []string{"account.view", "compute.view"}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("validRolePermissions() = %#v, %v; want %#v, true", got, ok, want)
	}
	if _, ok = validRolePermissions([]string{"account.view", "root.all"}); ok {
		t.Fatal("unknown capability was accepted")
	}
	if _, ok = validRolePermissions(nil); ok {
		t.Fatal("empty policy was accepted")
	}
}

func TestSameStrings(t *testing.T) {
	if !sameStrings([]string{"account.view", "compute.view"}, []string{"compute.view", "account.view"}) {
		t.Fatal("equivalent permission sets did not match")
	}
	if sameStrings([]string{"account.view"}, []string{"compute.view"}) {
		t.Fatal("different permission sets matched")
	}
}
