package auth

import (
	"math/big"
	"strings"
)

var bigOne = big.NewInt(1)
var (
	AuthRoot            = initAuth(0, "root")
	AuthAddUser         = initAuth(1, "add_user")
	AuthDelUser         = initAuth(2, "del_user")
	AuthCreateContract  = initAuth(3, "create_contract")
	AuthSendTransaction = initAuth(4, "send_transaction")
)
var _desc map[*Auth]string
//并非并发安全
func initAuth(off uint, desc string) (*Auth) {
	if _desc == nil {
		_desc = make(map[*Auth]string)
	}
	a := new(big.Int).Lsh(bigOne, off)
	_desc[FromBigInt(a)] = desc
	return FromBigInt(a)
}

type Auth big.Int

func FromBigInt(v *big.Int) *Auth {
	return (*Auth)(v)
}
func (a *Auth) BigInt() *big.Int {
	return (*big.Int)(a)
}
func (a *Auth) Add(auths ...*Auth) {
	for _, tmp := range auths {
		a.BigInt().Or(a.BigInt(), tmp.BigInt())
	}
}
func (a *Auth) Del(auths ...*Auth) {
	for _, tmp := range auths {
		a.BigInt().AndNot(a.BigInt(), tmp.BigInt())
	}
}
func (a *Auth) Set(auths ...*Auth) {
	a.BigInt().SetInt64(0)
	a.Add(auths...)
}

//所有权限都有 才返回true
func (a *Auth) HasAll(auths ...*Auth) (bool) {
	for _, tmp := range auths {
		r := new(big.Int).And(a.BigInt(), tmp.BigInt())
		if r.Cmp(tmp.BigInt()) != 0 {
			return false
		}
	}
	return true
}

//只要其中一个权限有 就返回true
func (a *Auth) HasOne(auths ...*Auth) (bool) {
	for _, tmp := range auths {
		r := new(big.Int).And(a.BigInt(), tmp.BigInt())
		if r.Cmp(tmp.BigInt()) == 0 {
			return true
		}
	}
	return false
}
func (a *Auth) IsRoot() (bool) {
	return a.HasAll(AuthRoot)
}

func (a *Auth) String() string {
	data := make([]string, 0)
	for k, v := range _desc {
		if a.HasAll(k) {
			data = append(data, v)
		}
	}
	return strings.Join(data, ",")
}
