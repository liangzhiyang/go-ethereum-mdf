package auth

import (
	"fmt"
	"math/big"
	"testing"
)

func TestAuth(t *testing.T) {
	a := new(Auth)
	a.Set(AuthRoot, AuthAddUser,AuthDelUser)
	fmt.Println(a)
	fmt.Println(a.HasOne(AuthRoot,AuthCreateContract))
	fmt.Println(a.HasAll(AuthRoot,AuthAddUser))


	fmt.Println(a.HasAll(AuthRoot,AuthCreateContract))
	fmt.Println(a.HasOne(AuthCreateContract,AuthDelUser))

	a.Add(AuthCreateContract)
	fmt.Println(a.HasAll(AuthRoot,AuthCreateContract))
	fmt.Println(a.HasOne(AuthCreateContract,AuthDelUser))

	a.Del(AuthRoot)
	fmt.Println(a.HasAll(AuthRoot,AuthCreateContract))
	fmt.Println(a.HasOne(AuthCreateContract,AuthDelUser))

	b:= FromBigInt(new(big.Int))
	b.Set(AuthAddUser,AuthDelUser)

	fmt.Println(a.HasAll(b))
	fmt.Println(a.HasOne(b))

	fmt.Println(a,b)
	a.Del(b)
	fmt.Println(a,b)
}
