package auth

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/auth/authconst"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
)

func IsEmptyAuth(address common.Address, state *state.StateDB) bool {
	h := state.GetState(address, authconst.KeyYglAddrAuth)
	return common.EmptyHash(h)
}
func GetAuthInfo(address common.Address, state *state.StateDB) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	auth := state.GetState(address, authconst.KeyYglAddrAuth).Big()
	num := state.GetState(address, authconst.KeyYglChildNum).Big().Int64()
	data["auth"] = common.Bytes2Hex(auth.Bytes())
	data["auth_desc"] = FromBigInt(auth).String()
	data["child_num"] = num
	data["parent_addr"], data["parent_pos"] = getParentInfo(state.GetState(address, authconst.KeyYglAddrParent))
	childs := make([]common.Address, 0)
	for i := 0; i < int(num); i++ {
		k := common.BytesToHash([]byte(authconst.KeyYglChildPrefix + strconv.Itoa(i)))
		h := state.GetState(address, k)
		if common.EmptyHash(h) {
			continue
		}
		addr := common.BytesToAddress(h.Bytes())
		childs = append(childs, addr)
	}
	data["childs"] = childs
	return data, state.Error()
}

func Add(from, to common.Address, addAuth *Auth, state *state.StateDB) (err error) {
	if addAuth.BigInt().Sign() == 0 {
		err = fmt.Errorf("auth.add  %v=>%v addAuth=(%v) is invalid;",
			from.Hex(), to.Hex(), addAuth.String())
		log.Warn("auth.add.param", "err", err)
		return
	}
	parentTo, _ := getParentInfo(state.GetState(to, authconst.KeyYglAddrParent))
	if parentTo.Big().Sign() != 0 && !bytes.Equal(parentTo[:], from[:]) {
		err = fmt.Errorf("auth.add  %v=>%v addAuth=(%v) parentTo=(%v) is not belong to you;",
			from.Hex(), to.Hex(), addAuth.String(), parentTo.Hex())
		log.Warn("auth.add.belong", "err", err)
		return
	}
	authTo := FromBigInt(state.GetState(to, authconst.KeyYglAddrAuth).Big())
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	if !(authFrom.IsRoot() || authFrom.HasAll(AuthAddUser, addAuth)) {
		err = fmt.Errorf("auth.add  %v(%v)=>%v(%v) is invalid;addAuth=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), authTo.String(), addAuth.String())
		log.Warn("auth.add", "err", err)
		return
	}
	if parentTo.Big().Sign() == 0 { //新添加的
		num := state.GetState(from, authconst.KeyYglChildNum).Big().Int64()
		state.SetState(from, authconst.KeyYglChildNum, common.BigToHash(big.NewInt(num+1)))
		k := common.BytesToHash([]byte(authconst.KeyYglChildPrefix + strconv.Itoa(int(num))))
		state.SetState(from, k, common.BytesToHash(to.Bytes()))
		state.SetState(to, authconst.KeyYglAddrParent, genParentInfo(to, num))
	}

	authTo.Add(addAuth)
	state.SetState(to, authconst.KeyYglAddrAuth, common.BigToHash(authTo.BigInt()))

	log.Debug("auth.add success", "from", from.Hex(), "to", to.Hex(),
		"addAuth", addAuth.String(), "authTo", authTo.String(), "err", state.Error())
	return state.Error()
}
func Del(from, to common.Address, delAuth *Auth, state *state.StateDB) (err error) {
	if delAuth.BigInt().Sign() == 0 {
		err = fmt.Errorf("auth.del  %v=>%v delAuth=(%v) is invalid;",
			from.Hex(), to.Hex(), delAuth.String())
		log.Warn("auth.del.param", "err", err)
		return
	}
	authTo := FromBigInt(state.GetState(to, authconst.KeyYglAddrAuth).Big())
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	if !(authFrom.IsRoot() || authFrom.HasAll(AuthDelUser, delAuth)) {
		err = fmt.Errorf("auth.del  %v(%v)=>%v(%v) is invalid;delAuth=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), authTo.String(), delAuth.String())
		log.Warn("auth.del", "err", err)
		return
	}
	//循环处理所有的child
	numTo := state.GetState(to, authconst.KeyYglChildNum).Big().Int64()
	for i := 0; i < int(numTo); i++ {
		k := common.BytesToHash([]byte(authconst.KeyYglChildPrefix + strconv.Itoa(i)))
		h := state.GetState(to, k)
		if common.EmptyHash(h) {
			continue
		}
		addr := common.BytesToAddress(h.Bytes())
		err = Del(from, addr, delAuth, state)
		if err != nil {
			return
		}
	}
	//将to的auth调整,这个要放到最后
	authTo.Del(delAuth)
	state.SetState(to, authconst.KeyYglAddrAuth, common.BigToHash(authTo.BigInt()))
	if authTo.BigInt().Sign() == 0 { //如果权限为空
		_delParentInfo(to, state)
	}

	log.Debug("auth.del success", "from", from.Hex(), "to", to.Hex(),
		"authTo", authTo.String(), "err", state.Error())
	return state.Error()
}
func _delParentInfo(addr common.Address, state *state.StateDB) {
	h := state.GetState(addr, authconst.KeyYglAddrParent)
	if common.EmptyHash(h) {
		return
	}
	parent, pos := getParentInfo(h)
	k := common.BytesToHash([]byte(authconst.KeyYglChildPrefix + strconv.Itoa(int(pos))))
	state.SetState(parent, k, common.Hash{})
	state.SetState(addr, authconst.KeyYglAddrParent, common.Hash{})
	return
}

const keyInputAdd = "ygl_auth_add"
const keyInputDel = "ygl_auth_del"

func DealAuth(from, to common.Address, input []byte, state *state.StateDB) (err error) {
	lenKey := len(keyInputAdd)
	if len(input) < lenKey {
		return
	}
	switch string(input[0:lenKey]) {
	case keyInputAdd:
		auth := FromBigInt(new(big.Int).SetBytes(input[lenKey:]))
		return Add(from, to, auth, state)
	case keyInputDel:
		auth := FromBigInt(new(big.Int).SetBytes(input[lenKey:]))
		return Del(from, to, auth, state)
	}
	return
}

func genParentInfo(parent common.Address, pos int64) (h common.Hash) {
	p := big.NewInt(pos).Bytes()
	copy(h[0:20], parent[:])
	copy(h[len(h)-len(p):], p)
	return
}
func getParentInfo(h common.Hash) (parent common.Address, pos int64) {
	parent = common.BytesToAddress(h[0:20])
	pos = new(big.Int).SetBytes(h[20:]).Int64()
	return
}
