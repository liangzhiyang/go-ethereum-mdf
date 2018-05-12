package auth

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
)

var KeyYglAddrLevel = common.BytesToHash([]byte("ygl_addr_auth"))
var KeyYglAddrParent = common.BytesToHash([]byte("ygl_addr_parent"))
var KeyYglChildNum = common.BytesToHash([]byte("ygl_addr_child_num"))
var KeyYglChildPrefix = "ygl_addr_child_prefix_"

func GetAuthInfo(address common.Address, state *state.StateDB) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	auth := state.GetState(address, KeyYglAddrLevel).Big()
	num := state.GetState(address, KeyYglChildNum).Big().Int64()
	data["auth"] = common.Bytes2Hex(auth.Bytes())
	data["auth_desc"] = FromBigInt(auth).String()
	data["child_num"] = num
	data["parent_addr"], data["parent_pos"] = getParentInfo(state.GetState(address, KeyYglAddrParent))
	childs := make([]common.Address, 0)
	for i := 0; i < int(num); i++ {
		k := common.BytesToHash([]byte(KeyYglChildPrefix + strconv.Itoa(i)))
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
	authTo := FromBigInt(state.GetState(to, KeyYglAddrLevel).Big())
	authFrom := FromBigInt(state.GetState(from, KeyYglAddrLevel).Big())
	if !(authFrom.HasOne(AuthRoot, AuthAddUser) && authFrom.HasAll(addAuth)) {
		err = fmt.Errorf("auth.add  %v(%v)=>%v(%v) is invalid;addAuth=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), authTo.String(),addAuth.String())
		log.Warn("auth.add", "err", err)
		return
	}
	num := state.GetState(from, KeyYglChildNum).Big().Int64()
	state.SetState(from, KeyYglChildNum, common.BigToHash(big.NewInt(num+1)))
	//err ???
	k := common.BytesToHash([]byte(KeyYglChildPrefix + strconv.Itoa(int(num))))
	state.SetState(from, k, common.BytesToHash(to.Bytes()))

	authTo.Add(addAuth)
	state.SetState(to, KeyYglAddrLevel, common.BigToHash(authTo.BigInt()))
	state.SetState(to, KeyYglAddrParent, genParentInfo(to, num))
	log.Debug("auth.add susscee", "from", from.Hex(), "to", to.Hex(), "addAuth", addAuth.String(), "err", state.Error())
	return state.Error()
}
func Del(from, to common.Address, delAuth *Auth, state *state.StateDB) (err error) {
	authTo := FromBigInt(state.GetState(to, KeyYglAddrLevel).Big())
	authFrom := FromBigInt(state.GetState(from, KeyYglAddrLevel).Big())
	if !(authFrom.HasOne(AuthRoot, AuthDelUser) && authFrom.HasAll(delAuth)) {
		err = fmt.Errorf("auth.del  %v(%v)=>%v(%v) is invalid;delAuth=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), authTo.String(),delAuth.String())
		log.Warn("auth.del", "err", err)
		return
	}
	//循环处理所有的child
	numTo := state.GetState(to, KeyYglChildNum).Big().Int64()
	for i := 0; i < int(numTo); i++ {
		k := common.BytesToHash([]byte(KeyYglChildPrefix + strconv.Itoa(i)))
		h := state.GetState(to, k)
		if common.EmptyHash(h) {
			continue
		}
		addr := common.BytesToAddress(h.Bytes())
		err = Del(to, addr,delAuth, state)
		if err != nil {
			return
		}
	}
	//将to的auth调整,这个要放到最后
	authTo.Del(delAuth)
	state.SetState(to, KeyYglAddrLevel, common.BigToHash(authTo.BigInt()))
	if authTo.BigInt().Sign()==0{ //如果权限为空
		parent, pos := getParentInfo(state.GetState(to, KeyYglAddrParent))
		k := common.BytesToHash([]byte(KeyYglChildPrefix + strconv.Itoa(int(pos))))
		state.SetState(parent, k, common.Hash{})
		state.SetState(to, KeyYglAddrParent, common.Hash{})
	}

	log.Debug("auth.del susscee", "from", from.Hex(), "to", to.Hex(), "err", state.Error())
	return state.Error()
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
