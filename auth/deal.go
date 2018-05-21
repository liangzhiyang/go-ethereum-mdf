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
	canAccessNum := state.GetState(address, authconst.KeyYglAddrCanAccessNum).Big().Int64()
	data["auth"] = common.Bytes2Hex(auth.Bytes())
	data["auth_desc"] = FromBigInt(auth).String()
	data["can_access_num"] = canAccessNum
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

func AddUser(from, to common.Address, addAuth *Auth, state *state.StateDB, onlyCheck bool) (err error) {
	mylog := log.Error
	if onlyCheck {
		mylog = log.Debug
	}
	if addAuth.BigInt().Sign() == 0 {
		err = fmt.Errorf("auth.AddUser  %v=>%v addAuth=(%v) is invalid;",
			from.Hex(), to.Hex(), addAuth.String())
		mylog("auth.AddUser.param", "err", err)
		return
	}
	parentTo, _ := getParentInfo(state.GetState(to, authconst.KeyYglAddrParent))
	if parentTo.Big().Sign() != 0 && !bytes.Equal(parentTo[:], from[:]) {
		err = fmt.Errorf("auth.AddUser  %v=>%v addAuth=(%v) parentTo=(%v) is not belong to you;",
			from.Hex(), to.Hex(), addAuth.String(), parentTo.Hex())
		mylog("auth.AddUser.belong", "err", err)
		return
	}
	authTo := FromBigInt(state.GetState(to, authconst.KeyYglAddrAuth).Big())
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	if !(authFrom.IsRoot() || authFrom.HasAll(AuthAddUser, addAuth)) {
		err = fmt.Errorf("auth.AddUser  %v(%v)=>%v(%v) is invalid;addAuth=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), authTo.String(), addAuth.String())
		mylog("auth.AddUser", "err", err)
		return
	}
	if onlyCheck {
		return
	}

	if parentTo.Big().Sign() == 0 { //新添加的
		num := state.GetState(from, authconst.KeyYglChildNum).Big().Int64()
		state.SetState(from, authconst.KeyYglChildNum, common.BigToHash(big.NewInt(num+1)))
		k := common.BytesToHash([]byte(authconst.KeyYglChildPrefix + strconv.Itoa(int(num))))
		state.SetState(from, k, common.BytesToHash(to.Bytes()))
		state.SetState(to, authconst.KeyYglAddrParent, genParentInfo(from, num))
	}

	authTo.Add(addAuth)
	state.SetState(to, authconst.KeyYglAddrAuth, common.BigToHash(authTo.BigInt()))

	log.Debug("auth.AddUser success", "from", from.Hex(), "to", to.Hex(),
		"addAuth", addAuth.String(), "authTo", authTo.String(), "err", state.Error())
	return state.Error()
}
func DelUser(from, to common.Address, delAuth *Auth, state *state.StateDB, onlyCheck bool) (err error) {
	mylog := log.Error
	if onlyCheck {
		mylog = log.Debug
	}
	if delAuth.BigInt().Sign() == 0 {
		err = fmt.Errorf("auth.DelUser  %v=>%v delAuth=(%v) is invalid;",
			from.Hex(), to.Hex(), delAuth.String())
		mylog("auth.DelUser.param", "err", err)
		return
	}
	authTo := FromBigInt(state.GetState(to, authconst.KeyYglAddrAuth).Big())
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	if !(authFrom.IsRoot() || authFrom.HasAll(AuthDelUser, delAuth)) {
		err = fmt.Errorf("auth.DelUser  %v(%v)=>%v(%v) is invalid;delAuth=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), authTo.String(), delAuth.String())
		mylog("auth.DelUser", "err", err)
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
		err = DelUser(from, addr, delAuth, state, onlyCheck)
		if err != nil {
			return
		}
	}
	if onlyCheck {
		return
	}
	//将to的auth调整,这个要放到最后
	authTo.Del(delAuth)
	state.SetState(to, authconst.KeyYglAddrAuth, common.BigToHash(authTo.BigInt()))
	if authTo.BigInt().Sign() == 0 { //如果权限为空
		_delParentInfo(to, state)
	}

	log.Debug("auth.DelUser success", "from", from.Hex(), "to", to.Hex(),
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
func OpAccessNum(from, to common.Address, num int64, state *state.StateDB, onlyCheck bool) (err error) {
	mylog := log.Error
	if onlyCheck {
		mylog = log.Debug
	}
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	if !(authFrom.IsRoot() || authFrom.HasAll(AuthOpAccessNum)) {
		err = fmt.Errorf("auth.AddAccessNum  %v(%v)=>%v is invalid;num=(%v)",
			from.Hex(), authFrom.String(), to.Hex(), num)
		mylog("auth.AddAccessNum", "err", err)
		return
	}
	if onlyCheck {
		return
	}
	canAccessNum := state.GetState(to, authconst.KeyYglAddrCanAccessNum).Big().Int64()
	state.SetState(to, authconst.KeyYglAddrCanAccessNum, common.BigToHash(big.NewInt(canAccessNum+num)))
	log.Debug("auth.OpAccessNum success", "from", from.Hex(), "to", to.Hex(),
		"num", num, "err", state.Error(), "key", authconst.KeyYglAddrCanAccessNum.Hex(),
		"val", common.BigToHash(big.NewInt(canAccessNum + num)).Hex())
	return
}

//仅仅做检查（ygl的新增的操作权限和普通权限），不修改数据
func DealAuthCheck(from, to common.Address, input []byte, state *state.StateDB) (err error) {
	err = checkAuth(from, to, input, state)
	if err != nil {
		return err
	}
	return _DealYglAuth(from, to, input, state, true)
}
func checkAuth(from, to common.Address, input []byte, state *state.StateDB) (err error) {
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	//authTo := FromBigInt(state.GetState(to, authconst.KeyYglAddrAuth).Big())
	if authFrom.IsRoot() {
		return
	}
	if to.Big().Sign() == 0 { //创建合约
		if !authFrom.HasAll(AuthCreateContract) {
			err = fmt.Errorf("you have no AuthCreateContract")
			return
		}
	}
	canAccessNum := state.GetState(from, authconst.KeyYglAddrCanAccessNum).Big().Int64()
	if !(authFrom.HasAll(AuthSendTransaction) || canAccessNum > 0) {
		err = fmt.Errorf("you have no AuthSendTransaction")
		return
	}
	return
}

//这里会做检查，并且 修改数据（只操作新增的那部分逻辑）
func DealYglAuth(from, to common.Address, input []byte, state *state.StateDB) (err error) {
	err = _DealYglAuth(from, to, input, state, false)
	if err != nil {
		return
	}
	//处理临时访问次数
	authFrom := FromBigInt(state.GetState(from, authconst.KeyYglAddrAuth).Big())
	canAccessNum := state.GetState(from, authconst.KeyYglAddrCanAccessNum).Big().Int64()
	if !authFrom.HasAll(AuthSendTransaction) && !authFrom.IsRoot() && canAccessNum > 0 {
		state.SetState(from, authconst.KeyYglAddrCanAccessNum, common.BigToHash(big.NewInt(canAccessNum-1)))
	}
	return
}
func _DealYglAuth(from, to common.Address, input []byte, state *state.StateDB, onlyCheck bool) (err error) {
	mylog := log.Error
	if onlyCheck {
		mylog = log.Debug
	}
	if len(input) <= 4 || string(input[0:3]) != "ygl" || int(input[3]) <= 0 { //"ygl1"
		return
	}
	if int(input[3]) != len(input[4:]) || int(input[3]) <= 0 {
		mylog("DealYglAuth.param not eq", "input", common.Bytes2Hex(input))
		return
	}
	input = input[4:4+int(input[3])]
	yglOP := int(input[0])
	switch yglOP {
	case authconst.OpAddUser:
		auth := FromBigInt(new(big.Int).SetBytes(input[1:]))
		err = AddUser(from, to, auth, state, onlyCheck)
	case authconst.OpDelUser:
		auth := FromBigInt(new(big.Int).SetBytes(input[1:]))
		err = DelUser(from, to, auth, state, onlyCheck)
	case authconst.OpAddAccessNum:
		addr := common.BytesToAddress(input[1:21])
		num := new(big.Int).SetBytes(input[21:]).Int64()
		err = OpAccessNum(from, addr, num, state, onlyCheck)
	case authconst.OpSubAccessNum:
		addr := common.BytesToAddress(input[1:21])
		num := new(big.Int).SetBytes(input[21:]).Int64()
		err = OpAccessNum(from, addr, -num, state, onlyCheck)
	default:
		err = fmt.Errorf("ygl_op=%v unknown", yglOP)
	}

	return
}
func SplitInput(input []byte) (yglInput, srcInput []byte, err error) {
	if len(input) <= 4 || string(input[0:3]) != "ygl" || int(input[3]) <= 0 {
		return nil, input, nil
	}
	tmpLen := int(input[3])
	if len(input) < 4+tmpLen {
		err = fmt.Errorf("input len is not ok")
		return
	}
	yglInput = input[0:4+tmpLen]
	srcInput = input[4+tmpLen:]
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
