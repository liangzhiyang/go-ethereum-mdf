package level

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
)

var KeyYglAddrLevel = common.BytesToHash([]byte("ygl_addr_level"))
var KeyYglAddrParent = common.BytesToHash([]byte("ygl_addr_parent"))
var KeyYglChildNum = common.BytesToHash([]byte("ygl_addr_child_num"))
var KeyYglChildPrefix = "ygl_addr_child_prefix_"

const maxAllowAddLevel = 10000 //超过这个级别的就不允许添加新用户了
func GetLevelInfo(address common.Address, state *state.StateDB) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	level := state.GetState(address, KeyYglAddrLevel).Big().Int64()
	num := state.GetState(address, KeyYglChildNum).Big().Int64()
	data["level"] = level
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

func Add(from, to common.Address, levelIncr int64, state *state.StateDB) (err error) {
	if levelIncr <= 0 {
		err = fmt.Errorf("level.add levelIncr=%v is invalid", levelIncr)
		log.Warn("level.add", "err", err)
		return
	}
	levelTo := state.GetState(to, KeyYglAddrLevel).Big().Int64()
	if levelTo > 0 {
		err = fmt.Errorf("level.add to address=%v is already exist", to.Hex())
		log.Warn("level.add", "err", err)
		return
	}
	levelFrom := state.GetState(from, KeyYglAddrLevel).Big().Int64()
	if levelFrom <= 0 || levelFrom > maxAllowAddLevel {
		err = fmt.Errorf("level.add  %v(%v)=>%v(%v) is invalid", from.Hex(), levelFrom, to.Hex(), levelTo)
		log.Warn("level.add", "err", err)
		return
	}
	num := state.GetState(from, KeyYglChildNum).Big().Int64()
	state.SetState(from, KeyYglChildNum, common.BigToHash(big.NewInt(num+1)))
	//err ???
	k := common.BytesToHash([]byte(KeyYglChildPrefix + strconv.Itoa(int(num))))
	state.SetState(from, k, common.BytesToHash(to.Bytes()))

	state.SetState(to, KeyYglAddrLevel, common.BigToHash(big.NewInt(levelFrom+levelIncr)))
	state.SetState(to, KeyYglAddrParent, genParentInfo(to, num))
	log.Debug("level.add susscee", "from", from.Hex(), "to", to.Hex(), "levelIncr", levelIncr,"err",state.Error())
	return state.Error()
}
func Del(from, to common.Address, state *state.StateDB) (err error) {
	levelTo := state.GetState(to, KeyYglAddrLevel).Big().Int64()
	if levelTo <= 0 {
		log.Warn("level.del to is not exist", "addr", to.Hex())
		return
	}
	levelFrom := state.GetState(from, KeyYglAddrLevel).Big().Int64()
	if levelFrom <= 0 || levelFrom >= levelTo || levelFrom > maxAllowAddLevel {
		err = fmt.Errorf("level.del  %v(%v)=>%v(%v) is invalid", from.Hex(), levelFrom, to.Hex(), levelTo)
		log.Warn("level.del", "err", err)
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
		err = Del(to, addr, state)
		if err != nil {
			return
		}
	}
	//将to的level置为0,这个要放到最后
	state.SetState(to, KeyYglAddrLevel, common.BigToHash(big.NewInt(0)))
	parent, pos := getParentInfo(state.GetState(to, KeyYglAddrParent))
	k := common.BytesToHash([]byte(KeyYglChildPrefix + strconv.Itoa(int(pos))))
	state.SetState(parent, k, common.Hash{})
	state.SetState(to, KeyYglAddrParent, common.Hash{})
	log.Debug("level.del susscee", "from", from.Hex(), "to", to.Hex(),"err",state.Error())
	return state.Error()
}

const keyInputAdd = "ygl_level_add"
const keyInputDel = "ygl_level_del"

func DealLevel(from, to common.Address, input []byte, state *state.StateDB) (err error) {
	lenKey := len(keyInputAdd)
	if len(input) < lenKey {
		return
	}
	switch string(input[0:lenKey]) {
	case keyInputAdd:
		num := new(big.Int).SetBytes(input[lenKey:]).Int64()
		return Add(from, to, num, state)
	case keyInputDel:
		return Del(from, to, state)
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
