package level

import (
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

var  KeyYglAddrLevel common.Hash = common.BytesToHash([]byte("ygl_addr_level"))
var  KeyYglChildNum common.Hash = common.BytesToHash([]byte("ygl_addr_child_num"))
var  KeyYglChildPrefix ="ygl_addr_child_prefix_"

func  GetLevelInfo(address common.Address,  state *state.StateDB) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	level := state.GetState(address, KeyYglAddrLevel).Big().Int64()
	num:=state.GetState(address, KeyYglChildNum).Big().Int64()
	data["level"] = level
	data["child_num"] = num
	childs := make([]common.Address,0)
	for i:=0;i<int(num);i++{
		k:=common.BytesToHash([]byte(KeyYglChildPrefix+strconv.Itoa(i)))
		h:=state.GetState(address, k)
		if common.EmptyHash(h){
			continue
		}
		addr:=common.BytesToAddress(h.Bytes())
		childs = append(childs,addr)
	}
	data["childs"] = childs
	return data, state.Error()
}