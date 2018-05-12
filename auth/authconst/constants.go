package authconst

import "github.com/ethereum/go-ethereum/common"

var KeyYglAddrAuth = common.BytesToHash([]byte("ygl_addr_auth"))
var KeyYglAddrParent = common.BytesToHash([]byte("ygl_addr_parent"))
var KeyYglChildNum = common.BytesToHash([]byte("ygl_addr_child_num"))
var KeyYglChildPrefix = "ygl_addr_child_prefix_"
