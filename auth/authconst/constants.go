package authconst

import "github.com/ethereum/go-ethereum/common"

var KeyYglAddrAuth common.Hash= common.BytesToHash([]byte("ygl_addr_auth"))                   //账户的权限
var KeyYglAddrCanAccessNum common.Hash= common.BytesToHash([]byte("ygl_addr_can_access_num")) //账户的临时访问次数
var KeyYglAddrParent common.Hash= common.BytesToHash([]byte("ygl_addr_parent"))               //账户的父节点
var KeyYglChildNum common.Hash= common.BytesToHash([]byte("ygl_addr_child_num"))              //账户的孩子总计（包括被删掉的）
var KeyYglChildPrefix = "ygl_addr_child_prefix_"                                   //账户的孩子账户的key前缀

const OpAddUser = 0x1      //添加用户
const OpDelUser = 0x2      //删除用户
const OpAddAccessNum = 0x3 //添加用户临时访问次数
const OpSubAccessNum = 0x4 //减少用户临时访问次数



