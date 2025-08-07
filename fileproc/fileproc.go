package fileproc

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ds_ana/dict"
	"ds_ana/global"
	"ds_ana/logger"
	"ds_ana/telnetcmd"

	"github.com/xuri/excelize/v2"
)

type StLogStat struct {
	AllCnt     int64
	ValidCnt   int64
	NullCnt    int64
	InvalidCnt int64
}

type StFileStat struct {
	FileNum    int64
	FileErrNum int64
	LogNum     StLogStat
}

type StDictStat struct {
	Name string
	Cnt  int
}

type SampleC0Info struct {
	Data        []dict.DataCode
	MatchNum    int
	Application int
	Business    int
	CrossBoard  int
	FileType    int
	FileSize    string
}

type SampleC1Info struct {
	Event    dict.RiskCode
	L7Proto  int
	FileType int
	FileSize string
	DataNum  int
}

type SampleC4Info struct {
	Keyword  string
	FileType int
	FileSize string
}

type SampleMapValue struct {
	C0Info []SampleC0Info
	C1Info []SampleC1Info
	C4Info []SampleC4Info
}

type CheckInfo struct {
	Reason   string
	Filenmae string
}

type LogIdInfo struct {
	Cnt    [global.IndexMax]int
	IdFlag int
}

var (
	Md5Map        [global.IndexMax]sync.Map   //MD5表，比对话单和取证文件是否对应
	LogidMap      sync.Map                    //logid是否重复判断
	AppProtoStat  sync.Map                    //统计应用层协议情况
	BusProtoStat  sync.Map                    //统计业务层协议情况
	FileTypeStat  sync.Map                    //文件类型，文件后缀类型
	DataProtoStat sync.Map                    //数据识别协议类型
	FileStat      [global.IndexMax]StFileStat //统计各类话单上报情况

	LogCheckMap    [global.IndexMax]map[string]CheckInfo //话单校验map表
	SampleMap      sync.Map
	SampleMapMutex sync.Mutex
)

func incFileCnt(index int) {
	atomic.AddInt64(&FileStat[index].FileNum, 1)
}

func incFileErrCnt(index int) {
	atomic.AddInt64(&FileStat[index].FileErrNum, 1)
}

func incLogAllCnt(index int) {
	atomic.AddInt64(&FileStat[index].LogNum.AllCnt, 1)
}

func incLogValidCnt(index int) {
	atomic.AddInt64(&FileStat[index].LogNum.ValidCnt, 1)
}

func incLogNullCnt(index int) {
	atomic.AddInt64(&FileStat[index].LogNum.NullCnt, 1)
}

func incLogInvalidCnt(index int) {
	atomic.AddInt64(&FileStat[index].LogNum.InvalidCnt, 1)
}

func LogidMapStoreInc(m *sync.Map, id string, index int) {
	//LogIdInfo
	value, ok := m.Load(id)
	if ok {
		v := value.(*LogIdInfo)
		v.Cnt[index]++
		v.IdFlag |= 1 << index
	} else {
		l := &LogIdInfo{
			IdFlag: 1 << index,
		}
		l.Cnt[index] = 1
		m.Store(id, l)
	}
}

func SampleMapUpdateC0(m *sync.Map, mu *sync.Mutex, md5 string, info SampleC0Info) {
	mu.Lock()
	defer mu.Unlock()

	value, ok := m.Load(md5)
	if ok {
		sample := value.(*SampleMapValue)
		sample.C0Info = append(sample.C0Info, info)
	} else {
		sample := &SampleMapValue{}
		sample.C0Info = append(sample.C0Info, info)
		m.Store(md5, sample)
	}
	return
}

func SampleMapUpdateC1(m *sync.Map, mu *sync.Mutex, md5 string, info SampleC1Info) {
	mu.Lock()
	defer mu.Unlock()

	value, ok := m.Load(md5)
	if ok {
		sample := value.(*SampleMapValue)
		sample.C1Info = append(sample.C1Info, info)
	} else {
		sample := &SampleMapValue{}
		sample.C1Info = append(sample.C1Info, info)
		m.Store(md5, sample)
	}
	return
}

func SampleMapUpdateC4(m *sync.Map, mu *sync.Mutex, md5 string, info SampleC4Info) {
	mu.Lock()
	defer mu.Unlock()

	value, ok := m.Load(md5)
	if ok {
		sample := value.(*SampleMapValue)
		sample.C4Info = append(sample.C4Info, info)
	} else {
		sample := &SampleMapValue{}
		sample.C4Info = append(sample.C4Info, info)
		m.Store(md5, sample)
	}
	return
}

func fieldsNull(key string) (string, bool) {
	msg := ""
	if key == "" {
		msg = "字段为空"
		return msg, false
	}
	return msg, true
}

func fieldsRuleId(id, desc string) (string, bool) {
	value, ok := dict.C13_DESC_DICT[id]
	if !ok {
		return "规则ID不存在", false
	}

	if value != desc {
		return "规则描述与ID不匹配", false
	}

	return "", true
}

func fieldsRuleIdMatch(id string, datacodes []dict.DataCode) (string, bool) {
	idInt, _ := strconv.Atoi(id)

	for _, v := range datacodes {
		if v.Rule == idInt {
			return "", true
		}
	}

	return fmt.Sprintf("RuleId字段 %s 不在DataInfoNum组别中，请核查", id), false
}

func fieldsCmdId(key string) (string, bool) {
	msg := ""
	if key == "" || len(key) > 13 {
		msg = "字段为空|字段长度大于13"
		return msg, false
	}
	return msg, true
}

func fieldsHouseId(key string) (string, bool) {
	msg := ""
	if key == "" || key != telnetcmd.Devinfo.Dev_HouseId {
		msg = "字段为空|机房ID校验失败"
		return msg, false
	}
	return msg, true
}

func fieldsKeyword(key string, hit *int) (string, bool) {
	msg := ""
	if key == "" || len(key) > 1024 {
		msg = "字段为空|字段长度大于1024"
		return msg, false
	}

	fs := strings.Split(key, ",")
	if len(fs) > 50 {
		msg = "关键词数量大于50"
		return msg, false
	}

	*hit = len(fs)

	return msg, true
}

func fieldsFeatureid(key string) (string, bool) {
	msg := ""
	if key == "" {
		return msg, true
	}

	if len(key) > 1024 {
		msg = "字段长度大于1024"
		return msg, false
	}

	fs := strings.Split(key, ",")
	for _, v := range fs {
		_, err := strconv.Atoi(v)
		if err != nil {
			msg = "字段存在非数值型字符"
			return msg, false
		}
	}

	return msg, true
}

func fieldsC4AssetsNum(key string, hit int) (string, bool) {
	msg := ""
	id, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值型字符"
		return msg, false
	}

	if id < hit {
		msg = "命中关键词的次数比关键词数量还少"
		return msg, false
	}

	return msg, true
}

func fieldsSize(key string) (string, bool) {
	msg := ""
	if key == "" {
		msg = "字段为空"
		return msg, false
	}

	if key == "0" {
		return msg, true
	}

	//小数点后两位
	re := regexp.MustCompile(`^\d+(\.\d{2}$)`)

	match := re.MatchString(key)
	if !match {
		msg = "字段不符合小数点后2位数值要求"
		return msg, false
	}

	return msg, true
}

func fieldsAttach(key string) (string, bool) {
	msg := ""
	if key == "" || len(key) > 128 {
		msg = "字段为空|字段长度大于128"
		return msg, false
	}

	return msg, true
}

func fieldsNoZero(key string) (string, bool) {
	msg := ""
	if key == "" {
		msg = "字段为空"
		return msg, false
	}

	n, err := strconv.Atoi(key)
	if err != nil || n == 0 {
		msg = "字段非数值型字符|字段等于0"
		return msg, false
	}
	return msg, true
}

func fieldsNullZero(key string) (string, bool) {
	msg := ""
	if key == "" || key == "0" {
		msg = "字段值为空|为0"
		return msg, false
	}
	return msg, true
}

func fieldsIntNoZero(num int) (string, bool) {
	msg := ""
	if num == 0 {
		msg = "字段值不能为0"
		return msg, false
	}
	return msg, true
}

func fieldsInt(key string) (string, bool) {
	msg := ""
	_, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值型字符"
		return msg, false
	}

	return msg, true
}

func fieldsAssetNum(key string, sum int) (string, bool) {
	msg := ""
	if key == "" {
		msg = "字段为空"
		return msg, false
	}
	num, err := strconv.Atoi(key)
	if err != nil {
		msg := "字段为非数值型字符"
		return msg, false
	}

	if num != sum || num == 0 {
		msg := "字段内敏感数量为0|不一致"
		return msg, false
	}

	return msg, true
}

func fieldsUpload(key string) (string, bool) {
	msg := ""
	if key != "0" {
		msg = "字段值必须是0"
		return msg, false
	}

	return msg, true
}

func extractDataCode(fs []string) (dict.DataCode, bool, int, string) {
	var datacode dict.DataCode
	id, err := strconv.Atoi(fs[0])
	if err != nil || (id != 1 && id != 2) {
		return datacode, false, 0, "DataType非数值,或者值非1|2"
	}

	subid, err := strconv.Atoi(fs[1])
	if err != nil || subid < 1 || subid > 6 {
		return datacode, false, 1, "DataLevel非数值，或者值不在[1-6]范围内"
	}

	list := strings.Split(fs[2], ",")
	if len(list) != 2 {
		return datacode, false, 2, "DataContent字段格式有误"
	}

	codeid, err := strconv.Atoi(list[0])
	if err != nil {
		return datacode, false, 2, "DataContent不在代码表中"
	}

	hit, err := strconv.Atoi(list[1])
	if err != nil || hit == 0 {
		return datacode, false, 2, "DataContent字段hit非数值，或者hit次数为0"
	}

	datacode = dict.DataCode{
		Class: id,
		Level: subid,
		Rule:  codeid,
		Hit:   hit,
	}

	return datacode, true, 0, ""
}

func fieldsDataInfoDict(datacode dict.DataCode, sum *int) (bool, string) {
	// 先求和
	*sum += datacode.Hit

	// 再重置查表，dict表中hit字段为0
	datacode.Hit = 0
	_, ok := dict.C11_12_13_DICT[datacode]
	if !ok {
		return false, "DataType/DataLevel/DataContent字段不在规范表中"
	}

	return true, ""
}

func fieldsDataInfo(key string, index int) bool {
	flag := false
	switch index {
	case 0:
		id, _ := strconv.Atoi(key)
		if id >= 1 && id <= 2 {
			flag = true
		}
	case 1:
		id, _ := strconv.Atoi(key)
		if id >= 1 && id <= 6 {
			flag = true
		}
	case 2:
		fs := strings.Split(key, ",")
		if len(fs) == 2 {
			flag = true
		}
	}
	return flag
}

func fieldsL4Proto(key string) (string, bool) {
	msg := ""
	if key != "1" && key != "2" {
		msg = "字段范围不对[1-2]"
		return msg, false
	}
	return msg, true
}

func fieldsMatch(key string) (string, bool) {
	msg := ""
	if key != "0" && key != "1" {
		msg = "字段范围不对[0-1]"
		return msg, false
	}

	return msg, true
}

func fieldsDomain(proto, key string) (string, bool) {
	msg := ""
	if proto == "1" {
		if key == "" {
			msg = "字段为空"
			return msg, false
		}

		if len(key) > 128 {
			msg = "字段长度大于128"
			return msg, false
		}
	} else if key != "" {
		msg = "非http协议的doamin非空"
		return msg, false
	}

	return msg, true
}

func fieldsUrl(proto, key string) (string, bool) {
	msg := ""
	if proto == "1" {
		if key == "" {
			msg = "字段为空"
			return msg, false
		}

		if len(key) > 2048 {
			msg = "字段长度大于2048"
			return msg, false
		}
	} else if key != "" {
		msg = "非http协议的url非空"
		return msg, false
	}

	return msg, true
}

func fieldsEvent(id, subid string) (string, bool) {
	msg := ""
	if id == "" || subid == "" {
		msg = "EventTypeID|EventSubType字段为空"
		return msg, false
	}

	a, err := strconv.Atoi(id)
	if err != nil {
		msg = "EventTypeID字段非数值型字符"
		return msg, false
	}
	b, err := strconv.Atoi(subid)
	if err != nil {
		msg = "EventSubType字段为空字段非数值型字符"
		return msg, false
	}

	risk := dict.RiskCode{
		RiskType:    a,
		RiskSubType: b,
	}

	_, ok := dict.C7_C8_DICT[risk]
	if !ok {
		msg = "EventTypeID/EventSubType字段不在规范表中"
		return msg, false
	}

	return msg, true
}

func fieldsDataType(id string) (string, bool) {
	msg := ""
	if id != "1" && id != "2" {
		msg = "字段范围有误，不在[1-2]中"
		return msg, false
	}
	return msg, true
}

func fieldsLogid(key string, index int) (string, bool) {
	msg := ""
	if key == "" || len(key) != 32 {
		msg = "字段为空|字段长度不等于32"
		return msg, false
	}

	if !strings.HasPrefix(key, global.TimeStr) {
		msg = "日期校验失败"
		return msg, false
	}

	/*
		devno := strings.TrimLeft(key[8:14], "0")
		if devno != telnetcmd.Devinfo.Dev_No {
			msg = fmt.Sprintf("设备编号校验失败: %s != %s", devno, telnetcmd.Devinfo.Dev_No)
			return msg, false
		}
	*/

	LogidMapStoreInc(&LogidMap, key, index)

	return msg, true
}

func fieldsIp(key string) (string, bool) {
	msg := ""
	if key == "" {
		msg = "字段为空"
		return msg, false
	}

	if net.ParseIP(key) == nil {
		msg = "IP地址校验失败"
		return msg, false
	}

	return msg, true
}

func fieldsPort(key string) (string, bool) {
	msg := ""
	if key == "" {
		msg = "字段为空"
		return msg, false
	}

	p, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值字符"
		return msg, false
	}

	if p < 1 || p > 65534 {
		msg = "端口范围有误"
		return msg, false
	}
	return msg, true
}

func fieldsMd5(key string, logType int) (string, bool) {
	msg := ""
	if key == "" || len(key) != 32 {
		msg = "字段为空|字段长度不等于32"
		return msg, false
	}
	md5 := strings.ToUpper(key)
	Md5Map[logType].Store(md5, 1)
	return msg, true
}

func fieldsDeviceId(key string) (string, bool) {
	msg := ""
	if key == "" || len(key) > 128 {
		msg = "字段为空|字段长度大于128"
		return msg, false
	}
	return msg, true
}

func fieldsFileName(key string) (string, bool) {
	msg := ""
	if key == "" || len(key) > 128 {
		msg = "字段为空|字段长度大于128"
		return msg, false
	}
	return msg, true
}

func fieldsOperateType(key string) (string, bool) {
	msg := ""
	if key != "1" && key != "2" && key != "3" {
		msg = "字段操作类型非法，不在[1-3]中"
		return msg, false
	}

	return msg, true
}

func fieldsA8LogType(key string) (string, bool) {
	msg := ""
	if key != "1" {
		msg = "LogType字段值必须为1"
		return msg, false
	}

	return msg, true
}

// 规范表C.14
func fieldsA8FileType(key string) (string, bool) {
	msg := ""
	t, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值型字符"
		return msg, false
	}

	if t < 1 || t > 67 {
		msg = "字段范围不在[1-67]中"
		return msg, false
	}

	return msg, true
}

func fieldsFileType(key string, index int) (string, bool) {
	msg := ""
	id, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值字符"
		return msg, false
	}

	value, ok := dict.C10_DICT[id]
	if !ok {
		LogidMapStoreInc(&FileTypeStat, "非法字段:"+key, index)
		msg = "不在C10表中"
		return msg, false
	}

	LogidMapStoreInc(&FileTypeStat, value, index)
	return msg, true
}

func fieldsAppProto(key string, index int) (string, bool) {
	msg := ""
	id, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值型字符"
		return msg, false
	}

	value, ok := dict.C3_DICT[id]
	if !ok {
		msg = "字段不在C3表中"
		LogidMapStoreInc(&AppProtoStat, "illegal:"+key, index)
		return msg, false
	}

	LogidMapStoreInc(&AppProtoStat, value, index)
	return msg, true
}

func fieldsBusProto(key string, index int) (string, bool) {
	msg := ""
	id, err := strconv.Atoi(key)
	if err != nil {
		msg = "字段非数值型字符"
		return msg, false
	}

	value, ok := dict.C4_DICT[id]
	if !ok {
		msg = "字段不在C4表中"
		LogidMapStoreInc(&BusProtoStat, "illegal:"+key, index)
		return msg, false
	}

	LogidMapStoreInc(&BusProtoStat, value, index)
	return msg, true
}

func fieldsDataProto(key string, index int) (string, bool) {
	msg := ""
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		msg = "字段非数值型字符"
		return msg, false
	}

	value, ok := dict.C9_DICT[id]
	if !ok {
		LogidMapStoreInc(&DataProtoStat, "illegal:"+key, index)
		msg = "字段不在C9表中"
		return msg, false
	}

	LogidMapStoreInc(&DataProtoStat, value, index)
	return msg, true
}

func procC0Fields(fs []string) (int, string, bool) {
	if msg, valid := fieldsLogid(fs[global.C0_LogID], global.IndexC0); !valid {
		return global.C0_LogID, msg, false
	}

	if msg, valid := fieldsCmdId(fs[global.C0_CommandID]); !valid {
		return global.C0_CommandID, msg, false
	}

	if msg, valid := fieldsHouseId(fs[global.C0_House_ID]); !valid {
		return global.C0_House_ID, msg, false
	}

	//后面可以尝试和分级分类一起进行校验
	// ruleId ruleDesc
	if msg, valid := fieldsRuleId(fs[global.C0_RuleID], fs[global.C0_Rule_Desc]); !valid {
		return global.C0_RuleID, msg, false
	}

	if msg, valid := fieldsIp(fs[global.C0_AssetsIP]); !valid {
		return global.C0_AssetsIP, msg, false
	}

	if msg, valid := fieldsFileType(fs[global.C0_DataFileType], global.IndexC0); !valid {
		return global.C0_DataFileType, msg, false
	}

	if msg, valid := fieldsSize(fs[global.C0_AssetsSize]); !valid {
		return global.C0_AssetsSize, msg, false
	}

	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	if msg, valid := fieldsIntNoZero(datainfoGroup); !valid {
		return global.C0_DataInfoNum, msg, false
	}

	offset := 0
	if datainfoGroup > 0 {
		offset = (datainfoGroup - 1) * 3
	}

	// 取DataCodeGroup
	var datacodeGroup []dict.DataCode
	for i := 0; i < datainfoGroup; i++ {
		if datacode, valid, ret, msg := extractDataCode(fs[global.C0_DataType+3*i : global.C0_DataType+3*i+3]); !valid {
			return global.C0_DataType + 3*i + ret, msg, false
		} else {
			datacodeGroup = append(datacodeGroup, datacode)
		}
	}

	// 校验DataCode
	hitsum := 0
	for _, datacode := range datacodeGroup {
		if valid, msg := fieldsDataInfoDict(datacode, &hitsum); !valid {
			return global.C0_DataType, msg, false
		}
	}

	// 校验ruleId，在前面的基础上，再进一步校验
	if msg, valid := fieldsRuleIdMatch(fs[global.C0_RuleID], datacodeGroup); !valid {
		return global.C0_RuleID, msg, false
	}

	//字段顺序在前面
	if msg, valid := fieldsAssetNum(fs[global.C0_AssetsNum], hitsum); !valid {
		return global.C0_AssetsNum, msg, false
	}

	if msg, valid := fieldsUpload(fs[global.C0_IsUploadFile+offset]); !valid {
		return global.C0_IsUploadFile, msg, false
	}

	if msg, valid := fieldsMd5(fs[global.C0_FileMD5+offset], global.IndexC0); !valid {
		return global.C0_FileMD5, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C0_CurTime+offset]); !valid {
		return global.C0_CurTime, msg, false
	}

	if msg, valid := fieldsIp(fs[global.C0_SrcIP+offset]); !valid {
		return global.C0_SrcIP, msg, false
	}

	if msg, valid := fieldsIp(fs[global.C0_DestIP+offset]); !valid {
		return global.C0_DestIP, msg, false
	}

	if msg, valid := fieldsPort(fs[global.C0_SrcPort+offset]); !valid {
		return global.C0_SrcPort, msg, false
	}

	if msg, valid := fieldsPort(fs[global.C0_DestPort+offset]); !valid {
		return global.C0_DestPort, msg, false
	}

	if msg, valid := fieldsL4Proto(fs[global.C0_ProtocolType+offset]); !valid {
		return global.C0_ProtocolType, msg, false
	}

	if msg, valid := fieldsAppProto(fs[global.C0_ApplicationProtocol+offset], global.IndexC0); !valid {
		return global.C0_ApplicationProtocol, msg, false
	}

	if msg, valid := fieldsBusProto(fs[global.C0_BusinessProtocol+offset], global.IndexC0); !valid {
		return global.C0_BusinessProtocol, msg, false
	}

	if msg, valid := fieldsMatch(fs[global.C0_IsMatchEvent+offset]); !valid {
		return global.C0_IsMatchEvent, msg, false
	}

	return 0, "", true
}

func procC1Fields(fs []string) (int, string, bool) {
	if msg, valid := fieldsLogid(fs[global.C1_LogID], global.IndexC1); !valid {
		return global.C1_LogID, msg, false
	}

	if msg, valid := fieldsCmdId(fs[global.C1_CommandId]); !valid {
		return global.C1_CommandId, msg, false
	}

	if msg, valid := fieldsHouseId(fs[global.C1_House_ID]); !valid {
		return global.C1_House_ID, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C1_RuleID]); !valid {
		return global.C1_RuleID, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C1_Rule_Desc]); !valid {
		return global.C1_Rule_Desc, msg, false
	}

	if msg, valid := fieldsDataProto(fs[global.C1_Proto], global.IndexC1); !valid {
		return global.C1_Proto, msg, false
	}

	if msg, valid := fieldsDomain(fs[global.C1_Proto], fs[global.C1_Domain]); !valid {
		return global.C1_Domain, msg, false
	}

	if msg, valid := fieldsUrl(fs[global.C1_Proto], fs[global.C1_Url]); !valid {
		return global.C1_Url, msg, false
	}

	if msg, valid := fieldsMatch(fs[global.C1_Title]); !valid {
		return global.C1_Title, msg, false
	}

	if msg, valid := fieldsEvent(fs[global.C1_EventTypeID], fs[global.C1_EventSubType]); !valid {
		return global.C1_EventTypeID, msg, false
	}

	if msg, valid := fieldsIp(fs[global.C1_SrcIP]); !valid {
		return global.C1_SrcIP, msg, false
	}

	if msg, valid := fieldsIp(fs[global.C1_DestIP]); !valid {
		return global.C1_DestIP, msg, false
	}

	if msg, valid := fieldsPort(fs[global.C1_SrcPort]); !valid {
		return global.C1_SrcPort, msg, false
	}

	if msg, valid := fieldsPort(fs[global.C1_DestPort]); !valid {
		return global.C1_DestPort, msg, false
	}

	if msg, valid := fieldsFileType(fs[global.C1_FileType], global.IndexC1); !valid {
		return global.C1_FileType, msg, false
	}

	if msg, valid := fieldsSize(fs[global.C1_FileSize]); !valid {
		return global.C1_FileSize, msg, false
	}

	if msg, valid := fieldsNoZero(fs[global.C1_DataNum]); !valid {
		return global.C1_DataNum, msg, false
	}

	if msg, valid := fieldsDataType(fs[global.C1_DataType]); !valid {
		return global.C1_DataType, msg, false
	}

	if msg, valid := fieldsMd5(fs[global.C1_FileMD5], global.IndexC1); !valid {
		return global.C1_FileMD5, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C1_GatherTime]); !valid {
		return global.C1_GatherTime, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C1_SrcCountry]); !valid {
		return global.C1_SrcCountry, msg, false
	}
	if msg, valid := fieldsNull(fs[global.C1_SrcProvince]); !valid {
		return global.C1_SrcProvince, msg, false
	}
	if msg, valid := fieldsNull(fs[global.C1_DstCountry]); !valid {
		return global.C1_DstCountry, msg, false
	}
	if msg, valid := fieldsNull(fs[global.C1_DstCountry]); !valid {
		return global.C1_DstCountry, msg, false
	}

	return 0, "", true
}

func procC4Fields(fs []string) (int, string, bool) {
	if msg, valid := fieldsCmdId(fs[global.C4_CommandId]); !valid {
		return global.C4_CommandId, msg, false
	}
	if msg, valid := fieldsLogid(fs[global.C4_LogID], global.IndexC4); !valid {
		return global.C4_LogID, msg, false
	}
	if msg, valid := fieldsHouseId(fs[global.C4_HouseID]); !valid {
		return global.C4_HouseID, msg, false
	}
	if msg, valid := fieldsNoZero(fs[global.C4_StrategyId]); !valid {
		return global.C4_StrategyId, msg, false
	}

	keyhit := 0
	if msg, valid := fieldsKeyword(fs[global.C4_KeyWord], &keyhit); !valid {
		return global.C4_KeyWord, msg, false
	}
	if msg, valid := fieldsFeatureid(fs[global.C4_Features]); !valid {
		return global.C4_Features, msg, false
	}
	if msg, valid := fieldsC4AssetsNum(fs[global.C4_AssetsNum], keyhit); !valid {
		return global.C4_AssetsNum, msg, false
	}
	if msg, valid := fieldsIp(fs[global.C4_SrcIP]); !valid {
		return global.C4_SrcIP, msg, false
	}
	if msg, valid := fieldsIp(fs[global.C4_DestIP]); !valid {
		return global.C4_DestIP, msg, false
	}
	if msg, valid := fieldsPort(fs[global.C4_ScrPort]); !valid {
		return global.C4_ScrPort, msg, false
	}
	if msg, valid := fieldsPort(fs[global.C4_DestPort]); !valid {
		return global.C4_DestPort, msg, false
	}
	if msg, valid := fieldsDomain(fs[global.C4_Proto], fs[global.C4_Domain]); !valid {
		return global.C4_Domain, msg, false
	}
	if msg, valid := fieldsUrl(fs[global.C4_Proto], fs[global.C4_Url]); !valid {
		return global.C4_Url, msg, false
	}
	if msg, valid := fieldsMatch(fs[global.C4_DataDirection]); !valid {
		return global.C4_DataDirection, msg, false
	}

	if msg, valid := fieldsDataProto(fs[global.C4_Proto], global.IndexC4); !valid {
		return global.C4_Proto, msg, false
	}

	if msg, valid := fieldsFileType(fs[global.C4_FileType], global.IndexC4); !valid {
		return global.C4_FileType, msg, false
	}

	if msg, valid := fieldsSize(fs[global.C4_FileSize]); !valid {
		return global.C4_FileSize, msg, false
	}

	if msg, valid := fieldsAttach(fs[global.C4_AttachMent]); !valid {
		return global.C4_AttachMent, msg, false
	}

	if msg, valid := fieldsMd5(fs[global.C4_FileMD5], global.IndexC4); !valid {
		return global.C4_FileMD5, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C4_GatherTime]); !valid {
		return global.C4_GatherTime, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C4_SrcCountry]); !valid {
		return global.C4_SrcCountry, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C4_SrcProvince]); !valid {
		return global.C4_SrcProvince, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C4_DstCountry]); !valid {
		return global.C4_DstCountry, msg, false
	}

	if msg, valid := fieldsNull(fs[global.C4_DstProvince]); !valid {
		return global.C4_DstProvince, msg, false
	}

	return 0, "", true
}

// 审计日志只检查logid是否重复
func procA8Fields(fs []string, index int) (int, string, bool) {
	if msg, valid := fieldsLogid(fs[global.A8_LogId], global.IndexA8); !valid {
		return global.A8_LogId, msg, false
	}

	if msg, valid := fieldsHouseId(fs[global.A8_HouseId]); !valid {
		return global.A8_HouseId, msg, false
	}

	if fs[global.A8_DeviceType] != "2" {
		return global.A8_HouseId, "DeviceType字段不是2", false
	}

	if msg, valid := fieldsDeviceId(fs[global.A8_DeviceId]); !valid {
		return global.A8_DeviceId, msg, false
	}

	if fs[global.A8_IP] != telnetcmd.Devinfo.Dev_IP {
		rea := fmt.Sprintf("设备ip地址不匹配:[%s != %s]", fs[global.A8_IP], telnetcmd.Devinfo.Dev_IP)
		return global.A8_IP, rea, false
	}

	if msg, valid := fieldsFileName(fs[global.A8_FileName]); !valid {
		return global.A8_FileName, msg, false
	}

	if msg, valid := fieldsA8FileType(fs[global.A8_FileType]); !valid {
		return global.A8_FileType, msg, false
	}

	if msg, valid := fieldsOperateType(fs[global.A8_OperateType]); !valid {
		return global.A8_OperateType, msg, false
	}

	if msg, valid := fieldsNull(fs[global.A8_OperateTime]); !valid {
		return global.A8_OperateTime, msg, false
	}

	if !global.IsCtcc {
		if msg, valid := fieldsA8LogType(fs[global.A8_LogType]); !valid {
			return global.A8_LogType, msg, false
		}
	}

	return 0, "", true
}

func recordC0Info(fs []string) {
	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	var codes []dict.DataCode
	for i := 0; i < datainfoGroup; i++ {
		var code dict.DataCode
		code.Class, _ = strconv.Atoi(fs[global.C0_DataType+i*3])
		code.Level, _ = strconv.Atoi(fs[global.C0_DataType+i*3+1])
		fields := strings.Split(fs[global.C0_DataType+i*3+2], ",")
		if len(fields) != 2 {
			fmt.Printf("deal c0 log failed: %s\n", fs[global.C0_DataType+i*3+2])
			continue
		}
		code.Rule, _ = strconv.Atoi(fields[0])
		code.Hit, _ = strconv.Atoi(fields[1])
		codes = append(codes, code)
	}
	offset := 0
	if datainfoGroup > 0 {
		offset = (datainfoGroup - 1) * 3
	}

	matchNum, _ := strconv.Atoi(fs[global.C0_AssetsNum])
	application, _ := strconv.Atoi(fs[global.C0_ApplicationProtocol+offset])
	business, _ := strconv.Atoi(fs[global.C0_BusinessProtocol+offset])
	cross, _ := strconv.Atoi(fs[global.C0_IsMatchEvent+offset])
	filetype, _ := strconv.Atoi(fs[global.C0_DataFileType])

	info := SampleC0Info{
		Data:        codes,
		MatchNum:    matchNum,
		Application: application,
		Business:    business,
		CrossBoard:  cross,
		FileType:    filetype,
		FileSize:    fs[global.C0_AssetsSize],
	}

	SampleMapUpdateC0(&SampleMap, &SampleMapMutex, fs[global.C0_FileMD5+offset], info)
	return
}

func recordC1Info(fs []string) {
	l7Proto, _ := strconv.Atoi(fs[global.C1_Proto])
	fileType, _ := strconv.Atoi(fs[global.C1_FileType])
	num, _ := strconv.Atoi(fs[global.C1_DataNum])

	var event dict.RiskCode
	event.RiskType, _ = strconv.Atoi(fs[global.C1_EventTypeID])
	event.RiskSubType, _ = strconv.Atoi(fs[global.C1_EventSubType])

	info := SampleC1Info{
		Event:    event,
		L7Proto:  l7Proto,
		FileType: fileType,
		FileSize: fs[global.C1_FileSize],
		DataNum:  num,
	}

	SampleMapUpdateC1(&SampleMap, &SampleMapMutex, fs[global.C1_FileMD5], info)
	return
}

func recordC4Info(fs []string) {
	filetype, _ := strconv.Atoi(fs[global.C4_FileType])
	info := SampleC4Info{
		Keyword:  fs[global.C4_KeyWord],
		FileType: filetype,
		FileSize: fs[global.C4_FileSize],
	}
	SampleMapUpdateC4(&SampleMap, &SampleMapMutex, fs[global.C4_FileMD5], info)
}

func recordLogInvalid(line string, info CheckInfo, index int) {
	LogCheckMap[index][line] = info
	incLogInvalidCnt(index)
}

func checkSampleFileName(fn string) bool {
	fs := strings.Split(filepath.Base(fn), "+")

	fname := global.LogTypeIndex_Name[global.IndexC3]

	if len(fs) != global.FN1_Max {
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s文件名字段个数[%d]不符", fname, len(fs)),
			Filenmae: fn,
		}
		recordLogInvalid(fn, info, global.IndexC3)
		return false
	}

	for i := 0; i < global.FN1_Max; i++ {
		var rea string
		invalid := false
		switch i {
		case global.FN1_Version:
			if fs[i] != "0x31" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN1_Fields_Name[i], i+1, fs[i])
			}
		case global.FN1_Module:
			if fs[i] != "0x06c3" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN1_Fields_Name[i], i+1, fs[i])
			}
		case global.FN1_CommandId:
			// todo later
		case global.FN1_Site:
			if fs[i] != telnetcmd.Devinfo.Dev_Site {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN1_Fields_Name[i], i+1, fs[i])
			}
		case global.FN1_Manu:
			if fs[i] != global.Manufactor {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN1_Fields_Name[i], i+1, fs[i])
			}
		case global.FN1_Devno:
			if fs[i] != telnetcmd.Devinfo.Dev_No {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN1_Fields_Name[i], i+1, fs[i])
			}
		case global.FN1_MD5:
			str := strings.TrimSuffix(fs[i], ".zip")
			if len(str) != 32 {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN1_Fields_Name[i], i+1, fs[i])
			} else {
				Md5Map[global.IndexC3].Store(str, 1)
			}
		}

		if invalid {
			info := CheckInfo{
				Reason:   rea,
				Filenmae: fn,
			}
			recordLogInvalid(fn, info, global.IndexC3)
			return false
		}
	}

	return true
}

func checkLogFileName(fn string, logtype int) bool {
	fs := strings.Split(filepath.Base(fn), "+")

	fname := global.LogTypeIndex_Name[logtype]

	if len(fs) != global.FN_Max {
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s文件名字段个数[%d]不符", fname, len(fs)),
			Filenmae: fn,
		}
		recordLogInvalid(fn, info, global.IndexC0)
		return false
	}
	for i := 0; i < global.FN_Max; i++ {
		var rea string
		invalid := false
		switch i {
		case global.FN_Version:
			if fs[i] != "0x31" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		case global.FN_Module:
			if logtype == global.IndexC0 && fs[i] != "0x06c0" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			} else if logtype == global.IndexC1 && fs[i] != "0x06c1" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			} else if logtype == global.IndexC4 && fs[i] != "0x06c4" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			} else if logtype == global.IndexA8 && global.IsCtcc && fs[i] != "0x04a8" {
				invalid = true
				rea = fmt.Sprintf("ctcc %s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			} else if logtype == global.IndexA8 && !global.IsCtcc && fs[i] != "0x00a8" {
				invalid = true
				rea = fmt.Sprintf("cucc %s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		case global.FN_Filetype:
			if fs[i] != "000" {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		case global.FN_Site:
			if fs[i] != telnetcmd.Devinfo.Dev_Site {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		case global.FN_Manu:
			if fs[i] != global.Manufactor {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		case global.FN_Devno:
			if fs[i] != telnetcmd.Devinfo.Dev_No {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		case global.FN_Date:
			str := strings.TrimSuffix(fs[i], ".tar.gz")
			if len(str) != 20 {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
			if str[:8] != global.TimeStr {
				invalid = true
				rea = fmt.Sprintf("%s文件名字段[%s][%d]错误: %s", fname, global.FN_Fields_Name[i], i+1, fs[i])
			}
		}

		if invalid {
			info := CheckInfo{
				Reason:   rea,
				Filenmae: fn,
			}
			recordLogInvalid(fn, info, logtype)
			return false
		}

	}

	return true
}

func procC0Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	fname := global.LogTypeIndex_Name[global.IndexC0]

	if len(fs) < 24 {
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexC0)
		return
	}
	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	if datainfoGroup > 1 {
		nums := 24 + (datainfoGroup-1)*3
		if len(fs) != nums {
			info := CheckInfo{
				Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
				Filenmae: filename,
			}
			recordLogInvalid(line, info, global.IndexC0)
			return
		}
	} else {
		if len(fs) != 24 {
			info := CheckInfo{
				Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
				Filenmae: filename,
			}
			recordLogInvalid(line, info, global.IndexC0)
			return
		}
	}

	if index, rea, valid := procC0Fields(fs); valid {
		recordC0Info(fs)
		incLogValidCnt(global.IndexC0)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段[%s][%d]校验失败: %s", global.C0_Name[index], index+1, rea),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexC0)
	}
	return
}

func procC1Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	fname := global.LogTypeIndex_Name[global.IndexC1]

	if len(fs) != global.C1_Max {
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexC1)
		return
	}

	if index, rea, valid := procC1Fields(fs); valid {
		recordC1Info(fs)
		incLogValidCnt(global.IndexC1)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段[%s][%d]校验失败: %s", global.C1_Name[index], index+1, rea),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexC1)
	}
	return
}

func procC2Ctx(ctx, filename string) {

}

func procC3Ctx(ctx, filename string) {

}

func procC4Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	fname := global.LogTypeIndex_Name[global.IndexC4]
	if len(fs) != global.C4_Max {
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexC4)

		return
	}

	if index, rea, valid := procC4Fields(fs); valid {
		incLogValidCnt(global.IndexC4)
		recordC4Info(fs)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段[%s][%d]校验失败: %s", global.C4_Name[index], index+1, rea),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexC4)
	}
	return
}

func procA8Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	fname := global.LogTypeIndex_Name[global.IndexA8]
	if global.IsCtcc && len(fs) != 9 {
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexA8)
		return
	} else if !global.IsCtcc && len(fs) != 10 {
		fname = "00a8"
		info := CheckInfo{
			Reason:   fmt.Sprintf("%s字段个数[%d]不符", fname, len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexA8)
		return
	}

	if index, rea, valid := procA8Fields(fs, global.IndexA8); valid {
		incLogValidCnt(global.IndexA8)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段[%s][%d]校验失败: %s", global.A8_Name[index], index+1, rea),
			Filenmae: filename,
		}
		recordLogInvalid(line, info, global.IndexA8)
	}
	return
}

func procLogData(ctx string, logType int, filename string) error {
	switch logType {
	case global.IndexC0:
		procC0Ctx(ctx, filename)
	case global.IndexC1:
		procC1Ctx(ctx, filename)
	case global.IndexC2:
		procC2Ctx(ctx, filename)
	case global.IndexC3:
		procC3Ctx(ctx, filename)
	case global.IndexC4:
		procC4Ctx(ctx, filename)
	case global.IndexA8:
		procA8Ctx(ctx, filename)
	default:
		fmt.Printf("Not support log type: %d\n", logType)
	}

	return nil
}

func procTargzFile(filename string, logType int) error {
	// 打开tar.gz文件
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return err
	}
	defer f.Close()

	// 创建gzip.Reader
	gr, err := gzip.NewReader(f)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return err
	}
	defer gr.Close()

	// 创建tar.Reader
	tr := tar.NewReader(gr)

	// 遍历tar文件中的每个文件
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading tar file:", err)
			return err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		scanner := bufio.NewScanner(tr)

		for scanner.Scan() {
			line := scanner.Text()
			incLogAllCnt(logType)
			if line == "" {
				incLogNullCnt(logType)
				continue
			}
			procLogData(line, logType, filename)
		}
	}

	return nil
}

func ProcLogPath(path string, wg *sync.WaitGroup, logType int) error {
	defer wg.Done()

	if exist := global.PathExists(path); !exist {
		fmt.Printf("Path %s not exist, skip it!\n", path)
		return nil
	}

	deep1 := strings.Count(path, string(os.PathSeparator))
	//fmt.Printf("DS Identify path: [%s]\n", path)
	err := filepath.WalkDir(path, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("filepath walk failed:%v\n", err)
			return err
		}

		deep2 := strings.Count(dir, string(os.PathSeparator))
		if deep2 > deep1+1 {
			//跳过子目录下的文件
			return nil
		}

		if !d.IsDir() {
			if strings.HasSuffix(d.Name(), "tar.gz") {
				if valid := checkLogFileName(dir, logType); !valid {
					incFileErrCnt(logType)
					return nil
				}
				incFileCnt(logType)
				procTargzFile(dir, logType)
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("filepath walk failed:%v\n", err)
	}

	return err
}

func ProcEvidencePath(dir string, wg *sync.WaitGroup) error {
	defer wg.Done()

	deep1 := strings.Count(dir, string(os.PathSeparator))
	err := filepath.WalkDir(dir, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("filepath walk failed:%v\n", err)
			return err
		}

		deep2 := strings.Count(dir, string(os.PathSeparator))
		if deep2 > deep1+1 {
			//跳过子目录下的文件
			return nil
		}

		if !d.IsDir() {
			if strings.HasSuffix(d.Name(), "zip") {
				if valid := checkSampleFileName(d.Name()); !valid {
					incFileErrCnt(global.IndexC3)
				} else {
					incFileCnt(global.IndexC3)
				}
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("filepath walk failed:%v\n", err)
	}

	return err
}

func getPathByParam(lpath, logpath, date string) string {
	var str string
	if date == "" {
		str = filepath.Join(lpath, logpath)
	} else {
		str = filepath.Join(lpath, logpath, date, "success")
	}

	logger.Logger.Printf("walk path :%s", str)
	return str
}

func AnalyzeLogFile(gptah, date, opath string) {
	cur := time.Now()
	var wg sync.WaitGroup

	//获取取证文件MD5值
	wg.Add(1)
	c3 := getPathByParam(gptah, global.EvidenceName, date)
	go ProcEvidencePath(c3, &wg)

	//处理识别话单
	wg.Add(1)
	c0 := getPathByParam(gptah, global.IdentifyName, date)
	go ProcLogPath(c0, &wg, global.IndexC0)

	//处理监测话单
	wg.Add(1)
	c1 := getPathByParam(gptah, global.MonitorName, date)
	go ProcLogPath(c1, &wg, global.IndexC1)

	//处理关键字话单
	wg.Add(1)
	c4 := getPathByParam(gptah, global.KeywordName, date)
	if exist := global.PathExists(c4); !exist {
		c4 = getPathByParam(gptah, global.KeywordNameB, date)
	}
	go ProcLogPath(c4, &wg, global.IndexC4)

	//处理审计日志
	wg.Add(1)
	a8 := getPathByParam(gptah, global.AuditNam, date)
	go ProcLogPath(a8, &wg, global.IndexA8)

	wg.Wait()

	//处理完以后，开始写文件
	excel := excelize.NewFile()
	defer func() {
		if err := excel.Close(); err != nil {
			fmt.Printf("close excel err: %v\n", err)
		}
	}()

	global.PrintReportPrefix("Report Start")
	GenerateResult(excel)
	global.PrintReportSuffix("Report End")
	//保存文件名
	os.Rename(opath, opath+"_bak")
	if err := excel.SaveAs(opath); err != nil {
		fmt.Printf("close xlsx file failed: %v\n", err)
		return
	}

	fmt.Printf("Check Complete, elapse %.2f 秒\n", time.Since(cur).Seconds())
	return
}

func init() {
	for i := 0; i < global.IndexMax; i++ {
		LogCheckMap[i] = make(map[string]CheckInfo)
	}
}
