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

	"github.com/xuri/excelize/v2"
)

type StLogStat struct {
	AllCnt     int64
	ValidCnt   int64
	NullCnt    int64
	InvalidCnt int64
}

type StFileStat struct {
	FileNum int64
	LogNum  StLogStat
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
}

type SampleC1Info struct {
	Event    dict.RiskCode
	L7Proto  int
	FileType int
	FileSize string
	DataNum  int
}

type SampleC4Info struct {
	Keyword string
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

	C0_CheckMap map[string]CheckInfo //识别话单必填项校验
	C1_CheckMap map[string]CheckInfo //监测话单必填项校验
	C4_CheckMap map[string]CheckInfo //关键字话单必填项校验
	A8_CheckMap map[string]CheckInfo //审计日志话单校验
	SampleMap   sync.Map
)

func incFileCnt(index int) {
	atomic.AddInt64(&FileStat[index].FileNum, 1)
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

func SampleMapUpdateC0(m *sync.Map, md5 string, info SampleC0Info) {
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

func SampleMapUpdateC1(m *sync.Map, md5 string, info SampleC1Info) {
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

func SampleMapUpdateC4(m *sync.Map, md5 string, info SampleC4Info) {
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

func fieldsNull(key string) bool {
	if key == "" {
		return false
	}
	return true
}

func fieldsFeatureid(key string) bool {
	if key == "" {
		return true
	}

	fs := strings.Split(key, ",")
	for _, v := range fs {
		_, err := strconv.Atoi(v)
		if err != nil {
			return false
		}
	}

	return true
}

func fieldsSize(key string) bool {
	if key == "" {
		return false
	}

	if key == "0" {
		return true
	}

	//小数点后两位
	re := regexp.MustCompile(`^\d+(\.\d{2}$)`)
	return re.MatchString(key)
}

func fieldsNoZero(key string) bool {
	if key == "" {
		return false
	}

	n, err := strconv.Atoi(key)
	if err != nil {
		return false
	}

	if n == 0 {
		return false
	}
	return true
}

func fieldsNullZero(key string) bool {
	if key == "" || key == "0" {
		return false
	}
	return true
}

func fieldsIntNoZero(num int) bool {
	if num == 0 {
		return false
	}
	return true
}

func fieldsInt(key string) bool {
	_, err := strconv.Atoi(key)
	if err != nil {
		return false
	}

	return true
}

func fieldsUpload(key string) bool {
	if key != "0" {
		return false
	}

	return true
}

func fieldsDataInfoDict(fs []string) (bool, int) {
	id, err := strconv.Atoi(fs[0])
	if err != nil {
		return false, 0
	}

	subid, err := strconv.Atoi(fs[1])
	if err != nil {
		return false, 1
	}

	list := strings.Split(fs[2], ",")
	if len(list) != 2 {
		return false, 2
	}

	codeid, err := strconv.Atoi(list[0])
	if err != nil {
		return false, 2
	}

	hit, err := strconv.Atoi(list[0])
	if err != nil || hit == 0 {
		return false, 2
	}

	datacode := dict.DataCode{
		Class: id,
		Level: subid,
		Rule:  codeid,
	}

	_, ok := dict.C11_12_13_DICT[datacode]
	if !ok {
		return false, 0
	}

	return true, 0
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

func fieldsL4Proto(key string) bool {
	if key != "1" && key != "2" {
		return false
	}
	return true
}

func fieldsMatch(key string) bool {
	if key != "0" && key != "1" {
		return false
	}

	return true
}

func fieldsDomain(proto, key string) bool {
	if proto == "1" {
		if key == "" {
			return false
		}

		if len(key) > 128 {
			return false
		}
	}

	return true
}

func fieldsUrl(proto, key string) bool {
	if proto == "1" {
		if key == "" {
			return false
		}

		if len(key) > 2048 {
			return false
		}
	}

	return true
}

func fieldsEvent(id, subid string) bool {
	if id == "" || subid == "" {
		return false
	}

	a, err := strconv.Atoi(id)
	if err != nil {
		return false
	}
	b, err := strconv.Atoi(subid)
	if err != nil {
		return false
	}

	risk := dict.RiskCode{
		RiskType:    a,
		RiskSubType: b,
	}

	_, ok := dict.C7_C8_DICT[risk]
	if !ok {
		return false
	}

	return true
}

func fieldsDataType(id string) bool {
	if id != "1" && id != "2" {
		return false
	}
	return true
}

func feildsLogid(key string, index int) bool {
	if key == "" || len(key) != 32 {
		return false
	}

	if !strings.HasPrefix(key, global.TimeStr) {
		return false
	}

	LogidMapStoreInc(&LogidMap, key, index)

	return true
}

func fieldsIp(key string) bool {
	if key == "" {
		return false
	}

	if net.ParseIP(key) == nil {
		return false
	}

	return true
}

func fieldsPort(key string) bool {
	if key == "" {
		return false
	}

	p, err := strconv.Atoi(key)
	if err != nil {
		return false
	}

	if p < 1 || p > 65535 {
		return false
	}
	return true
}

func fieldsMd5(key string, logType int) bool {
	if key == "" || len(key) != 32 {
		return false
	}
	md5 := strings.ToUpper(key)
	Md5Map[logType].Store(md5, 1)
	return true
}

func fieldsFileType(key string, index int) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C10_DICT[id]
	if !ok {
		//fmt.Printf("app proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&FileTypeStat, "illegal:"+key, index)
		return false
	}

	LogidMapStoreInc(&FileTypeStat, value, index)
	return true
}

func fieldsAppProto(key string, index int) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C3_DICT[id]
	if !ok {
		//fmt.Printf("app proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&AppProtoStat, "illegal:"+key, index)
		return false
	}

	LogidMapStoreInc(&AppProtoStat, value, index)
	return true
}

func fieldsBusProto(key string, index int) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C4_DICT[id]
	if !ok {
		//fmt.Printf("business proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&BusProtoStat, "illegal:"+key, index)
		return false
	}

	LogidMapStoreInc(&BusProtoStat, value, index)
	return true
}

func fieldsDataProto(key string, index int) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C9_DICT[id]
	if !ok {
		//fmt.Printf("business proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&DataProtoStat, "illegal:"+key, index)
		return false
	}

	LogidMapStoreInc(&DataProtoStat, value, index)
	return true
}

func procC0Fields(fs []string) (int, bool) {
	if valid := feildsLogid(fs[global.C0_LogID], global.IndexC0); !valid {
		return global.C0_LogID, false
	}

	if valid := fieldsNull(fs[global.C0_CommandID]); !valid {
		return global.C0_CommandID, false
	}

	if valid := fieldsNull(fs[global.C0_House_ID]); !valid {
		return global.C0_House_ID, false
	}

	//后面可以尝试和分级分类一起进行校验
	if valid := fieldsNull(fs[global.C0_RuleID]); !valid {
		return global.C0_RuleID, false
	}
	if valid := fieldsNull(fs[global.C0_Rule_Desc]); !valid {
		return global.C0_Rule_Desc, false
	}

	if valid := fieldsIp(fs[global.C0_AssetsIP]); !valid {
		return global.C0_AssetsIP, false
	}

	if valid := fieldsFileType(fs[global.C0_DataFileType], global.IndexC0); !valid {
		return global.C0_DataFileType, false
	}

	if valid := fieldsSize(fs[global.C0_AssetsSize]); !valid {
		return global.C0_AssetsSize, false
	}

	if valid := fieldsInt(fs[global.C0_AssetsNum]); !valid {
		return global.C0_AssetsNum, false
	}

	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	if valid := fieldsIntNoZero(datainfoGroup); !valid {
		return global.C0_DataInfoNum, false
	}

	offset := 0
	if datainfoGroup > 0 {
		offset = (datainfoGroup - 1) * 3
	}

	for i := 0; i < datainfoGroup; i++ {
		if valid, ret := fieldsDataInfoDict(fs[global.C0_DataType+3*i : global.C0_DataType+3*i+3]); !valid {
			return global.C0_DataType + 3*i + ret, false
		}
	}

	/*
		for i := 0; i < offset+3; i++ {
			if valid := fieldsDataInfo(fs[global.C0_DataType+i], i%3); !valid {
				return global.C0_DataType + i%3, false
			}
		}
	*/

	if valid := fieldsUpload(fs[global.C0_IsUploadFile+offset]); !valid {
		return global.C0_IsUploadFile, false
	}

	if valid := fieldsMd5(fs[global.C0_FileMD5+offset], global.IndexC0); !valid {
		return global.C0_FileMD5, false
	}

	if valid := fieldsNull(fs[global.C0_CurTime+offset]); !valid {
		return global.C0_CurTime, false
	}

	if valid := fieldsIp(fs[global.C0_SrcIP+offset]); !valid {
		return global.C0_SrcIP, false
	}

	if valid := fieldsIp(fs[global.C0_DestIP+offset]); !valid {
		return global.C0_DestIP, false
	}

	if valid := fieldsPort(fs[global.C0_SrcPort+offset]); !valid {
		return global.C0_SrcPort, false
	}

	if valid := fieldsPort(fs[global.C0_DestPort+offset]); !valid {
		return global.C0_DestPort, false
	}

	if valid := fieldsL4Proto(fs[global.C0_ProtocolType+offset]); !valid {
		return global.C0_ProtocolType, false
	}

	if valid := fieldsAppProto(fs[global.C0_ApplicationProtocol+offset], global.IndexC0); !valid {
		return global.C0_ApplicationProtocol, false
	}

	if valid := fieldsBusProto(fs[global.C0_BusinessProtocol+offset], global.IndexC0); !valid {
		return global.C0_BusinessProtocol, false
	}

	if valid := fieldsMatch(fs[global.C0_IsMatchEvent+offset]); !valid {
		return global.C0_IsMatchEvent, false
	}

	return 0, true
}

func procC1Fields(fs []string) (int, bool) {
	if valid := feildsLogid(fs[global.C1_LogID], global.IndexC1); !valid {
		return global.C1_LogID, false
	}

	if valid := fieldsNull(fs[global.C1_CommandId]); !valid {
		return global.C1_CommandId, false
	}

	if valid := fieldsNull(fs[global.C1_House_ID]); !valid {
		return global.C1_House_ID, false
	}

	if valid := fieldsNull(fs[global.C1_RuleID]); !valid {
		return global.C1_RuleID, false
	}

	if valid := fieldsNull(fs[global.C1_Rule_Desc]); !valid {
		return global.C1_Rule_Desc, false
	}

	if valid := fieldsDataProto(fs[global.C1_Proto], global.IndexC1); !valid {
		return global.C1_Proto, false
	}

	if valid := fieldsDomain(fs[global.C1_Proto], fs[global.C1_Domain]); !valid {
		return global.C1_Domain, false
	}

	if valid := fieldsUrl(fs[global.C1_Proto], fs[global.C1_Url]); !valid {
		return global.C1_Url, false
	}

	if valid := fieldsMatch(fs[global.C1_Title]); !valid {
		return global.C1_Title, false
	}

	if valid := fieldsEvent(fs[global.C1_EventTypeID], fs[global.C1_EventSubType]); !valid {
		return global.C1_EventTypeID, false
	}

	if valid := fieldsIp(fs[global.C1_SrcIP]); !valid {
		return global.C1_SrcIP, false
	}

	if valid := fieldsIp(fs[global.C1_DestIP]); !valid {
		return global.C1_DestIP, false
	}

	if valid := fieldsPort(fs[global.C1_SrcPort]); !valid {
		return global.C1_SrcPort, false
	}

	if valid := fieldsPort(fs[global.C1_DestPort]); !valid {
		return global.C1_DestPort, false
	}

	if valid := fieldsFileType(fs[global.C1_FileType], global.IndexC1); !valid {
		return global.C1_FileType, false
	}

	if valid := fieldsSize(fs[global.C1_FileSize]); !valid {
		return global.C1_FileSize, false
	}

	if valid := fieldsNoZero(fs[global.C1_DataNum]); !valid {
		return global.C1_DataNum, false
	}

	if valid := fieldsDataType(fs[global.C1_DataType]); !valid {
		return global.C1_DataType, false
	}

	if valid := fieldsMd5(fs[global.C1_FileMD5], global.IndexC1); !valid {
		return global.C1_FileMD5, false
	}

	if valid := fieldsNull(fs[global.C1_GatherTime]); !valid {
		return global.C1_GatherTime, false
	}

	return 0, true
}

func procC4Fields(fs []string) (int, bool) {
	if valid := fieldsNull(fs[global.C4_CommandId]); !valid {
		return global.C4_CommandId, false
	}
	if valid := feildsLogid(fs[global.C4_LogID], global.IndexC4); !valid {
		return global.C4_LogID, false
	}
	if valid := fieldsNull(fs[global.C4_HouseID]); !valid {
		return global.C4_HouseID, false
	}
	if valid := fieldsNoZero(fs[global.C4_StrategyId]); !valid {
		return global.C4_StrategyId, false
	}
	if valid := fieldsNull(fs[global.C4_KeyWord]); !valid {
		return global.C4_KeyWord, false
	}
	if valid := fieldsFeatureid(fs[global.C4_Features]); !valid {
		return global.C4_Features, false
	}
	if valid := fieldsNoZero(fs[global.C4_AssetsNum]); !valid {
		return global.C4_AssetsNum, false
	}
	if valid := fieldsIp(fs[global.C4_SrcIP]); !valid {
		return global.C4_SrcIP, false
	}
	if valid := fieldsIp(fs[global.C4_DestIP]); !valid {
		return global.C4_DestIP, false
	}
	if valid := fieldsPort(fs[global.C4_ScrPort]); !valid {
		return global.C4_ScrPort, false
	}
	if valid := fieldsPort(fs[global.C4_DestPort]); !valid {
		return global.C4_DestPort, false
	}
	if valid := fieldsDomain(fs[global.C4_Proto], fs[global.C4_Domain]); !valid {
		return global.C4_Domain, false
	}
	if valid := fieldsUrl(fs[global.C4_Proto], fs[global.C4_Url]); !valid {
		return global.C4_Url, false
	}
	if valid := fieldsMatch(fs[global.C4_DataDirection]); !valid {
		return global.C4_DataDirection, false
	}

	if valid := fieldsDataProto(fs[global.C4_Proto], global.IndexC4); !valid {
		return global.C4_Proto, false
	}

	if valid := fieldsFileType(fs[global.C4_FileType], global.IndexC4); !valid {
		return global.C4_FileType, false
	}

	if valid := fieldsSize(fs[global.C4_FileSize]); !valid {
		return global.C4_FileSize, false
	}

	if valid := fieldsNull(fs[global.C4_AttachMent]); !valid {
		return global.C4_AttachMent, false
	}

	if valid := fieldsMd5(fs[global.C4_FileMD5], global.IndexC4); !valid {
		return global.C4_FileMD5, false
	}

	if valid := fieldsNull(fs[global.C4_GatherTime]); !valid {
		return global.C4_GatherTime, false
	}

	return 0, true
}

// 审计日志只检查logid是否重复
func procA8Fields(fs []string, index int) (int, bool) {
	key := fs[0]
	if key == "" || len(key) != 32 {
		return 0, false
	}

	if !strings.HasPrefix(key, global.TimeStr) {
		return 0, false
	}

	LogidMapStoreInc(&LogidMap, key, index)
	return 0, true
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
	}

	SampleMapUpdateC0(&SampleMap, fs[global.C0_FileMD5+offset], info)
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

	SampleMapUpdateC1(&SampleMap, fs[global.C1_FileMD5], info)
	return
}

func recordLogInvalid(cmap map[string]CheckInfo, line string, info CheckInfo, index int) {
	cmap[line] = info
	incLogInvalidCnt(index)
}

func procC0Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	if len(fs) < 24 {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(C0_CheckMap, line, info, global.IndexC0)
		return
	}
	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	if datainfoGroup > 1 {
		nums := 24 + (datainfoGroup-1)*3
		if len(fs) != nums {
			info := CheckInfo{
				Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
				Filenmae: filename,
			}
			recordLogInvalid(C0_CheckMap, line, info, global.IndexC0)
			return
		}
	} else {
		if len(fs) != 24 {
			info := CheckInfo{
				Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
				Filenmae: filename,
			}
			recordLogInvalid(C0_CheckMap, line, info, global.IndexC0)
			return
		}
	}

	if index, valid := procC0Fields(fs); valid {
		recordC0Info(fs)
		incLogValidCnt(global.IndexC0)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("第%d个字段非法", index+1),
			Filenmae: filename,
		}
		recordLogInvalid(C0_CheckMap, line, info, global.IndexC0)
	}
	return
}

func procC1Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	if len(fs) != 21 {
		//fmt.Printf("invalid log:[%s]\n", line)
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(C1_CheckMap, line, info, global.IndexC1)
		return
	}

	if index, valid := procC1Fields(fs); valid {
		recordC1Info(fs)
		incLogValidCnt(global.IndexC1)
	} else {
		//fmt.Printf("invalid log:[%s]\n", line)
		info := CheckInfo{
			Reason:   fmt.Sprintf("第%d个字段非法", index+1),
			Filenmae: filename,
		}
		recordLogInvalid(C1_CheckMap, line, info, global.IndexC1)
	}
	return
}

func procC2Ctx(ctx, filename string) {

}

func procC3Ctx(ctx, filename string) {

}

func procC4Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	if len(fs) != 20 {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(C4_CheckMap, line, info, global.IndexC4)

		return
	}

	if index, valid := procC4Fields(fs); valid {
		incLogValidCnt(global.IndexC4)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("第%d个字段非法", index+1),
			Filenmae: filename,
		}
		recordLogInvalid(C4_CheckMap, line, info, global.IndexC4)
	}
	return
}

func procA8Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	if len(fs) != 9 && len(fs) != 10 {
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
			Filenmae: filename,
		}
		recordLogInvalid(A8_CheckMap, line, info, global.IndexA8)
		return
	}

	if index, valid := procA8Fields(fs, global.IndexA8); valid {
		incLogValidCnt(global.IndexA8)
	} else {
		info := CheckInfo{
			Reason:   fmt.Sprintf("第%d个字段非法", index+1),
			Filenmae: filename,
		}
		recordLogInvalid(A8_CheckMap, line, info, global.IndexA8)
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
				incFileCnt(global.IndexC3)
				basename := strings.TrimSuffix(filepath.Base(d.Name()), ".zip")
				fields := strings.Split(basename, "+")
				if len(fields) == 7 {
					Md5Map[global.IndexC3].Store(fields[6], 1)
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
	if date == "" {
		return filepath.Join(lpath, logpath)
	}
	return filepath.Join(lpath, logpath, date, "success")
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
	C0_CheckMap = make(map[string]CheckInfo)
	C1_CheckMap = make(map[string]CheckInfo)
	C4_CheckMap = make(map[string]CheckInfo)
	A8_CheckMap = make(map[string]CheckInfo)
}
