package global

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	IdentifyName = "ds_data_identify"
	MonitorName  = "ds_data_monitor"
	EvidenceName = "ds_evidence_file"
	KeywordName  = "ds_keyword_file"
	KeywordNameB = "ds_data_keyword"
	AuditNam     = "ds_audit_log"
)

const (
	IndexC0 = iota
	IndexC1
	IndexC2
	IndexC3
	IndexC4
	IndexA8
	IndexMax
)

var (
	LogTypeIndex_Name = map[int]string{
		IndexC0: "06c0",
		IndexC1: "06c1",
		IndexC2: "06c2",
		IndexC3: "06c3",
		IndexC4: "06c4",
		IndexA8: "04a8",
	}
	LogTypeName_Index = map[string]int{
		"06c0": IndexC0,
		"06c1": IndexC1,
		"06c2": IndexC2,
		"06c3": IndexC3,
		"06c4": IndexC4,
		"04a8": IndexA8,
	}
)

const (
	FN_Version = iota
	FN_Module
	FN_Filetype
	FN_Site
	FN_Manu
	FN_Devno
	FN_Date
	FN_Max
)

var FN_Fields_Name = map[int]string{
	FN_Version:  "Version",
	FN_Module:   "模块名称",
	FN_Filetype: "文件类型",
	FN_Site:     "设备部署位置",
	FN_Manu:     "上报厂家名",
	FN_Devno:    "上报设备编号",
	FN_Date:     "上报日期",
}

const (
	FN1_Version = iota
	FN1_Module
	FN1_CommandId
	FN1_Site
	FN1_Manu
	FN1_Devno
	FN1_MD5
	FN1_Max
)

var FN1_Fields_Name = map[int]string{
	FN1_Version:   "Version",
	FN1_Module:    "模块名称",
	FN1_CommandId: "采集指令Id",
	FN1_Site:      "设备部署位置",
	FN1_Manu:      "上报厂家名",
	FN1_Devno:     "上报设备编号",
	FN1_MD5:       "文件MD5",
}

// C0字段索引
const (
	C0_LogID = iota
	C0_CommandID
	C0_House_ID
	C0_RuleID
	C0_Rule_Desc
	C0_AssetsIP
	C0_DataFileType
	C0_AssetsSize
	C0_AssetsNum
	C0_DataInfoNum
	C0_DataType
	C0_DataLevel
	C0_DataContent
	C0_IsUploadFile
	C0_FileMD5
	C0_CurTime
	C0_SrcIP
	C0_DestIP
	C0_SrcPort
	C0_DestPort
	C0_ProtocolType
	C0_ApplicationProtocol
	C0_BusinessProtocol
	C0_IsMatchEvent
	C0_Max
)

var C0_Name = map[int]string{
	C0_LogID:               "LogID",
	C0_CommandID:           "CommandID",
	C0_House_ID:            "House_ID",
	C0_RuleID:              "RuleID",
	C0_Rule_Desc:           "Rule_Desc",
	C0_AssetsIP:            "AssetsIP",
	C0_DataFileType:        "DataFileType",
	C0_AssetsSize:          "AssetsSize",
	C0_AssetsNum:           "AssetsNum",
	C0_DataInfoNum:         "DataInfoNum",
	C0_DataType:            "DataType",
	C0_DataLevel:           "DataLevel",
	C0_DataContent:         "DataContent",
	C0_IsUploadFile:        "IsUploadFile",
	C0_FileMD5:             "FileMD5",
	C0_CurTime:             "CurTime",
	C0_SrcIP:               "SrcIP",
	C0_DestIP:              "DestIP",
	C0_SrcPort:             "SrcPort",
	C0_DestPort:            "DestPort",
	C0_ProtocolType:        "ProtocolType",
	C0_ApplicationProtocol: "ApplicationProtocol",
	C0_BusinessProtocol:    "BusinessProtocol",
	C0_IsMatchEvent:        "IsMatchEvent",
}

// C1字段索引
const (
	C1_LogID = iota
	C1_CommandId
	C1_House_ID
	C1_RuleID
	C1_Rule_Desc
	C1_Proto
	C1_Domain
	C1_Url
	C1_Title
	C1_EventTypeID
	C1_EventSubType
	C1_SrcIP
	C1_DestIP
	C1_SrcPort
	C1_DestPort
	C1_FileType
	C1_FileSize
	C1_DataNum
	C1_DataType
	C1_FileMD5
	C1_GatherTime
	C1_SrcCountry
	C1_SrcProvince
	C1_DstCountry
	C1_DstProvince
	C1_Max
)

var C1_Name = map[int]string{
	C1_LogID:        "LogID",
	C1_CommandId:    "CommandId",
	C1_House_ID:     "House_ID",
	C1_RuleID:       "RuleID",
	C1_Rule_Desc:    "Rule_Desc",
	C1_Proto:        "Proto",
	C1_Domain:       "Domain",
	C1_Url:          "Url",
	C1_Title:        "Title",
	C1_EventTypeID:  "EventTypeID",
	C1_EventSubType: "EventSubType",
	C1_SrcIP:        "SrcIP",
	C1_DestIP:       "DestIP",
	C1_SrcPort:      "SrcPort",
	C1_DestPort:     "DestPort",
	C1_FileType:     "FileType",
	C1_FileSize:     "FileSize",
	C1_DataNum:      "DataNum",
	C1_DataType:     "DataType",
	C1_FileMD5:      "FileMD5",
	C1_GatherTime:   "GatherTime",
}

// C4字段索引
const (
	C4_CommandId = iota
	C4_LogID
	C4_HouseID
	C4_StrategyId
	C4_KeyWord
	C4_Features
	C4_AssetsNum
	C4_SrcIP
	C4_DestIP
	C4_ScrPort
	C4_DestPort
	C4_Domain
	C4_Url
	C4_DataDirection
	C4_Proto
	C4_FileType
	C4_FileSize
	C4_AttachMent
	C4_FileMD5
	C4_GatherTime
	C4_SrcCountry
	C4_SrcProvince
	C4_DstCountry
	C4_DstProvince
	C4_Max
)

var C4_Name = map[int]string{
	C4_CommandId:     "CommandId",
	C4_LogID:         "LogID",
	C4_HouseID:       "HouseID",
	C4_StrategyId:    "StrategyId",
	C4_KeyWord:       "KeyWord",
	C4_Features:      "Features",
	C4_AssetsNum:     "AssetsNum",
	C4_SrcIP:         "SrcIP",
	C4_DestIP:        "DestIP",
	C4_ScrPort:       "ScrPort",
	C4_DestPort:      "DestPort",
	C4_Domain:        "Domain",
	C4_Url:           "Url",
	C4_DataDirection: "DataDirection",
	C4_Proto:         "Proto",
	C4_FileType:      "FileType",
	C4_FileSize:      "FileSize",
	C4_AttachMent:    "AttachMent",
	C4_FileMD5:       "FileMD5",
	C4_GatherTime:    "GatherTime",
}

// A8字段索引
const (
	A8_LogId = iota
	A8_HouseId
	A8_DeviceType
	A8_DeviceId
	A8_IP
	A8_FileName
	A8_FileType
	A8_OperateType
	A8_OperateTime
	A8_LogType
	A8_Max
)

var A8_Name = map[int]string{
	A8_LogId:       "LogId",
	A8_HouseId:     "HouseId",
	A8_DeviceType:  "DeviceType",
	A8_DeviceId:    "DeviceId",
	A8_IP:          "IP",
	A8_FileName:    "FileName",
	A8_FileType:    "FileType",
	A8_OperateType: "OperateType",
	A8_OperateTime: "OperateTime",
	A8_LogType:     "LogType",
}

var (
	LogName = [IndexMax]string{
		"06c0",
		"06c1",
		"06c2",
		"06c3",
		"06c4",
		"04a8",
	}
)

var (
	TimeStr    string
	Manufactor string
)

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func PrintReportPrefix(ctx string) {
	fmt.Printf("======================================\n")
	fmt.Printf("%s\n", ctx)
	fmt.Printf("----------------\n")
}

func PrintReportSuffix(ctx string) {
	fmt.Printf("----------------\n")
	fmt.Printf("%s\n", ctx)
	fmt.Printf("======================================\n")
}

func init() {
	TimeStr = time.Now().Format("20060102")
}

func GrepFile(filename, str string) (string, error) {
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return "", err
	}
	defer file.Close()

	// 创建一个Scanner
	scanner := bufio.NewScanner(file)

	// 逐行读取文件内容
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Manufactor") {
			return line, nil
		}
	}

	return "", fmt.Errorf("未找到Manufactor配置项")
}

func GetManuInfo(fn, str string) error {
	manu, err := GrepFile(fn, str)
	if err != nil {
		return err
	}
	fs := strings.Split(manu, ":")
	if len(fs) != 2 {
		return fmt.Errorf("错误的配置项，请确认")
	}
	m := strings.ReplaceAll(fs[1], "\"", "")
	Manufactor = strings.TrimSpace(m)
	return nil
}
