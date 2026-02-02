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
	AuditName    = "ds_audit_log"
	IdentifyRule = "ds_data_identify_rules"
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
	FN_C2_Max
	FN_END = 7
)

var FN_Fields_Name = map[int]string{
	FN_Version:  "Version",
	FN_Module:   "模块名称",
	FN_Filetype: "文件类型",
	FN_Site:     "设备部署位置",
	FN_Manu:     "上报厂家名",
	FN_Devno:    "上报设备编号",
	FN_Date:     "上报日期",
	FN_END:      "结束标志",
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

const (
	C9_ProtoHTTP = 1
)

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
	TimeList   []string
	Manufactor string
	IsCtcc     bool
)

func GetFileNameFieldsNum(logType int) int {
	if logType == IndexC2 {
		return FN_C2_Max
	}
	return FN_Max
}

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

// ParseTimeRange 解析时间范围，支持单日、多日范围和逗号分隔
func ParseTimeRange(timeStr string) ([]string, error) {
	if timeStr == "" {
		return []string{}, nil
	}

	// 检查是否包含逗号分隔
	if strings.Contains(timeStr, ",") {
		dates := strings.Split(timeStr, ",")
		var result []string
		for _, date := range dates {
			date = strings.TrimSpace(date)
			if len(date) == 8 {
				result = append(result, date)
			} else if strings.Contains(date, "-") {
				// 处理日期范围
				rangeDates, err := parseDateRange(date)
				if err != nil {
					return nil, err
				}
				result = append(result, rangeDates...)
			}
		}
		return result, nil
	}

	// 检查是否包含日期范围
	if strings.Contains(timeStr, "-") {
		return parseDateRange(timeStr)
	}

	// 单日情况
	if len(timeStr) == 8 {
		return []string{timeStr}, nil
	}

	return nil, fmt.Errorf("无效的日期格式: %s", timeStr)
}

// parseDateRange 解析日期范围
func parseDateRange(dateRange string) ([]string, error) {
	parts := strings.Split(dateRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的日期范围格式: %s", dateRange)
	}

	startDate := strings.TrimSpace(parts[0])
	endDate := strings.TrimSpace(parts[1])

	if len(startDate) != 8 || len(endDate) != 8 {
		return nil, fmt.Errorf("日期格式必须为8位数字: %s", dateRange)
	}

	startTime, err := time.Parse("20060102", startDate)
	if err != nil {
		return nil, fmt.Errorf("无效的开始日期: %s", startDate)
	}

	endTime, err := time.Parse("20060102", endDate)
	if err != nil {
		return nil, fmt.Errorf("无效的结束日期: %s", endDate)
	}

	if startTime.After(endTime) {
		return nil, fmt.Errorf("开始日期不能晚于结束日期: %s", dateRange)
	}

	var dates []string
	for d := startTime; !d.After(endTime); d = d.AddDate(0, 0, 1) {
		dates = append(dates, d.Format("20060102"))
	}

	return dates, nil
}

// IsDateInRange 检查日期是否在指定的时间范围内
func IsDateInRange(dateStr string) bool {

	for _, validDate := range TimeList {
		if strings.HasPrefix(dateStr, validDate) {
			return true
		}
	}

	return false
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
