package global

import (
	"fmt"
	"os"
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
)

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
)

var (
	LogName = [IndexMax]string{
		"识别",
		"监测",
		"规则",
		"样本",
		"关键字",
		"审计日志",
	}
)

var (
	TimeStr string
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
