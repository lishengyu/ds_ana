package fileproc

import (
	"bufio"
	"compress/gzip"
	"ds_ana/global"
	"ds_ana/logger"
	"ds_ana/telnetcmd"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type LogFields struct {
	LogID       string
	HouseID     string
	DeviceType  string
	DeviceID    string
	DeviceIP    string
	FileName    string
	FileType    string
	OperateType string
	OperateTime string
	LogType     string
}

type AuditFileInfo struct {
	LogType  global.LogType
	Filename string
}

type Template struct {
	FileName  string
	LogTemp   string
	LogFields LogFields
}

var seq uint64
var ErrDirNil = fmt.Errorf("dir is nil")

func generateLogID(deviceID, str string) string {
	atomic.AddUint64(&seq, 1)
	return fmt.Sprintf("%s1%06s%011d", str[:14], deviceID, atomic.LoadUint64(&seq))
}

func getOperateType(logType global.LogType) string {
	switch logType {
	case global.IndexC0:
		return "15"
	case global.IndexC1:
		return "16"
	case global.IndexC2:
		return "24"
	case global.IndexC3:
		return "17"
	case global.IndexC4:
		return "36"
	case global.IndexA8:
		return "35"
	default:
		return ""
	}
}

func getOperateTime(str string) int64 {
	ts := str[:14]

	t, err := time.ParseInLocation("20060102150405", ts, time.Local)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func LogLine2Fields(line string) (LogFields, error) {
	fields := strings.Split(line, "|")
	if len(fields) == 9 {
		return LogFields{
			LogID:       fields[0],
			HouseID:     fields[1],
			DeviceType:  fields[2],
			DeviceID:    fields[3],
			DeviceIP:    fields[4],
			FileName:    fields[5],
			FileType:    fields[6],
			OperateType: fields[7],
			OperateTime: fields[8],
		}, nil
	} else if len(fields) == 10 {
		return LogFields{
			LogID:       fields[0],
			HouseID:     fields[1],
			DeviceType:  fields[2],
			DeviceID:    fields[3],
			DeviceIP:    fields[4],
			FileName:    fields[5],
			FileType:    fields[6],
			OperateType: fields[7],
			OperateTime: fields[8],
			LogType:     fields[9],
		}, nil
	}

	return LogFields{}, fmt.Errorf("audit log line format error: %s", line)
}

func Fields2LogLine(fields LogFields) string {
	if fields.LogType == "" {
		return strings.Join([]string{
			fields.LogID,
			fields.HouseID,
			fields.DeviceType,
			fields.DeviceID,
			fields.DeviceIP,
			fields.FileName,
			fields.FileType,
			fields.OperateType,
			fields.OperateTime,
		}, "|") + "\n"
	} else {
		return strings.Join([]string{
			fields.LogID,
			fields.HouseID,
			fields.DeviceType,
			fields.DeviceID,
			fields.DeviceIP,
			fields.FileName,
			fields.FileType,
			fields.OperateType,
			fields.OperateTime,
			fields.LogType,
		}, "|") + "\n"
	}
}

func getFirstLine(filename string) string {
	// 读取tar.gz文件首行内容
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return ""
	}
	defer gr.Close()

	scanner := bufio.NewScanner(gr)
	if !scanner.Scan() {
		return ""
	}
	return scanner.Text()
}

var uniqID uint64 = 3333

func replaceFilenameByPath(fn, replace string) string {
	dir := filepath.Dir(fn)
	filename := filepath.Base(strings.TrimSuffix(fn, ".tar.gz"))
	fields := strings.Split(filename, "+")
	if len(fields) != global.FN_END {
		return filename + ".bak"
	}

	old := fields[global.FN_Date]

	if len(old) != 20 {
		return filename + ".bak"
	}

	// 如果已经存在了，添加序号
	for i := 0; i < 100; i++ {
		atomic.AddUint64(&uniqID, 1)
		if uniqID > 999999 {
			uniqID = 1
		}
		fields[global.FN_Date] = fmt.Sprintf("%s%06d", replace[:14], uniqID)
		fullDir := filepath.Join(dir, strings.Join(fields, "+")+".tar.gz")

		_, ok := FileNameMap[fullDir]
		if ok {
			continue
		}

		return fullDir
	}

	return filename + ".bak"
}

func newLogField(fa AuditFileInfo, temp Template, str string, operateType string) LogFields {
	return LogFields{
		LogID:       generateLogID(telnetcmd.Devinfo.Dev_No, str),
		HouseID:     temp.LogFields.HouseID,
		DeviceType:  temp.LogFields.DeviceType,
		DeviceID:    temp.LogFields.DeviceID,
		DeviceIP:    temp.LogFields.DeviceIP,
		FileName:    strings.Replace(fa.Filename, "data", "udpi_log", 1),
		FileType:    getOperateType(fa.LogType),
		OperateType: operateType,
		OperateTime: fmt.Sprintf("%d", getOperateTime(str)),
	}
}

func NewLogFields(fa AuditFileInfo, temp Template, str string) []LogFields {
	return []LogFields{
		newLogField(fa, temp, str, "1"),
		newLogField(fa, temp, str, "3"),
	}
}

func getFileNameMondifyTime(filename string) string {
	fi, err := os.Stat(filename)
	if err != nil {
		return time.Now().Format("20060102150405") + "111111"
	}
	return fi.ModTime().Format("20060102150405") + "111111"
}

// 从文件名或者文件中提取时间
func getTimeStrByFile(afi AuditFileInfo) string {
	fields := strings.Split(filepath.Base(afi.Filename), "+")
	switch afi.LogType {
	case global.IndexC0, global.IndexC1, global.IndexC4:
		if len(fields) != int(global.FN_Max) {
			return getFileNameMondifyTime(afi.Filename)
		}
		return fields[global.FN_Date]
	case global.IndexC2:
		if len(fields) != int(global.FN_C2_Max) {
			return getFileNameMondifyTime(afi.Filename)
		}
		return fields[global.FN_Date]
	case global.IndexC3:
		return getFileNameMondifyTime(afi.Filename)
	default:
		return getFileNameMondifyTime(afi.Filename)
	}
}

func extractAuditLog(dir string) (Template, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return Template{}, err
	}
	if len(files) == 0 {
		return Template{}, ErrDirNil
	}

	nums := len(files)

	for i := nums - 1; i >= 0; i-- {
		if files[i].IsDir() {
			continue
		}

		filename := files[i].Name()
		if strings.HasPrefix(filename, "0x31") && strings.HasSuffix(filename, ".tar.gz") {
			line := getFirstLine(filepath.Join(dir, filename))
			if line == "" {
				continue
			}
			return Template{FileName: filename, LogTemp: line}, nil
		}
	}

	return Template{}, ErrDirNil
}

func compressFile(srcFile, dstFile string) error {
	defer os.Remove(srcFile)
	// 打开源文件
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer src.Close()

	// 创建目标文件
	dst, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	// 压缩文件
	gz := gzip.NewWriter(dst)
	defer gz.Close()

	// 复制文件内容
	_, err = io.Copy(gz, src)
	if err != nil {
		return err
	}

	return nil
}

func newAuditFile(fa AuditFileInfo, temp Template, bakDir string) error {
	str := getTimeStrByFile(fa)
	filename := replaceFilenameByPath(temp.FileName, str)

	logs := NewLogFields(fa, temp, str)

	logger.Logger.Printf("生成审计日志文件: %s, str: %s, filename: %s, logType: %d, bakDir: %s\n", filename, str, fa.Filename, fa.LogType, bakDir)
	textFile := filepath.Join(bakDir, strings.TrimSuffix(filepath.Base(filename), ".tar.gz"))
	TargzFile := filepath.Join(bakDir, filepath.Base(filename))

	file, err := os.Create(textFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, log := range logs {
		_, err = file.WriteString(Fields2LogLine(log))
		if err != nil {
			return err
		}
	}

	// 压缩文件
	err = compressFile(textFile, TargzFile)
	if err != nil {
		return err
	}

	return nil
}

func updateDirToAbs(fileToAudit []AuditFileInfo, gpath string, dateList []string, bak bool) []AuditFileInfo {
	var result []AuditFileInfo
	var logTypeName string

	for _, fa := range fileToAudit {
		switch fa.LogType {
		case global.IndexC0:
			logTypeName = global.IdentifyName
		case global.IndexC1:
			logTypeName = global.MonitorName
		case global.IndexC2:
			logTypeName = global.IdentifyRule
		case global.IndexC3:
			logTypeName = global.EvidenceName
		case global.IndexC4:
			logTypeName = global.KeywordName
		default:
			fmt.Printf("logType: %d, not support\n", fa.LogType)
			continue
		}

		dirs := getPathsByParam(gpath, logTypeName, dateList, bak)

		var found bool
		var fullName string
		for _, dir := range dirs {
			// 在当前路径下查找该文件名是否存在
			_, err := os.Stat(filepath.Join(dir, fa.Filename))
			if err == nil {
				fullName = filepath.Join(dir, fa.Filename)
				found = true
				break
			}
		}

		if found {
			result = append(result, AuditFileInfo{
				Filename: fullName,
				LogType:  fa.LogType,
			})
		} else {
			fmt.Printf("file not found: %s in dir: %v\n", fa.Filename, dirs)
		}
	}

	if len(result) != len(fileToAudit) {
		fmt.Printf("获取所有待补报的文件有遗漏, report: %d, want: %d\n", len(result), len(fileToAudit))
	}

	return result
}

// 生成审计日志文件
func GenAuditByFileSlice(fileToAudit []AuditFileInfo, gpath string, dateList []string, bak bool) error {
	var auditPaths = getPathsByParam(gpath, global.AuditName, dateList, bak)

	// 获取审计日志文件名和日志模板示例
	var err error
	var found bool
	var temp Template
	for _, auditPath := range auditPaths {
		temp, err = extractAuditLog(auditPath)
		if err == nil {
			found = true
		} else if err != ErrDirNil {
			return err
		}
	}

	if !found {
		return fmt.Errorf("no audit log found in %v", auditPaths)
	}

	os.MkdirAll("ds_audit_report", 0755)
	temp.LogFields, err = LogLine2Fields(temp.LogTemp)
	if err != nil {
		return err
	}

	fileToAudit = updateDirToAbs(fileToAudit, gpath, dateList, bak)

	for _, fa := range fileToAudit {
		err = newAuditFile(fa, temp, "ds_audit_report")
		if err != nil {
			return err
		}
	}

	return nil
}
