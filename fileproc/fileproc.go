package fileproc

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
	Data        string
	MatchNum    string
	Application int
	Business    int
	CrossBoard  string
}

type SampleC1Info struct {
	Event    string
	L7Proto  int
	FileType int
	FileSize string
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

func LogidMapStoreInc(m *sync.Map, id string) {
	value, ok := m.LoadOrStore(id, 1)
	if ok {
		cnt := value.(int) + 1
		m.Store(id, cnt)
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

func fieldsNullZero(key string) bool {
	if key == "" || key == "0" {
		return false
	}
	return true
}

func fieldsIntZero(num int) bool {
	if num == 0 {
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

func fieldsHttp(proto, key string) bool {
	if proto == "1" {
		if key == "" {
			return false
		}
	}

	return true
}

func fieldsEvent(id, subid string) bool {
	if id == "" || subid == "" {
		return false
	}

	//校验正确性，存map表

	return true
}

func fieldsDataType(id string) bool {
	if id != "1" && id != "2" {
		return false
	}
	return true
}

func feildsLogid(key string) bool {
	if key == "" || len(key) != 32 {
		return false
	}

	LogidMapStoreInc(&LogidMap, key)

	return true
}

func fieldsMd5(key string, logType int) bool {
	md5 := strings.ToUpper(key)
	Md5Map[logType].Store(md5, 1)
	return true
}

func fieldsFileType(key string) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C10_DICT[id]
	if !ok {
		//fmt.Printf("app proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&FileTypeStat, "illegal:"+key)
		return false
	}

	LogidMapStoreInc(&FileTypeStat, value)
	return true
}

func fieldsAppProto(key string) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C3_DICT[id]
	if !ok {
		//fmt.Printf("app proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&AppProtoStat, "illegal:"+key)
		return false
	}

	LogidMapStoreInc(&AppProtoStat, value)
	return true
}

func fieldsBusProto(key string) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C4_DICT[id]
	if !ok {
		//fmt.Printf("business proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&BusProtoStat, "illegal:"+key)
		return false
	}

	LogidMapStoreInc(&BusProtoStat, value)
	return true
}

func fieldsDataProto(key string) bool {
	id, err := strconv.Atoi(key)
	if err != nil {
		fmt.Printf("transfer string to int failed: %v\n", err)
		return false
	}

	value, ok := dict.C9_DICT[id]
	if !ok {
		//fmt.Printf("business proto value is not in rfc: [%d]\n", id)
		LogidMapStoreInc(&DataProtoStat, "illegal:"+key)
		return false
	}

	LogidMapStoreInc(&DataProtoStat, value)
	return true
}

func procC0Fields(fs []string) (int, bool) {
	if valid := feildsLogid(fs[global.C0_LogID]); !valid {
		return global.C0_LogID, false
	}

	if valid := fieldsNull(fs[global.C0_CommandID]); !valid {
		return global.C0_CommandID, false
	}

	if valid := fieldsNull(fs[global.C0_House_ID]); !valid {
		return global.C0_House_ID, false
	}

	if valid := fieldsFileType(fs[global.C0_DataFileType]); !valid {
		return global.C0_DataFileType, false
	}

	if valid := fieldsNull(fs[global.C0_AssetsSize]); !valid {
		return global.C0_AssetsSize, false
	}

	if valid := fieldsNull(fs[global.C0_AssetsNum]); !valid {
		return global.C0_AssetsNum, false
	}

	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	if valid := fieldsIntZero(datainfoGroup); !valid {
		return global.C0_DataInfoNum, false
	}

	offset := 0
	if datainfoGroup > 0 {
		offset = (datainfoGroup - 1) * 3
	}

	for i := 0; i < offset+3; i++ {
		if valid := fieldsDataInfo(fs[global.C0_DataType+i], i%3); !valid {
			return global.C0_DataType + i%3, false
		}
	}

	if valid := fieldsUpload(fs[global.C0_IsUploadFile+offset]); !valid {
		return global.C0_IsUploadFile, false
	}

	if valid := fieldsMd5(fs[global.C0_FileMD5+offset], global.IndexC0); !valid {
		return global.C0_FileMD5, false
	}

	if valid := fieldsNull(fs[global.C0_CurTime+offset]); !valid {
		return global.C0_CurTime, false
	}

	if valid := fieldsNull(fs[global.C0_SrcIP+offset]); !valid {
		return global.C0_SrcIP, false
	}

	if valid := fieldsNull(fs[global.C0_DestIP+offset]); !valid {
		return global.C0_DestIP, false
	}

	if valid := fieldsNull(fs[global.C0_SrcPort+offset]); !valid {
		return global.C0_SrcPort, false
	}

	if valid := fieldsNull(fs[global.C0_DestPort+offset]); !valid {
		return global.C0_DestPort, false
	}

	if valid := fieldsL4Proto(fs[global.C0_ProtocolType+offset]); !valid {
		return global.C0_ProtocolType, false
	}

	if valid := fieldsAppProto(fs[global.C0_ApplicationProtocol+offset]); !valid {
		return global.C0_ApplicationProtocol, false
	}

	if valid := fieldsBusProto(fs[global.C0_BusinessProtocol+offset]); !valid {
		return global.C0_BusinessProtocol, false
	}

	if valid := fieldsMatch(fs[global.C0_IsMatchEvent+offset]); !valid {
		return global.C0_IsMatchEvent, false
	}

	return 0, true
}

func procC1Fields(fs []string) (int, bool) {
	if valid := feildsLogid(fs[global.C1_LogID]); !valid {
		return global.C1_LogID, false
	}

	if valid := fieldsNull(fs[global.C1_CommandId]); !valid {
		return global.C1_CommandId, false
	}

	if valid := fieldsNull(fs[global.C1_House_ID]); !valid {
		return global.C1_House_ID, false
	}

	if valid := fieldsDataProto(fs[global.C1_Proto]); !valid {
		return global.C1_Proto, false
	}

	if valid := fieldsHttp(fs[global.C1_Proto], fs[global.C1_Domain]); !valid {
		return global.C1_Domain, false
	}

	if valid := fieldsHttp(fs[global.C1_Proto], fs[global.C1_Url]); !valid {
		return global.C1_Url, false
	}

	if valid := fieldsEvent(fs[global.C1_EventTypeID], fs[global.C1_EventSubType]); !valid {
		return global.C1_EventTypeID, false
	}

	if valid := fieldsNull(fs[global.C1_SrcIP]); !valid {
		return global.C1_SrcIP, false
	}

	if valid := fieldsNull(fs[global.C1_DestIP]); !valid {
		return global.C1_DestIP, false
	}

	if valid := fieldsNull(fs[global.C1_SrcPort]); !valid {
		return global.C1_SrcPort, false
	}

	if valid := fieldsNull(fs[global.C1_DestPort]); !valid {
		return global.C1_DestPort, false
	}

	if valid := fieldsFileType(fs[global.C1_FileType]); !valid {
		return global.C1_FileType, false
	}

	if valid := fieldsNull(fs[global.C1_FileSize]); !valid {
		return global.C1_FileSize, false
	}

	if valid := fieldsNull(fs[global.C1_DataNum]); !valid {
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
	if valid := fieldsMd5(fs[global.C4_FileMD5], global.IndexC4); !valid {
		return global.C4_FileMD5, false
	}

	return 0, true
}

func recordC0Info(fs []string) {
	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	var data string
	for i := 0; i < datainfoGroup; i++ {
		if i == 0 {
			data = fs[global.C0_DataType+i*3]
		} else {
			data = data + "|" + fs[global.C0_DataType+i*3]
		}
		data += fs[global.C0_DataType+i*3]
		data += "," + fs[global.C0_DataType+i*3+1]
		data += "," + fs[global.C0_DataType+i*3+2]
	}
	offset := 0
	if datainfoGroup > 0 {
		offset = (datainfoGroup - 1) * 3
	}

	matchNum := fs[global.C0_AssetsNum]
	application, _ := strconv.Atoi(fs[global.C0_ApplicationProtocol+offset])
	business, _ := strconv.Atoi(fs[global.C0_BusinessProtocol+offset])
	cross := fs[global.C0_IsMatchEvent+offset]

	info := SampleC0Info{
		Data:        data,
		MatchNum:    matchNum,
		Application: application,
		Business:    business,
		CrossBoard:  cross,
	}

	SampleMapUpdateC0(&SampleMap, fs[global.C0_FileMD5+offset], info)
	return
}

func recordC1Info(fs []string) {
	l7Proto, _ := strconv.Atoi(fs[global.C1_Proto])
	fileType, _ := strconv.Atoi(fs[global.C1_FileType])

	info := SampleC1Info{
		Event:    fs[global.C1_EventTypeID] + "," + fs[global.C1_EventSubType],
		L7Proto:  l7Proto,
		FileType: fileType,
		FileSize: fs[global.C1_FileSize],
	}

	SampleMapUpdateC1(&SampleMap, fs[global.C1_FileMD5], info)
	return
}

func procC0Ctx(line, filename string) {
	fs := strings.Split(line, "|")
	if len(fs) < 24 {
		//fmt.Printf("invalid log:[%s]\n", line)
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
			Filenmae: filename,
		}
		C0_CheckMap[line] = info
		incLogInvalidCnt(global.IndexC0)
		return
	}
	datainfoGroup, _ := strconv.Atoi(fs[global.C0_DataInfoNum])
	if datainfoGroup > 1 {
		nums := 24 + (datainfoGroup-1)*3
		if len(fs) != nums {
			//fmt.Printf("invalid log:[%s]\n", line)
			info := CheckInfo{
				Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
				Filenmae: filename,
			}
			C0_CheckMap[line] = info
			incLogInvalidCnt(global.IndexC0)
			return
		}
	} else {
		if len(fs) != 24 {
			//fmt.Printf("invalid log:[%s]\n", line)
			info := CheckInfo{
				Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
				Filenmae: filename,
			}
			C0_CheckMap[line] = info
			incLogInvalidCnt(global.IndexC0)
			return
		}
	}

	if index, valid := procC0Fields(fs); valid {
		recordC0Info(fs)
		incLogValidCnt(global.IndexC0)
	} else {
		//fmt.Printf("invalid log:[%s]\n", line)
		info := CheckInfo{
			Reason:   fmt.Sprintf("第%d个字段非法", index+1),
			Filenmae: filename,
		}
		C0_CheckMap[line] = info
		incLogInvalidCnt(global.IndexC0)
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
		C1_CheckMap[line] = info
		incLogInvalidCnt(global.IndexC1)
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
		C1_CheckMap[line] = info
		incLogInvalidCnt(global.IndexC1)
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
		//fmt.Printf("invalid log:[%s]\n", line)
		info := CheckInfo{
			Reason:   fmt.Sprintf("字段个数%d不符", len(fs)),
			Filenmae: filename,
		}
		C4_CheckMap[line] = info
		incLogInvalidCnt(global.IndexC4)
		return
	}

	if index, valid := procC4Fields(fs); valid {
		incLogValidCnt(global.IndexC4)
	} else {
		//fmt.Printf("invalid log:[%s]\n", line)
		info := CheckInfo{
			Reason:   fmt.Sprintf("第%d个字段非法", index+1),
			Filenmae: filename,
		}
		C4_CheckMap[line] = info
		incLogInvalidCnt(global.IndexC4)
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
	//fmt.Printf("DS Identify path: [%s]\n", path)
	err := filepath.WalkDir(path, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("filepath walk failed:%v\n", err)
			return err
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

	err := filepath.WalkDir(dir, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("filepath walk failed:%v\n", err)
			return err
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

func AnalyzeLogFile(c0, c1, c3, c4, dst string) {
	cur := time.Now()

	var wg sync.WaitGroup

	//获取取证文件MD5值
	wg.Add(1)
	go ProcEvidencePath(c3, &wg)

	//处理识别话单
	wg.Add(1)
	go ProcLogPath(c0, &wg, global.IndexC0)

	//处理监测话单
	wg.Add(1)
	go ProcLogPath(c1, &wg, global.IndexC1)

	//处理关键字话单
	wg.Add(1)
	go ProcLogPath(c4, &wg, global.IndexC4)

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
	os.Rename(dst, dst+"_bak")
	if err := excel.SaveAs(dst); err != nil {
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
}
