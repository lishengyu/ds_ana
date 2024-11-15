package fileproc

import (
	"ds_ana/dict"
	"ds_ana/global"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/xuri/excelize/v2"
)

func printfItemResult(item, res string, succ int) {
	if succ == 0 {
		fmt.Printf("\t[PASS] %s:\t%s\n", item, res)
	} else {
		fmt.Printf("\t[FAIL] %s:\t%s\n", item, res)
	}
}

func CheckMd5(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [校验话单和取证文件]\n", index)

	_, err := ex.NewSheet("MD5")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("MD5")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
		if err = ex.SetColWidth("MD5", "A", "B", 32); err != nil {
			fmt.Printf("set col width failed: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"MD5", "原因"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	record := 0
	invalid := 0
	row := 0
	Md5Map[global.IndexC0].Range(func(key, value interface{}) bool {
		record++
		_, ok := Md5Map[global.IndexC3].Load(key)
		if !ok {
			tmp := []interface{}{
				key,
				"识别话单C0 缺失取证文件",
			}
			invalid++
			row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		}
		return true
	})

	var res string
	if invalid == 0 {
		res = fmt.Sprintf("total %d records", record)
	} else {
		res = fmt.Sprintf("total %d recrods; invalid %d records", record, invalid)
	}
	printfItemResult("识别话单C0", res, invalid)

	record = 0
	invalid = 0
	Md5Map[global.IndexC1].Range(func(key, value interface{}) bool {
		record++
		_, ok := Md5Map[global.IndexC3].Load(key)
		if !ok {
			tmp := []interface{}{
				key,
				"监测话单C1 缺失取证文件",
			}
			invalid++
			row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		}
		return true
	})

	if invalid == 0 {
		res = fmt.Sprintf("total %d records", record)
	} else {
		res = fmt.Sprintf("total %d recrods; invalid %d records", record, invalid)
	}
	printfItemResult("识别话单C1", res, invalid)

	record = 0
	invalid = 0
	Md5Map[global.IndexC4].Range(func(key, value interface{}) bool {
		record++
		_, ok := Md5Map[global.IndexC3].Load(key)
		if !ok {
			tmp := []interface{}{
				key,
				"关键词话单C4 缺失取证文件",
			}
			invalid++
			row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		}
		return true
	})

	if invalid == 0 {
		res = fmt.Sprintf("total %d records", record)
	} else {
		res = fmt.Sprintf("total %d recrods; invalid %d records", record, invalid)
	}
	printfItemResult("关键词话单C4", res, invalid)

	//C3
	record = 0
	invalid = 0
	Md5Map[global.IndexC3].Range(func(key, value interface{}) bool {
		record++
		_, ok1 := Md5Map[global.IndexC0].Load(key)
		_, ok2 := Md5Map[global.IndexC1].Load(key)
		_, ok3 := Md5Map[global.IndexC4].Load(key)

		if (ok1 && ok2) || ok3 {
			return true
		}

		var str string
		if !ok1 && !ok2 {
			str = "取证文件C3 缺失C0/C1话单文件"
		} else if !ok1 {
			str = "取证文件C3 缺失C0话单文件"
		} else if !ok2 {
			str = "取证文件C3 缺失C1话单文件"
		}
		tmp := []interface{}{
			key,
			str,
		}
		invalid++
		row++
		_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		return true
	})

	if invalid == 0 {
		res = fmt.Sprintf("total %d records", record)
	} else {
		res = fmt.Sprintf("total %d recrods; invalid %d records", record, invalid)
	}
	printfItemResult("取证文件C3", res, invalid)

	return
}

func CheckLogCnt(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [日志条目数统计]\n", index)

	err := ex.SetSheetName("Sheet1", "日志统计")
	//_, err := ex.NewSheet("日志统计")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("日志统计")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"日志类型", "文件数量", "日志数量", "有效日志", "空行", "错误日志"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	row := 2
	for i, cnt := range FileStat {
		tmp := []interface{}{
			global.LogName[i],
			cnt.FileNum,
			cnt.LogNum.AllCnt,
			cnt.LogNum.ValidCnt,
			cnt.LogNum.NullCnt,
			cnt.LogNum.InvalidCnt,
		}
		if err := streamWriter.SetRow("A"+strconv.Itoa(row), tmp); err != nil {
			fmt.Printf("stream writer write failed: %v\n", err)
			return
		}
		row++
	}

	return
}

func CheckLogId(ex *excelize.File, index int, name string, m *sync.Map) {
	fmt.Printf("Check Item %03d [%s唯一性校验]\n", index, name)

	_, err := ex.NewSheet(name)
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter(name)
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{name, "出现次数"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	record := 0
	invalid := 0
	m.Range(func(key, value interface{}) bool {
		record++
		if value != 1 {
			tmp := []interface{}{
				key,
				value,
			}
			invalid++
			_ = streamWriter.SetRow("A"+strconv.Itoa(invalid+1), tmp)
		}
		return true
	})

	var res string
	if invalid == 0 {
		res = fmt.Sprintf("total %d records", record)
	} else {
		res = fmt.Sprintf("total %d records; invalid %d records", record, invalid)
	}
	printfItemResult(fmt.Sprintf("%s唯一性校验", name), res, invalid)

	return
}

func checkDict(ex *excelize.File, m *sync.Map, name string) (int, int) {
	_, err := ex.NewSheet(name)
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return 0, 0
	}

	streamWriter, err := ex.NewStreamWriter(name)
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return 0, 0
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"类型", "计数"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return 0, 0
	}

	record := 0
	invalid := 0
	m.Range(func(key, value interface{}) bool {
		record++
		tmp := []interface{}{
			key,
			value,
		}
		if strings.Contains(key.(string), "illegal:") {
			invalid++
		}
		_ = streamWriter.SetRow("A"+strconv.Itoa(record+1), tmp)
		return true
	})

	return record, invalid
}

func CheckDict(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [附录表校验]\n", index)

	total, invalid := checkDict(ex, &AppProtoStat, "C3表")
	res := fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("应用层协议类型代码表C3", res, invalid)

	total, invalid = checkDict(ex, &BusProtoStat, "C4表")
	res = fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("业务层协议类型代码表C4", res, invalid)

	total, invalid = checkDict(ex, &DataProtoStat, "C9表")
	res = fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("数据识别协议列表C9", res, invalid)

	total, invalid = checkDict(ex, &FileTypeStat, "C10表")
	res = fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("数据识别文件格式类别C10", res, invalid)

	return
}

func CheckC0LogMap(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [C0话单必填项校验]\n", index)

	_, err := ex.NewSheet("识别话单")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("识别话单")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"原始日志", "错误原因", "文件名"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	total := 0
	for key, value := range C0_CheckMap {
		tmp := []interface{}{
			key,
			value.Reason,
			value.Filenmae,
		}
		total++
		_ = streamWriter.SetRow("A"+strconv.Itoa(total+1), tmp)
	}

	var res string
	if total == 0 {
		res = fmt.Sprintf("Pass")
	} else {
		res = fmt.Sprintf("invalid %d records", total)
	}
	printfItemResult("C0话单合法性校验", res, total)

	return
}

func CheckC1LogMap(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [C1话单必填项校验]\n", index)

	_, err := ex.NewSheet("监测话单")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("监测话单")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"原始日志", "错误原因", "文件名"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	total := 0
	for key, value := range C1_CheckMap {
		tmp := []interface{}{
			key,
			value.Reason,
			value.Filenmae,
		}
		total++
		_ = streamWriter.SetRow("A"+strconv.Itoa(total+1), tmp)
	}

	var res string
	if total == 0 {
		res = fmt.Sprintf("Pass")
	} else {
		res = fmt.Sprintf("invalid %d records", total)
	}
	printfItemResult("C1话单合法性校验", res, total)

	return
}

func genExlTitle() []interface{} {
	title := []interface{}{
		"MD5",
		"文件类型",
		"文件大小(KB)",
		"L7Proto",
		"Application",
		"Business",
		"是否跨境",
		"匹配次数",
		"识别结果",
		"监测风险",
	}

	return title
}

func genExlLine(key, value any) []interface{} {
	md5 := key.(string)
	info := value.(*SampleMapValue)

	var data string
	var matchnum int
	var app string
	var business string
	var cross string

	for _, v := range info.C0Info {
		for _, m := range v.Data {
			if data == "" {
				data = fmt.Sprintf("%d|%d|%d,%d", m.Class, m.Level, m.Rule, m.Hit)
			} else {
				data += fmt.Sprintf("|%d|%d|%d,%d", m.Class, m.Level, m.Rule, m.Hit)
			}
		}

		matchnum = v.MatchNum
		app = dict.C3_DICT[v.Application]
		business = dict.C4_DICT[v.Business]
		if v.CrossBoard == 0 {
			cross = "是"
		} else {
			cross = "否"
		}
	}

	var risk string
	var l7Proto string
	var fileType string
	var fileSize string
	for i, v := range info.C1Info {
		if i == 0 {
			risk = fmt.Sprintf("%d|%d", v.Event.RiskType, v.Event.RiskSubType)
		} else {
			risk += fmt.Sprintf("|%d|%d", v.Event.RiskType, v.Event.RiskSubType)
		}
		l7Proto = dict.C9_DICT[v.L7Proto]
		fileType = dict.C10_DICT[v.FileType]
		fileSize = v.FileSize
	}

	tmp := []interface{}{
		md5,
		fileType,
		fileSize,
		l7Proto,
		app,
		business,
		cross,
		matchnum,
		data,
		risk,
	}

	return tmp
}

func RecordSample(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [记录所有样本扫描信息]\n", index)

	_, err := ex.NewSheet("Sample")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("Sample")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	title := genExlTitle()

	if err := streamWriter.SetRow("A1", title); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	record := 0
	SampleMap.Range(func(key, value interface{}) bool {
		record++
		tmp := genExlLine(key, value)
		_ = streamWriter.SetRow("A"+strconv.Itoa(record+1), tmp)
		return true
	})

	res := fmt.Sprintf("total %d records", record)
	printfItemResult("样本扫描信息", res, 0)

	return
}

func CheckRelation(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [校验识别和监测话单关联字段]\n", index)

	_, err := ex.NewSheet("C0_C1")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("C0_C1")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
		if err = ex.SetColWidth("MD5", "A", "B", 32); err != nil {
			fmt.Printf("set col width failed: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"MD5", "原因"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	record := 0
	invalid := 0
	row := 0
	nummap := make(map[int]int)
	SampleMap.Range(func(key, value interface{}) bool {
		record++
		md5 := key.(string)
		info := value.(*SampleMapValue)
		nummap = map[int]int{}
		for _, v := range info.C0Info {
			nummap[v.MatchNum]++
		}
		for _, v := range info.C1Info {
			nummap[v.DataNum]++
		}

		if len(nummap) != 1 {
			tmp := []interface{}{
				md5,
				"识别、监测话单中敏感信息数量不一致",
			}
			invalid++
			row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		}

		cross := 0
		eflag := false
		for i, v := range info.C0Info {
			if i == 0 {
				cross = v.CrossBoard
			} else {
				if cross != v.CrossBoard {
					eflag = true
					break
				}
			}
		}
		if eflag {
			tmp := []interface{}{
				md5,
				"识别话单中的跨境字段有误",
			}
			invalid++
			row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		}

		eflag = false
		if cross == 0 {
			//跨境
			for _, v := range info.C1Info {
				if v.Event.RiskType != 400 {
					eflag = true
					break
				}
			}
		} else {
			for _, v := range info.C1Info {
				if v.Event.RiskType < 200 || (v.Event.RiskType > 203 && v.Event.RiskType != 999) {
					eflag = true
					break
				}
			}
		}
		if eflag {
			tmp := []interface{}{
				md5,
				"识别话单跨境字段和风险类型不符",
			}
			invalid++
			row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(row+1), tmp)
		}

		return true
	})

	var res string
	if invalid == 0 {
		res = fmt.Sprintf("total %d records", record)
	} else {
		res = fmt.Sprintf("total %d recrods; invalid %d records", record, invalid)
	}
	printfItemResult("敏感信息数量/跨境校验", res, invalid)

	return
}

func GenerateResult(excel *excelize.File) {
	checkNum := 1
	CheckMd5(excel, checkNum)
	checkNum++
	CheckLogCnt(excel, checkNum)
	checkNum++
	CheckLogId(excel, checkNum, "Logid", &LogidMap)
	checkNum++
	CheckLogId(excel, checkNum, "审计Logid", &AuditLogidMap)
	checkNum++
	CheckDict(excel, checkNum)
	checkNum++
	CheckC0LogMap(excel, checkNum)
	checkNum++
	CheckC1LogMap(excel, checkNum)
	checkNum++
	RecordSample(excel, checkNum)
	checkNum++
	CheckRelation(excel, checkNum)

	return
}
