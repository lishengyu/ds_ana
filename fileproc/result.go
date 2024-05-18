package fileproc

import (
	"ds_ana/dict"
	"ds_ana/global"
	"fmt"
	"strconv"
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

		if ok1 && ok2 {
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

func CheckLogId(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [LogId唯一性校验]\n", index)

	_, err := ex.NewSheet("Logid")
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter("Logid")
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}
	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"Logid", "出现次数"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	record := 0
	invalid := 0
	LogidMap.Range(func(key, value interface{}) bool {
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
	printfItemResult("Logid唯一性校验", res, invalid)

	return
}

func checkDict(ex *excelize.File, m sync.Map, name string) (int, int) {
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
		if key == "illegal" {
			invalid++
		}
		_ = streamWriter.SetRow("A"+strconv.Itoa(record+1), tmp)
		return true
	})

	return record, invalid
}

func CheckDict(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [附录表校验]\n", index)

	total, invalid := checkDict(ex, AppProtoStat, "C3表")
	res := fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("应用层协议类型代码表C3", res, invalid)

	total, invalid = checkDict(ex, BusProtoStat, "C4表")
	res = fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("业务层协议类型代码表C4", res, invalid)

	total, invalid = checkDict(ex, DataProtoStat, "C9表")
	res = fmt.Sprintf(" total %d records; invalid %d records", total, invalid)
	printfItemResult("数据识别协议列表C9", res, invalid)

	total, invalid = checkDict(ex, FileTypeStat, "C10表")
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
	var matchnum string
	var app string
	var business string
	var cross string

	for i, v := range info.C0Info {
		if i == 0 {
			data = v.Data
		} else {
			data = data + "|" + v.Data
		}
		matchnum = v.MatchNum
		app = dict.C3_DICT[v.Application]
		business = dict.C4_DICT[v.Business]
		if v.CrossBoard == "0" {
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
			risk = v.Event
		} else {
			risk = risk + "|" + v.Event
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

func PrintMd5() {
	for i := 0; i < global.IndexMax; i++ {
		switch i {
		case global.IndexC0:
			fmt.Printf("DS identify md5 >>>>>>>>>>>>>>>>>>\n")
		case global.IndexC1:
			fmt.Printf("DS monitor md5 >>>>>>>>>>>>>>>>>>\n")
		case global.IndexC2:
			fmt.Printf("DS rule md5 >>>>>>>>>>>>>>>>>>\n")
		case global.IndexC3:
			fmt.Printf("DS evidence md5 >>>>>>>>>>>>>>>>>>\n")
		case global.IndexC4:
			fmt.Printf("DS keyword md5 >>>>>>>>>>>>>>>>>>\n")
		default:
			return
		}
		count := 0
		Md5Map[i].Range(func(key, value interface{}) bool {
			count++
			fmt.Printf("\tC%d\t%05d\t%v\n", i, count, key)
			return true
		})
	}
	return
}

func GenerateResult(excel *excelize.File) {
	checkNum := 1
	CheckMd5(excel, checkNum)
	checkNum++
	CheckLogCnt(excel, checkNum)
	checkNum++
	CheckLogId(excel, checkNum)
	checkNum++
	CheckDict(excel, checkNum)
	checkNum++
	CheckC0LogMap(excel, checkNum)
	checkNum++
	CheckC1LogMap(excel, checkNum)
	checkNum++
	RecordSample(excel, checkNum)

	return
}
