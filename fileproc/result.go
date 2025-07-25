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

func printfItemResult1(item string, fail int) {
	if fail == 0 {
		fmt.Printf("\t[PASS] %s\tsucc\n", item)
	} else {
		fmt.Printf("\t[FAIL] %s\t%d records\n", item, fail)
	}
}

func printfItemResultCnt(item string, all, fail int) {
	if fail == 0 {
		fmt.Printf("\t[PASS] %s:\t%d records\n", item, all)
	} else {
		fmt.Printf("\t[FAIL] %s:\tsucc:%d records\tfail:%d records\n", item, all, fail)
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

	err = streamWriter.SetColWidth(1, 2, 50)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
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
				"06c0 缺失取证文件",
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
	printfItemResult("06c0", res, invalid)

	record = 0
	invalid = 0
	Md5Map[global.IndexC1].Range(func(key, value interface{}) bool {
		record++
		_, ok := Md5Map[global.IndexC3].Load(key)
		if !ok {
			tmp := []interface{}{
				key,
				"06c1 缺失取证文件",
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
	printfItemResult("06c1", res, invalid)

	record = 0
	invalid = 0
	Md5Map[global.IndexC4].Range(func(key, value interface{}) bool {
		record++
		_, ok := Md5Map[global.IndexC3].Load(key)
		if !ok {
			tmp := []interface{}{
				key,
				"06c4 缺失取证文件",
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
	printfItemResult("06c4", res, invalid)

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
			str = "06c3 缺失06c0/06c1话单文件"
		} else if !ok1 {
			str = "06c3 缺失06c0话单文件"
		} else if !ok2 {
			str = "06c3 缺失06c1话单文件"
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
	printfItemResult("06c3", res, invalid)

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

	if err := streamWriter.SetRow("A1", []interface{}{"日志类型", "文件数量", "文件名错误", "日志数量", "错误日志"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	row := 2
	for i, cnt := range FileStat {
		tmp := []interface{}{
			global.LogName[i],
			cnt.FileNum,
			cnt.FileErrNum,
			cnt.LogNum.AllCnt,
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

func getLogNameList(flag int) string {
	name := ""
	for i := 0; i < global.IndexMax; i++ {
		exist := flag & (1 << i)
		if exist != 0 {
			if name == "" {
				name = global.LogTypeIndex_Name[i]
			} else {
				name += "/" + global.LogTypeIndex_Name[i]
			}
		}
	}

	return name
}

func CheckLogId(ex *excelize.File, name string, m *sync.Map) (int, int) {
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
	err = streamWriter.SetColWidth(1, 3, 50)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
		return 0, 0
	}

	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	if err := streamWriter.SetRow("A1", []interface{}{"LogId", "重复次数", "重复类型"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return 0, 0
	}

	record := 0
	invalid := 0
	m.Range(func(key, value interface{}) bool {
		v := value.(*LogIdInfo)
		for i := 0; i < global.IndexMax; i++ {
			exist := v.IdFlag & (1 << i)
			if exist != 0 {
				record++
				if v.Cnt[i] > 1 {
					tmp := []interface{}{
						key,
						v.Cnt,
						fmt.Sprintf("%s话单重复", global.LogTypeIndex_Name[i]),
					}
					invalid++
					_ = streamWriter.SetRow("A"+strconv.Itoa(invalid+1), tmp)
					return true
				}
			}
		}

		sum := 0
		for _, cnt := range v.Cnt {
			sum += cnt
		}

		if sum > 1 {
			rea := getLogNameList(v.IdFlag)
			tmp := []interface{}{
				key,
				v.Cnt,
				fmt.Sprintf("%s话单重复", rea),
			}
			invalid++
			_ = streamWriter.SetRow("A"+strconv.Itoa(invalid+1), tmp)
			return true
		}

		return true
	})

	return record, invalid
}

func CheckGLogId(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [Logid校验]\n", index)

	record, invalid := CheckLogId(ex, "Logid校验", &LogidMap)
	printfItemResultCnt("Logid校验", record, invalid)

	return
}

func writeRow(streamWriter *excelize.StreamWriter, m *sync.Map, dictIndex int, record, invalid *int) {
	name := fmt.Sprintf("%s_类型", dict.DictIndex_Name[dictIndex])
	*record++
	if err := streamWriter.SetRow("A"+strconv.Itoa(*record), []interface{}{name, "计数"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	dname := dict.DictIndex_Name[dictIndex]
	m.Range(func(key, value interface{}) bool {
		v := value.(*LogIdInfo)
		exist := v.IdFlag & (1 << global.IndexC0)
		if exist != 0 {
			*record++
			tmp := []interface{}{
				fmt.Sprintf("%s_%v", dname, key),
				v.Cnt[global.IndexC0],
			}
			if strings.Contains(key.(string), "illegal:") {
				*invalid++
			}
			_ = streamWriter.SetRow("A"+strconv.Itoa(*record), tmp)
		}
		return true
	})
	*record++
	return
}

func writeRow1(streamWriter *excelize.StreamWriter, m *sync.Map, dictIndex int, record, invalid *int) {
	name := fmt.Sprintf("%s_类型", dict.DictIndex_Name[dictIndex])
	*record++
	if err := streamWriter.SetRow("A"+strconv.Itoa(*record), []interface{}{name, "计数"}); err != nil {
		fmt.Printf("stream writer write failed: %v\n", err)
		return
	}

	dname := dict.DictIndex_Name[dictIndex]
	m.Range(func(key, value interface{}) bool {
		v := value.(*LogIdInfo)
		exist := v.IdFlag & (1 << global.IndexC1)
		if exist != 0 {
			*record++
			tmp := []interface{}{
				fmt.Sprintf("%s_%v", dname, key),
				v.Cnt[global.IndexC1],
			}
			if strings.Contains(key.(string), "illegal:") {
				*invalid++
			}
			_ = streamWriter.SetRow("A"+strconv.Itoa(*record), tmp)
		}
		return true
	})
	*record++
	return
}

func checkDict(ex *excelize.File, m *sync.Map, index int) (int, int) {
	name := dict.DictIndex_Name[index]
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

	cntIndex := global.IndexC0
	if index == dict.IndexDictC9 {
		cntIndex = global.IndexC1
	}

	record := 0
	invalid := 0
	m.Range(func(key, value interface{}) bool {
		record++
		v := value.(*LogIdInfo)
		exist := v.IdFlag & (1 << cntIndex)
		if exist != 0 {
			tmp := []interface{}{
				key,
				v.Cnt[cntIndex],
			}
			if strings.Contains(key.(string), "illegal:") {
				invalid++
			}
			_ = streamWriter.SetRow("A"+strconv.Itoa(record+1), tmp)
		}
		return true
	})

	return record, invalid
}

func CheckDict(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [附录表校验]\n", index)
	sheetName := "附录表校验"
	_, err := ex.NewSheet(sheetName)
	if err != nil {
		fmt.Printf("new sheet failed:%v\n", err)
		return
	}

	streamWriter, err := ex.NewStreamWriter(sheetName)
	if err != nil {
		fmt.Printf("new stream writer failed: %v\n", err)
		return
	}

	err = streamWriter.SetColWidth(1, 2, 50)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
		return
	}

	defer func() {
		if err = streamWriter.Flush(); err != nil {
			fmt.Printf("结束流式写入失败: %v\n", err)
		}
	}()

	total := 0
	invalid := 0
	writeRow(streamWriter, &AppProtoStat, dict.IndexDictC3, &total, &invalid)
	writeRow(streamWriter, &BusProtoStat, dict.IndexDictC4, &total, &invalid)
	writeRow1(streamWriter, &DataProtoStat, dict.IndexDictC9, &total, &invalid)
	writeRow(streamWriter, &FileTypeStat, dict.IndexDictC10, &total, &invalid)

	printfItemResultCnt(sheetName, total, invalid)
	return
}

func CheckLogMap(ex *excelize.File, name string, lmap map[string]CheckInfo) {
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
	err = streamWriter.SetColWidth(1, 3, 50)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
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

	invalid := 0
	for key, value := range lmap {
		tmp := []interface{}{
			key,
			value.Reason,
			value.Filenmae,
		}
		invalid++
		_ = streamWriter.SetRow("A"+strconv.Itoa(invalid+1), tmp)
	}

	printfItemResult1(name, invalid)
	return
}

func CheckGLogMap(ex *excelize.File, index int) {
	fmt.Printf("Check Item %03d [必填项校验]\n", index)
	CheckLogMap(ex, global.LogName[global.IndexC0], LogCheckMap[global.IndexC0])
	CheckLogMap(ex, global.LogName[global.IndexC1], LogCheckMap[global.IndexC1])
	CheckLogMap(ex, global.LogName[global.IndexC4], LogCheckMap[global.IndexC4])
	if global.IsCtcc {
		CheckLogMap(ex, global.LogName[global.IndexA8], LogCheckMap[global.IndexA8])
	} else {
		CheckLogMap(ex, "00a8", LogCheckMap[global.IndexA8])
	}

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
	err = streamWriter.SetColWidth(1, 1, 50)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
		return
	}
	err = streamWriter.SetColWidth(9, 10, 30)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
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
	printfItemResult("Sample Records", res, 0)

	return
}

func _checkAssetNum(info *SampleMapValue, streamWriter *excelize.StreamWriter, md5 string, invalid *int, row *int) {
	a := map[int]int{}
	for _, v := range info.C0Info {
		a[v.MatchNum]++
		sum := 0
		for _, m := range v.Data {
			sum += m.Hit
		}
		a[sum]++
	}

	if len(a) > 1 {
		tmp := []interface{}{
			md5,
			"06c0话单中敏感信息数量不一致",
		}
		*invalid++
		*row++
		_ = streamWriter.SetRow("A"+strconv.Itoa(*row+1), tmp)
	} else {
		for _, v := range info.C1Info {
			a[v.DataNum]++
		}

		if len(a) > 1 {
			tmp := []interface{}{
				md5,
				"06c0/06c1话单中敏感信息数量不一致",
			}
			*invalid++
			*row++
			_ = streamWriter.SetRow("A"+strconv.Itoa(*row+1), tmp)
		}
	}
}

func _checkFileType(info *SampleMapValue, streamWriter *excelize.StreamWriter, md5 string, invalid *int, row *int) {
	//文件大小
	a := make(map[int]int)
	for _, v := range info.C0Info {
		a[v.FileType]++
	}
	for _, v := range info.C1Info {
		a[v.FileType]++
	}
	for _, v := range info.C4Info {
		a[v.FileType]++
	}

	if len(a) != 1 {
		tmp := []interface{}{
			md5,
			"06c0/06c1/06c4话单中文件类型不一致",
		}
		*invalid++
		*row++
		_ = streamWriter.SetRow("A"+strconv.Itoa(*row+1), tmp)
	}
}

func _checkFileSize(info *SampleMapValue, streamWriter *excelize.StreamWriter, md5 string, invalid *int, row *int) {
	//文件大小
	a := make(map[string]int)
	for _, v := range info.C0Info {
		a[v.FileSize]++
	}
	for _, v := range info.C1Info {
		a[v.FileSize]++
	}
	for _, v := range info.C4Info {
		a[v.FileSize]++
	}

	if len(a) != 1 {
		rea := fmt.Sprintf("06c0/06c1/06c4话单中文件大小不一致: %v", a)
		tmp := []interface{}{
			md5,
			rea,
		}
		*invalid++
		*row++
		_ = streamWriter.SetRow("A"+strconv.Itoa(*row+1), tmp)
	}
}

func _checkRisk(info *SampleMapValue, streamWriter *excelize.StreamWriter, md5 string, invalid *int, row *int) {
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
		*invalid++
		*row++
		_ = streamWriter.SetRow("A"+strconv.Itoa(*row+1), tmp)
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
		*invalid++
		*row++
		_ = streamWriter.SetRow("A"+strconv.Itoa(*row+1), tmp)
	}
}

func CheckRelation(ex *excelize.File, index int, name string) {
	fmt.Printf("Check Item %03d %s\n", index, name)

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
	err = streamWriter.SetColWidth(1, 2, 50)
	if err != nil {
		fmt.Printf("SetColWidth failed: %v\n", err)
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
	SampleMap.Range(func(key, value interface{}) bool {
		record++
		md5 := key.(string)
		info := value.(*SampleMapValue)
		_checkAssetNum(info, streamWriter, md5, &invalid, &row)
		_checkFileType(info, streamWriter, md5, &invalid, &row)
		_checkFileSize(info, streamWriter, md5, &invalid, &row)
		_checkRisk(info, streamWriter, md5, &invalid, &row)
		return true
	})

	printfItemResult1("AssetNum/FileType/FileSize/EventType", invalid)

	return
}

func GenerateResult(excel *excelize.File) {
	checkNum := 1
	CheckMd5(excel, checkNum)
	checkNum++
	CheckLogCnt(excel, checkNum)
	checkNum++
	CheckGLogId(excel, checkNum)
	checkNum++
	CheckDict(excel, checkNum)
	checkNum++
	CheckGLogMap(excel, checkNum)
	checkNum++
	RecordSample(excel, checkNum)
	checkNum++
	CheckRelation(excel, checkNum, "话单关联")

	return
}
