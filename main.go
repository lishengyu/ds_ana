package main

import (
	"flag"
	"os"
	"path/filepath"

	"ds_ana/fileproc"
	"ds_ana/global"
)

var (
	gPath string
	oPath string
	date  string
)

func main() {
	flag.StringVar(&gPath, "s", "", "数安话单文件路径，各话单路径参考标准格式查找, 示例: /home/udpi_log")
	flag.StringVar(&oPath, "o", "report.xlsx", "话单文件核查，生成报告文件名")
	flag.StringVar(&date, "d", "", "指定时间日期，示例20061226")
	flag.Parse()

	if date != "" {
		global.TimeStr = date
	}

	if gPath != "" {
		pathc0 := filepath.Join(gPath, global.IdentifyName)
		pathc1 := filepath.Join(gPath, global.MonitorName)
		pathc3 := filepath.Join(gPath, global.EvidenceName)
		pathc4 := filepath.Join(gPath, global.KeywordName)
		if exist := global.PathExists(pathc4); !exist {
			pathc4 = filepath.Join(gPath, global.KeywordNameB)
		}
		fileproc.AnalyzeLogFile(pathc0, pathc1, pathc3, pathc4, oPath)
	} else {
		flag.Usage()
		os.Exit(-1)
	}

	return
}
