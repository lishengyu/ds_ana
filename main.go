package main

import (
	"flag"
	"os"

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
		fileproc.AnalyzeLogFile(gPath, date, oPath)
	} else {
		flag.Usage()
		os.Exit(-1)
	}

	return
}
