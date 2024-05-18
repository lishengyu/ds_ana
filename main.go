package main

import (
	"flag"
	"os"
	"path/filepath"

	"ds_ana/fileproc"
	"ds_ana/global"
)

var (
	gPath  string
	C0Path string
	C1Path string
	C3Path string
	C4Path string
	oPath  string
)

func main() {

	flag.StringVar(&gPath, "s", "", "数安话单文件路径，各话单路径参考被准格式查找, 示例: /home/udpi_log")
	flag.StringVar(&C0Path, "c0", "", "逐一指定话单文件路径，数安识别话单文件路径")
	flag.StringVar(&C1Path, "c1", "", "逐一指定话单文件路径，数安监测话单文件路径")
	flag.StringVar(&C3Path, "c3", "", "逐一指定话单文件路径，数安取证文件路径")
	flag.StringVar(&C4Path, "c4", "", "逐一指定话单文件路径，数安关键字话单文件路径")
	flag.StringVar(&oPath, "o", "report.xlsx", "话单文件核查，生成报告文件名")
	flag.Parse()

	if gPath != "" {
		pathc0 := filepath.Join(gPath, global.IdentifyName)
		pathc1 := filepath.Join(gPath, global.MonitorName)
		pathc3 := filepath.Join(gPath, global.EvidenceName)
		pathc4 := filepath.Join(gPath, global.KeywordName)
		fileproc.AnalyzeLogFile(pathc0, pathc1, pathc3, pathc4, oPath)
	} else if C0Path != "" && C1Path != "" && C3Path != "" {
		fileproc.AnalyzeLogFile(C0Path, C1Path, C3Path, C4Path, oPath)
	} else {
		flag.Usage()
		os.Exit(-1)
	}

	return
}
