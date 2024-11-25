package main

import (
	"flag"
	"fmt"
	"os"

	"ds_ana/fileproc"
	"ds_ana/global"
	"ds_ana/telnetcmd"
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

	cli, err := telnetcmd.NewTelCli("127.0.0.1:36500")
	if err != nil {
		fmt.Println(err)
		return
	}
	err = cli.ChangeView("sw fa")
	if err != nil {
		fmt.Println(err)
		return
	}
	cli.Exec("show dev info")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = global.GetManuInfo("/home/filescan/config.yaml", "Manufactor")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("\tManufactor:[%s]\n", global.Manufactor)

	if gPath != "" {
		fileproc.AnalyzeLogFile(gPath, date, oPath)
	} else {
		flag.Usage()
		os.Exit(-1)
	}

	return
}
