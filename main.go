package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"ds_ana/fileproc"
	"ds_ana/global"
	"ds_ana/logger"
	"ds_ana/telnetcmd"
	"ds_ana/yamlreader"
)

var (
	gPath         string
	oPath         string
	date          string
	Ver           bool
	Verbose       bool
	DetailVerbose bool
	Port          int
)

var (
	Version   string
	BuildTime string
)

const (
	DpiConfFile = "/home/updpi/conf/config.yaml"
	DpiCmdPort  = "base.cmd_port"
	DpiIspCode  = "base.isp_code"
)

func setLogLevel(Detail, Verbose bool) {
	if Verbose {
		// 启用常规日志输出到控制台
		logger.SetLogger(log.New(os.Stdout, "[Fextra Logger] ", log.LstdFlags))
		// 启用调试日志
		logger.SetDebugLogger(log.New(os.Stdout, "[Fextra Logger Debug] ", log.LstdFlags))
	} else if Detail {
		// 启用常规日志输出到控制台
		logger.SetLogger(log.New(os.Stdout, "[Fextra Logger] ", log.LstdFlags))
		// 启用调试日志
		logger.DebugLogger = log.New(io.Discard, "", 0)
	}
}

func argsCheck() {
	flag.StringVar(&gPath, "s", "", "数安话单文件路径，各话单路径参考标准格式查找, 示例: /home/udpi_log")
	flag.StringVar(&oPath, "o", "report.xlsx", "话单文件核查，生成报告文件名")
	flag.StringVar(&date, "d", "", "指定时间日期，示例20061226")
	flag.BoolVar(&Ver, "v", false, "查询版本信息")
	flag.BoolVar(&Verbose, "info", false, "verbose")
	flag.BoolVar(&DetailVerbose, "debug", false, "detail verbose")
	//flag.IntVar(&Port, "p", 36500, "指定Dpi命令行端口号")
	flag.Parse()

	if Ver {
		fmt.Printf("Version   : %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		os.Exit(0)
	}

	if date != "" {
		global.TimeStr = date
	}

	if gPath == "" {
		flag.Usage()
		os.Exit(-1)
	}
}

func readDpiCfg() error {
	r, err := yamlreader.NewReader(DpiConfFile)
	if err != nil {
		return err
	}

	Port = r.GetInt(DpiCmdPort)
	isp_code := r.GetInt(DpiIspCode)
	global.IsCtcc = (isp_code == 10)

	logger.Logger.Printf("dpi_cmd_port:%d", Port)
	logger.Logger.Printf("isCtcc: %v, isp_code:%d", global.IsCtcc, isp_code)

	return nil
}

func getDpiInfo() error {
	cli, err := telnetcmd.NewTelCli(fmt.Sprintf("127.0.0.1:%d", Port))
	if err != nil {
		return err
	}
	err = cli.ChangeView("sw fa")
	if err != nil {
		return err
	}
	cli.Exec("show dev info")
	if err != nil {
		return err
	}
	return nil
}

func getFsConf() error {
	fmt.Printf("读取FileScan配置文件 /home/filescan/config.yaml ...\n")
	if err := global.GetManuInfo("/home/filescan/config.yaml", "Manufactor"); err != nil {
		return err
	}
	fmt.Printf("\tManufactor:[%s]\n", global.Manufactor)
	return nil
}

func main() {

	argsCheck()

	setLogLevel(Verbose, DetailVerbose)

	if err := readDpiCfg(); err != nil {
		fmt.Println(err)
		return
	}

	if err := getDpiInfo(); err != nil {
		fmt.Println(err)
		return
	}

	if err := getFsConf(); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("开始解析日志话单文件 ...\n")
	fileproc.AnalyzeLogFile(gPath, date, oPath)
	return
}
