package telnetcmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/ziutek/telnet"
)

type TelCli struct {
	conn *telnet.Conn
}

type DevInfo struct {
	Dev_IP      string
	Dev_Site    string
	Dev_No      string
	Dev_HouseId string
}

var Devinfo DevInfo

func NewTelCli(addr string) (*TelCli, error) {
	conn, err := telnet.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	time.Sleep(1 * time.Second)
	return &TelCli{conn: conn}, nil
}

func (c *TelCli) ChangeView(view string) error {
	_, err := c.conn.Write([]byte(view + "\n"))
	if err != nil {
		return err
	}

	time.Sleep(1 * time.Second)
	return nil
}

func ParseOutput(out string) error {
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "dev_ip:") {
			Devinfo.Dev_IP = strings.TrimSpace(strings.TrimPrefix(line, "dev_ip:"))
		} else if strings.HasPrefix(line, "dev_no:") {
			no := strings.TrimSpace(strings.TrimPrefix(line, "dev_no:"))
			Devinfo.Dev_No = strings.TrimLeft(no, "0") // 剔除前面可能存在的0
		} else if strings.HasPrefix(line, "site_name:") {
			Devinfo.Dev_Site = strings.TrimSpace(strings.TrimPrefix(line, "site_name:"))
		} else if strings.HasPrefix(line, "house_id:") {
			Devinfo.Dev_HouseId = strings.TrimSpace(strings.TrimPrefix(line, "house_id:"))
		}
	}

	fmt.Printf("DevInfo:\n\tIP:[%s]\n\tNo:[%s]\n\tSite:[%s]\n\tHouseId:[%s]\n",
		Devinfo.Dev_IP, Devinfo.Dev_No, Devinfo.Dev_Site, Devinfo.Dev_HouseId)

	if Devinfo.Dev_IP == "" || Devinfo.Dev_No == "" || Devinfo.Dev_Site == "" || Devinfo.Dev_HouseId == "" {
		return fmt.Errorf("设备信息获取失败\n")
	}

	return nil
}

func (c *TelCli) Exec(cmd string) error {
	_, err := c.conn.Write([]byte(cmd + "\n"))
	if err != nil {
		return err
	}
	buf := make([]byte, 1024)
	time.Sleep(1 * time.Second)
	n, err := c.conn.Read(buf[:])
	if err != nil {
		return err
	}

	output := string(buf[:n])
	err = ParseOutput(output)
	if err != nil {
		return err
	}

	return nil
}
