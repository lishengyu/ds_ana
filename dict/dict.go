package dict

var C3_DICT = map[int]string{
	1:    "FTP",
	2:    "SSH",
	3:    "TELNET",
	4:    "SMTP",
	5:    "HTTP",
	6:    "POP3",
	7:    "LDAP",
	8:    "HTTPS",
	9:    "RDP",
	10:   "DNS",
	11:   "SNMP",
	12:   "SSDP",
	13:   "VNC",
	14:   "MDNS",
	15:   "PPTP VPN",
	16:   "L2TP VPN",
	17:   "IPSEC VPN",
	18:   "ICMP",
	19:   "IMAP",
	20:   "DHCP",
	21:   "H.323",
	22:   "SOCKS4",
	23:   "SOCKS5",
	24:   "RADIUS",
	25:   "HTTP FLV",
	26:   "NTP",
	27:   "SNTP",
	28:   "TFTP",
	29:   "RTMP",
	30:   "SIP",
	31:   "RTP",
	32:   "RTCP",
	33:   "RTSP",
	34:   "XMPP",
	35:   "HLS",
	36:   "HDS",
	37:   "POP3S",
	38:   "SMTPS",
	39:   "TLS",
	40:   "JT/T808",
	41:   "JT/T809",
	9999: "其他",
}

var C4_DICT = map[int]string{
	1:  "即时通信",
	2:  "阅读",
	3:  "微博",
	4:  "地图导航",
	5:  "视频",
	6:  "音乐",
	7:  "应用商店",
	8:  "网上商城",
	9:  "影像处理",
	10: "直播业务",
	11: "游戏",
	12: "支付",
	13: "动漫",
	14: "邮箱",
	15: "P2P业务",
	16: "VoIP业务",
	17: "彩信",
	18: "浏览下载",
	19: "财经",
	20: "安全杀毒",
	21: "购物",
	22: "出行旅游",
	23: "VPN类应用",
	24: "WAP类应用",
	25: "网盘云服务",
	26: "自营业务",
	27: "公共流量",
	28: "其它",
}

var C9_DICT = map[int]string{
	1:   "HTTP",
	2:   "SMTP",
	3:   "POP3",
	4:   "IMAP",
	5:   "FTP",
	6:   "mysql",
	7:   "tds",
	8:   "tns",
	9:   "PostgreSQL",
	10:  "其他通用协议",
	11:  "PPTP VPN",
	12:  "L2TP VPN",
	13:  "IPSEC VPN",
	14:  "其他vpn协议",
	201: "MongoDB",
	202: "Redis",
	203: "Cassandra",
	204: "ElasticSearch",
	114: "其他",
}

var C10_DICT = map[int]string{
	1:   "html",
	2:   "txt",
	3:   "xml",
	4:   "json",
	5:   "csv",
	6:   "其他文本类",
	7:   "doc",
	8:   "docx",
	9:   "xls",
	10:  "xlsx",
	11:  "ppt",
	12:  "pptx",
	13:  "pdf",
	14:  "xlsb",
	15:  "odt",
	16:  "rtf",
	17:  "其他文件类",
	201: "vsdx",
	202: "vsd",
	18:  "tar",
	19:  "gz",
	20:  "tar.gz",
	21:  "zip",
	22:  "7z",
	23:  "rar",
	24:  "bz2",
	25:  "jar",
	26:  "war",
	27:  "arj",
	28:  "lzh",
	29:  "xz",
	30:  "其他压缩文件类",
	31:  "jpeg/jpg",
	32:  "png",
	33:  "tif/tiff",
	34:  "webp",
	35:  "wbmp",
	36:  "其他图片类",
	401: "fpx",
	402: "pbm",
	403: "pgm",
	404: "bmp",
	114: "其他类",
}

type DataCode struct {
	Class int
	Level int
	Rule  int
}

var C11_12_13_DICT = map[DataCode]string{
	{Class: 1, Level: 1, Rule: 1001}: "个人姓名",
	{Class: 1, Level: 1, Rule: 1002}: "生日",
	{Class: 1, Level: 1, Rule: 1003}: "性别",
	{Class: 1, Level: 1, Rule: 1004}: "民族",
	{Class: 1, Level: 1, Rule: 1005}: "国籍",
	{Class: 1, Level: 1, Rule: 1006}: "家庭关系",
	{Class: 1, Level: 1, Rule: 1007}: "住址",
	{Class: 1, Level: 1, Rule: 1008}: "个人电话号码",
	{Class: 1, Level: 1, Rule: 1009}: "邮箱地址",
	{Class: 1, Level: 1, Rule: 1010}: "个人信息主体账号",
	{Class: 1, Level: 1, Rule: 1011}: "IP地址",
	{Class: 1, Level: 1, Rule: 1012}: "个人数字证书",
	{Class: 1, Level: 1, Rule: 1013}: "个人职业",
	{Class: 1, Level: 1, Rule: 1014}: "职位",
	{Class: 1, Level: 1, Rule: 1015}: "工作单位",
	{Class: 1, Level: 1, Rule: 1016}: "学历",
	{Class: 1, Level: 1, Rule: 1017}: "学位",
	{Class: 1, Level: 1, Rule: 1018}: "教育经历",
	{Class: 1, Level: 1, Rule: 1019}: "工作经历",
	{Class: 1, Level: 1, Rule: 1020}: "培训记录",
	{Class: 1, Level: 1, Rule: 1021}: "成绩单",
	{Class: 1, Level: 1, Rule: 1028}: "通讯录",
	{Class: 1, Level: 1, Rule: 1029}: "好友列表",
	{Class: 1, Level: 1, Rule: 1030}: "群列表",
	{Class: 1, Level: 1, Rule: 1031}: "电子邮件地址列表",
	{Class: 1, Level: 1, Rule: 1032}: "网站浏览记录",
	{Class: 1, Level: 1, Rule: 1033}: "软件使用记录",
	{Class: 1, Level: 1, Rule: 1034}: "点击记录",
	{Class: 1, Level: 1, Rule: 1035}: "收藏列表",
	{Class: 1, Level: 1, Rule: 1036}: "硬件序列号",
	{Class: 1, Level: 1, Rule: 1037}: "设备MAC地址",
	{Class: 1, Level: 1, Rule: 1038}: "软件列表",
	{Class: 1, Level: 1, Rule: 1039}: "唯一设备识别码",
	{Class: 1, Level: 1, Rule: 1040}: "行踪轨迹",
	{Class: 1, Level: 1, Rule: 1041}: "精准定位信息",
	{Class: 1, Level: 1, Rule: 1042}: "住宿信息",
	{Class: 1, Level: 1, Rule: 1043}: "航班信息",
	{Class: 1, Level: 1, Rule: 1044}: "经纬度",
	{Class: 1, Level: 2, Rule: 1045}: "身份证号码",
	{Class: 1, Level: 2, Rule: 1046}: "军官证号码",
	{Class: 1, Level: 2, Rule: 1047}: "护照号码",
	{Class: 1, Level: 2, Rule: 1048}: "驾驶证号码",
	{Class: 1, Level: 2, Rule: 1049}: "社保卡号码",
	{Class: 1, Level: 2, Rule: 1050}: "居住证号码",
	{Class: 1, Level: 2, Rule: 1051}: "身份证图片",
	{Class: 1, Level: 2, Rule: 1052}: "军官证图片",
	{Class: 1, Level: 2, Rule: 1053}: "护照图片",
	{Class: 1, Level: 2, Rule: 1054}: "驾驶证图片",
	{Class: 1, Level: 2, Rule: 1055}: "工作证图片",
	{Class: 1, Level: 2, Rule: 1056}: "出入证图片",
	{Class: 1, Level: 2, Rule: 1057}: "社保卡图片",
	{Class: 1, Level: 2, Rule: 1058}: "居住证图片",
	{Class: 1, Level: 2, Rule: 1059}: "户口薄图片",
	{Class: 1, Level: 2, Rule: 1060}: "个人基因",
	{Class: 1, Level: 2, Rule: 1061}: "指纹",
	{Class: 1, Level: 2, Rule: 1062}: "声纹",
	{Class: 1, Level: 2, Rule: 1063}: "掌纹",
	{Class: 1, Level: 2, Rule: 1064}: "耳廓",
	{Class: 1, Level: 2, Rule: 1065}: "虹膜",
	{Class: 1, Level: 2, Rule: 1066}: "面部识别特征",
	{Class: 1, Level: 2, Rule: 1067}: "病历本",
	{Class: 1, Level: 2, Rule: 1068}: "住院日志",
	{Class: 1, Level: 2, Rule: 1069}: "医嘱单",
	{Class: 1, Level: 2, Rule: 1070}: "检验报告",
	{Class: 1, Level: 2, Rule: 1071}: "手术及麻醉记录",
	{Class: 1, Level: 2, Rule: 1072}: "护理记录",
	{Class: 1, Level: 2, Rule: 1073}: "用药记录",
	{Class: 1, Level: 2, Rule: 1074}: "药物食物过敏信息",
	{Class: 1, Level: 2, Rule: 1075}: "生育信息",
	{Class: 1, Level: 2, Rule: 1076}: "以往病史",
	{Class: 1, Level: 2, Rule: 1077}: "诊治情况",
	{Class: 1, Level: 2, Rule: 1078}: "家族病史",
	{Class: 1, Level: 2, Rule: 1079}: "现病史",
	{Class: 1, Level: 2, Rule: 1080}: "传染病史",
	{Class: 1, Level: 2, Rule: 1081}: "银行帐户",
	{Class: 1, Level: 2, Rule: 1082}: "银行卡图片",
	{Class: 1, Level: 2, Rule: 1083}: "鉴别信息",
	{Class: 1, Level: 2, Rule: 1084}: "存款信息",
	{Class: 1, Level: 2, Rule: 1085}: "房产信息",
	{Class: 1, Level: 2, Rule: 1086}: "信贷记录",
	{Class: 1, Level: 2, Rule: 1087}: "征信信息",
	{Class: 1, Level: 2, Rule: 1088}: "交易和消费记录",
	{Class: 1, Level: 2, Rule: 1089}: "流水记录",
	{Class: 1, Level: 2, Rule: 1090}: "虚拟财产信息",
	{Class: 1, Level: 2, Rule: 1091}: "婚史",
	{Class: 1, Level: 2, Rule: 1092}: "宗教信仰",
	{Class: 1, Level: 2, Rule: 1093}: "性取向",
	{Class: 1, Level: 2, Rule: 1094}: "未公开的违法犯罪记录",
	{Class: 2, Level: 3, Rule: 2001}: "网络建设",
	{Class: 2, Level: 3, Rule: 2002}: "网络规划研究",
	{Class: 2, Level: 3, Rule: 2003}: "咨询",
	{Class: 2, Level: 3, Rule: 2004}: "咨询",
	{Class: 2, Level: 3, Rule: 2005}: "网络拓扑结构",
	{Class: 2, Level: 3, Rule: 2006}: "新增设备信息",
	{Class: 2, Level: 3, Rule: 2007}: "核心技术",
	{Class: 2, Level: 3, Rule: 2008}: "设备采购",
	{Class: 2, Level: 3, Rule: 2009}: "位置",
	{Class: 2, Level: 3, Rule: 2010}: "性能",
	{Class: 2, Level: 3, Rule: 2011}: "供应商",
	{Class: 2, Level: 3, Rule: 2012}: "项目建设方案",
	{Class: 2, Level: 3, Rule: 2013}: "可研文件",
	{Class: 2, Level: 3, Rule: 2014}: "设计文件",
	{Class: 2, Level: 5, Rule: 2015}: "网络建设",
	{Class: 2, Level: 5, Rule: 2016}: "网络规划研究",
	{Class: 2, Level: 5, Rule: 2017}: "咨询",
	{Class: 2, Level: 5, Rule: 2018}: "咨询",
	{Class: 2, Level: 5, Rule: 2019}: "网络拓扑结构",
	{Class: 2, Level: 5, Rule: 2020}: "新增设备信息",
	{Class: 2, Level: 5, Rule: 2021}: "核心技术",
	{Class: 2, Level: 5, Rule: 2022}: "设备采购",
	{Class: 2, Level: 5, Rule: 2023}: "位置",
	{Class: 2, Level: 5, Rule: 2024}: "性能",
	{Class: 2, Level: 5, Rule: 2025}: "供应商",
	{Class: 2, Level: 5, Rule: 2026}: "项目建设方案",
	{Class: 2, Level: 5, Rule: 2027}: "可研文件",
	{Class: 2, Level: 5, Rule: 2028}: "设计文件",
	{Class: 2, Level: 3, Rule: 2029}: "资源机架",
	{Class: 2, Level: 3, Rule: 2030}: "DDM数字诊断监视功能模块",
	{Class: 2, Level: 3, Rule: 2031}: "DDF数字配线架",
	{Class: 2, Level: 3, Rule: 2032}: "ODM光配线架连接模块",
	{Class: 2, Level: 3, Rule: 2033}: "ODF光纤配线架",
	{Class: 2, Level: 3, Rule: 2034}: "光交箱内的ODF",
	{Class: 2, Level: 3, Rule: 2035}: "跳线和光缆的数量、芯数、长度",
	{Class: 2, Level: 3, Rule: 2036}: "分支接头盒",
	{Class: 2, Level: 3, Rule: 2037}: "传输专业信息",
	{Class: 2, Level: 3, Rule: 2038}: "承载网设备及系统信息",
	{Class: 2, Level: 3, Rule: 2039}: "核心网网元基本信息",
	{Class: 2, Level: 3, Rule: 2040}: "接入网基站设备",
	{Class: 2, Level: 3, Rule: 2041}: "业务支撑等平台相关的基本信息",
	{Class: 2, Level: 3, Rule: 2042}: "负载均衡等基础信息",
	{Class: 2, Level: 3, Rule: 2043}: "信令数据",
	{Class: 2, Level: 3, Rule: 2044}: "网络与系统的路由信息",
	{Class: 2, Level: 3, Rule: 2045}: "网段、网址、VLAN分配与划分等信息",
	{Class: 2, Level: 3, Rule: 2046}: "设备监测、告警等信息",
	{Class: 2, Level: 3, Rule: 2047}: "信令的监测信息",
	{Class: 2, Level: 3, Rule: 2048}: "流量的监测信息",
	{Class: 2, Level: 3, Rule: 2049}: "运维日志",
	{Class: 2, Level: 3, Rule: 2050}: "运维系统账号密码",
	{Class: 2, Level: 3, Rule: 2051}: "网络及系统的运行统计分析数据等",
	{Class: 2, Level: 3, Rule: 2052}: "安全审计记录",
	{Class: 2, Level: 3, Rule: 2053}: "网络安全应急预案",
	{Class: 2, Level: 3, Rule: 2054}: "违法有害信息监测处置",
	{Class: 2, Level: 3, Rule: 2055}: "舆情态势监测预警等数据",
	{Class: 2, Level: 3, Rule: 2056}: "核心区域视频监控记录数据",
	{Class: 2, Level: 3, Rule: 2057}: "僵木蠕监控信息",
	{Class: 2, Level: 3, Rule: 2058}: "移动恶意软件监控信息",
	{Class: 2, Level: 3, Rule: 2059}: "IDCISP告警信息",
	{Class: 2, Level: 3, Rule: 2060}: "安全事件记录",
	{Class: 2, Level: 6, Rule: 2061}: "产品ID",
	{Class: 2, Level: 6, Rule: 2062}: "套餐设置",
	{Class: 2, Level: 6, Rule: 2063}: "销售品ID",
	{Class: 2, Level: 5, Rule: 2064}: "渠道数据",
	{Class: 2, Level: 5, Rule: 2065}: "CP/SP数据",
	{Class: 2, Level: 5, Rule: 2066}: "满意度调研数据",
	{Class: 2, Level: 5, Rule: 2067}: "分析报告",
	{Class: 2, Level: 5, Rule: 2068}: "实体渠道第三方监测",
	{Class: 2, Level: 5, Rule: 2069}: "营业厅服务质检信息",
	{Class: 2, Level: 5, Rule: 2070}: "充值数据",
	{Class: 2, Level: 5, Rule: 2071}: "精准营销和服务应用号码及标签",
	{Class: 2, Level: 5, Rule: 2072}: "各类预缴、促销、捆绑和营销奖",
	{Class: 2, Level: 5, Rule: 2073}: "励用户号码",
	{Class: 2, Level: 5, Rule: 2074}: "终端业务各类指标完成数据",
	{Class: 2, Level: 5, Rule: 2075}: "终端经营日常生产数据",
	{Class: 2, Level: 6, Rule: 2076}: "产品数字内容业务运营数据",
	{Class: 2, Level: 6, Rule: 2077}: "资费信息、公开的业务运营数据等",
	{Class: 2, Level: 4, Rule: 2078}: "市场发展策略",
	{Class: 2, Level: 4, Rule: 2079}: "市场经营专项研究报告",
	{Class: 2, Level: 4, Rule: 2080}: "市场发展指导意见",
	{Class: 2, Level: 4, Rule: 2081}: "品牌及传播推广策略",
	{Class: 2, Level: 4, Rule: 2082}: "业务发展策略",
	{Class: 2, Level: 4, Rule: 2083}: "管理办法",
	{Class: 2, Level: 4, Rule: 2084}: "资费方案",
	{Class: 2, Level: 4, Rule: 2085}: "资费管理",
	{Class: 2, Level: 4, Rule: 2086}: "产品试点方案",
	{Class: 2, Level: 4, Rule: 2087}: "试商用方案",
	{Class: 2, Level: 4, Rule: 2088}: "业务融合方案",
	{Class: 2, Level: 4, Rule: 2089}: "技术体制类规范",
	{Class: 2, Level: 4, Rule: 2090}: "企业标准",
	{Class: 2, Level: 4, Rule: 2091}: "技术成果",
	{Class: 2, Level: 4, Rule: 2092}: "创新成果",
	{Class: 2, Level: 4, Rule: 2093}: "试验测试数据",
	{Class: 2, Level: 4, Rule: 2094}: "试验分析报告",
	{Class: 2, Level: 4, Rule: 2095}: "专利申请技术交底书",
	{Class: 2, Level: 4, Rule: 2096}: "专利布局相关报告",
	{Class: 2, Level: 4, Rule: 2097}: "专利风险分析报告",
	{Class: 2, Level: 4, Rule: 2098}: "专利纠纷应对策略",
	{Class: 2, Level: 5, Rule: 2099}: "采购招标的技术规范相关信息",
	{Class: 2, Level: 5, Rule: 2100}: "招标及采购该过程信息",
	{Class: 2, Level: 5, Rule: 2101}: "投标",
	{Class: 2, Level: 5, Rule: 2102}: "订单",
	{Class: 2, Level: 5, Rule: 2103}: "采购物资数量",
	{Class: 2, Level: 5, Rule: 2104}: "类型",
	{Class: 2, Level: 5, Rule: 2105}: "合作方信息",
	{Class: 2, Level: 5, Rule: 2106}: "合同台账",
	{Class: 2, Level: 5, Rule: 2107}: "各类采购合同",
	{Class: 2, Level: 5, Rule: 2108}: "供应商考核",
	{Class: 2, Level: 5, Rule: 2109}: "音视频等互联网内容数据",
	{Class: 2, Level: 4, Rule: 2110}: "战略计划",
	{Class: 2, Level: 4, Rule: 2111}: "战略风险",
	{Class: 2, Level: 4, Rule: 2112}: "重大事项决策",
	{Class: 2, Level: 4, Rule: 2113}: "重要干部任免",
	{Class: 2, Level: 4, Rule: 2114}: "重大项目投资决策",
	{Class: 2, Level: 4, Rule: 2115}: "大额资金使用相关信息",
	{Class: 2, Level: 4, Rule: 2116}: "运行管理相关的规程",
	{Class: 2, Level: 4, Rule: 2117}: "运行管理相关的操作指南",
	{Class: 2, Level: 4, Rule: 2118}: "运行管理相关的计划",
	{Class: 2, Level: 4, Rule: 2119}: "预算大盘子",
	{Class: 2, Level: 4, Rule: 2120}: "各部门年度预算",
	{Class: 2, Level: 4, Rule: 2121}: "季度滚动预算的相关数据及材料",
	{Class: 2, Level: 4, Rule: 2122}: "关联交易额度",
	{Class: 2, Level: 4, Rule: 2123}: "金融投资计划",
	{Class: 2, Level: 4, Rule: 2124}: "信息披露相关材料",
	{Class: 2, Level: 4, Rule: 2125}: "业绩披露信息",
	{Class: 2, Level: 4, Rule: 2126}: "经营业绩考核办法等信息",
	{Class: 2, Level: 4, Rule: 2127}: "统计快报",
	{Class: 2, Level: 4, Rule: 2128}: "年报数据",
	{Class: 2, Level: 4, Rule: 2129}: "财务报表",
	{Class: 2, Level: 4, Rule: 2130}: "生产经营分析材料",
	{Class: 2, Level: 4, Rule: 2131}: "市场经营数据及分析报告",
	{Class: 2, Level: 4, Rule: 2132}: "IT系统生产经营报告",
	{Class: 2, Level: 5, Rule: 2133}: "人员管理数据",
	{Class: 2, Level: 5, Rule: 2134}: "机构管理数据",
	{Class: 2, Level: 5, Rule: 2135}: "劳动用工管理数据",
	{Class: 2, Level: 5, Rule: 2136}: "薪酬管理数据",
	{Class: 2, Level: 5, Rule: 2137}: "收入",
	{Class: 2, Level: 5, Rule: 2138}: "利润",
	{Class: 2, Level: 5, Rule: 2139}: "预算",
	{Class: 2, Level: 5, Rule: 2140}: "决算数据",
	{Class: 2, Level: 5, Rule: 2141}: "邮件",
	{Class: 2, Level: 5, Rule: 2142}: "行政文件",
	{Class: 2, Level: 5, Rule: 2143}: "签报",
}

type RiskCode struct {
	RiskType    int
	RiskSubType int
}

var C7_C8_DICT = map[RiskCode]string{
	{RiskType: 200, RiskSubType: 1}:  "重要数据明文传输",
	{RiskType: 200, RiskSubType: 3}:  "数据接口不安全",
	{RiskType: 201, RiskSubType: 4}:  "个人信息未去标识化",
	{RiskType: 202, RiskSubType: 5}:  "数据越权访问",
	{RiskType: 202, RiskSubType: 6}:  "数据批量访问",
	{RiskType: 202, RiskSubType: 7}:  "数据高频访问",
	{RiskType: 203, RiskSubType: 8}:  "数据流转范围异常",
	{RiskType: 203, RiskSubType: 9}:  "数据流转时间异常",
	{RiskType: 203, RiskSubType: 10}: "数据流转路径异常",
	{RiskType: 999, RiskSubType: 11}: "其它",
	{RiskType: 400, RiskSubType: 1}:  "重要数据明文跨境传输",
	{RiskType: 400, RiskSubType: 2}:  "数据批量跨境",
	{RiskType: 400, RiskSubType: 3}:  "境外对数据高频访问",
	{RiskType: 400, RiskSubType: 4}:  "数据跨境流转范围异常",
	{RiskType: 400, RiskSubType: 5}:  "数据跨境时间异常",
	{RiskType: 400, RiskSubType: 6}:  "数据跨境路径异常",
	{RiskType: 400, RiskSubType: 7}:  "其它",
}
