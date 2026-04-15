# 编译
## 编译环境设置
go env -w GOOS=windows GOARCH=amd64
go env -w GOOS=linux GOARCH=amd64

## 编译命令
go build -o ds_ana main.go

# Release

## Version v1.2.15
    1. 审计日志LogType字段修复
    2. 审计日志中的DeviceID字段校验

## Version v1.2.14
    1. 定义指定宏数据类型；
    2. 新增审计日志的补报功能；
    3. 修改审计日志中的文件名路径并打包再压缩；
    
## Version v1.2.12
    1. 修改端口校验边界；
    2. 对map操作加锁，避免多协程并发操作导致的统计结果异常场景；
    3. 审计文件本身不出审计日志；
    4. 添加文件类型和取证文件后缀校验；

## Version v1.2.10
    1. 添加bak参数，指定查询路径；
    2. 修复多日期并发处理问题；
    3. 修复规则库文件名校验；

## Version v1.2.9
    1. 修复在linux系统下，使用彩色输出时，导致输出内容包含颜色转义字符的问题。
    2. 新增对样本文件添加指令id的校验
    
## Version v1.2.7
    1. 增加对多日期匹配的支持，格式：20061226-20061228,20061229

## Version v1.2.6
    1. 增加对多日期匹配的支持，格式：20061226-20061228,20061229

## Version v1.2.5
    1. 识别日志中对RuleId/RuleDesc/DataCodeGroup做关联性校验；
    2. 添加06c3日志记录错误信息；
    3. 添加logid中deviceNo校验方式；

## Version v1.2.4
    1.读取updpi配置文件，增加对联通电信项目审计日志的支持
    2.添加调试日志打印方式
    3.修复多协程存map表导致的统计结果异常场景
    
