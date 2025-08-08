# 编译
## 编译环境设置
go env -w GOOS=windows GOARCH=amd64
go env -w GOOS=linux GOARCH=amd64

## 编译命令
go build -o ds_ana main.go

# Release

## Version v1.2.5
    1. 识别日志中对RuleId/RuleDesc/DataCodeGroup做关联性校验；
    2. 添加06c3日志记录错误信息；
    3. 添加logid中deviceNo校验方式；

## Version v1.2.4
    1.读取updpi配置文件，增加对联通电信项目审计日志的支持
    2.添加调试日志打印方式
    3.修复多协程存map表导致的统计结果异常场景
    
