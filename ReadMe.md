go env -w GOOS=windows GOARCH=amd64
go env -w GOOS=linux GOARCH=amd64

go build -o ds_ana main.go
