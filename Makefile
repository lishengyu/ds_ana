VERSION=$(shell cat ./VERSION.txt)
BUILD_TIME=$(shell date +%F-%Z/%T)

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"


all:
	go build  ${LDFLAGS} -o ds_ana main.go

clean:
	rm -rf ds_ana
