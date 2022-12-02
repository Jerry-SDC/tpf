@echo off

set releaseDir="%cd%\release\tpf_%~1"

md %releaseDir%

copy config_example.json %releaseDir%
copy config_example.json %releaseDir%\config.json

cd src

set GOARCH=amd64
set GOOS=linux
go build -o "%releaseDir%/tpf_linux_amd64"

set GOARCH=arm64
go build -o "%releaseDir%/tpf_linux_arm64"

set GOARCH=mips
go build -o "%releaseDir%/tpf_linux_mips"

set GOARCH=mipsle
go build -o "%releaseDir%/tpf_linux_mipsle"

set GOARCH=amd64
set GOOS=windows
go build -o "%releaseDir%/tpf_windows_x64.exe"