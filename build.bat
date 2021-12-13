@echo off

set releaseDir="%cd%\release\tpf_%~1"

md %releaseDir%

copy config_example.json %releaseDir%

set GOARCH=amd64
set GOOS=linux
go build -o "%releaseDir%/tpf_amd64"

set GOARCH=arm64
go build -o "%releaseDir%/tpf_arm64"

set GOARCH=amd64
set GOOS=windows
go build -o "%releaseDir%/tpf_x64.exe"