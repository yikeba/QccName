@echo off
rem Windows 家庭节点（冗余节点）启动。qccname.properties 放在本目录。
rem 需要 JDK 23+ 在 PATH 中（JDK 23 时 lib 下必须有 bcprov-jdk18on-1.81.jar）。
chcp 65001 >nul
cd /d %~dp0..
set QCCNAME_OPTS=-Xmx128m
call bin\qccname.bat
