@echo off
REM Build helper: generate sources.txt with quoted full paths and run javac
cd /d "%~dp0"
cd "d:\Final year project\Packet_analyzer-main\java"
if not exist out mkdir out
if exist sources.txt del sources.txt
setlocal enabledelayedexpansion
for /r "src\main\java" %%f in (*.java) do (
	set "p=%%~ff"
	set "p=!p:\=/!"
	echo "!p!" >> sources.txt
)
javac -d out @sources.txt
echo javac exit code %ERRORLEVEL%
exit /b %ERRORLEVEL%
