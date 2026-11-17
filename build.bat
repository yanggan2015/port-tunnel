@echo off
setlocal
cd /d "%~dp0"
set "PATH=C:\msys64\mingw64\bin;%PATH%"
if not exist output mkdir output

windres -I src src\app.rc -O coff -o output\app.res
if errorlevel 1 exit /b 1

gcc -O2 -s -mwindows -DUNICODE -D_UNICODE -o output\PortTunnel.exe ^
  src\app.c src\portmap.c src\frp_worker.c output\app.res ^
  -lws2_32 -lsecur32 -lcrypt32 -lbcrypt -lcomctl32 -lshell32 -lole32 -lshlwapi ^
  -lcomdlg32 -lgdi32 -luser32 -ladvapi32
if errorlevel 1 exit /b 1
echo [OK] output\PortTunnel.exe
exit /b 0
