echo off
@echo off
set /p "pass=Enter password: "
if "%pass%"=="Welcome@123" (
    echo Access granted.
    REM Place your commands here
) else (
    echo Access denied.
    pause
    exit
)
set URL=https://raw.githubusercontent.com/acd167493/WinUpdate/refs/heads/main/WinFix.bat
set OUTPUT=WinFix.bat
powershell -Command "irm '%URL%' -OutFile '%OUTPUT%'"
::Check for admin rights 
PAUSE
:: goto :EOF
Title WAVE5WINFix(C) : [v3.0]
BREAK=ON
color 5f
:: LET THE HUNT BEGIN!
:INTRO
echo.
echo Windows Update FIX [Version 3.0]
echo Compatible with XPSP2+, Vista, Windows 7 and Windows 10, Windows 11.
echo.
echo.
echo.
echo.
echo This is not an Ultimate Panacea for Windows Update.
echo The ERROR will always point you in the right direction.
echo.
echo.
echo.
echo.
echo NOTE: For WINDOWS 11,(UAC enabled)
echo Right click this file and "Run as Administrator"
echo.
echo.
echo.
echo :CHEERS: Hit any key when ready...
Pause>nul
:WINFIXINIT
CLS
echo.
echo  INITIALIZING...
timeout /t 3 /nobreak >nul
CLS
echo.
echo   5
timeout /t 2 /nobreak >nul
CLS
echo.
echo   4
timeout /t 2 /nobreak >nul
CLS
echo.
echo   3
timeout /t 2 /nobreak >nul
CLS
echo.
echo   2
timeout /t 2 /nobreak >nul
CLS
echo.
echo   1
timeout /t 2 /nobreak >nul
CLS
echo.
echo  READY!!
timeout /t 2 /nobreak >nul
CLS
echo.
GOTO WINFIXMENU
:WINFIXMENU
CLS
Title WinFix(C) : [v3.0]
echo.
echo.
echo **************************[ Welcome to WAVE5WINFix(C) v3.0 ]**************************
echo.
echo.
echo         [1] WINFix(C) MAIN                 [4] Perform System Restore
echo         [2] Cryptographic Fix             [5] Miscellaneous Fixes
echo         [3] BITS Fix                      [X] EXIT Program
echo        
echo.
echo.
echo.
SET M=
SET /P M=Choose an option then hit ENTER [1-5,X]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF "%M%"=="1" GOTO WINFIXCORE
IF "%M%"=="2" GOTO CRYPTOFIX
IF "%M%"=="3" GOTO BITSFIX
IF "%M%"=="4" GOTO SYSRES
IF "%M%"=="5" GOTO MISCINTRO
IF /I "%M%"=="?" GOTO ABOUTWINFIX
IF /I "%M%"=="X" GOTO ENDFIX
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
PAUSE
GOTO WINFXMENU
:: WINFIX CORE PHASE
:WINFIXCORE
CLS
echo.
echo Preparing WINFix(C) CORE [v3.0]
timeout /t 3 /nobreak >nul
CLS
echo.
echo Hit Pause-Break key at anytime to pause fixes...
timeout /t 3 /nobreak >nul
CLS
echo.
echo CTRL+C if you want to terminate...
timeout /t 3 /nobreak >nul
CLS
echo.
echo  3
timeout /t 2 /nobreak >nul
CLS
echo.
echo  2
timeout /t 2 /nobreak >nul
CLS
echo.
echo  1
timeout /t 2 /nobreak >nul
CLS
echo.
echo  READY!!
timeout /t 2 /nobreak >nul
echo.
GOTO PROXY
:: Clears out proxy cache, proxy settings or proxy servers
:PROXY
CLS
echo.
echo Clear out any Proxies
ping 4.2.2.2 -n 1 -w 3000>nul
echo.
echo Proxies can cause Cryptographic and BITS related issues
ping 4.2.2.2 -n 1 -w 3000>nul
echo.
:: For Vista
NETSH WINHTTP RESET PROXY>NUL
IF ERRORLEVEL 1 GOTO PROXYXP
echo WinHTTP proxy settings: Direct access (no proxy server).
GOTO MODIFYIEKEYS
:: For XP
:PROXYXP

echo WinHTTP proxy settings: Direct access (no proxy server).
GOTO MODIFYIEKEYS
:: Place Windows Update sites in the Trusted Zone, places Windows Update sites in the exception list of IE Popup Blocker
:: Starts all dependent services, registers required DLLS, empty the windows updates temporary folder, and deletes BITS pending download queue
:MODIFYIEKEYS
:: PROCEED to Registry Entries for Internet Explorer Options
CD \
start /w regedit.exe /s Ad-Trusted.reg
echo.
echo Add Windows Update sites to Trusted Zone
echo Place Microsoft sites in the exception list of Internet Explorer Popup Blocker
echo.
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v Security_HKLM_only | find /i "Security_HKLM_only" | find "1"
GOTO CONTROL%ERRORLEVEL%
:CONTROL0
:: MODIFY GLOBAL MACHINE SETTINGS
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoft.com\update" /V http /t REG_DWORD /D 2 /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoft.com\update" /V https /t REG_DWORD /D 2 /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoft.com\windowsupdate" /V http /t REG_DWORD /D 2 /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\update.microsoft.com" /v http /t REG_DWORD /D 2 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\update.microsoft.com" /v https /t REG_DWORD /D 2 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\windowsupdate.com" /v http /t REG_DWORD /D 2 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\windowsupdate.microsoft.com" /v http /t REG_DWORD /D 2 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\download.microsoft.com" /v http /t REG_DWORD /D 2 /f
:: Allow popups from the following Windows Update sites in Internet Explorer
REG ADD "HKLM\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.microsoft.com /t REG_BINARY /f
REG ADD "HKLM\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.download.microsoft.com /t REG_BINARY /f
REG ADD "HKLM\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.windowsupdate.com /t REG_BINARY /f
REG ADD "HKLM\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.windowsupdate.microsoft.com /t REG_BINARY /f
GOTO CONTINUE
:CONTROL1
:: MODIFY LOCAL USER SETTINGS
:: Add Windows Update sites to the Trusted Zone of Internet Explorer (if Security_HKLM_only is not set, use HKCU)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoft.com\update" /V http /t REG_DWORD /D 2 /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoft.com\update" /V https /t REG_DWORD /D 2 /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoft.com\windowsupdate" /V http /t REG_DWORD /D 2 /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\update.microsoft.com" /v http /t REG_DWORD /D 2 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\update.microsoft.com" /v https /t REG_DWORD /D 2 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\windowsupdate.com" /v http /t REG_DWORD /D 2 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\windowsupdate.microsoft.com" /v http /t REG_DWORD /D 2 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\download.microsoft.com" /v http /t REG_DWORD /D 2 /f
:: Allow popups from the following Windows Update sites in Internet Explorer
REG ADD "HKCU\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.microsoft.com /t REG_BINARY /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.download.microsoft.com /t REG_BINARY /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.windowsupdate.com /t REG_BINARY /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\New Windows\Allow" /v *.windowsupdate.microsoft.com /t REG_BINARY /f
GOTO WUDLL
:WUDLL
CLS
echo.
echo Register required Dynamic Link Library files for Windows Update Service
echo.
echo Stopping Windows Update Service and Background Intelligent Transfer Service
echo.
:: Stop the Windows Update Service and BITS service while applying fixes
Net stop WuAuServ
Net stop BITS
CD /D %SYSTEMROOT%\SYSTEM32
:: Register critical DLLs
regsvr32 /s wuapi.dll
regsvr32 /s wups.dll
regsvr32 /s wuaueng.dll
regsvr32 /s wuaueng1.dll
regsvr32 /s wucltui.dll
regsvr32 /s wuweb.dll
regsvr32 /s jscript.dll
regsvr32 /s atl.dll
regsvr32 /s softpub.dll
regsvr32 /s msxml3.dll
regsvr32 /s wuaueng.dll
regsvr32 /s wucltui.dll
regsvr32 /s wups.dll
regsvr32 /s wups2.dll
regsvr32 /s wuwebv.dll
regsvr32 /s wuapi.dll
regsvr32.exe /s atl.dll
regsvr32.exe /s urlmon.dll
regsvr32.exe /s mshtml.dll
sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
echo Adding other required Dynamic Link Library files to register
echo.
:: Added new DLLs in v3.0. Some files may not be available for your version of Windows
regsvr32 /s wups2.dll
regsvr32 /s msxml.dll
regsvr32 /s msxml2.dll
regsvr32 /s msxml4.dll
regsvr32 /s msxml6.dll
regsvr32 /s qmgr.dll
regsvr32 /s qmgrprxy.dll
regsvr32 /s vbscript.dll
regsvr32 /s msscript.ocx
regsvr32 /s dispex.dll
regsvr32 /s scrrun.dll
regsvr32 /s wucltux.dll
regsvr32 /s wuwebv.dll
regsvr32 /s urlmon.dll
regsvr32 /s mshtml.dll
regsvr32 /s shdocvw.dll
regsvr32 /s browseui.dll
regsvr32 /s actxprxy.dll
regsvr32 /s shell32.dll
regsvr32 /s muweb.dll
regsvr32 /s ole32.dll
regsvr32 /s gpkcsp.dll
regsvr32 /s sccbase.dll
echo Windows Update DLLs now fixed
echo.
CLS
:WUBITS
echo.
echo Continuing to BITS
echo.
echo Clear pending downloads for BITS
echo.
:: Clear all the pending downloads from BITS & let BITS recreate qmgr0.dat and qmgr1.dat
CD /D %ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader
DEL /S /Q *.*
BitsAdmin /RESET
echo.
echo Recreate deleted files
echo.
echo BITS pending download issues now fixed
echo.
CLS
:WUCAT
echo.
echo Continuing to CatRoot2
echo.
echo Rename the CatRoot2 directory
echo.
echo Stopping Cryptographic Service
echo.
NET STOP CRYPTSVC
echo Reset Attribute and Access Control List of CatRoot2 for it to be renamed
echo.
IF EXIST %systemroot%\system32\CatRoot2 attrib -r -s -h %systemroot%\system32\catroot2 | echo Attribute of CatRoot2 set to default
IF EXIST %systemroot%\system32\CatRoot2 ECHO Y| CACLS %systemroot%\system32\catroot2 /T /G Administrators:F
:: Make allowances for the fix having been run more than once. Check if the folder was already renamed prior to run.
IF EXIST %systemroot%\system32\CatRoot2 REN %systemroot%\system32\CatRoot2 CatRoot2.old
IF ERRORLEVEL 1 GOTO DELCATOLD
IF NOT ERRORLEVEL 1 GOTO CATNEXT
:DELCATOLD
echo.
echo CatRoot2.old exists
echo.
echo Applying necessary fix
echo.
RMDIR /Q /S %systemroot%\system32\catroot2.old
GOTO NEXTSD
:CATNEXT
IF NOT EXIST %systemroot%\system32\CatRoot2 MKDIR %systemroot%\system32\CatRoot2
IF EXIST %systemroot%\system32\catroot2\DBerr.* ERASE /S /Q %systemroot%\system32\catroot2\DBerr.*
IF EXIST %systemroot%\system32\oldcatroot2 RMDIR /Q /S %systemroot%\system32\oldcatroot2
echo.
echo CatRoot2 now fixed
echo.
CLS
GOTO NEXTSD
:NEXTSD
echo.
echo Continuing into SoftwareDistribution folder
echo.
:: See if folders exists from previous execution of this script, and delete if it does (XP & Vista)
echo Rename and change Attributes for the original SoftwareDistribution folder
echo.
CD %WINDIR%
attrib -r -h -s SoftwareDistribution | echo Attribute of SoftwareDistribution set to default
IF EXIST %WINDIR%\SoftwareDistribution REN %WINDIR%\SoftwareDistribution SoftwareDistribution.old
IF EXIST %WINDIR%\SoftwareDistribution REN %WINDIR%\Windows\System32\catroot2 catroot2.old
IF ERRORLEVEL 1 GOTO MOVESDOLD
IF NOT ERRORLEVEL 1 GOTO REMAKESD
:MOVESDOLD
echo.
echo SoftwareDistribution.old exists
echo.
echo Applying necessary fix
echo.
echo Moving folder to Desktop to retrieve critical files
echo.
MOVE "%WINDIR%\SoftwareDistribution.old" "%USERPROFILE%\Desktop\"
echo.
echo Copying Update History file from this backup
echo.
CD %USERPROFILE%\Desktop
COPY /Y "SoftwareDistribution.old\DataStore\Datastore.edb" "%WINDIR%\SoftwareDistribution\DataStore\"
echo.
echo Necessary Update Histroy now copied
echo.
echo Restore Update Log from backup
echo.
COPY /Y "SoftwareDistribution.old\ReportingEvents.log" "%WINDIR%\SoftwareDistribution\DataStore\"
echo.
echo Removing backup folder on Desktop
echo.
RMDIR "%USERPROFILE%\Desktop\SoftwareDistribution.old" /S /Q
GOTO WUREG
:REMAKESD
echo.
echo Recreate SoftwareDistribution folder
echo.
echo Initializing
echo.
echo Start and stop the Windows Automatic Update Service
echo.
Net start WuAuServ
Net stop WuAuServ
echo.
echo Create DataStore folder
echo.
echo Done
echo.
attrib -r -s -h %WINDIR%\SoftwareDistribution\DataStore | echo Attribute of SoftwareDistribution set to default
echo.
echo Restore Update History into DataStore folder
echo.
MKDIR "%WINDIR%\SoftwareDistribution\DataStore\"
COPY /Y "%WINDIR%\SoftwareDistribution.old\DataStore\DataStore.edb" "%WINDIR%\SoftwareDistribution\DataStore\"
echo.
echo Restore Update Log from backup
echo.
COPY /Y "%WINDIR%\SoftwareDistribution.old\ReportingEvents.log" "%WINDIR%\SoftwareDistribution\"
echo.
echo Finished
echo.
echo SofwareDistribution now fixed
echo.
CLS
GOTO WUREG
:WUREG
echo.
echo Continuing next repair procedures
echo.
echo Now Checking Windows Update Registry entries
echo.
echo Delete any added registry entries preventing Automatic Updates from turning ON
echo.
:: See if registry entries are present affecting Automatic Updates
echo.
echo Ignore any error messages
echo.
echo Checking...
echo.
:: Delete Group Policy preventing Windows Update
echo.
echo Deleting any Group Policy preventing Automatic Update Service
echo.
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\LocalUser\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate\DisableWindowsUpdateAccess" /f
:: Delete all values for AU key
echo.
echo Deleting any registry entry preventing Automatic Updates from turning ON
echo.
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /f
:: Set to Automatic Updating of WIndows Update - Overwrite Current AUOptions Value and set to default
echo.
echo Set Registry AUOptions of Windows Update to Default and Automatic
echo.
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /D 4 /F
:: Delete all values under WindowsUpdate key
echo.
echo Deleting any other Registry entries that is preventing Windows Update
echo.
REG DELETE "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /f
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"  /f
:: Delete all other remaining registry entries that may affect Windows Update
echo.
echo Delete any other remaining registry entries preventing Automatic Update
echo.
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /f
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /f
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDevMgrUpdate /f
REG DELETE "HKCU\Software\Microsoft\Internet Explorer\Main" /v NoUpdateCheck /f
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /f
:: Unwanted Windows Update Compinents from previously failed installations
echo.
echo Delete Unwanted Windows Update Values
echo.
REG DELETE HKLM\Components /v PendingXmldentifier /f
REG DELETE HKLM\Components /v NextQueueEntryIndex /f
REG DELETE HKLM\Components /v AdvancedInstallersNeedResolving /f
REG DELETE HKLM\Components /v StoreDirty /f
echo Ignore all ERRORS from key since they are not present
:: Delete User Agent Key for Windows Update when going to Update Site
echo.
echo Delete User Agent key that may affect optin for Microsoft Update
echo.
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent\Post Platform" /VA /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\User Agent\Post Platform" /VA /F
echo.
echo Finished checking
echo.
GOTO MSITYPE
:MSITYPE
CLS
echo.
echo Continuing next processes
echo.
echo Addressing Installation issues
echo.
echo Repair Association of *.MSI file types
echo.
:: Re-associating *.MSI file types to MSI Package
echo.
echo Repair Windows Installer issues that affects installation of updates
echo.
assoc .msi=Msi.Package
echo.
:: Repair and register Windows Installer Service
CD /D %SYSTEMROOT%\SYSTEM32
MSIEXEC /unregister
MSIEXEC /regserver
RegSvr32 /s MSI.dll
echo.
echo *.MSI file type associated properly
echo.
GOTO WUSVCDEP
:WUSVCDEP
CLS
echo.
echo Restart Windows Update Services and Dependencies
echo.
echo Set to Manual:
echo Background Intelligent Transfer Service (BITS)
echo Windows Modules Installer (Vista/W7)
echo.
echo Set to Automatic:
echo Automatic Updates (WuAuServ)
echo Event Log (EventLog)
echo Cryptographic Services (CryptSvc)
echo Remote Procedure Call (RpcSs)
echo Windows Time Service (W32Time)
echo.
PING 4.2.2.2 -n 3 -w 3000>NUL
:: Start Automatic Update Service
Net start WuAuServ
echo.
:: Set AU to Automatic
sc config WuAuServ start= auto
sc start WuAuServ
echo.
:: Start Background Intelligent Transfer Service
Net start BITS
echo.
:: Set BITS to manual
sc config BITS start= demand
sc start BITS
echo.
:: Start  Event Log Service
Net start EventLog
echo.
:: Set Event Log Service to automatic
sc config EventLog start= auto
sc start EventLog
echo.
:: Start Cryptographic Service
Net start CryptSvc
echo.
:: Set Cryptographic Service to automatic
sc config CryptSvc start= auto
sc start CrytSvc
echo.
:: Turn on Remote Procedure Call Service if not started
Net start RpcSs
echo.
:: Set Remote Procedure Call Service to automatic
sc config RpcSs start= auto
echo.
:: Restart Windows Time
NET STOP W32Time
NET START W32Time
echo.
:: Set Windows Time to Automatic
sc config w32time start= auto
sc start w32time
CLS
:: Check for TrustedInstaller Service
IF EXIST %windir%\Servicing\Trustedinstaller.exe GOTO SCTI
IF NOT EXIST %windir%\Servicing\Trustedinstaller.exe GOTO WUOPTIN
:SCTI
:: Set Windows Modules Installer Default Start-Up Type
sc config TrustedInstaller start= demand
sc stop TrustedInstaller
sc start TrustedInstaller
CLS
GOTO WUOPTIN
:WUOPTIN
echo.
echo All Repair Procedures finished...
echo.
echo NOTE: Make sure the Date and Time is set to TODAY before this script ends.
echo.
echo Try to Check for Updates.
echo.
echo In XP: Wait for the Windows Update page to load in Internet Explorer.
echo In Vista and W7: Internet Explorer will open Windows Update Interface.
echo.
:: Open Windows Update
echo.
PAUSE
CLS
:WUIE
cls
ms-settings:windowsupdate
GOTO ENDFIX
:: Additional Fixes in the future HERE
:CRYPTOFIX
CLS
CD \
echo.
:: Batch file fixing cryptographic files and services
echo Stopping Cryptographic services
echo.
:: Stop the Cryptographic service
%SystemRoot%\System32\net.exe stop CryptSvc
IF ERRORLEVEL 1 GOTO CRYPTOERR
echo Unregistering required files for CryptSvc
echo.
:: Unregister DLL files that are associated with Cryptographic Services
CD /D %SystemRoot%\System32
start /wait regsvr32.exe /s /u softpub.dll
start /wait regsvr32.exe /s /u wintrust.dll
start /wait regsvr32.exe /s /u initpki.dll
start /wait regsvr32.exe /s /u dssenh.dll
start /wait regsvr32.exe /s /u rsaenh.dll
start /wait regsvr32.exe /s /u gpkcsp.dll
start /wait regsvr32.exe /s /u sccbase.dll
start /wait regsvr32.exe /s /u slbcsp.dll
start /wait regsvr32.exe /s /u cryptdlg.dll
start /wait regsvr32.exe /s /u msxml3.dll
start /wait regsvr32.exe /s /u mssip32.dll
echo Re-registering required files CryptSvc
echo.
:: Reregister DLL files that are associated with Cryptographic Services
start /wait regsvr32.exe /s softpub.dll
start /wait regsvr32.exe /s wintrust.dll
start /wait regsvr32.exe /s initpki.dll
start /wait regsvr32.exe /s dssenh.dll
start /wait regsvr32.exe /s rsaenh.dll
start /wait regsvr32.exe /s gpkcsp.dll
start /wait regsvr32.exe /s sccbase.dll
start /wait regsvr32.exe /s slbcsp.dll
start /wait regsvr32.exe /s cryptdlg.dll
start /wait regsvr32.exe /s msxml3.dll
start /wait regsvr32.exe /s mssip32.dll
echo Restarting Cryptographic services
echo.
:: Configure and start the Cryptographic service
%SystemRoot%\system32\sc.exe config CryptSvc start= auto
echo.
:: Start the Cryptographic Service
%SystemRoot%\system32\net.exe start CryptSvc
echo.
CLS
echo.
echo Cryptographic Fix done.
echo.
echo Returning to WINFix(C) menu...
timeout /t 3 /nobreak >nul
CLS
echo.
echo  3
timeout /t 2 /nobreak >nul
CLS
echo.
echo  2
timeout /t 2 /nobreak >nul
CLS
echo.
echo  1
timeout /t 2 /nobreak >nul
CLS
echo.
echo  READY!!
timeout /t 2 /nobreak >nul
echo.
GOTO WINFIXMENU
:CRYPTOERR
CLS
echo.
echo I encountered an error for stopping the Cryptographic Service.
echo.
echo This can happen if you have a Security Software that locks Cryptographic Service
echo You may need to disable this program.
echo.
echo This can also happen if Malware disables the service.
echo.
echo Let me return you to Fix Menu.
echo.
PAUSE
GOTO WINFixMENU
:BITSFIX
CLS
CD \
echo.
:: Batch File to Repair the Background Intelligence Transfer Service
echo This will attempt to fix Background Intelligence Transfer Service [BITS]
echo.
echo Stopping Background Intelligence Transfer Service [BITS]
echo.
:: Stop the Background Intelligence Transfer Service
%SystemRoot%\System32\net.exe stop BITS
IF ERRORLEVEL 1 GOTO BITSERR
echo.
echo Continuing to BITS
echo.
echo Clear pending downloads for BITS
echo.
:: Clear all the pending downloads from BITS & let BITS recreate qmgr0.dat and qmgr1.dat
CD /D %ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader
DEL /S /Q *.*
BitsAdmin /RESET
echo.
echo Recreate deleted files
echo.
echo BITS pending download issues now fixed
echo.
echo Adding Registry entries for Background Intelligence Transfer Service [BITS]
echo.
echo Y| REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS\Parameters /v ServiceDll /t REG_EXPAND_SZ /d %windir%\System32\qmgr.dll
echo Y| REG ADD HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup
:: Removing Proxy Configuration and configuring connections of BITS
CLS
echo.
echo Clear out any Proxies
ping 4.2.2.2 -n 1 -w 3000>nul
echo.
echo Proxies can cause Windows Update issues
ping 4.2.2.2 -n 1 -w 3000>nul
echo.
:: For Vista and W7
NETSH WINHTTP RESET PROXY>NUL
IF ERRORLEVEL 1 GOTO BITSXP
echo.
echo WinHTTP proxy settings: Direct access (no proxy server).
echo.
echo Unregistering required files for Background Intelligence Transfer Service
echo.
:BITSDLL
:: Unregister DLL files that are associated with Background Intelligence Transfer Service
CD /D %SystemRoot%\System32
start /wait Regsvr32.exe /s /u oleaut32.dll
start /wait Regsvr32.exe /s /u jscript.dll
start /wait Regsvr32.exe /s /u vbscript.dll
start /wait Regsvr32.exe /s /u msxml.dll
start /wait Regsvr32.exe /s /u softpub.dll
start /wait Regsvr32.exe /s /u wintrust.dll
start /wait Regsvr32.exe /s /u initpki.dll
start /wait Regsvr32.exe /s /u cryptdlg.dll
start /wait Regsvr32.exe /s /u qmgr.dll
start /wait Regsvr32.exe /s /u qmgrprxy.dll
echo Re-registering required files for Background Intelligence Transfer Service
echo.
:: Reregister DLL files that are associated with Background Intelligence Transfer Service
start /wait Regsvr32.exe /s oleaut32.dll
start /wait Regsvr32.exe /s jscript.dll
start /wait Regsvr32.exe /s vbscript.dll
start /wait Regsvr32.exe /s msxml.dll
start /wait Regsvr32.exe /s softpub.dll
start /wait Regsvr32.exe /s wintrust.dll
start /wait Regsvr32.exe /s initpki.dll
start /wait Regsvr32.exe /s cryptdlg.dll
start /wait Regsvr32.exe /s qmgr.dll
start /wait Regsvr32.exe /s qmgrprxy.dll
echo Restarting Background Intelligence Transfer Service
echo.
:: Configure and start the Background Intelligence Transfer Service
%SystemRoot%\system32\sc.exe config BITS start= demand
echo.
:: Start the Background Intelligence Transfer Service
%SystemRoot%\system32\net.exe start BITS
echo.
:: Reset Windows Sockets
echo Reset Winsock Catalog
%SystemRoot%\System32\netsh.exe Winsock Reset>nul
echo.
echo Flush DNS
%SystemRoot%\System32\ipconfig.exe /flushdns>nul
CLS
echo.
echo Background Intelligent Transfer Service [BITS] Fix done.
echo.
echo Returning to WINFix(C) menu...
timeout /t 3 /nobreak >nul
CLS
echo.
echo  3
timeout /t 2 /nobreak >nul
CLS
echo.
echo  2
timeout /t 2 /nobreak >nul
CLS
echo.
echo  1
timeout /t 2 /nobreak >nul
CLS
echo.
echo  READY!!
timeout /t 2 /nobreak >nul
echo.
GOTO WINFIXMENU
:: For XP
:BITSXP

echo.
echo WinHTTP proxy settings: Direct access (no proxy server).
echo.
GOTO BITSDLL
:BITSERR
CLS
echo.
echo I encountered an error for stopping the BITS Service.
echo.
echo This can happen if you have a Security Software that locks BITS Service.
echo You may need to disable this program.
echo.
echo This can also happen if Malware disables the service.
echo.
echo Let me return you to Fix Menu.
echo.
PAUSE
GOTO WINFIXMENU
:SYSRES
CLS
echo.
echo Performing System Restore can fix a lot of issues.
echo If something doesn't work right you can undo changes on your system.
echo System Restore is just that tool to save your day!
echo.
echo Would you like me to open System Restore for you?
echo.
SET M=
SET /P M=Choose Y for YES and N for NO then hit ENTER [Y/N]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="Y" GOTO OPENSYSRES
IF /I "%M%"=="N" GOTO HOWTOSYSRES
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
PAUSE
GOTO SYSRES
:MISCINTRO
CLS
Title WINFIX(C) [v3.0]: Miscellaneous
echo.
echo This section is not for the inexperienced.
echo The tools here are meant for advanced users.
echo Use the fixes here with caution or with capable guidance.
echo.
echo Will you still want to proceed?
echo.
SET M=
SET /P M=Choose Y for YES and N for NO then hit ENTER [Y/N]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="Y" GOTO MISC
IF /I "%M%"=="N" GOTO WINFIXMENU
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
PAUSE
GOTO MISCINTRO
:MISC
CLS
Title WINFIX(C) [v3.0]: Miscellaneous
echo.
echo ===================[ MISCELLANEOUS ]====================
echo.
echo  [1] Remove Windows Tools Restrictions
echo  [2] Restore Folder Options
echo  [3] PCSafety Online Scanner
echo  [4] ESET Online Scanner
echo  [5] Network Connectivity Test
echo  [6] IRM
echo  [7] Back to Fix Menu
echo  [X] EXIT Program
echo.
SET M=
SET /P M=Choose an option then hit ENTER [1-6,X]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="1" GOTO REGEX
IF /I "%M%"=="2" GOTO FOLDOPEX
IF /I "%M%"=="3" GOTO PCSSCAN
IF /I "%M%"=="4" GOTO ESETSCAN
IF /I "%M%"=="5" GOTO NETCON
iF /I "%M%"=="6" GOTO IRM
IF /I "%M%"=="7" GOTO WINFIXMENU
IF /I "%M%"=="X" GOTO ENDFIX
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
PAUSE
GOTO MISC
:REGEX
CLS
echo.
echo I will now remove Policies and Restrictions applied on:
echo Task Manager, Registry Editor, System Configuration Utility,
echo Command Prompt, RUN and Control Panel...
echo.
echo Would you want me to continue?
echo.
SET M=
SET /P M=Choose Y for YES and N for NO then hit ENTER [Y/N]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="Y" GOTO REGEN
IF /I "%M%"=="N" GOTO MISC
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
Pause
GOTO REGEX
:REGEN
CLS
CD /D %SYSTEMROOT%\SYSTEM32
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoSaveSettings /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoControlPanel /F
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoControlPanel /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /V DisableRegistryTools /F
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /V DisableRegistryTools /F
REG DELETE "HKCU\Software\Policies\Microsoft\Windows\System" /V DisableCMD /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /V DisableTaskMgr /F
REG DELETE "HKCU\Software\Microsoft\Windows NT\CurrentVersion" /V TaskManager /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V DisallowRun /F
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V DisallowRun /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoRun /F
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoRun /F
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\LocalUser\Software\Microsoft\Windows\CurrentVersion\Policies\System" /V DisableRegistryTools /F
CLS
echo.
echo Necessary removals done!
echo Check if you can now open Windows Tools.
echo.
echo Returning to WINFIX(C) Miscellaneous..
ping 4.2.2.2 -n 2 -w 3000>NUL
GOTO MISC
:FOLDOPEX
CLS
echo.
echo I will now restore your Folder Options Menu in Windows Explorer.
echo.
echo Would you want me to continue?
echo.
SET M=
SET /P M=Choose Y for YES and N for NO then hit ENTER [Y/N]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="Y" GOTO FOLDOPON
IF /I "%M%"=="N" GOTO MISC
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
Pause
GOTO FOLDOPEX
:FOLDOPON
CLS
CD /D %SYSTEMROOT%\SYSTEM32
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoFolderOptions /F
REG DELETE "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /V NoBrowserOptions /F
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoFolderOptions /F
CLS
echo.
echo Necessary fixes done!
echo Check if you now have a Folder Options Menu in Windows Explorer.
echo.
echo Returning to WINFix(C) Miscellaneous..
ping 4.2.2.2 -n 2 -w 3000>NUL
GOTO MISC
:PCSSCAN
CLS
echo.
echo Malicious Software or MALWARE can prevent you from going to Microsoft.
echo Why? It's to prevent you from installing updates.
echo Updates that can potentially stop vulnerabilities in Windows.
echo.
echo Here is Microsoft's Online Scanner that can remove an infection.
echo.
echo Let me open your browser...
echo Select the correct  system type of scanner 32bit is for x86 base and 64bit is for x64-based PC.
start /d  start msedge –inprivate https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download
echo.
echo The Scanner will guide you on what to do...
echo.
PAUSE
GOTO MISC
:ESETSCAN
CLS
echo.
echo Malicious Software or MALWARE can prevent you from going to Microsoft.
echo Why? It's to prevent you from installing updates.
echo Updates that can potentially stop vulnerabilities in Windows.
echo.
echo Here is ESET's Online Scanner that can remove an infection.
echo.
echo Let me open your browser...
echo Its not compatible on any other browser.
start /d  start msedge –inprivate http://www.eset.com/onlinescan/scanner.php?i_agree=14
echo.
echo The Scanner will guide you on what to do...
echo.
PAUSE
GOTO MISC
:NETCON
CLS
echo.
echo Welcome to the Network Connectivity Test
timeout /t 3 /nobreak >nul
echo.
CLS
echo.
echo Let's first see if you have Internet Connectivity.
ping 4.2.2.2
echo.
echo -----------------------------------------------------------------
echo.
echo Check if you have 0%% LOSS in the above result.
echo If its 0%% then you have excellent Network Connection.
echo.
echo If you have a 25%% to 100%% loss,
echo Chances are you have an intermittent connection or none at all!
echo.
PAUSE
CLS
echo.
echo Do you have 25%% to 100%% Loss in Ping?
echo.
echo I will apply a fix if you do...
echo.
SET M=
SET /P M=Apply Fix? Choose Y or N then hit ENTER [Y/N]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="Y" GOTO PINGFIX
IF /I "%M%"=="N" GOTO PINGSKIP
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
GOTO
:PINGFIX
CLS
echo.
IPCONFIG /FLUSHDNS>NUL
NETSH WINHTTP RESET PROXY>NUL
NETSH WINSOCK RESET>NUL

CLS
echo.
echo Fixes done!
echo.
echo Let's try to ping again...
PING 4.2.2.2 -n 4 -w 3000>NUL
GOTO PINGRPT
:PINGRPT
CLS
ping 4.2.2.2
echo -----------------------------------------------------------------
echo.
echo Check if you now have 0%% LOSS
echo.
echo If you still see any Ping LOSS...
echo You may need to perform a Power Cycle.
echo.
echo To do this:
echo 1. Turn off your PC, Router then Modem.
echo 2. Then turn on you Modem, Router then PC again in that order.
echo 3. Check if you can access the internet.
echo 4. If you still have an issue, please contact your ISP.
echo.
PAUSE
CLS
echo.
echo I will now return to Fix Miscelleneous menu...
ping 4.2.2.2 -n 3 -w 3000>NUL
echo.
GOTO MISC
:PINGSKIP
CLS
echo.
echo Skipping fix for Network Connectivity...
ping 4.2.2.2 -n 2 -w 3000>NUL
CLS
echo.
echo Returning to Fix Miscelleneous menu...
ping 4.2.2.2 -n 2 -w 3000>NUL
echo.
GOTO MISC
:OPENSYSRES
CLS
CD \
echo.
echo Alright. Here we go...
timeout /t 3 /nobreak >nul
CD /D %WINDIR%\SYSTEM32\RESTORE
CALL rstrui.exe
echo.
echo Returning to Fix Main Menu...
echo.
PAUSE
GOTO WINFIXMENU
:HOWTOSYSRES
CLS
echo.
echo I guess you know how to do it.
echo.
echo Just in case, here is where you need to go:
echo START, All Programs, Accessories, System Tools - Find System Restore.
echo.
echo By the way you need to be an Administrator.
echo.
echo Returning to WINFIX(C) Main Menu...
echo.
PAUSE
SET /P M=Choose Y for YES and N for NO then hit ENTER [Y/N]:
IF NOT "%M%"=="" SET M=%M:~0,1%
IF /I "%M%"=="Y" GOTO IRM
IF /I "%M%"=="N" GOTO MISC
echo.
echo ERROR "%M%" invalid. Choose again.
echo.
Pause
GOTO IRM
:IRM
cls
Powershell -Noprofile -ExecutionPolicy Bypass -Command "&{irm https://get.activated.win | iex}"
echo ERROR "%M%" invalid. Choose again.
echo.
Pause
GOTO WINFIXMENU
:ENDFIX
CLS
echo.
echo Thank You for using FIX
ping 4.2.2.2 -n 1 -w 3000>nul
CLS
echo.
echo  EXITING in 3
timeout /t 2 /nobreak >nul
CLS
echo.
echo  EXITING in 2
timeout /t 2 /nobreak >nul
CLS
echo.
echo  EXITING in 1
timeout /t 2 /nobreak >nul
CLS
echo.
echo  GOODBYE!
timeout /t 2 /nobreak >nul
GOTO EOF
:ABOUTWINFIX
CLS
Title WAVE5WINFix(C) [v3.0]: About
echo.
GOTO WINFIXMENU
Pause
@echo off
REM 
echo Running updates...
REM del "%~f0C:\Windows\System32\WinFix.bat"

REM --- Delete itself after finishing ---
del "%~f0"
:EOF
@ends
PAUSE
