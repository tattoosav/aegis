; Aegis AI Security Defense — NSIS Installer Script
; Requires NSIS 3.x: https://nsis.sourceforge.io/

!include "MUI2.nsh"

; --- General ---
Name "Aegis AI Security Defense"
OutFile "AegisSetup.exe"
InstallDir "$PROGRAMFILES64\Aegis"
RequestExecutionLevel admin

; --- Interface ---
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; --- Install Section ---
Section "Install"
    SetOutPath "$INSTDIR"

    ; Copy application files
    File /r "..\dist\aegis.exe"

    ; Create data directory
    CreateDirectory "$INSTDIR\data"

    ; Create Start Menu shortcut
    CreateDirectory "$SMPROGRAMS\Aegis"
    CreateShortcut "$SMPROGRAMS\Aegis\Aegis.lnk" "$INSTDIR\aegis.exe"
    CreateShortcut "$SMPROGRAMS\Aegis\Uninstall.lnk" "$INSTDIR\uninstall.exe"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Write registry keys for Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis" \
        "DisplayName" "Aegis AI Security Defense"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis" \
        "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis" \
        "Publisher" "Aegis Contributors"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis" \
        "DisplayVersion" "0.1.0"
SectionEnd

; --- Uninstall Section ---
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\aegis.exe"
    Delete "$INSTDIR\uninstall.exe"
    RMDir /r "$INSTDIR\data"
    RMDir "$INSTDIR"

    ; Remove shortcuts
    Delete "$SMPROGRAMS\Aegis\Aegis.lnk"
    Delete "$SMPROGRAMS\Aegis\Uninstall.lnk"
    RMDir "$SMPROGRAMS\Aegis"

    ; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis"
SectionEnd
