; ============================================================================
; Aegis Security Defense System — NSIS Installer Script
; ============================================================================
;
; Builds a Windows installer wizard that packages the PyInstaller output
; (dist/aegis/) into a single Setup executable.
;
; Usage:
;   makensis build\installer.nsi
;
; Prerequisites:
;   - PyInstaller build must have completed (dist/aegis/ must exist)
;   - NSIS 3.x with MUI2 plugin
;
; ============================================================================

; ---------------------------------------------------------------------------
; Build configuration
; ---------------------------------------------------------------------------

!define APP_NAME        "Aegis Security Defense System"
!define APP_SHORT_NAME  "Aegis"
!define APP_PUBLISHER   "Aegis Security"
!define APP_VERSION     "0.1.0"
!define APP_EXE         "aegis.exe"
!define APP_URL         "https://github.com/aegis-security/aegis"

; Registry key for Add/Remove Programs
!define UNINST_REG_KEY  "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_SHORT_NAME}"

; Source and output paths (relative to this .nsi file's directory)
!define DIST_DIR        "..\dist\aegis"
!define SYSMON_DIR      "..\tools\sysmon"
!define LICENSE_FILE    "license.txt"
!define ICON_FILE       "..\assets\aegis.ico"

; Output installer filename
!define INSTALLER_NAME  "AegisSetup-${APP_VERSION}.exe"

; ---------------------------------------------------------------------------
; General installer attributes
; ---------------------------------------------------------------------------

Name        "${APP_NAME}"
OutFile     "..\dist\${INSTALLER_NAME}"
InstallDir  "$PROGRAMFILES\${APP_PUBLISHER}"
Unicode     True

; Request administrator privileges (required for service registration)
RequestExecutionLevel admin

; Use solid LZMA compression for smallest installer size
SetCompressor /SOLID lzma

; ---------------------------------------------------------------------------
; Modern UI 2 configuration
; ---------------------------------------------------------------------------

!include "MUI2.nsh"
!include "FileFunc.nsh"

; Branding text shown in the installer footer
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to ${APP_NAME} Setup"
!define MUI_WELCOMEPAGE_TEXT \
    "This wizard will guide you through the installation of \
    ${APP_NAME} v${APP_VERSION}.$\r$\n$\r$\n\
    ${APP_NAME} is an autonomous AI security defense system that \
    monitors your Windows PC for threats in real time.$\r$\n$\r$\n\
    Click Next to continue."

!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APP_SHORT_NAME} now"
!define MUI_FINISHPAGE_LINK "Visit ${APP_SHORT_NAME} on the web"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_URL}"

; Use the application icon if it exists; NSIS will fall back to its
; default icon if the file is missing at compile time.
!if /FileExists "${ICON_FILE}"
    !define MUI_ICON "${ICON_FILE}"
    !define MUI_UNICON "${ICON_FILE}"
!endif

; ---------------------------------------------------------------------------
; Installer pages
; ---------------------------------------------------------------------------

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSE_FILE}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; ---------------------------------------------------------------------------
; Uninstaller pages
; ---------------------------------------------------------------------------

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ---------------------------------------------------------------------------
; Language (must come after all MUI page macros)
; ---------------------------------------------------------------------------

!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Installer Sections
; ============================================================================

; ---------------------------------------------------------------------------
; Section: Core Application (required — cannot be deselected)
; ---------------------------------------------------------------------------

Section "Core Application (required)" SecCore

    ; This section is mandatory
    SectionIn RO

    ; Set the installation directory as the output path
    SetOutPath "$INSTDIR"

    ; ------------------------------------------------------------------
    ; Copy all files from the PyInstaller dist output
    ; ------------------------------------------------------------------
    ; The /r flag recursively copies the entire directory tree.
    File /r "${DIST_DIR}\*.*"

    ; ------------------------------------------------------------------
    ; Register the Windows service
    ; ------------------------------------------------------------------
    ; aegis.exe --service install registers itself with the SCM.
    ; We use nsExec to run silently and capture the exit code.
    DetailPrint "Registering Aegis Windows service..."
    nsExec::ExecToLog '"$INSTDIR\${APP_EXE}" --service install'
    Pop $0
    ${If} $0 != 0
        DetailPrint "Note: Service registration returned code $0 (may already exist)"
    ${EndIf}

    ; ------------------------------------------------------------------
    ; Start Menu shortcuts
    ; ------------------------------------------------------------------
    CreateDirectory "$SMPROGRAMS\${APP_SHORT_NAME}"
    CreateShortcut  "$SMPROGRAMS\${APP_SHORT_NAME}\${APP_NAME}.lnk" \
                    "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
    CreateShortcut  "$SMPROGRAMS\${APP_SHORT_NAME}\Uninstall ${APP_SHORT_NAME}.lnk" \
                    "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0

    ; ------------------------------------------------------------------
    ; Write uninstaller
    ; ------------------------------------------------------------------
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; ------------------------------------------------------------------
    ; Add/Remove Programs registry entries
    ; ------------------------------------------------------------------
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "DisplayName"     "${APP_NAME}"
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "Publisher"        "${APP_PUBLISHER}"
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "UninstallString"  '"$INSTDIR\Uninstall.exe"'
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "QuietUninstallString" \
                  '"$INSTDIR\Uninstall.exe" /S'
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "InstallLocation"  "$INSTDIR"
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "DisplayIcon"      "$INSTDIR\${APP_EXE},0"
    WriteRegStr   HKLM "${UNINST_REG_KEY}" "URLInfoAbout"     "${APP_URL}"
    WriteRegDWORD HKLM "${UNINST_REG_KEY}" "NoModify"         1
    WriteRegDWORD HKLM "${UNINST_REG_KEY}" "NoRepair"         1

    ; Compute installed size for Add/Remove Programs
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "${UNINST_REG_KEY}" "EstimatedSize" $0

SectionEnd

; ---------------------------------------------------------------------------
; Section: Sysmon Integration (optional, default checked)
; ---------------------------------------------------------------------------

Section "Sysmon Integration" SecSysmon

    ; Copy Sysmon binaries and configuration into the tools subdirectory
    SetOutPath "$INSTDIR\tools\sysmon"
    File /nonfatal /r "${SYSMON_DIR}\*.*"

    ; Install Sysmon with the Aegis configuration if Sysmon64.exe is present
    IfFileExists "$INSTDIR\tools\sysmon\Sysmon64.exe" 0 +4
        DetailPrint "Installing Sysmon with Aegis configuration..."
        nsExec::ExecToLog '"$INSTDIR\tools\sysmon\Sysmon64.exe" -accepteula -i "$INSTDIR\tools\sysmon\sysmonconfig.xml"'
        Pop $0
        DetailPrint "Sysmon installation returned code $0"

SectionEnd

; ---------------------------------------------------------------------------
; Section: Desktop Shortcut (optional, default unchecked)
; ---------------------------------------------------------------------------

Section /o "Desktop Shortcut" SecDesktop

    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" \
                   "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0

SectionEnd

; ---------------------------------------------------------------------------
; Component descriptions (shown in the description area on the
; Components page when the user hovers over a component)
; ---------------------------------------------------------------------------

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} \
        "Core Aegis engine, sensors, detection modules, and user interface. This component is required."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecSysmon} \
        "Install Microsoft Sysmon with an Aegis-optimised configuration for enhanced event logging."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} \
        "Create a desktop shortcut for quick access to ${APP_SHORT_NAME}."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ============================================================================
; Uninstaller
; ============================================================================

Section "Uninstall"

    ; ------------------------------------------------------------------
    ; Stop and remove the Windows service
    ; ------------------------------------------------------------------
    DetailPrint "Stopping Aegis service..."
    nsExec::ExecToLog '"$INSTDIR\${APP_EXE}" --service stop'
    Pop $0

    DetailPrint "Removing Aegis service..."
    nsExec::ExecToLog '"$INSTDIR\${APP_EXE}" --service remove'
    Pop $0

    ; ------------------------------------------------------------------
    ; Uninstall Sysmon if it was installed by Aegis
    ; ------------------------------------------------------------------
    IfFileExists "$INSTDIR\tools\sysmon\Sysmon64.exe" 0 +3
        DetailPrint "Uninstalling Sysmon..."
        nsExec::ExecToLog '"$INSTDIR\tools\sysmon\Sysmon64.exe" -u'
        Pop $0

    ; ------------------------------------------------------------------
    ; Remove Start Menu and Desktop shortcuts
    ; ------------------------------------------------------------------
    Delete "$SMPROGRAMS\${APP_SHORT_NAME}\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_SHORT_NAME}\Uninstall ${APP_SHORT_NAME}.lnk"
    RMDir  "$SMPROGRAMS\${APP_SHORT_NAME}"

    Delete "$DESKTOP\${APP_NAME}.lnk"

    ; ------------------------------------------------------------------
    ; Remove installed files
    ; ------------------------------------------------------------------
    ; Remove the entire installation directory tree.
    ; Using /r on INSTDIR is safe here because the installer writes
    ; all files under this dedicated directory.
    RMDir /r "$INSTDIR"

    ; ------------------------------------------------------------------
    ; Remove registry entries
    ; ------------------------------------------------------------------
    DeleteRegKey HKLM "${UNINST_REG_KEY}"

SectionEnd
