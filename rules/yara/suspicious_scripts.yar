/*
    Aegis — Suspicious Script Detection Rules
    Detects obfuscated PowerShell, batch droppers, and encoded commands.
*/

rule Powershell_Encoded_Command
{
    meta:
        description = "PowerShell with base64-encoded command"
        severity = "high"
        mitre = "T1059.001"
        author = "Aegis"

    strings:
        $ps1 = "powershell" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-e " nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/

    condition:
        $ps1 and (1 of ($enc*)) and $b64
}

rule Powershell_Download_Execute
{
    meta:
        description = "PowerShell download and execute pattern"
        severity = "high"
        mitre = "T1059.001"
        author = "Aegis"

    strings:
        $dl1 = "Invoke-WebRequest" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "DownloadString" nocase
        $dl4 = "Net.WebClient" nocase
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "IEX" nocase
        $exec3 = "Start-Process" nocase

    condition:
        (1 of ($dl*)) and (1 of ($exec*))
}

rule Batch_Dropper
{
    meta:
        description = "Batch file with download and execution commands"
        severity = "medium"
        mitre = "T1059.003"
        author = "Aegis"

    strings:
        $bat1 = "certutil" nocase
        $bat2 = "bitsadmin" nocase
        $bat3 = "curl " nocase
        $bat4 = "wget " nocase
        $exec1 = "start /b" nocase
        $exec2 = "cmd /c" nocase

    condition:
        (1 of ($bat*)) and (1 of ($exec*))
}
