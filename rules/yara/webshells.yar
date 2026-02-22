/*
    Aegis — Web Shell Detection Rules
    Detects common web shell patterns in script files.
*/

rule WebShell_Generic_PHP
{
    meta:
        description = "Generic PHP webshell indicators"
        severity = "critical"
        mitre = "T1505.003"
        author = "Aegis"

    strings:
        $fn1 = "system(" nocase
        $fn2 = "exec(" nocase
        $fn3 = "passthru(" nocase
        $fn4 = "shell_exec(" nocase
        $fn5 = "eval(" nocase
        $input1 = "$_GET" nocase
        $input2 = "$_POST" nocase
        $input3 = "$_REQUEST" nocase

    condition:
        (2 of ($fn*)) and (1 of ($input*))
}

rule WebShell_Generic_ASPX
{
    meta:
        description = "Generic ASPX webshell indicators"
        severity = "critical"
        mitre = "T1505.003"
        author = "Aegis"

    strings:
        $asp1 = "Process.Start" nocase
        $asp2 = "cmd.exe" nocase
        $asp3 = "Request.Form" nocase
        $asp4 = "Response.Write" nocase

    condition:
        ($asp1 or $asp2) and ($asp3 or $asp4)
}
