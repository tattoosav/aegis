/*
    Aegis — Ransomware Indicator Rules
    Detects common ransomware artifacts in files.
*/

rule Ransomware_Note_Generic
{
    meta:
        description = "Generic ransomware note keywords"
        severity = "critical"
        mitre = "T1486"
        author = "Aegis"

    strings:
        $a1 = "your files have been encrypted" nocase
        $a2 = "decrypt your files" nocase
        $a3 = "bitcoin wallet" nocase
        $a4 = "pay the ransom" nocase
        $a5 = "restore your files" nocase

    condition:
        2 of ($a*)
}

rule Ransomware_Extension_Dropper
{
    meta:
        description = "File contains ransomware extension list"
        severity = "high"
        mitre = "T1486"
        author = "Aegis"

    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypted" nocase
        $ext4 = ".crypt" nocase
        $ext5 = ".enc" nocase

    condition:
        3 of ($ext*)
}
