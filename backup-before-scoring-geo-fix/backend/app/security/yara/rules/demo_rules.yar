/*
 * Demonstrative local rule set for the YARA scanner.
 * These are intentionally simple, illustrative rules for a hackathon
 * build - NOT a production malware-detection rule set. A "no match"
 * result must never be reported as "file is safe" (see scanner.py).
 */

rule Suspicious_PowerShell_Dropper
{
    meta:
        severity = "high"
        description = "Common obfuscated PowerShell download-and-execute pattern"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX(" nocase
        $c = "-EncodedCommand" nocase
        $d = "FromBase64String" nocase
    condition:
        2 of ($a, $b, $c, $d)
}

rule Suspicious_Executable_Indicators
{
    meta:
        severity = "medium"
        description = "Windows PE executable content indicators"
    strings:
        $mz = { 4D 5A }
        $stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $stub
}

rule Suspicious_Macro_AutoExec_Shell
{
    meta:
        severity = "high"
        description = "Office macro auto-execution combined with shell/command execution"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Auto_Open" nocase
        $auto3 = "Document_Open" nocase
        $shell1 = "WScript.Shell" nocase
        $shell2 = "Shell(" nocase
        $shell3 = "cmd.exe" nocase
    condition:
        1 of ($auto1, $auto2, $auto3) and 1 of ($shell1, $shell2, $shell3)
}

rule Suspicious_Script_Obfuscation
{
    meta:
        severity = "medium"
        description = "Common obfuscated-script execution patterns in HTML/JS attachments"
    strings:
        $a = "eval(unescape(" nocase
        $b = "document.write(unescape(" nocase
        $c = "ActiveXObject(\"WScript.Shell\")" nocase
    condition:
        any of them
}
