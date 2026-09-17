/*
 * Local static-content YARA rule set for the Attachment Security
 * Engine. These rules are intentionally conservative: every rule
 * either requires a COMBINATION of narrow indicators, or a single
 * indicator specific enough that it is not expected to appear in
 * ordinary documents/images/media by chance. There are deliberately
 * no generic single-word rules (e.g. matching on "powershell" or
 * "shell" alone) because those produce false positives on completely
 * benign files (README text, changelog entries, product manuals,
 * etc. routinely mention such words).
 *
 * This is NOT a general-purpose antivirus engine and does not claim
 * to detect all - or even most - malicious content. It exists to add
 * a second, independent, content/byte-based evidence source on top
 * of the filename/extension/magic-byte checks in
 * attachment_analysis.py. A "no match" result must never be reported
 * as "file is safe" (see scanner.py).
 *
 * Scope reminder: these rules only ever look at the file's bytes.
 * Filename, extension, declared content-type, and magic-byte
 * mismatch detection are handled elsewhere
 * (backend/app/services/attachment_analysis.py and
 * file_type_detector.py) and must stay there.
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

rule Suspicious_PowerShell_Hidden_Execution
{
    meta:
        severity = "high"
        description = "PowerShell invoked with a hidden/no-profile window combined with a remote-download or encoded-command indicator"
    strings:
        // Hidden-window / no-profile launch flags (how the process is started)
        $flag1 = "-windowstyle hidden" nocase
        $flag2 = "-w hidden" nocase
        $flag3 = "-noprofile" nocase
        $flag4 = "-nop " nocase
        // What it does once running - remote fetch or encoded payload
        $action1 = "Net.WebClient" nocase
        $action2 = "DownloadString" nocase
        $action3 = "DownloadFile" nocase
        $action4 = "-EncodedCommand" nocase
        $action5 = "FromBase64String" nocase
    condition:
        1 of ($flag1, $flag2, $flag3, $flag4) and 1 of ($action1, $action2, $action3, $action4, $action5)
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

rule Suspicious_PE_Process_Injection_APIs
{
    meta:
        severity = "high"
        description = "PE import-table strings for a common process-injection API combination (allocate + write + execute in a remote process)"
    strings:
        $mz = { 4D 5A }
        $api1 = "VirtualAllocEx" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "NtUnmapViewOfSection" nocase
    condition:
        $mz at 0 and 2 of ($api1, $api2, $api3, $api4)
}

rule Suspicious_PE_Remote_Download_Execute_APIs
{
    meta:
        severity = "high"
        description = "PE import-table strings combining a remote-download API with a local-execution API"
    strings:
        $mz = { 4D 5A }
        $dl1 = "URLDownloadToFileA" nocase
        $dl2 = "URLDownloadToFileW" nocase
        $dl3 = "InternetOpenUrlA" nocase
        $exec1 = "WinExec" nocase
        $exec2 = "ShellExecuteA" nocase
        $exec3 = "ShellExecuteW" nocase
    condition:
        $mz at 0 and 1 of ($dl1, $dl2, $dl3) and 1 of ($exec1, $exec2, $exec3)
}

rule Suspicious_Base64_Embedded_PE
{
    meta:
        severity = "high"
        description = "Base64 encoding of an MZ/PE header embedded in non-binary content (e.g. a script or document dropping an executable payload)"
    strings:
        // Base64 for the first bytes of a standard Windows PE header
        // ("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00...") - specific
        // enough that it essentially only appears when a PE binary has
        // been base64-encoded, not in ordinary text/documents.
        $b64_mz = "TVqQAAMAAAAEAAAA"
    condition:
        $b64_mz
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
        $shell4 = "powershell.exe" nocase
        $shell5 = "Shell.Application" nocase
    condition:
        1 of ($auto1, $auto2, $auto3) and 1 of ($shell1, $shell2, $shell3, $shell4, $shell5)
}

rule Suspicious_Macro_AutoExec_Network
{
    meta:
        severity = "high"
        description = "Office macro auto-execution combined with a network-fetch API (macro downloads a remote payload without necessarily invoking a shell directly)"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Auto_Open" nocase
        $auto3 = "Document_Open" nocase
        $net1 = "Net.WebClient" nocase
        $net2 = "URLDownloadToFile" nocase
        $net3 = "MSXML2.XMLHTTP" nocase
        $net4 = "WinHttp.WinHttpRequest" nocase
    condition:
        1 of ($auto1, $auto2, $auto3) and 1 of ($net1, $net2, $net3, $net4)
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

rule Suspicious_VBScript_Shell_Execution
{
    meta:
        severity = "high"
        description = "VBScript/JScript instantiating a shell automation object and immediately invoking it (distinct from merely mentioning WScript.Shell in passing)"
    strings:
        $create1 = "CreateObject(\"WScript.Shell\")" nocase
        $create2 = "CreateObject(\"Shell.Application\")" nocase
        $run1 = ".Run(" nocase
        $run2 = ".Run \"" nocase
        $run3 = ".Exec(" nocase
    condition:
        1 of ($create1, $create2) and 1 of ($run1, $run2, $run3)
}

rule Suspicious_LOLBin_Remote_Content
{
    meta:
        severity = "high"
        description = "A living-off-the-land Windows binary (mshta, regsvr32, rundll32) invoked together with a remote http(s) URL - a narrow, specific combination associated with fileless-malware delivery, not a match on the binary name alone"
    strings:
        $lolbin1 = "mshta.exe" nocase
        $lolbin2 = "mshta " nocase
        $lolbin3 = "regsvr32 /i:" nocase
        $lolbin4 = "regsvr32.exe /i:" nocase
        $lolbin5 = "rundll32.exe" nocase
        $url1 = "http://" nocase
        $url2 = "https://" nocase
    condition:
        1 of ($lolbin1, $lolbin2, $lolbin3, $lolbin4, $lolbin5) and 1 of ($url1, $url2)
}

rule Suspicious_HTA_Script_Application
{
    meta:
        severity = "high"
        description = "HTML Application (HTA) markup combined with a script-automation object - HTA files execute embedded VBScript/JScript with full local privileges when opened, unlike ordinary HTML"
    strings:
        $hta = "<hta:application" nocase
        $auto1 = "ActiveXObject" nocase
        $auto2 = "WScript.Shell" nocase
    condition:
        $hta and 1 of ($auto1, $auto2)
}

rule Suspicious_Certutil_Decode_Abuse
{
    meta:
        severity = "medium"
        description = "certutil invoked with its undocumented base64-decode flags - a well-known living-off-the-land technique for smuggling an encoded payload past naive content filters"
    strings:
        $a = "certutil -decode" nocase
        $b = "certutil.exe -decode" nocase
        $c = "certutil -urlcache" nocase
        $d = "certutil.exe -urlcache" nocase
    condition:
        any of them
}
