import "pe"
rule "rat_stigma" {
    meta:
        Date = "09-26-2026"
        author = "d@rs1ev"
    strings:
        $hkey0 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide
        $hkey1 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $path0 = "MSDCSC" ascii wide
        $path1 = "msdcsc.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and 
        all of $hkey* and 
        all of $path* and 
        pe.imports("advapi32.dll", "RegOpenKeyExA" )
}