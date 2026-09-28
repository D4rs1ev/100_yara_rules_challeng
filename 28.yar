rule "client_build " {
    meta:
        Date = "09-28-2026"
        Author = "D@rs1ev"
    strings: 
        $name = "svchost.exe" ascii wide
        $path = "\\AppData\\Roaming\\svchost\\svchost.exe" ascii wide
        $realname = "client_build.exe" ascii wide
        $path1 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii wide
        $InternalName = "client_build.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and $name and 1 of $path* and $realname and $InternalName
}