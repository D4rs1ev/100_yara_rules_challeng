rule "stealer" {
    meta:
        Date = "09-17-2026"
        author = "d@rs1ev"
    strings:
        $mutex = "fapj32p0jf2jkfsju025jfgds"
        $name = "[^']+.exe"
    condition:
        all of them  and 
        uint16(0) == 0x5A4D 
}