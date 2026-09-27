import "pe" 
rule "svchost_update.exe" {
    meta: 
        Date = "09-27-2026"
        Author = "D@rs1ev"
    strings:
        $echooff = "@echo off" ascii wide
        $start = "timeout 3 > NUL" ascii wide
        $start0 =  "C:\\Users\\admin\\AppData\\Roaming\\svchost_update.exe" ascii wide
        $del = /DEL "[^"]+\.tmp\.bat" \/f \/q/ ascii wide
        $name0 = "tmp" ascii wide
        $name1 = ".tmp.bat" ascii wide
        $internal_name = "Stub.exe" ascii wide
        $original_name = "OriginalFileName" ascii wide
        $internal_field = "InternalName" ascii wide
    condition:
        ($echooff and $start and $start0 and $del and all of $name* and (filesize > 140 and filesize < 250)) or
        (uint16(0) == 0x5A4D and $internal_name and $original_name and $internal_field and pe.timestamp == 1776113863 and  (pe.sections[0].raw_data_size > 40000 and pe.sections[0].raw_data_size < 50000) and
        pe.sections[1].raw_data_size == 2560 )
}