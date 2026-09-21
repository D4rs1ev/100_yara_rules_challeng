rule "BrockenDoor" {
    meta: 
        Date = "09-21-2026"
        Author = "D@rs1ev"
        site = "https://securelist.ru/remcos-darkgate-brockendoor/111207/"
    strings:
        $cmd0 = "cmd \/c ping 127.0.0.1 -n 2 > nul & del"
        $mutex0 = "hEg15Thk" ascii 
        $mutex1 = "Silhouette0" ascii
        $mutex2 = "Silhouettes1" ascii
        $mutex3 = "Silhouettess" ascii
        $avz = "SELECT * FROM AntiVirusProduct"
        $port0 = "7180"
        $port1 = "6180"
        $domain0 = "mofcomp.space"
        $domain1 = "vmiadap.xyz"
    condition:
        uint16(0) == 0x5A4D and 
                filesize < 10MB and
        ($cmd0 and any of $mutex* and $avz) or  
        ($cmd0 and any of $mutex* and $avz and any of $port*) or 
        ($cmd0 and  any of $mutex* and any of $port*) 
}