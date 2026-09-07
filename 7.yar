rule "DarkTrack" {
    meta: 
        Data = "09-07-2026"
        Author = "D@rs1ev"
        description = ""
    strings:
        $mutex = "I_AM_DTBmcmrMz"
        $cmd = "cmd /c serv.bat"
        $replaced = "'\+'" 
        $replaced2 = "'DgTre'"
    condition:
        $mutex or $cmd or ($replaced and $replaced2)
}
