rule 'Paper Werewolf' {
    meta:
        Data = "09-06-2026"
        Author = "D4rs1ev"
        apt = "Paper Werewolf"
        description = "https://bi.zone/expertise/blog/paper-werewolf-sovmeshchaet-kibershpionazh-s-destruktivnymi-deystviyami/" 
    strings:
        $filename = "UserCache.ini"
        $filepath = "%USERPROFILE%\\UserCache.ini"
        $keyword = "DigitalRSASignature"
        $runkey = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LOAD"
    condition:
        ($filename and $filepath and $keyword) or $runkey or ($filename and $filepath)
}