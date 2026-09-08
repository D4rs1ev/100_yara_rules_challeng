rule Core_Werewolf_7zSFX_Dropper {
    meta:
        Date = "2026-09-08"
        Author = "D@rs1ev"
        Description = "Detects Core Werewolf 7zSFX dropper"
        Reference = "https://bi.zone/expertise/blog/core-werewolf-menyaet-klyki-troyan-corerat-v-atakakh-na-rossiyskie-organizatsii/"
    
    strings:

        $cmd0 = "cmd.exe /c copy /y \"%CD%\\*.*\" \"%CD%\\..\\\\\"" wide ascii
        $cmd1 = "cmd.exe /c copy \"%CD%\\..\\\\FOhf6\" \"%HOMEPATH%\\Desktop\\CyzG.pdf\"" wide ascii
        $cmd2 = "cmd.exe /c copy \"%CD%\\..\\\\yNtns.GqV\" \"%HOMEPATH%\\Links\\Firepoin.exe\"" wide ascii
        $cmd3 = "cmd.exe /c cd \"%HOMEPATH%\\Links\" & start \"\" \"Firepoin.exe\"" wide ascii
        $cmd4 = "cmd.exe /c cd \"%HOMEPATH%\\Desktop\" & start \"\" \"CyzG.pdf\"" wide ascii
        $filename0 = "FOhf6" wide ascii
        $filename1 = "yNtns.GqV" wide ascii
        $filename2 = "Firepoin.exe" wide ascii
        $filename3 = "CyzG.pdf" wide ascii
        $mutex = "301525677" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and 
        all of ($cmd0, $cmd1, $cmd2, $cmd3, $cmd4) >= 4 and
        any of ($filename0, $filename1, $filename2, $filename3) or 
        $mutex
}