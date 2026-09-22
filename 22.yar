import "pe"
rule "DarkComet.exe" {
        meta: 
            Date = "09-22-2026"
            author = "D@rs1ev"
        strings: 
            $Sysstringbytes0 = {56 42 24 41 6E 6F 6E 79 6D 6F 75 73 44}
            $Sysstringbytes1 = {65 6C 65 67 61 74 65 5F 30 00 5F 4C 61 6D 62 64}
            $Sysstringbytes2 = {61 24 5F 5F 31 00 5F 4C 61 6D 62 64 61 24 5F 5F}
            $Sysstringbytes3 = {32 00 5F 4C 61 6D 62 64 61 24 5F 5F 33}
            $powershell0 = "Add-MpPreference" ascii nocase
            $powershell1 = "-ExclusionPath" ascii nocase
            $powershell2 = "$env:UserProfile" ascii nocase
            $powershell3 = "$env:SystemDrive" ascii nocase
            $b64 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgAEAAKAAkAGUAbgB2ADoAVQBzAGUAcgBQAHIAbwBmAGkAbABlACwAJABlAG4AdgA6AFMAeQBzAHQAZQBtAEQA" ascii
            $mutex = "WhRe0hwCg6HSfVdR"
         condition:
            all of $powershell*
            or $b64 or 
            ( 2 of $Sysstringbytes*
            and pe.sections[0].name contains ".text"
            and pe.sections[1].name contains ".rsrc"
            and pe.sections[2].name contains ".reloc"         
            and pe.imports("mscoree.dll")
            )
            or $mutex
}