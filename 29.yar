rule "malecuas_zip" {
        meta: 
            Date = "09-29-2026"
            Author = "D@rs1ev"
        strings:
            $Start_Process = "Start-Process cmd.exe -ArgumentList /c taskkill /IM RegAsm.exe /F &" ascii wide
            $Task_kill = "taskkill /IM Vbc.exe /F & taskkill /IM MsBuild.exe /F -WindowStyle Hidden -Wait" ascii wide
            $r4HoIIvPP = "$r4HoIIvPP" ascii wide
            $strings = {20 4E 65 77 2D 4F 62 6A 65 63 74 20 53 79 73}
            $strings0 = {74 65 6D 2E 4E 65 74 2E 57 65 62 43 6C 69 65}
            $strings1 = {6E 74 3B 20 0D 0A 20 20 20 20 24 61 32 20 3D}
            $strings2 = {20 47 65 74 2D 52 61 6E 64 6F 6D 20 2D 49 6E}
            $strings3 = {70 75 74 4F 62 6A 65 63 74 20 24 61 30 20 2D}
            $strings4 = {43 6F 75 6E 74 20 24 61 30 2E 4C 65 6E 67 74}
            $strings5 = {68 3B 20 0D 0A 20 20 20 20 66 6F 72 65 61 63}
            $strings6 = {68 20 28 24 61 33 20 69 6E 20 24 61 32 29 20}
            $strings7 = {7B 20 74 72 79 20 7B 20 72 65 74 75 72 6E 20}
            $strings8 = {24 61 31 2E 44 6F 77 6E 6C 6F 61 64 44 61 74}
            $strings9 = {61 28 24 61 33 29 20 7D 20 63 61 74 63 68 20}
            $strings10 = {7B 20 63 6F 6E 74 69 6E 75 65 20 7D 20 7D 3B}
            $strings11 = {20 0D 0A 20 20 20 20 72 65 74 75 72 6E 20 24}
            $strings12 = {6E 75 6C 6C 20 7D 3B 20 0D 0A 20 20 20 20 24}
        condition:
            $Start_Process and $Task_kill and $r4HoIIvPP and 5 of $strings*
    }
