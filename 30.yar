rule "RATNIK_BAT" {
        meta: 
            Date = "09-30-2026"
            author = "d@rs1ev"
        strings:
            $wsscript = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> m.vbs"
            $vbs = "echo SET om = ow.CreateShortcut(\"C:\\Users\\admin\\AppData\\Local\\Temp\\@WanaDecryptor@.exe.lnk\")>> m.vbs"
            $path = "echo om.TargetPath = \"C:\\Users\\admin\\AppData\\Local\\Temp\\@WanaDecryptor@.exe\">> m.vbs"
            $save = "echo om.Save>> m.vbs"
            $scripts = "cscript.exe //nologo m.vbs"
            $del = "del m.vbs"
            $del0 = "del /a %0"
        condition:
            all of them
}