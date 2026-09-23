rule "DarkCore" {
    meta:
        Date = "09-23-2026"
        Author = "D@rs1ev"
    strings:
        $path0 = "wctk.dat" ascii wide
        $path1 = "AFH64" ascii wide
        $path2 = ".wctt_paths" ascii wide
        $path3 = "UsoClient.exe" ascii wide
        $mutex = "DCSI65ECEDAB98D54DB5" ascii
        $reg_name = "WindowsUpdateSvc" ascii wide
        $vm0 = "vboxogl.dll" ascii wide
        $vm1 = "VBoxService.exe" ascii wide
        $vm2 = "vmware" ascii wide nocase
    condition:
        (
            $mutex and
            (any of ($path*) or $reg_name)
        ) or
        (
            2 of ($path*) and
            $reg_name
        ) or
        (
            3 of ($path*)
        ) or
        (
            $path1 and
            $mutex and
            any of ($vm*)
        )
}