rule "PowerShell_MediaFire_Startup_Persistence" {
    meta:
        date = "10-03-2026"
        author = "D@rs1ev"
        description = "PowerShell script: downloads Real.zip from MediaFire, drops to AppData\\Local\\Real, persists via Startup"
        mitre       = "T1059.001, T1105, T1547.001"
        reference   = "PASTE_ANYRUN_OR_VT_LINK"
    strings:
        $startup_ascii = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii
        $startup_hex   = { 41 70 70 44 61 74 61 5C 52 6F 61 6D 69 6E 67 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 53 74 61 72 74 20 4D 65 6E 75 5C 50 72 6F 67 72 61 6D 73 5C 53 74 61 72 74 75 70 }
        $new_item  = "New-Item -ItemType Directory -Path" ascii
        $join_path = "Join-Path" ascii
        $where_obj = "Where-Object" ascii  
        $winid = "System.Security.Principal.WindowsIdentity" ascii
      condition:
        $mediafire and
        ($startup_ascii or $startup_hex) and
        2 of ($new_item, $join_path, $where_obj, $winid)
}