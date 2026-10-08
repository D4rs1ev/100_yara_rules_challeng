rule PowerShell_NibbleLoader_Riwell_Goham
{
    meta:
        date        = "2026-03-11"
        author      = "D@rs1ev"
        description = "PowerShell nibble-encoded loader (Item,Riwell,Goham table)"
        reference   = "https://app.any.run/tasks/25991b24-e4b5-4e04-86b7-7ec232996ac8"
        mitre       = "T1059.001, T1027, T1055"

    strings:
        $start = "New-Object System.Collections.Generic.List[byte]" ascii
        $table = "Item,Riwell,Goham" ascii

        $s3a = "System.Collections.Generic.List`1[[System.Byte, mscorlib" ascii
        $s3b = "-> Add(System.Byte)" ascii
        $sw  = "StartsWith('Item')" ascii
        $pinv = "DefinePInvokeMethod" ascii
        $freeh = "FreeHGlobal" ascii

    condition:
        $start and $table and 2 of ($s3a, $s3b, $sw, $pinv, $freeh)
}