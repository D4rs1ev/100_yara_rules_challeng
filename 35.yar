rule PowerShell_AES_Dropper_Obfuscated_Reflection
{
    meta:
        date        = "2026-04-10"
        author      = "D@rs1ev"
        description = "Obfuscated PowerShell: AES-decrypts payload, drops to Temp, executes, deletes"
        mitre       = "T1059.001, T1027, T1140, T1070.004"

    strings:
        $f_syst   = "'Syst'" ascii
        $f_emcon  = "'em.Con'" ascii
        $f_vert   = "'vert'" ascii
        $f_from   = "'FromBase'" ascii
        $f_64str  = "'64Str'" ascii
        $f_ing    = "'ing'" ascii
        $f_aes    = "'y.AesC'" ascii
        $f_crypto = "'rypto'" ascii
        $f_serv   = "'ServiceP'" ascii
        $f_rovi   = "'rovi'" ascii
        $f_cdec   = "'CreateDecr'" ascii
        $f_yptor  = "'yptor'" ascii
        $f_trans  = "'Transfor'" ascii
        $f_mfin   = "'mFinalB'" ascii
        $f_lock   = "'lock'" ascii
        $f_write  = "'WriteAl'" ascii
        $f_lbytes = "'lBytes'" ascii
        $f_io     = "'IO.F'" ascii
        $b_refl1  = "GetMethod" ascii
        $b_refl2  = ".Invoke(" ascii
        $b_enum   = "[Enum]::Parse" ascii
        $b_tick   = "[Environment]::TickCount" ascii
        $b_math   = "[Math]::Abs" ascii
        $b_mode   = "CipherMode" ascii
        $b_padd   = "PaddingMode" ascii
        $b_keysz  = "KeySize" ascii

    condition:
        (
            2 of ($f_syst, $f_emcon, $f_vert) and
            2 of ($f_from, $f_64str, $f_ing) and
            3 of ($f_aes, $f_crypto, $f_serv, $f_rovi) and
            1 of ($f_cdec, $f_yptor) and
            1 of ($f_trans, $f_mfin, $f_lock) and
            1 of ($f_write, $f_lbytes)
        )
        and
        3 of ($b_*)
        and
        filesize < 500KB
}