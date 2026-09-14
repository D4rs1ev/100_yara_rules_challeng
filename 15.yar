rule "raswifrovka" {
    meta:
        Date = "09-15-2026"
        author = "D4rs1ev"
    strings:
        $wifr0 = "$a.Mode=[System.Security.Cryptography.CipherMode]::ECB" ascii 
        $wifr1 = "$a.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7" 
        $wifr2 = "$a.KeySize=256"
        $wifr3 = "$a.Key=$k"
        $wifr4 = "$p=$a.CreateDecryptor().TransformFinalBlock($e,0,$e.Length)"
        $wifr5 = "$off=0"
        $wifr6 = "if($p.Length -ge 3 -and $p[0] -eq 0xEF -and $p[1] -eq 0xBB -and $p[2] -eq 0xBF){$off=3}"
        $wifr7 = "$t=[System.Text.Encoding]::UTF8.GetString($p,$off,$p.Length-$off)"
        $pid = "$pld=[IO.File]::ReadAllText('C:\\Users\\[^']+\\AppData\\Local\\Temp\\cache[0-9]{1,8}\\policy[0-9]{1,8}.dat')"
        $remove = "Remove-Item 'C:\\Users\\[^']+\\AppData\\Local\\Temp\\cache[0-9]{1,8}\\policy[0-9]{1,8}.dat' -Force -ErrorAction SilentlyContinue"
    condition: 
        8 of $wifr* and $pid and $remove
}
