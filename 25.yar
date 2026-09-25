rule "stelear" {
    meta:
        Date = "09-25-2026"
        Author = "d@rsiev"
    strings:
   strings:
        $opera0 = "Opera Software\\Opera GX Stable" ascii wide
        $opera1 = "Opera GX Stable" ascii wide
        $chrome0 = "Google\\Chrome\\User Data" ascii wide
        $chrome1 = "Microsoft\\Edge\\User Data" ascii wide
        $brave0 = "BraveSoftware\\Brave-Browser\\User Data" ascii wide
        $file0 = "Login Data" ascii wide
        $file1 = "Web Data" ascii wide
        $file2 = "Local State" ascii wide
        $file3 = "Network\\Cookies" ascii wide
        $crypto0 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii wide
        $crypto1 = "System.Net.ServicePointManager" ascii wide
        $fmt0 = "$sid=" ascii wide
        $fmt1 = "$nonce=" ascii wide
        $fmt2 = "$ts=" ascii wide
        $fmt3 = "$encryptedData=" ascii wide
    condition:
        (
            (any of ($opera*) or any of ($chrome*) or any of ($brave*)) and
            (any of ($file*)) and
            (any of ($crypto*) or 2 of ($fmt*))
        ) or
        (
            any of ($opera*) and
            any of ($crypto*) and
            all of ($fmt*)
        )
}  