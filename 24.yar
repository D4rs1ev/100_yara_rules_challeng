rule PowerShell_AES_Downloader {
    meta:
        Date = "09-24-2026"
        Author = "D@rs1ev"
    strings:
        $dotnet0 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii wide
        $dotnet1 = "System.Net.ServicePointManager" ascii wide
        $dotnet2 = "Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject" ascii wide
        $ps0 = "$ProgressPreference = 'SilentlyContinue'" ascii wide
        $ps1 = "$ErrorActionPreference = 'Stop'" ascii wide
        $ps2 = "[Net.SecurityProtocolType]::Tls12" ascii wide
        $ps3 = "[Net.SecurityProtocolType]::Tls11" ascii wide
        $iwr0 = "Invoke-WebRequest" ascii wide nocase
        $iwr1 = "wgET" ascii wide nocase
        $enc = "$encryptedData='X6ux3C4BrL" ascii wide
        $var0 = "$sid=" ascii wide
        $var1 = "$nonce=" ascii wide
        $var2 = "$ts=" ascii wide
    condition:
        (
            2 of ($dotnet*) and
            2 of ($ps*) and
            1 of ($iwr*)
        ) or
        (
            all of ($dotnet*) and
            1 of ($iwr*)
        ) or
        (
            $enc and
            1 of ($dotnet*) and
            all of ($var*)
        )
}