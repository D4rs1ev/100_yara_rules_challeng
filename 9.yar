rule "Clubfoot Wolf" {
    meta: 
        Data = "09-09-2026"
        Author = "D@rs1ev"
        Description = "https://bi.zone/expertise/blog/clubfoot-wolf-massovo-komprometiruet-rossiyskie-kompanii/"
    strings:
        $ps0 = "[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12;" wide ascii
        $ps1 = "$marie=(gcm *vo*p*s*n).name;" wide ascii
        $ps2 = "$claire=New-Object -ComObject MSXML2.ServerXMLHTTP;" wide ascii
        $ps3 = "$claire.open(\"GET\", $magazine, $false);" wide ascii  
        $ps4 = "$claire.send();" wide ascii
        $ps5 = "& $marie $claire.responseText;" wide ascii
        $filenamefish = "TextDocument_N0213411.txt" wide ascii
        $url = "crop.sh" wide ascii
    condition:
        (hash.sha256(0, filesize) == "fa07773b3af0539442504f86973fe2a68e040f80ebea388c5ed62d8f94eddb6a" or 
        hash.sha256(0, filesize) == "d3c90e61c3ffa059658c36e39334cb38c0b23cbde46f5078705fcfad67c9f3d8" or
        hash.sha256(0, filesize) == "6a8dfd602daa3b9dc2ceb146837a7966a37af8ab224ed11478e1f6d87f375b7f") or 
        all of  ($ps*) or 
        ($filenamefish or $url)
}