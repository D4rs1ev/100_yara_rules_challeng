rule "ratnik s wifrovaniem" {
    meta: 
        Date = "09-14-2026"
        author = "D4rs1ev"
    strings:
        $string0 = "$k=[Convert]::FromBase64String(" wide ascii    
        $string1 = "$sk=[byte[]]::new(32)" wide ascii   
        $string2 = "$si=[byte[]]::new(16)" wide ascii   
        $string3 = "for($q=0;$q -lt 32;$q++){$sk[$q]=[Convert]::ToByte($sh.Substring($q*2,2),16)}" wide ascii   
        $string4 = "for($q=0;$q -lt 16;$q++){$si[$q]=[Convert]::ToByte($sv.Substring($q*2,2),16)}" wide ascii   
        $string5 = "for($i=0;$i -lt $e.Length;$i++){" wide ascii   
        $string6 = "$e[$i]=$e[$i] -bxor $si[$i -band 15]" wide ascii   
        $string7 = "$r=($sk[($i+7) -band 31]%7)+" wide ascii   
        $string8 = "$e[$i]=[byte]((($e[$i] -shr $r) -bor ($e[$i] -shl (8-$r))) -band 0xFF)" wide ascii   
        $string9 = "$e[$i]=$e[$i] -bxor $sk[($i+17) -band 31]" wide ascii   
        $string10 = "$e[$i]=$e[$i] -bxor $sk[$i -band 31]}" wide ascii   
        $string11 = "$a=New-Object System.Security.Cryptography.AesCryptoServiceProvider" wide ascii   
    condition: 
        7 of them

}