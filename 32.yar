rule "vbscript"  {
    meta:
        date = "10-02-2026"
        author = "d@rs1ev"
    strings:
        $wscript = "WScript.Shell"
        $path0 = "%PUBLIC%"
        $file1 ="C:\\Users\\Public\\{^!}.fuq"
        $bs64 = "UEsDBBQAAAAIAGRWcVoG9DGHrFUrAACmbAUPAAAASkZpUWdZUU9QWFouZnVxzL0NWBTX9TA+uzvAAqu7IEY0RjGSqNEYCCbRIMkqovi98iWixhDZDRgEuswoaYxCB6KT6bb0801b2ya/2DZt87Y0bZWYtFlYBTQmQUwVJR8Y02ZwTYLVIipx/ufce2fZRcxH83uf5++T5c4999xzzj333HPP/ZjJ8gIHZ+Q4juesnKZxXCNH/9m5cdwX/jNw3H4bN3LiXyLfmNRoWPbGpPr6nOKSyoQKd/mj7sLNCZvFSiHhEWeCWyxLEMuKnO6E1SVlKXePiEq8j/v/yT9HBsctM0Rzk+Nf26TDujmjIdpgHMsdL+C4IzFhCJv7L3i2wUNvAdEOeQbFhbM6eso9XB4GyiT/jJy9hiDaMWejdTiWJG3gdmLqfYhbgeXPujjuJXPYdQI+vIH7cHbE5zRgAxc/DHju6w9x3khktoGLs11fPlNwVgmQzvCwdn2ngNPl1v8lAPeZJRQxfxHKCDiZkH6/4Hq8okKhEJ7bnzJQHe2C9FQoHjTTO/ORykp8jksD5VWvu1GrvDNLKEGiG9ARNx/SR9ZdT6+IIpI2Ql"
        $file2 = "C:\\Users\\Public\\{^!}.zip"
        $mutex = "Mutexf01b4d95cf55d32a.automaticDestinations-ms"
    condition:
        ($wscript and $path0 and $file1 and $bs64 and $file2 and $mutex) or ($wscript and $path0 and $file1 and $file2 and $mutex)
}