rule "stealer2" {
    meta: 
        Date = "09-20-2026"
        Author = "D@rs1ev"
    strings:
        $install = {3A 49 4E 53 54 41 4C 4C}
        $cd = {0A 63 64 20 2F 64 20 22 25 7E 64 70 30}
        $for = {66 6F 72 20 25 25 49 20 69 6E 20}
        $dir ={6E 28 22 25 53 52 43 5F 44 49 52 25 5C 2E 2E 22 29}
        $zip = {20 64 6F 20 73 65 74 20 22 50 41 52 45 4E 54 5F}
        $zip2 ={44 49 52 3D 25 25 7E 66 49 74}
        $zip3 = {25 50 41 52 45 4E 54 5F 44 49 52 25 5C 25 43 41 43 48 45 5F 4E 41 4D 45 25}
    condition:
        $install and $cd and $for and $dir and 2 of $zip* and filesize < 200
}