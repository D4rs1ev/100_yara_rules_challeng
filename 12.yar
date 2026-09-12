rule "bb1b8e1eed1ae71cc0fe57b38436b5240f4a068bb1bf307e93ef6a88173c66e2" {
    meta: 
        date: "09-12-2026"
        author: "D@rs1ev"
    strings:
        $s0 = {24 74 20 3D 20 24 65 6E 76 3A 54 45 4D 50} 
        $s1 = {24 73 65 76 65 6E 5A 69 70 20 3D 20 4A 6F 69}
        $s2 = {6E 2D 50 61 74 68 20 24 77 6F 72 6B 44 69 72 20}
        $s3 = {27 37 7A 72 2E 65 27}
        $s4 = {24 4F 75 74 65 72 50 61 73 73 77 6F}
        $s5 = {72 64 20 3D  20 27 [4-] }
        $s6 = {6D 72 35 33 58 27}
    condition:
        all of them
}