rule "ratnik" {
    meta:
        Data = "09-13-2026"
        author = "D4rs1ev"
    strings:
        $bytes0 = {24 6F 6B 37 7A 20 3D 20}
        $bytes1 = {24 66 61 6C 73 65 0A 66 6F 72 65 61 63 68 20 28 }
        $bytes2 = {24 75 20 69 6E 20 40 28 0A 20 20 20 20 27 68 74}
        $bytes3 = {74 70 73 3A 2F 2F 67 69 74 68 75 62 2E 63 6F 6D}
        $bytes3 = {2F 69 70 37 7A 2F 37 7a 69 70 2F 72 65 6C 65 61}
        $bytes4 = {73 65 73 2F 64 6F 77 6E 6C 6F 66 64 2F}
    condition:
        all of them
}