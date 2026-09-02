rule Masquerading_Right_to_Left_Override {
    meta:
        data = "09-03-2026"
        author = "D4rs1ev"
        description = "Masquerading: Right-to-Left Override"
        reference = "https://attack.mitre.org/techniques/T1036/002/"

    strings: 
       \\u202Excod.scr вывод символа, который переворачивает название всего что идет после него, тем самым позволяя замаскировать вредоностный файл под какой-либо стандартный формат (например Docs)
        $RTLO = {E2 80 AE} 
    
    condition:
        $RTLO

}

