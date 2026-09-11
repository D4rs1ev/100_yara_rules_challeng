rule "lazarus" {
	meta: 
		Date: "09-10-2026"
		author: "D4rs1ev"
		Description: "https://ptsecurity.com/research/pt-esc-threat-intelligence/lazarus-recruitment/"
	condition:
		uint16(0) == 0x5A4D 
		and pe.imports("ADVAPI32.dll")
		and pe.imports("bcrypt.dll", "BCryptGenRandom")
		and pe.imports("KERNEL32.dll")
		and pe.imports("ole32.dll")
		and pe.imports("api-ms-win-crt-heap-l1-1-0.dll")
		and pe.imports("api-ms-win-crt-string-l1-1-0.dll")
		and pe.imports("api-ms-win-crt-convert-l1-1-0.dll", "strtoull")
		and pe.imports("VCRUNTIME140.dll")
		and pe.imports("api-ms-win-crt-runtime-l1-1-0.dll")
		and ( filesize < 1.8 MB 
		or filesize > 1.7 MB)
		
}
