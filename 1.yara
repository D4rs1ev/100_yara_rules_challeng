rule svchosts_exe_reserch {
	meta:
		date = "09-01-2026"
		author = "D4rs1ev"
		description = "T1036.005 - Masquerading"
		reference = "https://attack.mitre.org/techniques/T1036/"
	
	strings:
		$svchost_name = "svchost.exe" nocase ascii wide
		$system32 = "C:\\Windows\\System32\\svchost.exe" nocase ascii wide
		$syswow64 = "C:\\Windows\\SysWOW64\\svchost.exe" nocase ascii wide
	
	condition:
		$svchost_name and
		 not ($system32 or $syswow64) and 
		uint16(0) == 0x5A4D 
}
