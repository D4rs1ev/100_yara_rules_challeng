rule svchosts_exe_reserch {
	meta:
		date = "09-02-2026"
		author = "D4rs1ev"
		description = "T1036.005 - Masquerading"
		reference = "https://attack.mitre.org/techniques/T1036/"
	
	strings:
		$svchost_name = "svchost.exe" nocase ascii wide
		$rundll32 = "rundll32.exe" nocase ascii wide
		$regsvr32 = "regsvr32.exe" nocase ascii wide
		$mshta = "msht.exe" nocase ascii wide
		$cmd = "cmd.exe" nocase ascii wide
		$powershell ="powershell.exe" nocase ascii wide
		$system32 = "C:\\Windows\\System32\\" nocase ascii wide
		$syswow64 = "C:\\Windows\\SysWOW64\\" nocase ascii wide
	
	condition:
		($svchost_name or $rundll32 or $regsvr32 or $mshta or $cmd or $powershell) and
		not ($system32 or $syswow64) and 
		uint16(0) == 0x5A4D 
}
