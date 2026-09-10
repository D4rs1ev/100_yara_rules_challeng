rule "Fluffy Wolf" {
	meta: 
		Date = "09-10-2026"
		author = "D4rs1ev"
		description = "https://bi.zone/expertise/blog/fluffy-wolf-ispytal-novinki-na-rossiyskikh-kompaniyakh/"
	strings:
		$cmd0 = "cmd.exe \/C choice \/C Y \/N /D Y \/T 3 & Del"
		$cmd1 = "ping 127.2 -n 5 & fsutil file setZeroData offset=0 length=20000000 %USERPROFILE%\Desktop\static-i386-amd64.exe & cd \/d %USERPROFILE%\\Desktop & Del \/f \/q \/a"
		$cmd2a = "powershell.exe -WindowStyle Hidden -Command"
		$cmd2b = "while(1){try{irm"
		$cmd2c = "\/script?id="
		$cmd2d = "country=RU&admin=true"
		$cmd2e = "|iex}catch{};Start-Sleep -Seconds 60"
		$cmd3 = "cmd.exe \/c shutdown \/r \/t 0"
		$cmd4 = "cmd.exe \/c shutdown \/s \/t 0"
	condition:
		($cmd0 and $cmd1)  or
		all of ($cmd2*) or
		($cmd3 and $cmd4)
		
}
