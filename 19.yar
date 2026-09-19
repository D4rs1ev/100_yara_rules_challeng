rule "stealer" {
    meta:
        Date = "09-19-2026"
        author = "D@rs1ev"
    strings:
        $cd = "cd /d \"%~dp0\""
        $set0 = "set \"CACHE_NAME=cache_[^']+.bin\""
        $set1 = "set \"BAT_NAME=%~nx0\""
        $call0 = "call :SEARCH_ROOT \"%USERPROFILE%\\Desktop\""
        $call1 = "call :SEARCH_ROOT \"%OneDrive%\\Desktop\""
        $call2 = "call :SEARCH_ROOT \"%USERPROFILE%\\Downloads\""
        $call3 = "for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do ("
        $call4 = " if exist \"%%D:\\\" ("
        $call5 = "call :SEARCH_ROOT \"%%D:\\\""
        $call6 = "if defined CACHE_FILE goto :FOUND"
    condition:
        $cd and all of $set* and 4 of $call* and  filesize < 200 
}