rule {
    meta: 
        data = "09-04-2026"
        author = "D4rs1ev"

    strings:
        $s1 = "if (!empty($_GET['view']))" 
        $s2 = "$_GET['view']=='html'"
        $s3 = "base64_decode($extension)"

        $s4 = "if (!empty($_POST['file_path']))"
        $s5 = "Content-Disposition: attachment; filename="
        $s6 = "readfile($file_path)"
        
        $s7 = "if (!empty($_FILES['uploaded_file'])"
        $s8 = "isset($_POST['upload_path'])"
        $s9 = "file_put_contents($upload_path"
        $s10 = "file_get_contents($_FILES['uploaded_file']['tmp_name'])"
        
        $class = "class DbDocumentHtmlView"
        $config_class = "class EnvrDataConfig"
    condition: 
        or ($re2 or $re4) and ($re3 or $re5) and $re1 and $re6
}