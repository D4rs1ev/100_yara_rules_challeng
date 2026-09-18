rule "tealer_PWS_dcqapz" {
    meta:
        Date = "09-18-2026"
        author = "d@rs1ev"
    strings:
        $mutex = "AD1F12AF3F363C28B3512CE4"
        $request0 = "http://dcqapz.shop/PWS/fre.php"
        $request1 = "Content-Key: 51310A18"
    condition:
        $mutex or any of $request*


}