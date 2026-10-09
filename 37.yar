rule steams_stealer {
    meta: 
        Date = "10-07-2026"
        author = "D@rs1ev"
    strings:
        $function0 = "OldItems= [arg1]" ascii
        $function1 = "NotifyCollectionChangedAction.Add" ascii
        $function2 = "this.NewItems = [arg1]" ascii
        $function3 = "this.NewStartingIndex= arg2" ascii
        $function4 = "action === NotifyCollectionChangedAction.Remove" ascii
        $function5 = "NotifyCollectionChangedAction.Replace" ascii
        $function6 = "function Vector2(x, y)" ascii
        $function7 = "NotifyCollectionChangedEventArgs" ascii
        $function8 = "DmArray.prototype.CopyTo = function (array, arrayIndex)" ascii
        $roundkeys0 = "roundKeys[i][0]" ascii
        $roundkeys1 = "roundKeys[i - 1][0]" ascii
        $roundkeys2 = "roundKeys[i][1]= (roundKeys[i - 1][1] ^ i" ascii
        $atribute = "rootAttribute.ID= \"root-attribute-01\"" ascii
    condition:
        6 of $function* and 2 of $roundkeys* and $atribute
}