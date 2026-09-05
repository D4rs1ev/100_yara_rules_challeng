rule: search_SppExtComObj.Exe
	meta
		data = "09-05-2026"
		author = "D4rs1ev"
		reference = "https://gti.bi.zone/search#file%3A9b3c167a764e34065080bdc3e6fbb65d989ec76ca04a56eea96c9d4cd0d68ee8"

	strings:
		$name = "SppExtComObj.Exe"
	condition:
		$name and 
		(hash.sha256(0, filesize) == "9b3c167a764e34065080bdc3e6fbb65d989ec76ca04a56eea96c9d4cd0d68ee8" or
		hash.sha256(0, filesize) == "43ece915f9e5d8af286ad366145ca488b11e6e78375348bed7527a4e3a155f7c" or 
		hash.sha256(0, filesize) == "75fa39181260a559c315cb3a17a159afd96aab9326792c8d30e00d33bbf1239f" or 
		hash.sha256(0, filesize) == "61b48a4b1f561cb6a52e797f917b7a98b63e97d571d560ba8bb5a539e4f227fb" or 
		hash.sha256(0, filesize) == "cebdc66a7b13242e763fe8c5f6c0dd646346ed01280b5fd4afb13d79095eaaf6") and
		uint16(0) == 0x5A4D and 
		filesize >=180000
		filesize <=170000
}
