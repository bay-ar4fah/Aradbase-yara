import "pe"

rule MAL_WannaCry_Ransomware_DLL {
    meta:
        description = "Detects WannaCry Ransomware payload, spreader, and killswitch domain"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "WannaCry / WanaCrypt0r"
		reference_hash = "1c4a7589d26c97c38d4f826242b6740b35441e43ddd7394d399dbf94ab868483"
		reference_hash = "55e7e424f6e98d7996fa457a46310d0172ce842b85dbfd294b0aa7afaa703a02"
		reference_hash = "f020f75d6fac088b78abeaf848cba5b53ac0a2dd79be1ebe458f7a9514aa94b5"
		reference_hash = "f867112deb0335e3a33464fe4e1737cc2176d5c118ce9fc7a5a0d45417035184"
     
    strings:
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
        
        $service_name = "mssecsvc2.0" ascii wide
        
        $file1 = "mssecsvc.exe" ascii wide nocase
        $file2 = "tasksche.exe" ascii wide nocase
        $file3 = "library.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 10MB 
        and (
            (
                pe.imphash() == "2e5708ae5fed0403e8117c645fb23e5b" and 
                pe.is_dll()
            )
            or $killswitch
            or (
                $service_name and 
                any of ($file*)
            )
        )
}
