import "pe"

rule MAL_Lumma_Stealer_5726b610 {
    meta:
        description = "Detects Lumma Stealer payload and its masquerading artifacts"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "Lumma Stealer"
     
    strings:
        $internal_name = "wmisvc.exe" ascii wide nocase
        $internal_name2 = "root1.exe" ascii wide nocase
        
        $ip_api1 = "ipapi.co" ascii wide
        $ip_api2 = "ipinfo.io" ascii wide
        $ip_api3 = "ip-api.com" ascii wide
        
        $ua_pattern = "Mozilla/5.0 (Windows NT" ascii wide

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 15MB 
        and (
            (
                pe.imphash() == "23612bb4e22cb0d3ce43e1f4bcba3008" and 
                any of ($internal_name*)
            )
            or (
                pe.is_64bit() and
                $internal_name and
                2 of ($ip_api*) and
                $ua_pattern
            )
        )
}
