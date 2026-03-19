import "pe"

rule MAL_XWorm_RAT_88e15629 {
    meta:
        description = "Detects XWorm RAT payload and dropper artifacts"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "XWorm RAT"
     
    strings:
        $mutex = "1w2rTMtnUzDsC3SD" ascii wide
        $internal_name = "QdkD.exe" ascii wide
        $ip_c2 = "172.94.15.100" ascii wide
        
        $drop_file1 = "xwormclient.exe" ascii wide nocase
        $drop_file2 = "xwormclient.lnk" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 5MB 
        and (
            $mutex or
            $internal_name or
            $ip_c2 or
            (
                pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and 
                any of ($drop_file*)
            )
        )
}
