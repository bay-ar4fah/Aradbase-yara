import "pe"

rule MAL_XWorm_RAT_aa23c7a8 {
    meta:
        description = "Detects XWorm RAT payload and configuration"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "XWorm RAT"
     
    strings:
        $c2_domain = "cbzr-98pq1.ydns.eu" ascii wide
        $mutex = "X8MDmNrfQmpwUMyv" ascii wide
        
        $internal_name = "XWorm Ch.exe" ascii wide
        
        $drop_file1 = "Document.exe" ascii wide
        $drop_file2 = "Document.lnk" ascii wide
        $drop_file3 = "8xkpis.exe" ascii wide

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 5MB 
        and (
            $c2_domain or
            $mutex or
            $internal_name or
            (
                pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and 
                any of ($drop_file*)
            )
        )
}
