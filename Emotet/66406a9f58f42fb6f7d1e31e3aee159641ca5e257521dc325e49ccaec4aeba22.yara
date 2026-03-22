import "pe"

rule MAL_Emotet_Arma3_66406a9f {
    meta:
        description = "Detects Emotet payload masquerading as Arma 3"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "Emotet / Heodo"
     
    strings:
        $internal_name = "Arma SE7.exe" ascii wide nocase
        $internal_name2 = "armase7.exe" ascii wide nocase
        $internal_name3 = "Arma3" ascii wide nocase
        
        $fake_copyright = "1996-2025 BOHEMIA INTERACTIVE" ascii wide nocase
        $fake_desc = "Arma 3" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d 
        and filesize > 10MB 
        and filesize < 50MB
        and (
            (
                pe.imphash() == "1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoY" and 
                any of ($internal_name*)
            )
            or (
                pe.is_64bit() and
                $fake_copyright and
                $fake_desc and
                any of ($internal_name*)
            )
        )
}
