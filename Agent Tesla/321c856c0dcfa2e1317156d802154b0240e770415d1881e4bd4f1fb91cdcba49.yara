import "pe"

rule MAL_zgRAT_RunPE_Loader_321c856c {
    meta:
        description = "Detects zgRAT/Jalapeno RunPE Loader DLL packed with ConfuserEx"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "zgRAT / Jalapeno"
     
    strings:
        $internal_name = "RunPE.dll" ascii wide nocase
        $file_name1 = "attachment.dll" ascii wide nocase
        $file_name2 = "init.dll" ascii wide nocase
        
        $mutex = "168:WilStaging_02" ascii wide
        
        $obf_confuser = "ConfuserEx" ascii wide nocase
        $obf_reactor = ".NET Reactor" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 500KB 
        and pe.is_dll()
        and (
            (
                pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and 
                $internal_name
            )
            or (
                pe.is_32bit() and
                $mutex
            )
            or (
                any of ($obf_*) and
                (
                    $internal_name or 
                    any of ($file_name*)
                )
            )
        )
}
