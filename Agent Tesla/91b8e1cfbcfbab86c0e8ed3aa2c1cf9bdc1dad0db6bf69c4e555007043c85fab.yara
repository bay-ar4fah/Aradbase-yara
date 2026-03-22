import "pe"

rule MAL_Obfuscated_Loader_DLL_91b8e1cf {
    meta:
        description = "Detects obfuscated .NET Loader DLL using ConfuserEx"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "Loader / Rhadamanthys / Heracles"
     
    strings:
        $internal_name = "2.4.dll" ascii wide nocase
        $internal_name2 = "oui.dll" ascii wide nocase
        
        $mutex = "Local\\SM0:5508:168:WilStaging_02" ascii wide
        
        $obf_confuser = "ConfuserEx" ascii wide nocase
        $obf_reactor = ".NET Reactor" ascii wide nocase
        
        $api_write = "WriteProcessMemory" ascii
        $api_virtual = "VirtualProtect" ascii

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 100KB 
        and pe.is_dll()
        and (
            (
                pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and 
                any of ($internal_name*)
            )
            or (
                pe.is_32bit() and
                $mutex
            )
            or (
                any of ($obf_*) and
                all of ($api_*) and
                any of ($internal_name*)
            )
        )
}
