import "pe"

rule MAL_XWorm_V5_6_Campaign {
    meta:
        description = "Mendeteksi loader dan payload XWorm RAT V5.6"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "XWorm RAT"
     
    strings:
        $c2_url = "https://pastebin.com/raw/Fxzr3jeT" ascii wide
        $mutex = "teEgLm0aeViE3IZi" ascii wide
        
        $cfg_version = "XWorm V5.6" ascii wide
        $cfg_spl = "<Xwormmm>" ascii wide
        $cfg_aes = "<666666>" ascii wide

        $sec_fptable = ".fptable" ascii fullword
        $sec_retplne = ".retplne" ascii fullword

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 5MB 
        and (
            (
                pe.imphash() == "75d930149d98b9b34c55459c6a79b293" or 
                all of ($sec_*)
            )
            or (
                $c2_url or
                $mutex or
                ($cfg_version and $cfg_spl) or
                ($cfg_spl and $cfg_aes)
            )
        )
}
