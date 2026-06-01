import "pe"

rule MAL_DotNet_R77_Rootkit_Dropper {
    meta:
        description = "Detects .NET Dropper for R77 Rootkit and SheetRat/AsyncRAT"
        author = "bay-ar4fah"
        date = "2026-06-1"
        malware_family = "R77 Rootkit / SheetRat"
        reference_hash1 = "6c8930b5d3168902e080afe5fad0adaeb89975f706ba08e738d1ee1fbae06e8f"
        reference_hash2 = "a04ee025d13c0be594ecc7d52bbb586b3003205091fd8234e7462431ee857615"
     
    strings:
        $res_r77_x64 = "Client.Resources.r77-x64.dll" ascii wide nocase
        $res_r77_x86 = "Client.Resources.r77-x86.dll" ascii wide nocase
        $res_stager = "Client.Helper.Stager.efi" ascii wide nocase
        
        $mutex = "CurZ\\'A>" ascii wide
        $campaign = "8ThEhD+p" ascii wide
        
        $name1 = "MalwareBytes" ascii wide fullword
        $name2 = "svchost" ascii wide fullword

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 15MB 
        and (
            any of ($res_*) or
            ($mutex and $campaign) or
            (
                any of ($name*) and 
                (any of ($res_*) or $mutex)
            )
        )
}
