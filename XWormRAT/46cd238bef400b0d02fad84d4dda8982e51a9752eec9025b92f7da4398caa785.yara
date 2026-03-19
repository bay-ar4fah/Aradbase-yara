import "pe"

rule APT_SideWinder_Fake_WindTerm_Installer
{
    meta:
        description = "Detects a malicious Inno Setup installer masquerading as WindTerm, associated with SideWinder APT. Uses Tencent Cloud SCF for C2."
        author = "bay-ar4fah"
        date = "2026-03-18"
        reference_hash = "46cd238bef400b0d02fad84d4dda8982e51a9752eec9025b92f7da4398caa785"
        threat_name = "Trojan.SideWinder.WindTerm"

    strings:
        $meta_desc = "Advanced Terminal Client Installer" ascii wide nocase
        $meta_prod = "TerminalClient" ascii wide nocase
        $meta_copy = "Copyright \xc2\xa9 2024 TerminalTools Studio" ascii wide nocase
        $file_name1 = "WindTerm_Setup.exe" ascii wide nocase
        $file_name2 = "WindTerm_v1.0_Setup.exe" ascii wide nocase

        $inno_sig1 = "Inno Setup Setup Data" ascii wide
        $inno_sig2 = "Inno Setup Messages" ascii wide

        $c2_tencent = "1372464148-199ypekue7.ap-hongkong.tencentscf.com" ascii wide nocase

        $drop_hash1 = "079a55deaf0bdba2c042e9c0a075874b7a9b69bbf30eba9291a356b4a2a8f286" ascii wide nocase
        $drop_hash2 = "0a3a0863300eaaa52d22128f53ab410b748458567011f8bb97b45be388a9f378" ascii wide nocase
        $drop_hash3 = "26e1916b58d688e28b5746b2d81c10a4a09c8fc13e78db62bb590d8cd648fba9" ascii wide nocase

        $api_rm1 = "RmStartSession" ascii wide
        $api_rm2 = "RmGetList" ascii wide
        $api_rm3 = "RmRegisterResources" ascii wide
        $dll_rm = "RstrtMgr.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            hash.sha256(0, filesize) == "46cd238bef400b0d02fad84d4dda8982e51a9752eec9025b92f7da4398caa785"
            or
            (any of ($inno_sig*) and (2 of ($meta_*) or any of ($file_name*)))
            or
            $c2_tencent
            or
            any of ($drop_hash*)
            or
            (any of ($inno_sig*) and $dll_rm and any of ($api_rm*) and any of ($meta_*))
        )
}
