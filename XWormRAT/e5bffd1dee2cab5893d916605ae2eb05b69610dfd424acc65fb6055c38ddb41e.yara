import "pe"

rule Malware_Hybrid_XWorm_AsyncRAT_XMRig
{
    meta:
        description = "Detects a hybrid XWorm/AsyncRAT trojan that also functions as an XMRig cryptominer. Delivered via a malicious Inno Setup installer."
        author = "bay-ar4fah"
        date = "2026-03-18"
        reference_hash = "e5bffd1dee2cab5893d916605ae2eb05b69610dfd424acc65fb6055c38ddb41e"
        threat_name = "Trojan.Win32.XWorm.AsyncRAT.Miner"

    strings:
        $mutex1 = "8FhK4zCLETjo4IYxf" ascii wide
        $c2_network = "196.251.107.104:1177" ascii wide
        $installer_sig = "Inno Setup" ascii wide nocase
        $fake_product = "Purple Scale Sync" ascii wide nocase
        $filename1 = "syncubic.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            hash.sha256(0, filesize) == "e5bffd1dee2cab5893d916605ae2eb05b69610dfd424acc65fb6055c38ddb41e"
            or
            pe.imphash() == "88016fcdef7f227c62171d0afad9aae4"
            or
            $mutex1 or $c2_network
            or
            ($installer_sig and $fake_product and $filename1)
        )
}
