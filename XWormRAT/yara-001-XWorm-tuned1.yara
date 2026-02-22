import "pe"

rule XWorm_RAT_IOC_Behavior
{
    meta:
        description = "Detects XWorm RAT via LOLBIN abuse, crypto API usage, and campaign IoCs"
        author = "bay-ar4fah"
        type = "rat_detection"

    strings:

        $werf1 = "WerFault.exe -u -p" ascii wide nocase
        $werf2 = "WerFault.exe -pss" ascii wide nocase

        $cfg = "# RMA Configuration File - Generated" ascii wide

        $def1 = "MPCLIENT.DLL" ascii wide nocase
        $def2 = "MsMpLics.dll" ascii wide nocase

        $ni1 = "NativeImages_v4.0.30319_32" ascii wide
        $ni2 = "Accessibility" ascii wide
        $ni3 = "System" ascii wide

        $c1 = "CryptDestroyKey" ascii wide
        $c2 = "CryptDuplicateKey" ascii wide
        $c3 = "CryptGetProvParam" ascii wide
        $c4 = "CryptImportKey" ascii wide
        $c5 = "CryptSetKeyParam" ascii wide


        $inj = "FlushProcessWriteBuffer" ascii wide

        $dom = "cbzr-98pq1.ydns.eu" ascii wide nocase

        $ip1 = "178.16.52.243" ascii wide
        $ip2 = "104.21.44.66" ascii wide
        $ip3 = "149.154.166.110" ascii wide

    condition:

        uint16(0) == 0x5A4D and
        (
            any of ($werf*) or

            (2 of ($c*) and $inj) or

            (any of ($def*) and 2 of ($ni*)) or

            ($dom or 2 of ($ip*))
        )
}
