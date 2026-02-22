import "pe"

rule XWorm_RAT_Infra_Loader_Artifacts
{
    meta:
        description = "Detect XWorm RAT via C2 IoCs, Python loader artifacts, ADBService abuse, and networking behavior"
        author = "bay-ar4fah"
        hashfile = "1beba7bcaf594abc134967d46daba76c2b554b2358df3e1b6dcc993e336e6490, 46cd238bef400b0d02fad84d4dda8982e51a9752eec9025b92f7da4398caa785"

    strings:

        $dom1 = "eyadking.linkpc.net" ascii wide nocase
        $dom2 = "uziss.wtf" ascii wide nocase
        $dom3 = "yassinbessen.store" ascii wide nocase
        $tencent = "tencentscf.com" ascii wide nocase

        $ip1 = "157.254.165.172" ascii wide
        $ip2 = "46.247.108.170" ascii wide


        $pyd1 = "_raw_des.pyd" ascii wide nocase
        $pyd2 = "_scrypt.pyd" ascii wide nocase


        $fake1 = "ED4EmVDECs.exed.exe" ascii wide nocase


        $adb1 = "adbservice.exe" ascii wide nocase
        $adb2 = "ADBService.exe" ascii wide nocase


        $crypto = "libcrypto-3.dll" ascii wide nocase
        $loader = "LibraryLoader.LoadLibrary" ascii wide


        $ws1 = "WSAStartup" ascii wide
        $ws2 = "WSARecv" ascii wide
        $ws3 = "WSASend" ascii wide
        $ws4 = "WSARecvFrom" ascii wide
        $ws5 = "WSASendTo" ascii wide


        $guid = "00000000-00001316" ascii wide

        $wsman = "Microsoft.WSMan.Management" ascii wide
        $termclient = "TerminalClient\\Exec\\terminal" ascii wide nocase

    condition:

        uint16(0) == 0x5A4D and

        (
            any of ($dom*) or
            any of ($ip*) or

            (any of ($pyd*) and ($crypto or $loader)) or

            any of ($adb*) or

            (3 of ($ws*) and ($crypto or any of ($dom*))) or

            ($wsman and $termclient) or
            $guid
        )
}
