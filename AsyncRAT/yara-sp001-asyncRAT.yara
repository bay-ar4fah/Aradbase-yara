import "pe"

rule AsyncRAT_sp001
{
    meta:
        description = "AsyncRAT detection with extended campaign-specific IoCs"
        author = "bay-ar4fah"
        type = "specific"
        hashfiles = "0ca4bc3c6b18e0565b056cb644750860a7b26b4a172837155aaca1d45934d9e5, 594403b943ccccb6926833e355d3ca3d8af15251499bb36426d1f17bd7e5ec5d, aa23c7a817e7e7a30ce207e5f26fd3a7c020a3f92cd7d1233eda0046b975b367"

    strings:

        $core1 = "Rfc2898DeriveBytes" ascii wide
        $core2 = "AesManaged" ascii wide
        $core3 = "SslStream" ascii wide
        $core4 = "TcpClient" ascii wide

        $mutex = "AsyncMutex_6SI8OkPnk" ascii wide

        $domains = /(
            Modyhr\.ddnsfree\.com|
            hoxt1\.duckdns\.org|
            luawhjkuk\.localto\.net|
            fenix35630\.duckdns\.org|
            goodforlitme\.dynuddns\.com|
            y2mate\.it\.com|
            ecqiea\.ru\.com|
            cityforum\.sa\.com|
            roninhk\.com|
            xoilac[a-z]*\.tv|
            hoathinh3d\.la|
            gomabkiruna\.ru\.com|
            nhl\.it\.com|
            vn-vlxx\.com|
            cbzr-98pq1\.ydns\.eu
        )/ nocase ascii wide

        $ips = /(
            197\.147\.230\.202|
            69\.148\.168\.199|
            107\.172\.31\.10[12]|
            138\.252\.132\.50|
            210\.87\.69\.224|
            185\.149\.146\.164|
            147\.45\.44\.131|
            178\.16\.52\.243
        )/ ascii wide

        $ports = /(5000|25565|8891|8888|8881|8808)/ ascii wide

        $slui = "slui.exe -Embedding" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and

        3 of ($core*) and

        (
            $mutex or
            $domains or
            ($ips and $ports) or
            $slui
        )
}
