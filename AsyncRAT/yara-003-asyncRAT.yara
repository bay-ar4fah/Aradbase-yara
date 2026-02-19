import "pe"

rule AsyncRAT_IOC_Enriched_v3
{
    meta:
        description = "AsyncRAT detection with extended campaign-specific IoCs"
        author = "bay-ar4fah"
        version = "3.0"
        type = "ioc_enriched"
        strategy = "core_async_rat + network_ioc"

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
            vn-vlxx\.com
        )/ nocase ascii wide

        $ips = /(
            197\.147\.230\.202|
            69\.148\.168\.199|
            107\.172\.31\.10[12]|
            138\.252\.132\.50|
            210\.87\.69\.224|
            185\.149\.146\.164|
            147\.45\.44\.131
        )/ ascii wide

        $ports = /(5000|25565|8891|8888|8881|8808)/ ascii wide

    condition:
        uint16(0) == 0x5A4D and
        3 of ($core*) and
        (
            $mutex or
            $domains or
            ($ips and $ports)
        )
}
