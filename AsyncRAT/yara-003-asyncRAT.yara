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


        $mutex_exact = "AsyncMutex_6SI8OkPnk" ascii wide

        $c2_old_1 = "Modyhr.ddnsfree.com" ascii wide nocase
        $c2_old_2 = "hoxt1.duckdns.org" ascii wide nocase
        $c2_old_3 = "luawhjkuk.localto.net" ascii wide nocase
        $c2_old_4 = "fenix35630.duckdns.org" ascii wide nocase
        $c2_old_5 = "goodforlitme.dynuddns.com" ascii wide nocase


        $c2_new_1 = "y2mate.it.com" ascii wide nocase
        $c2_new_2 = "ecqiea.ru.com" ascii wide nocase
        $c2_new_3 = "cityforum.sa.com" ascii wide nocase
        $c2_new_4 = "roninhk.com" ascii wide nocase
        $c2_new_5 = "www.xoilaciu.tv" ascii wide nocase
        $c2_new_6 = "hoathinh3d.la" ascii wide nocase
        $c2_new_7 = "gomabkiruna.ru.com" ascii wide nocase
        $c2_new_8 = "www.xoilaczzasz.tv" ascii wide nocase
        $c2_new_9 = "nhl.it.com" ascii wide nocase
        $c2_new_10 = "vn-vlxx.com" ascii wide nocase


        $ip_1 = "197.147.230.202" ascii wide
        $ip_2 = "69.148.168.199" ascii wide
        $ip_3 = "107.172.31.101" ascii wide
        $ip_4 = "107.172.31.102" ascii wide
        $ip_5 = "138.252.132.50" ascii wide
        $ip_6 = "210.87.69.224" ascii wide
        $ip_7 = "185.149.146.164" ascii wide
        $ip_8 = "147.45.44.131" ascii wide


        $port_1 = "5000" ascii wide
        $port_2 = "25565" ascii wide
        $port_3 = "8891" ascii wide
        $port_4 = "8888" ascii wide
        $port_5 = "8881" ascii wide
        $port_6 = "8808" ascii wide

    condition:

        uint16(0) == 0x5A4D and

        3 of ($core*) and

        (
            $mutex_exact or

            2 of ($c2_old_*, $c2_new_*) or

            (1 of ($ip*) and 1 of ($port*))
        )
}
