import "pe"

rule AsyncRAT_IOC_Enriched
{
    meta:
        description = "AsyncRAT detection with campaign-specific IoCs"
        author = "bay-ar4fah"
        version = "1.0"
        type = "ioc_enriched"
        confidence = "high"

    strings:

        $a1 = "Rfc2898DeriveBytes" ascii wide
        $a2 = "AesManaged" ascii wide
        $a3 = "SslStream" ascii wide
        $a4 = "TcpClient" ascii wide

        $mutex_exact = "AsyncMutex_6SI8OkPnk" ascii wide

        $op_string = "| Edit 3LOSH RAT" ascii wide

        $c2_1 = "Modyhr.ddnsfree.com" ascii wide nocase
        $c2_2 = "hoxt1.duckdns.org" ascii wide nocase
        $c2_3 = "luawhjkuk.localto.net" ascii wide nocase
        $c2_4 = "fenix35630.duckdns.org" ascii wide nocase
        $c2_5 = "goodforlitme.dynuddns.com" ascii wide nocase

        $ip1 = "43.134.163.224" ascii wide
        $ip2 = "103.165.81.230" ascii wide
        $ip3 = "193.161.193.99" ascii wide

        $port1 = "6606" ascii wide
        $port2 = "7707" ascii wide
        $port3 = "8808" ascii wide
        $port4 = "4444" ascii wide
        $port5 = "8848" ascii wide

    condition:
        uint16(0) == 0x5A4D and

        3 of ($a*) and

        (
            $mutex_exact or
            $op_string or
            2 of ($c2_*) or
            (1 of ($ip*) and 1 of ($port*))
        )
}
