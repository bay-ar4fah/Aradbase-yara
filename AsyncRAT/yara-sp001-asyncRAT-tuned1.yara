import "pe"

rule AsyncRAT_sp001_tuned
{
    meta:
        description = "AsyncRAT detection tuned for obfuscated variants"
        author = "bay-ar4fah"

    strings:

        $core1 = "Rfc2898DeriveBytes" ascii wide
        $core2 = "AesManaged" ascii wide
        $core3 = "SslStream" ascii wide
        $core4 = "TcpClient" ascii wide

        $mutex = "AsyncMutex_6SI8OkPnk" ascii wide
        $domains = /(cbzr-98pq1\.ydns\.eu)/ nocase ascii wide
        $slui = "slui.exe -Embedding" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and

        (
            2 of ($core*) or
            $mutex or
            $domains or
            $slui
        )
}
