import "pe"

rule MAL_WorldWind_AsyncRAT_594403b9 {
    meta:
        description = "Detecting Telegram-based Information Stealers/RATs (WorldWind/AsyncRAT)"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "WorldWind Stealer / AsyncRAT"
     
    strings:
        $tg_bot_token = "bot7470121493:AAEBDdDQBD1gy-jjf9jaXMgNs-6GuMFRteQ" ascii wide
        $tg_api = "api.telegram.org" ascii wide
        
        $mutex = "AsyncMutex_6SI8OkPnk" ascii wide
        
        $cmd_netsh = "netsh wlan show profile name=" ascii wide nocase
        $cmd_key = "key=clear" ascii wide nocase
        
        $internal_name = "WorldWindClient.exe" ascii wide

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 5MB 
        and (
            $tg_bot_token or
            $mutex or
            ($tg_api and $internal_name) or
            (
                pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and 
                $cmd_netsh and 
                $cmd_key
            )
        )
}
