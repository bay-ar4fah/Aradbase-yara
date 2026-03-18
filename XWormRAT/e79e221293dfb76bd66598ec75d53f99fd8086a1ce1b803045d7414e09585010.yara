import "pe"
import "hash"

rule Malware_DLL_Downloader_XWorm_Alien
{
    meta:
        description = "Detects a malicious XWorm/Alien downloader DLL. This malware uses PowerShell to fetch next-stage payloads from GitHub and a C2 server, and is often executed via DLL sideloading."
        author = "bay-ar4fah"
        date = "2026-03-18"
        reference_hash = "e79e221293dfb76bd66598ec75d53f99fd8086a1ce1b803045d7414e09585010"
        threat_name = "Trojan.Win64.XWorm.Downloader"

    strings:
        $mutex1 = "ET0DWtzPAKXaBbC8" ascii wide
        $campaign1 = "Robloxy" ascii wide nocase
        $ip_c2_1 = "103.67.197.187:8000" ascii wide
        $ip_c2_2 = "103.67.197.187:9999" ascii wide
        $github_repo = "vth-cloud/vvasfvavasv" ascii
        $ps_script = "cachdebienthanhtungsahur.ps1" ascii

    condition:
        uint16(0) == 0x5A4D and pe.is_dll() and
        (
            hash.sha256(0, filesize) == "e79e221293dfb76bd66598ec75d53f99fd8086a1ce1b803045d7414e09585010"
            or
            pe.imphash() == "43bf517e4c1882fb42feb5707092d8eb"
            or
            $mutex1 or $campaign1
            or
            (
                (any of ($ip_c2*)) and 
                ($github_repo or $ps_script)
            )
        )
}
