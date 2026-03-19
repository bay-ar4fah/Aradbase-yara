import "pe"

rule Malware_Clipper_Downloader_Amadey_SmokeLoader
{
    meta:
        description = "Detects a specific Clipper/Downloader malware and its variants, associated with Amadey, SmokeLoader, and Stealc. Utilizes a unique mutex, specific C2 communication patterns, and persistence via scheduled tasks."
        author = "bay-ar4fah"
        date = "2026-03-18"
        reference_hash = "95b9cfba9339553903e7bec515a05851b75bb601b06169cb5d11b1f1b8005d84"
        threat_name = "Win32/Clipper.Downloader.Amadey"

    strings:
        $mutex1 = "0f2qckzHkxL0ez4T" ascii wide
        $ip_c2 = "62.60.226.159" ascii wide
        $url_path1 = "/geter/index.php" ascii
        $url_path2 = "/Setup.exe" ascii
        $file1 = "synckgu.exe" ascii wide nocase
        $file2 = "ca43irkh.exe" ascii wide nocase
        $file3 = "synchost" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            hash.sha256(0, filesize) == "95b9cfba9339553903e7bec515a05851b75bb601b06169cb5d11b1f1b8005d84"
            or
            pe.imphash() == "1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoY"
            or
            $mutex1
            or
            ($ip_c2 and any of ($url_path*))
            or
            (any of ($file*) and $ip_c2)
        )
}
