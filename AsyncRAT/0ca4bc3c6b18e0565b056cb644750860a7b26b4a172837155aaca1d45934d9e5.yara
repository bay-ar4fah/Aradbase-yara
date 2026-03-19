import "pe"
import "hash"

rule IOC_Malware_0ca4bc3c
{
    meta:
        description = "YARA rule for malware AsyncRAT"
        author = "bay-ar4fah"
        date = "2026-03-19"
        reference_hash = "0ca4bc3c6b18e0565b056cb644750860a7b26b4a172837155aaca1d45934d9e5"

    strings:
        $mutex = "X8MDmNrfQmpwUMyv" ascii wide
        $domain = "cbzr-98pq1.ydns.eu" ascii wide
        $file1 = "Document.exe" ascii wide
        $file2 = "dzs2aohau.exe" ascii wide
        $reg_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Document" ascii wide

    condition:
        uint16(0) == 0x5a4d and (
            $mutex or
            $domain or
            $file2 or
            ($file1 and $reg_key)
        )
}
