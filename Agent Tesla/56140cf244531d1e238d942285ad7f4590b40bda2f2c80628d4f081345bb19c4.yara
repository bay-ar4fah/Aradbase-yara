import "pe"

rule MAL_AgentTesla_AutoIt_56140cf2 {
    meta:
        description = "Detects AutoIt-packed Agent Tesla and its specific drop artifacts"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "Agent Tesla"
     
    strings:
        $exfil_ftp = "ftp.antoniomayol.com" ascii wide
        $exfil_user = "johnson@antoniomayol.com" ascii wide
        
        $drop_file1 = "Idonna.exe" ascii wide nocase
        $drop_file2 = "Idonna.vbs" ascii wide nocase
        $drop_dir = "preinhered" ascii wide nocase
        
        $autoit_sig = "AU3!EA06" ascii
        $autoit_str = "AutoIt v3 Script" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d 
        and filesize < 5MB 
        and (
            (
                pe.imphash() == "c1d258acab237961164a925272293413" and 
                any of ($autoit_*)
            )
            or (
                $exfil_ftp and 
                $exfil_user
            )
            or (
                any of ($autoit_*) and 
                any of ($drop_*)
            )
        )
}
