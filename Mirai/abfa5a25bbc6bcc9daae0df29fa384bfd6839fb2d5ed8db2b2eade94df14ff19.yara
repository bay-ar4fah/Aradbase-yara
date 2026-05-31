import "elf"

rule MAL_ELF_Go_DDoS_Flooder_abfa5a25 {
    meta:
        description = "Detects ELF Golang DDoS Flooder and persistence artifacts"
        author = "bay-ar4fah"
        date = "2026-03-19"
        malware_family = "DDoS Flooder"
     
    strings:
        $c2_ip = "176.65.139.148" ascii wide
        
        $path1 = "/usr/bin/sysdg" ascii wide
        $path2 = "/etc/profile" ascii wide
        $path3 = "/root/.bashrc" ascii wide

    condition:
        uint32(0) == 0x464c457f 
        and filesize < 10MB 
        and elf.machine == elf.EM_386
        and (
            $c2_ip or
            (
                $path1 and 
                any of ($path2, $path3)
            )
        )
}
