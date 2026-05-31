import "elf"

rule MAL_ELF_Mirai_Botnet_m68k {
    meta:
        description = "Detects Mirai Botnet payload compiled for Motorola m68k architecture"
        author = "bay-ar4fah"
        date = "2026-05-31"
        malware_family = "Mirai / Gafgyt / Bashlite"
        reference_hash = "71c82f634bab1b7d8b619cc9d49e34bc903276b3295ab29154bf1be8af74aa5e"

    condition:
        uint32be(0) == 0x7F454C46 
        and filesize < 150KB 
        and elf.machine == elf.EM_68K
        and elf.type == elf.ET_EXEC
}
