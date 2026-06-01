import "elf"

rule MAL_ELF_Mirai_Gafgyt_SuperH {
    meta:
        description = "Detects Mirai/Gafgyt Botnet payloads compiled for SuperH architecture"
        author = "bay-ar4fah"
        date = "2026-06-1"
        malware_family = "Mirai / Gafgyt"
        reference_hash1 = "d43b6df9cb7cfe7dd9eb222f9e9ed0294554cad689b91260f8da3174081a4e23"
        reference_hash2 = "b6390cdb45eb24738869b60f158e54678b7d1447bdd3b035697f91c175a1a705"
     
    condition:
        uint32be(0) == 0x7F454C46 
        and filesize < 150KB 
        and elf.type == elf.ET_EXEC
        and elf.machine == 42
}
