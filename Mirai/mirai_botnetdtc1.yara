import "elf"

rule MAL_ELF_Mirai_Botnet_MultiArch {
    meta:
        description = "Detects Mirai/Gafgyt Botnet payloads across SPARC, SuperH, and ARM architectures"
        author = "bay-ar4fah"
        date = "2026-05-31"
        malware_family = "Mirai / Gafgyt"
        reference_hash1 = "3bff1b00397d89f81ca0ad45a0403d4951d5f031ece85c26919ac7c0fc7dc81f"
        reference_hash2 = "b6390cdb45eb24738869b60f158e54678b7d1447bdd3b035697f91c175a1a705"
        reference_hash3 = "88b8605224a45ff308b49a18e557b4a24b011abd9c611103cda2ad6e81a67409"
     
    condition:
        uint32be(0) == 0x7F454C46 
        and filesize < 200KB 
        and elf.type == elf.ET_EXEC
        and (
            elf.machine == elf.EM_SPARC or
            elf.machine == 42 or
            elf.machine == elf.EM_ARM
        )
}
