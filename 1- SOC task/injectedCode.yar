rule Injected_Memory_Shellcode
{
    meta:
        description = "Detects injected shellcode or unpacked payloads in memory"
        author = "Salma + online sources"
        reference = "Volatility3 malfind, SearchApp, MsMpEng, suspicious memory region"
        date = "2025-07-23"

    strings:
        // Common shellcode prologue: push registers, setup stack
        $prologue = { 56 57 53 55 41 54 41 55 48 83 EC 28 }

        // Trampoline jmp rdx (e.g., shellcode jump to payload)
        $jmp_rdx = { ff e2 }

        // Common shellcode cleanup + return
        $ret_block = { 48 83 C4 28 41 5D 41 5C 5D 5B 5F 5E C3 }

        $add_rax_junk1 = { 48 05 ?? ?? ?? ?? }
        $add_rax_junk2 = { 48 2d ?? ?? ?? ?? }

        // MZ Header in memory (unpacked PE)
        $mz = "MZ"

        // Optional: short loop of indirect pointer dereference (evasion technique)
        $indirect_call = { 48 8B 45 ?? 48 89 C2 48 8B 45 ?? 48 8B 00 }

    condition:
        (
            $prologue and $jmp_rdx and $ret_block
        )
        and
        (
            #add_rax_junk1 > 2 or #add_rax_junk2 > 1
        )
        or
        (
            uint16(0) == 0x5A4D and $mz
        )
        or
        $indirect_call
}
