import capstone

with open("dump_head.bin", "rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Look for indirect calls / jumps (call [reg], jmp [reg], call reg, etc.) in .text
print("Scanning indirect calls/jmps in .text...")
for i in range(0x218000, 0x21c000):
    insns = list(md.disasm(data[i:i+15], 0x140000000 + i, count=1))
    if insns:
        insn = insns[0]
        if insn.mnemonic in ('call', 'jmp') and ('[' in insn.op_str or insn.op_str in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')):
            print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
