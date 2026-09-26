
// Function at 0x1480 — original: _start
void _start() {

    // TODO: lift to C++ based on opcodes above
    // calls: []
}


// Function at 0x1110 — original: main
void main() {
    // 0x1110: 4157         push     r15
    // 0x1112: 4156         push     r14
    // 0x1114: 4155         push     r13
    // 0x1116: 4154         push     r12
    // 0x1118: 55           push     rbp
    // 0x1119: 53           push     rbx
    // 0x111a: 4883ec28     sub      rsp, 0x28
    // 0x111e: 83ff01       cmp      edi, 1
    // 0x1121: 0f8ef8020000 jle      0x141f
    // 0x1127: 488d05cd0f0000 lea      rax, [rip + 0xfcd]
    // 0x112e: 4189fe       mov      r14d, edi
    // 0x1131: 4531c0       xor      r8d, r8d
    // 0x1134: 31ff         xor      edi, edi
    // 0x1136: 4889442418   mov      qword ptr [rsp + 0x18], rax
    // 0x113b: 488d05ce0f0000 lea      rax, [rip + 0xfce]
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x1090', '0x1090', '0x1090']
}


// Function at 0x1570 — original: print_help
void print_help() {
    // 0x1570: 4883ec08     sub      rsp, 8
    // 0x1574: 4889fe       mov      rsi, rdi
    // 0x1577: 488d3d860a0000 lea      rdi, [rip + 0xa86]
    // 0x157e: 31c0         xor      eax, eax
    // 0x1580: e8dbfaffff   call     0x1060
    // 0x1585: 488d3d8d0a0000 lea      rdi, [rip + 0xa8d]
    // 0x158c: e89ffaffff   call     0x1030
    // 0x1591: 488d3d8a0a0000 lea      rdi, [rip + 0xa8a]
    // 0x1598: e893faffff   call     0x1030
    // 0x159d: 488d3d240c0000 lea      rdi, [rip + 0xc24]
    // 0x15a4: e887faffff   call     0x1030
    // 0x15a9: 488d3d380c0000 lea      rdi, [rip + 0xc38]
    // 0x15b0: e87bfaffff   call     0x1030
    // 0x15b5: 488d3d640c0000 lea      rdi, [rip + 0xc64]
    // 0x15bc: e86ffaffff   call     0x1030
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x1060', '0x1030', '0x1030']
}


// Function at 0x15e0 — original: print_version
void print_version() {
    // 0x15e0: 488d15580a0000 lea      rdx, [rip + 0xa58]
    // 0x15e7: 488d355d0a0000 lea      rsi, [rip + 0xa5d]
    // 0x15ee: 31c0         xor      eax, eax
    // 0x15f0: 488d3dd10c0000 lea      rdi, [rip + 0xcd1]
    // 0x15f7: e964faffff   jmp      0x1060
    // 0x15fc: 0f1f4000     nop      dword ptr [rax]
    // TODO: lift to C++ based on opcodes above
    // calls: []
}


// Function at 0x1600 — original: read_config
void read_config() {
    // 0x1600: 4157         push     r15
    // 0x1602: 488d35480a0000 lea      rsi, [rip + 0xa48]
    // 0x1609: 4156         push     r14
    // 0x160b: 4155         push     r13
    // 0x160d: 4154         push     r12
    // 0x160f: 55           push     rbp
    // 0x1610: 53           push     rbx
    // 0x1611: 4889fb       mov      rbx, rdi
    // 0x1614: 4881ec08010000 sub      rsp, 0x108
    // 0x161b: e8a0faffff   call     0x10c0
    // 0x1620: 4885c0       test     rax, rax
    // 0x1623: 0f84d3000000 je       0x16fc
    // 0x1629: 4889de       mov      rsi, rbx
    // 0x162c: 4889c5       mov      rbp, rax
    // 0x162f: 31c0         xor      eax, eax
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x10c0', '0x1060', '0x1080']
}


// Function at 0x1800 — original: try_connect
void try_connect() {

    // TODO: lift to C++ based on opcodes above
    // calls: []
}


// Function at 0x1740 — original: write_output
void write_output() {
    // 0x1740: 4154         push     r12
    // 0x1742: 4989f4       mov      r12, rsi
    // 0x1745: 488d355f090000 lea      rsi, [rip + 0x95f]
    // 0x174c: 55           push     rbp
    // 0x174d: 4889fd       mov      rbp, rdi
    // 0x1750: 53           push     rbx
    // 0x1751: e86af9ffff   call     0x10c0
    // 0x1756: 4885c0       test     rax, rax
    // 0x1759: 0f8481000000 je       0x17e0
    // 0x175f: 4889c3       mov      rbx, rax
    // 0x1762: 4889c1       mov      rcx, rax
    // 0x1765: ba10000000   mov      edx, 0x10
    // 0x176a: be01000000   mov      esi, 1
    // 0x176f: 488d3d44090000 lea      rdi, [rip + 0x944]
    // 0x1776: e865f9ffff   call     0x10e0
    // TODO: lift to C++ based on opcodes above
    // calls: []
}
