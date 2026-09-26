
// Function at 0x401060 — original: sub_0x401060
void sub_0x401060() {
    // 0x401060: 55           push     ebp
    // 0x401061: 8bec         mov      ebp, esp
    // 0x401063: 56           push     esi
    // 0x401064: 8bf1         mov      esi, ecx
    // 0x401066: 0f57c0       xorps    xmm0, xmm0
    // 0x401069: 8d4604       lea      eax, [esi + 4]
    // 0x40106c: 50           push     eax
    // 0x40106d: c70664cb4300 mov      dword ptr [esi], 0x43cb64
    // 0x401073: 660fd600     movq     qword ptr [eax], xmm0
    // 0x401077: 8b4508       mov      eax, dword ptr [ebp + 8]
    // 0x40107a: 83c004       add      eax, 4
    // 0x40107d: 50           push     eax
    // 0x40107e: e8631d0200   call     0x422de6
    // 0x401083: 83c408       add      esp, 8
    // 0x401086: 8bc6         mov      eax, esi
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x422de6']
}


// Function at 0x4010a0 — original: sub_0x4010a0
void sub_0x4010a0() {
    // 0x4010a0: 55           push     ebp
    // 0x4010a1: 8bec         mov      ebp, esp
    // 0x4010a3: 56           push     esi
    // 0x4010a4: 8bf1         mov      esi, ecx
    // 0x4010a6: 8d4604       lea      eax, [esi + 4]
    // 0x4010a9: c70664cb4300 mov      dword ptr [esi], 0x43cb64
    // 0x4010af: 50           push     eax
    // 0x4010b0: e8941d0200   call     0x422e49
    // 0x4010b5: 83c404       add      esp, 4
    // 0x4010b8: f6450801     test     byte ptr [ebp + 8], 1
    // 0x4010bc: 740b         je       0x4010c9
    // 0x4010be: 6a0c         push     0xc
    // 0x4010c0: 56           push     esi
    // 0x4010c1: e80e0d0200   call     0x421dd4
    // 0x4010c6: 83c408       add      esp, 8
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x422e49', '0x421dd4', '0x422e49']
}


// Function at 0x401120 — original: sub_0x401120
void sub_0x401120() {
    // 0x401120: 55           push     ebp
    // 0x401121: 8bec         mov      ebp, esp
    // 0x401123: 83e4f8       and      esp, 0xfffffff8
    // 0x401126: ff7510       push     dword ptr [ebp + 0x10]
    // 0x401129: 6a00         push     0
    // 0x40112b: ff7508       push     dword ptr [ebp + 8]
    // 0x40112e: 52           push     edx
    // 0x40112f: 51           push     ecx
    // 0x401130: e8dbffffff   call     0x401110
    // 0x401135: ff7004       push     dword ptr [eax + 4]
    // 0x401138: ff30         push     dword ptr [eax]
    // 0x40113a: e893790200   call     0x428ad2
    // 0x40113f: 83c9ff       or       ecx, 0xffffffff
    // 0x401142: 83c41c       add      esp, 0x1c
    // 0x401145: 85c0         test     eax, eax
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x401110', '0x428ad2']
}


// Function at 0x401150 — original: sub_0x401150
void sub_0x401150() {
    // 0x401150: 55           push     ebp
    // 0x401151: 8bec         mov      ebp, esp
    // 0x401153: 83e4f8       and      esp, 0xfffffff8
    // 0x401156: ff7514       push     dword ptr [ebp + 0x14]
    // 0x401159: 6a00         push     0
    // 0x40115b: ff7510       push     dword ptr [ebp + 0x10]
    // 0x40115e: ff750c       push     dword ptr [ebp + 0xc]
    // 0x401161: ff7508       push     dword ptr [ebp + 8]
    // 0x401164: e8a7ffffff   call     0x401110
    // 0x401169: 8b08         mov      ecx, dword ptr [eax]
    // 0x40116b: ff7004       push     dword ptr [eax + 4]
    // 0x40116e: 83c902       or       ecx, 2
    // 0x401171: 51           push     ecx
    // 0x401172: e81a790200   call     0x428a91
    // 0x401177: 83c9ff       or       ecx, 0xffffffff
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x401110', '0x428a91']
}


// Function at 0x401190 — original: sub_0x401190
void sub_0x401190() {
    // 0x401190: 55           push     ebp
    // 0x401191: 8bec         mov      ebp, esp
    // 0x401193: 51           push     ecx
    // 0x401194: 8d4514       lea      eax, [ebp + 0x14]
    // 0x401197: 50           push     eax
    // 0x401198: ff7510       push     dword ptr [ebp + 0x10]
    // 0x40119b: ff750c       push     dword ptr [ebp + 0xc]
    // 0x40119e: ff7508       push     dword ptr [ebp + 8]
    // 0x4011a1: e8aaffffff   call     0x401150
    // 0x4011a6: 83c410       add      esp, 0x10
    // 0x4011a9: 59           pop      ecx
    // 0x4011aa: 5d           pop      ebp
    // 0x4011ab: c3           ret      
    // 0x4011ac: cc           int3     
    // 0x4011ad: cc           int3     
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x401150']
}


// Function at 0x4011b0 — original: sub_0x4011b0
void sub_0x4011b0() {
    // 0x4011b0: 55           push     ebp
    // 0x4011b1: 8bec         mov      ebp, esp
    // 0x4011b3: 83e4e0       and      esp, 0xffffffe0
    // 0x4011b6: 83ec38       sub      esp, 0x38
    // 0x4011b9: 56           push     esi
    // 0x4011ba: 33c0         xor      eax, eax
    // 0x4011bc: 6689542412   mov      word ptr [esp + 0x12], dx
    // 0x4011c1: 8bf1         mov      esi, ecx
    // 0x4011c3: 894c2414     mov      dword ptr [esp + 0x14], ecx
    // 0x4011c7: 57           push     edi
    // 0x4011c8: 8b7d08       mov      edi, dword ptr [ebp + 8]
    // 0x4011cb: 39051cc84400 cmp      dword ptr [0x44c81c], eax
    // 0x4011d1: 7448         je       0x40121b
    // 0x4011d3: 83ff10       cmp      edi, 0x10
    // 0x4011d6: 7243         jb       0x40121b
    // TODO: lift to C++ based on opcodes above
    // calls: []
}


// Function at 0x4012ec — original: sub_0x4012ec
void sub_0x4012ec() {
    // 0x4012ec: 55           push     ebp
    // 0x4012ed: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x4012f0: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x4012f4: 8bec         mov      ebp, esp
    // 0x4012f6: 83ec10       sub      esp, 0x10
    // 0x4012f9: 56           push     esi
    // 0x4012fa: 33c0         xor      eax, eax
    // 0x4012fc: 8955f8       mov      dword ptr [ebp - 8], edx
    // 0x4012ff: 8bf1         mov      esi, ecx
    // 0x401301: 894dfc       mov      dword ptr [ebp - 4], ecx
    // 0x401304: 57           push     edi
    // 0x401305: 8bfa         mov      edi, edx
    // 0x401307: 8b5308       mov      edx, dword ptr [ebx + 8]
    // 0x40130a: 8945f0       mov      dword ptr [ebp - 0x10], eax
    // 0x40130d: 39051cc84400 cmp      dword ptr [0x44c81c], eax
    // TODO: lift to C++ based on opcodes above
    // calls: []
}


// Function at 0x401470 — original: sub_0x401470
void sub_0x401470() {
    // 0x401470: 55           push     ebp
    // 0x401471: 8bec         mov      ebp, esp
    // 0x401473: 83ec0c       sub      esp, 0xc
    // 0x401476: 8d4df4       lea      ecx, [ebp - 0xc]
    // 0x401479: e872fcffff   call     0x4010f0
    // 0x40147e: 687c904400   push     0x44907c
    // 0x401483: 8d45f4       lea      eax, [ebp - 0xc]
    // 0x401486: 50           push     eax
    // 0x401487: e87e220200   call     0x42370a
    // 0x40148c: cc           int3     
    // 0x40148d: cc           int3     
    // 0x40148e: cc           int3     
    // 0x40148f: cc           int3     
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x4010f0', '0x42370a']
}


// Function at 0x401490 — original: sub_0x401490
void sub_0x401490() {
    // 0x401490: 55           push     ebp
    // 0x401491: 8bec         mov      ebp, esp
    // 0x401493: 56           push     esi
    // 0x401494: 8bf1         mov      esi, ecx
    // 0x401496: 0f57c0       xorps    xmm0, xmm0
    // 0x401499: 8d4604       lea      eax, [esi + 4]
    // 0x40149c: 50           push     eax
    // 0x40149d: c70664cb4300 mov      dword ptr [esi], 0x43cb64
    // 0x4014a3: 660fd600     movq     qword ptr [eax], xmm0
    // 0x4014a7: 8b4508       mov      eax, dword ptr [ebp + 8]
    // 0x4014aa: 83c004       add      eax, 4
    // 0x4014ad: 50           push     eax
    // 0x4014ae: e833190200   call     0x422de6
    // 0x4014b3: 83c408       add      esp, 8
    // 0x4014b6: c7067ccb4300 mov      dword ptr [esi], 0x43cb7c
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x422de6']
}


// Function at 0x4014d0 — original: sub_0x4014d0
void sub_0x4014d0() {
    // 0x4014d0: 55           push     ebp
    // 0x4014d1: 8bec         mov      ebp, esp
    // 0x4014d3: 56           push     esi
    // 0x4014d4: 8bf1         mov      esi, ecx
    // 0x4014d6: 0f57c0       xorps    xmm0, xmm0
    // 0x4014d9: 8d4604       lea      eax, [esi + 4]
    // 0x4014dc: 50           push     eax
    // 0x4014dd: c70664cb4300 mov      dword ptr [esi], 0x43cb64
    // 0x4014e3: 660fd600     movq     qword ptr [eax], xmm0
    // 0x4014e7: 8b4508       mov      eax, dword ptr [ebp + 8]
    // 0x4014ea: 83c004       add      eax, 4
    // 0x4014ed: 50           push     eax
    // 0x4014ee: e8f3180200   call     0x422de6
    // 0x4014f3: 83c408       add      esp, 8
    // 0x4014f6: c70670cb4300 mov      dword ptr [esi], 0x43cb70
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x422de6', '0x4216b7']
}


// Function at 0x401520 — original: sub_0x401520
void sub_0x401520() {
    // 0x401520: 55           push     ebp
    // 0x401521: 8bec         mov      ebp, esp
    // 0x401523: 83e4f8       and      esp, 0xfffffff8
    // 0x401526: 83ec5c       sub      esp, 0x5c
    // 0x401529: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x40152e: 33c4         xor      eax, esp
    // 0x401530: 89442458     mov      dword ptr [esp + 0x58], eax
    // 0x401534: 53           push     ebx
    // 0x401535: 56           push     esi
    // 0x401536: 8bf1         mov      esi, ecx
    // 0x401538: 8d5c245e     lea      ebx, [esp + 0x5e]
    // 0x40153c: 8b4d0c       mov      ecx, dword ptr [ebp + 0xc]
    // 0x40153f: 8974240c     mov      dword ptr [esp + 0xc], esi
    // 0x401543: 89742424     mov      dword ptr [esp + 0x24], esi
    // 0x401547: 8974240c     mov      dword ptr [esp + 0xc], esi
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x41d7d0', '0x421969']
}


// Function at 0x40169c — original: sub_0x40169c
void sub_0x40169c() {
    // 0x40169c: 55           push     ebp
    // 0x40169d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x4016a0: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x4016a4: 8bec         mov      ebp, esp
    // 0x4016a6: 6aff         push     -1
    // 0x4016a8: 689d634300   push     0x43639d
    // 0x4016ad: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x4016b3: 50           push     eax
    // 0x4016b4: 53           push     ebx
    // 0x4016b5: 83ec48       sub      esp, 0x48
    // 0x4016b8: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4016bd: 33c5         xor      eax, ebp
    // 0x4016bf: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x4016c2: 56           push     esi
    // 0x4016c3: 57           push     edi
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a010]', 'esi', '0x41dd70']
}


// Function at 0x401a6c — original: sub_0x401a6c
void sub_0x401a6c() {
    // 0x401a6c: 55           push     ebp
    // 0x401a6d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x401a70: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x401a74: 8bec         mov      ebp, esp
    // 0x401a76: 6aff         push     -1
    // 0x401a78: 68eb634300   push     0x4363eb
    // 0x401a7d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x401a83: 50           push     eax
    // 0x401a84: 53           push     ebx
    // 0x401a85: 81eca8020000 sub      esp, 0x2a8
    // 0x401a8b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x401a90: 33c5         xor      eax, ebp
    // 0x401a92: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x401a95: 56           push     esi
    // 0x401a96: 57           push     edi
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x401690', '0x401690', '0x421969']
}


// Function at 0x401ed0 — original: sub_0x401ed0
void sub_0x401ed0() {
    // 0x401ed0: 55           push     ebp
    // 0x401ed1: 8bec         mov      ebp, esp
    // 0x401ed3: 83ec14       sub      esp, 0x14
    // 0x401ed6: 83791407     cmp      dword ptr [ecx + 0x14], 7
    // 0x401eda: 53           push     ebx
    // 0x401edb: 56           push     esi
    // 0x401edc: 8bf2         mov      esi, edx
    // 0x401ede: 7602         jbe      0x401ee2
    // 0x401ee0: 8b09         mov      ecx, dword ptr [ecx]
    // 0x401ee2: 6a00         push     0
    // 0x401ee4: 6880000000   push     0x80
    // 0x401ee9: 6a03         push     3
    // 0x401eeb: 6a00         push     0
    // 0x401eed: 6a01         push     1
    // 0x401eef: 6800000080   push     0x80000000
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a174]', 'dword ptr [0x43a134]', '0x41f580']
}


// Function at 0x402020 — original: sub_0x402020
void sub_0x402020() {
    // 0x402020: 55           push     ebp
    // 0x402021: 8bec         mov      ebp, esp
    // 0x402023: 6aff         push     -1
    // 0x402025: 682d644300   push     0x43642d
    // 0x40202a: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x402030: 50           push     eax
    // 0x402031: 83ec48       sub      esp, 0x48
    // 0x402034: 56           push     esi
    // 0x402035: 57           push     edi
    // 0x402036: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x40203b: 33c5         xor      eax, ebp
    // 0x40203d: 50           push     eax
    // 0x40203e: 8d45f4       lea      eax, [ebp - 0xc]
    // 0x402041: 64a300000000 mov      dword ptr fs:[0], eax
    // 0x402047: 8bc2         mov      eax, edx
    // TODO: lift to C++ based on opcodes above
    // calls: ['0x401ed0', 'dword ptr [0x43a1f0]', 'dword ptr [0x43a1f0]']
}


// Function at 0x402560 — original: sub_0x402560
void sub_0x402560() {
    // 0x402560: 55           push     ebp
    // 0x402561: 8bec         mov      ebp, esp
    // 0x402563: 56           push     esi
    // 0x402564: 8bf1         mov      esi, ecx
    // 0x402566: ff7604       push     dword ptr [esi + 4]
    // 0x402569: c706e8634400 mov      dword ptr [esi], 0x4463e8
    // 0x40256f: ff1504a44300 call     dword ptr [0x43a404]
    // 0x402575: 8b4508       mov      eax, dword ptr [ebp + 8]
    // 0x402578: a801         test     al, 1
    // 0x40257a: 741d         je       0x402599
    // 0x40257c: a804         test     al, 4
    // 0x40257e: 750e         jne      0x40258e
    // 0x402580: 56           push     esi
    // 0x402581: ff1588a34300 call     dword ptr [0x43a388]
    // 0x402587: 8bc6         mov      eax, esi
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a404]', 'dword ptr [0x43a388]', '0x41c670']
}


// Function at 0x4025a0 — original: sub_0x4025a0
void sub_0x4025a0() {
    // 0x4025a0: 55           push     ebp
    // 0x4025a1: 8bec         mov      ebp, esp
    // 0x4025a3: 51           push     ecx
    // 0x4025a4: 56           push     esi
    // 0x4025a5: 8bf1         mov      esi, ecx
    // 0x4025a7: c745fc00000000 mov      dword ptr [ebp - 4], 0
    // 0x4025ae: 8d45fc       lea      eax, [ebp - 4]
    // 0x4025b1: 50           push     eax
    // 0x4025b2: ff7604       push     dword ptr [esi + 4]
    // 0x4025b5: ff15a4a34300 call     dword ptr [0x43a3a4]
    // 0x4025bb: 85c0         test     eax, eax
    // 0x4025bd: 7403         je       0x4025c2
    // 0x4025bf: 894608       mov      dword ptr [esi + 8], eax
    // 0x4025c2: 6a0c         push     0xc
    // 0x4025c4: ff15f8a34300 call     dword ptr [0x43a3f8]
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a3a4]', 'dword ptr [0x43a3f8]', 'dword ptr [0x43a3f4]']
}


// Function at 0x402600 — original: sub_0x402600
void sub_0x402600() {
    // 0x402600: 55           push     ebp
    // 0x402601: 8bec         mov      ebp, esp
    // 0x402603: 56           push     esi
    // 0x402604: 8bf1         mov      esi, ecx
    // 0x402606: ff7604       push     dword ptr [esi + 4]
    // 0x402609: c70614644400 mov      dword ptr [esi], 0x446414
    // 0x40260f: ff15f4a34300 call     dword ptr [0x43a3f4]
    // 0x402615: 8b4508       mov      eax, dword ptr [ebp + 8]
    // 0x402618: a801         test     al, 1
    // 0x40261a: 741d         je       0x402639
    // 0x40261c: a804         test     al, 4
    // 0x40261e: 750e         jne      0x40262e
    // 0x402620: 56           push     esi
    // 0x402621: ff1588a34300 call     dword ptr [0x43a388]
    // 0x402627: 8bc6         mov      eax, esi
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a3f4]', 'dword ptr [0x43a388]', '0x41c670']
}


// Function at 0x402680 — original: sub_0x402680
void sub_0x402680() {
    // 0x402680: 55           push     ebp
    // 0x402681: 8bec         mov      ebp, esp
    // 0x402683: 83ec10       sub      esp, 0x10
    // 0x402686: 56           push     esi
    // 0x402687: 57           push     edi
    // 0x402688: 8d45f4       lea      eax, [ebp - 0xc]
    // 0x40268b: f30f1155fc   movss    dword ptr [ebp - 4], xmm2
    // 0x402690: 50           push     eax
    // 0x402691: 8bf1         mov      esi, ecx
    // 0x402693: c745f400000000 mov      dword ptr [ebp - 0xc], 0
    // 0x40269a: 6a00         push     0
    // 0x40269c: 68ec384400   push     0x4438ec
    // 0x4026a1: c70600000000 mov      dword ptr [esi], 0
    // 0x4026a7: ff15e8a34300 call     dword ptr [0x43a3e8]
    // 0x4026ad: 8b55f4       mov      edx, dword ptr [ebp - 0xc]
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a3e8]', 'dword ptr [0x43a38c]', 'dword ptr [0x43a3d8]']
}


// Function at 0x402790 — original: sub_0x402790
void sub_0x402790() {
    // 0x402790: 55           push     ebp
    // 0x402791: 8bec         mov      ebp, esp
    // 0x402793: 51           push     ecx
    // 0x402794: 56           push     esi
    // 0x402795: 8bf1         mov      esi, ecx
    // 0x402797: c745fc00000000 mov      dword ptr [ebp - 4], 0
    // 0x40279e: 8d45fc       lea      eax, [ebp - 4]
    // 0x4027a1: 50           push     eax
    // 0x4027a2: ff7604       push     dword ptr [esi + 4]
    // 0x4027a5: ff15eca34300 call     dword ptr [0x43a3ec]
    // 0x4027ab: 85c0         test     eax, eax
    // 0x4027ad: 7403         je       0x4027b2
    // 0x4027af: 894608       mov      dword ptr [esi + 8], eax
    // 0x4027b2: 6a10         push     0x10
    // 0x4027b4: ff15f8a34300 call     dword ptr [0x43a3f8]
    // TODO: lift to C++ based on opcodes above
    // calls: ['dword ptr [0x43a3ec]', 'dword ptr [0x43a3f8]']
}
