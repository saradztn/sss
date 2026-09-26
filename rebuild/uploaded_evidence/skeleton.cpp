
// Function at 0x401060 — heuristic
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
    // calls: ['0x422de6']
}


// Function at 0x4010a0 — heuristic
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
    // calls: ['0x422e49', '0x421dd4', '0x422e49']
}


// Function at 0x401120 — heuristic
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
    // calls: ['0x401110', '0x428ad2']
}


// Function at 0x401150 — heuristic
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
    // calls: ['0x401110', '0x428a91']
}


// Function at 0x401190 — heuristic
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
    // calls: ['0x401150']
}


// Function at 0x4011b0 — heuristic
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
    // calls: []
}


// Function at 0x4012ec — heuristic32
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
    // calls: []
}


// Function at 0x401470 — heuristic
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
    // calls: ['0x4010f0', '0x42370a']
}


// Function at 0x401490 — heuristic
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
    // calls: ['0x422de6']
}


// Function at 0x4014d0 — heuristic
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
    // calls: ['0x422de6', '0x4216b7']
}


// Function at 0x401520 — heuristic
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
    // calls: ['0x41d7d0', '0x421969']
}


// Function at 0x40169c — heuristic32
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
    // calls: ['dword ptr [0x43a010]', 'esi', '0x41dd70']
}


// Function at 0x401a6c — heuristic32
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
    // calls: ['0x401690', '0x401690', '0x421969']
}


// Function at 0x401ed0 — heuristic
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
    // calls: ['dword ptr [0x43a174]', 'dword ptr [0x43a134]', '0x41f580']
}


// Function at 0x402020 — heuristic
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
    // calls: ['0x401ed0', 'dword ptr [0x43a1f0]', 'dword ptr [0x43a1f0]']
}


// Function at 0x402560 — heuristic
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
    // calls: ['dword ptr [0x43a404]', 'dword ptr [0x43a388]', '0x41c670']
}


// Function at 0x4025a0 — heuristic
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
    // calls: ['dword ptr [0x43a3a4]', 'dword ptr [0x43a3f8]', 'dword ptr [0x43a3f4]']
}


// Function at 0x402600 — heuristic
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
    // calls: ['dword ptr [0x43a3f4]', 'dword ptr [0x43a388]', '0x41c670']
}


// Function at 0x402680 — heuristic
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
    // calls: ['dword ptr [0x43a3e8]', 'dword ptr [0x43a38c]', 'dword ptr [0x43a3d8]']
}


// Function at 0x402790 — heuristic
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
    // calls: ['dword ptr [0x43a3ec]', 'dword ptr [0x43a3f8]']
}


// Function at 0x4027e0 — heuristic
void sub_0x4027e0() {
    // 0x4027e0: 55           push     ebp
    // 0x4027e1: 8bec         mov      ebp, esp
    // 0x4027e3: 6aff         push     -1
    // 0x4027e5: 6865644300   push     0x436465
    // 0x4027ea: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x4027f0: 50           push     eax
    // 0x4027f1: 83ec50       sub      esp, 0x50
    // 0x4027f4: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4027f9: 33c5         xor      eax, ebp
    // 0x4027fb: 8945f0       mov      dword ptr [ebp - 0x10], eax
    // 0x4027fe: 53           push     ebx
    // 0x4027ff: 56           push     esi
    // 0x402800: 57           push     edi
    // 0x402801: 50           push     eax
    // 0x402802: 8d45f4       lea      eax, [ebp - 0xc]
    // calls: ['0x41e610', '0x41d130', '0x421dd4']
}


// Function at 0x402bb0 — heuristic
void sub_0x402bb0() {
    // 0x402bb0: 55           push     ebp
    // 0x402bb1: 8bec         mov      ebp, esp
    // 0x402bb3: 83ec38       sub      esp, 0x38
    // 0x402bb6: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x402bbb: 33c5         xor      eax, ebp
    // 0x402bbd: 8945fc       mov      dword ptr [ebp - 4], eax
    // 0x402bc0: 8d45cc       lea      eax, [ebp - 0x34]
    // 0x402bc3: 0f57c0       xorps    xmm0, xmm0
    // 0x402bc6: 50           push     eax
    // 0x402bc7: ff354cc84400 push     dword ptr [0x44c84c]
    // 0x402bcd: 0f1145cc     movups   xmmword ptr [ebp - 0x34], xmm0
    // 0x402bd1: ff158ca24300 call     dword ptr [0x43a28c]
    // 0x402bd7: 8b4dd4       mov      ecx, dword ptr [ebp - 0x2c]
    // 0x402bda: ff750c       push     dword ptr [ebp + 0xc]
    // 0x402bdd: c745f00a000000 mov      dword ptr [ebp - 0x10], 0xa
    // calls: ['dword ptr [0x43a28c]', 'dword ptr [0x43a338]', '0x421969']
}


// Function at 0x402c60 — heuristic
void sub_0x402c60() {
    // 0x402c60: 55           push     ebp
    // 0x402c61: 8bec         mov      ebp, esp
    // 0x402c63: 83ec08       sub      esp, 8
    // 0x402c66: 56           push     esi
    // 0x402c67: 6a08         push     8
    // 0x402c69: 8955f8       mov      dword ptr [ebp - 8], edx
    // 0x402c6c: 894dfc       mov      dword ptr [ebp - 4], ecx
    // 0x402c6f: ff15f8a34300 call     dword ptr [0x43a3f8]
    // 0x402c75: 8bf0         mov      esi, eax
    // 0x402c77: 85f6         test     esi, esi
    // 0x402c79: 7414         je       0x402c8f
    // 0x402c7b: 56           push     esi
    // 0x402c7c: 6a00         push     0
    // 0x402c7e: c70600000000 mov      dword ptr [esi], 0
    // 0x402c84: ff1510a44300 call     dword ptr [0x43a410]
    // calls: ['dword ptr [0x43a3f8]', 'dword ptr [0x43a410]', 'dword ptr [0x43a3e4]']
}


// Function at 0x402e60 — heuristic
void sub_0x402e60() {
    // 0x402e60: 55           push     ebp
    // 0x402e61: 8bec         mov      ebp, esp
    // 0x402e63: 51           push     ecx
    // 0x402e64: 833d2cc8440000 cmp      dword ptr [0x44c82c], 0
    // 0x402e6b: 0f85fd000000 jne      0x402f6e
    // 0x402e71: 53           push     ebx
    // 0x402e72: 56           push     esi
    // 0x402e73: 6a0a         push     0xa
    // 0x402e75: 6a68         push     0x68
    // 0x402e77: ff3578c94400 push     dword ptr [0x44c978]
    // 0x402e7d: ff15e0a14300 call     dword ptr [0x43a1e0]
    // 0x402e83: 8bf0         mov      esi, eax
    // 0x402e85: 85f6         test     esi, esi
    // 0x402e87: 741c         je       0x402ea5
    // 0x402e89: 56           push     esi
    // calls: ['dword ptr [0x43a1e0]', 'dword ptr [0x43a1dc]', 'dword ptr [0x43a1bc]']
}


// Function at 0x402f90 — heuristic
void sub_0x402f90() {
    // 0x402f90: 55           push     ebp
    // 0x402f91: 8bec         mov      ebp, esp
    // 0x402f93: 83e4f0       and      esp, 0xfffffff0
    // 0x402f96: 83ec38       sub      esp, 0x38
    // 0x402f99: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x402f9e: 33c4         xor      eax, esp
    // 0x402fa0: 89442434     mov      dword ptr [esp + 0x34], eax
    // 0x402fa4: 56           push     esi
    // 0x402fa5: 57           push     edi
    // 0x402fa6: 8bf1         mov      esi, ecx
    // 0x402fa8: 8bfa         mov      edi, edx
    // 0x402faa: 89742408     mov      dword ptr [esp + 8], esi
    // 0x402fae: 89742408     mov      dword ptr [esp + 8], esi
    // 0x402fb2: 85ff         test     edi, edi
    // 0x402fb4: 7525         jne      0x402fdb
    // calls: ['0x421969', 'dword ptr [0x43a214]', '0x41d520']
}


// Function at 0x403080 — heuristic
void sub_0x403080() {
    // 0x403080: 55           push     ebp
    // 0x403081: 8bec         mov      ebp, esp
    // 0x403083: 83e4f0       and      esp, 0xfffffff0
    // 0x403086: 83ec38       sub      esp, 0x38
    // 0x403089: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x40308e: 33c4         xor      eax, esp
    // 0x403090: 89442434     mov      dword ptr [esp + 0x34], eax
    // 0x403094: 56           push     esi
    // 0x403095: 57           push     edi
    // 0x403096: 8bf1         mov      esi, ecx
    // 0x403098: 8bfa         mov      edi, edx
    // 0x40309a: 89742408     mov      dword ptr [esp + 8], esi
    // 0x40309e: 89742408     mov      dword ptr [esp + 8], esi
    // 0x4030a2: 85ff         test     edi, edi
    // 0x4030a4: 7528         jne      0x4030ce
    // calls: ['0x421969', 'dword ptr [0x43a190]', '0x41dd70']
}


// Function at 0x403180 — heuristic
void sub_0x403180() {
    // 0x403180: 55           push     ebp
    // 0x403181: 8bec         mov      ebp, esp
    // 0x403183: 83e4f8       and      esp, 0xfffffff8
    // 0x403186: 51           push     ecx
    // 0x403187: 53           push     ebx
    // 0x403188: 56           push     esi
    // 0x403189: 57           push     edi
    // 0x40318a: 8bf9         mov      edi, ecx
    // 0x40318c: 8bdf         mov      ebx, edi
    // 0x40318e: 837f1407     cmp      dword ptr [edi + 0x14], 7
    // 0x403192: 8b4710       mov      eax, dword ptr [edi + 0x10]
    // 0x403195: 7602         jbe      0x403199
    // 0x403197: 8b1f         mov      ebx, dword ptr [edi]
    // 0x403199: 83f804       cmp      eax, 4
    // 0x40319c: 721e         jb       0x4031bc
    // calls: ['0x421280', '0x421280', '0x421280']
}


// Function at 0x40339c — heuristic32
void sub_0x40339c() {
    // 0x40339c: 55           push     ebp
    // 0x40339d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x4033a0: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x4033a4: 8bec         mov      ebp, esp
    // 0x4033a6: 6aff         push     -1
    // 0x4033a8: 68da644300   push     0x4364da
    // 0x4033ad: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x4033b3: 50           push     eax
    // 0x4033b4: 53           push     ebx
    // 0x4033b5: 81eca0000000 sub      esp, 0xa0
    // 0x4033bb: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4033c0: 33c5         xor      eax, ebp
    // 0x4033c2: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x4033c5: 56           push     esi
    // 0x4033c6: 57           push     edi
    // calls: ['0x421260', '0x41dea0', '0x41dea0']
}


// Function at 0x4039a0 — heuristic
void sub_0x4039a0() {
    // 0x4039a0: 55           push     ebp
    // 0x4039a1: 8bec         mov      ebp, esp
    // 0x4039a3: 81ec0c040000 sub      esp, 0x40c
    // 0x4039a9: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4039ae: 33c5         xor      eax, ebp
    // 0x4039b0: 8945fc       mov      dword ptr [ebp - 4], eax
    // 0x4039b3: 56           push     esi
    // 0x4039b4: 57           push     edi
    // 0x4039b5: 6800040000   push     0x400
    // 0x4039ba: 8bf1         mov      esi, ecx
    // 0x4039bc: 8d85fcfbffff lea      eax, [ebp - 0x404]
    // 0x4039c2: 6a00         push     0
    // 0x4039c4: 89b5f8fbffff mov      dword ptr [ebp - 0x408], esi
    // 0x4039ca: 50           push     eax
    // 0x4039cb: 89b5f8fbffff mov      dword ptr [ebp - 0x408], esi
    // calls: ['0x4235b0', 'dword ptr [0x43a1a4]', 'dword ptr [0x43a19c]']
}


// Function at 0x403aa0 — heuristic
void sub_0x403aa0() {
    // 0x403aa0: 55           push     ebp
    // 0x403aa1: 8bec         mov      ebp, esp
    // 0x403aa3: 6aff         push     -1
    // 0x403aa5: 682e654300   push     0x43652e
    // 0x403aaa: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x403ab0: 50           push     eax
    // 0x403ab1: 83ec10       sub      esp, 0x10
    // 0x403ab4: 56           push     esi
    // 0x403ab5: 57           push     edi
    // 0x403ab6: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x403abb: 33c5         xor      eax, ebp
    // 0x403abd: 50           push     eax
    // 0x403abe: 8d45f4       lea      eax, [ebp - 0xc]
    // 0x403ac1: 64a300000000 mov      dword ptr fs:[0], eax
    // 0x403ac7: 8bf1         mov      esi, ecx
    // calls: ['0x41e0b0', '0x41e0b0', '0x41e0b0']
}


// Function at 0x403d2c — heuristic32
void sub_0x403d2c() {
    // 0x403d2c: 55           push     ebp
    // 0x403d2d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x403d30: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x403d34: 8bec         mov      ebp, esp
    // 0x403d36: 6aff         push     -1
    // 0x403d38: 685d654300   push     0x43655d
    // 0x403d3d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x403d43: 50           push     eax
    // 0x403d44: 53           push     ebx
    // 0x403d45: 83ec30       sub      esp, 0x30
    // 0x403d48: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x403d4d: 33c5         xor      eax, ebp
    // 0x403d4f: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x403d52: 56           push     esi
    // 0x403d53: 57           push     edi
    // calls: ['dword ptr [0x43a010]', 'esi', '0x41dd70']
}


// Function at 0x403f6c — heuristic32
void sub_0x403f6c() {
    // 0x403f6c: 55           push     ebp
    // 0x403f6d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x403f70: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x403f74: 8bec         mov      ebp, esp
    // 0x403f76: 6aff         push     -1
    // 0x403f78: 68b9654300   push     0x4365b9
    // 0x403f7d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x403f83: 50           push     eax
    // 0x403f84: 53           push     ebx
    // 0x403f85: 83ec78       sub      esp, 0x78
    // 0x403f88: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x403f8d: 33c5         xor      eax, ebp
    // 0x403f8f: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x403f92: 56           push     esi
    // 0x403f93: 57           push     edi
    // calls: ['esi', 'esi', 'dword ptr [0x43a450]']
}


// Function at 0x40438c — heuristic32
void sub_0x40438c() {
    // 0x40438c: 55           push     ebp
    // 0x40438d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x404390: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x404394: 8bec         mov      ebp, esp
    // 0x404396: 6aff         push     -1
    // 0x404398: 6816664300   push     0x436616
    // 0x40439d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x4043a3: 50           push     eax
    // 0x4043a4: 53           push     ebx
    // 0x4043a5: 83ec40       sub      esp, 0x40
    // 0x4043a8: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4043ad: 33c5         xor      eax, ebp
    // 0x4043af: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x4043b2: 56           push     esi
    // 0x4043b3: 57           push     edi
    // calls: ['dword ptr [0x43a360]', 'dword ptr [0x43a348]', 'dword ptr [0x43a368]']
}


// Function at 0x4046f0 — heuristic
void sub_0x4046f0() {
    // 0x4046f0: 55           push     ebp
    // 0x4046f1: 8bec         mov      ebp, esp
    // 0x4046f3: 6aff         push     -1
    // 0x4046f5: 685e664300   push     0x43665e
    // 0x4046fa: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x404700: 50           push     eax
    // 0x404701: 83ec2c       sub      esp, 0x2c
    // 0x404704: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x404709: 33c5         xor      eax, ebp
    // 0x40470b: 8945f0       mov      dword ptr [ebp - 0x10], eax
    // 0x40470e: 53           push     ebx
    // 0x40470f: 56           push     esi
    // 0x404710: 57           push     edi
    // 0x404711: 50           push     eax
    // 0x404712: 8d45f4       lea      eax, [ebp - 0xc]
    // calls: ['0x404380', '0x404380', '0x421dd4']
}


// Function at 0x4047dc — heuristic32
void sub_0x4047dc() {
    // 0x4047dc: 55           push     ebp
    // 0x4047dd: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x4047e0: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x4047e4: 8bec         mov      ebp, esp
    // 0x4047e6: 6aff         push     -1
    // 0x4047e8: 689d664300   push     0x43669d
    // 0x4047ed: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x4047f3: 50           push     eax
    // 0x4047f4: 53           push     ebx
    // 0x4047f5: 83ec50       sub      esp, 0x50
    // 0x4047f8: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4047fd: 33c5         xor      eax, ebp
    // 0x4047ff: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x404802: 56           push     esi
    // 0x404803: 57           push     edi
    // calls: ['dword ptr [0x43a360]', 'dword ptr [0x43a348]', 'dword ptr [0x43a368]']
}


// Function at 0x404b1c — heuristic32
void sub_0x404b1c() {
    // 0x404b1c: 55           push     ebp
    // 0x404b1d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x404b20: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x404b24: 8bec         mov      ebp, esp
    // 0x404b26: 6aff         push     -1
    // 0x404b28: 68ed664300   push     0x4366ed
    // 0x404b2d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x404b33: 50           push     eax
    // 0x404b34: 53           push     ebx
    // 0x404b35: 83ec60       sub      esp, 0x60
    // 0x404b38: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x404b3d: 33c5         xor      eax, ebp
    // 0x404b3f: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x404b42: 56           push     esi
    // 0x404b43: 57           push     edi
    // calls: ['0x41f9d0', '0x41f9d0', '0x404e50']
}


// Function at 0x404e5c — heuristic32
void sub_0x404e5c() {
    // 0x404e5c: 55           push     ebp
    // 0x404e5d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x404e60: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x404e64: 8bec         mov      ebp, esp
    // 0x404e66: 6aff         push     -1
    // 0x404e68: 6846674300   push     0x436746
    // 0x404e6d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x404e73: 50           push     eax
    // 0x404e74: 53           push     ebx
    // 0x404e75: 83ec30       sub      esp, 0x30
    // 0x404e78: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x404e7d: 33c5         xor      eax, ebp
    // 0x404e7f: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x404e82: 56           push     esi
    // 0x404e83: 57           push     edi
    // calls: ['0x421250', '0x41e210', '0x4293e7']
}


// Function at 0x405010 — heuristic
void sub_0x405010() {
    // 0x405010: 55           push     ebp
    // 0x405011: 8bec         mov      ebp, esp
    // 0x405013: 6aff         push     -1
    // 0x405015: 687d674300   push     0x43677d
    // 0x40501a: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x405020: 50           push     eax
    // 0x405021: 83ec44       sub      esp, 0x44
    // 0x405024: 53           push     ebx
    // 0x405025: 56           push     esi
    // 0x405026: 57           push     edi
    // 0x405027: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x40502c: 33c5         xor      eax, ebp
    // 0x40502e: 50           push     eax
    // 0x40502f: 8d45f4       lea      eax, [ebp - 0xc]
    // 0x405032: 64a300000000 mov      dword ptr fs:[0], eax
    // calls: ['esi', 'esi', 'dword ptr [0x43a1d4]']
}


// Function at 0x40526c — heuristic32
void sub_0x40526c() {
    // 0x40526c: 55           push     ebp
    // 0x40526d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x405270: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x405274: 8bec         mov      ebp, esp
    // 0x405276: 6aff         push     -1
    // 0x405278: 68d1674300   push     0x4367d1
    // 0x40527d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x405283: 50           push     eax
    // 0x405284: 53           push     ebx
    // 0x405285: 81ecf0020000 sub      esp, 0x2f0
    // 0x40528b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x405290: 33c5         xor      eax, ebp
    // 0x405292: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x405295: 56           push     esi
    // 0x405296: 57           push     edi
    // calls: ['0x4235b0', 'dword ptr [0x43a154]', '0x41dea0']
}


// Function at 0x405b0c — heuristic32
void sub_0x405b0c() {
    // 0x405b0c: 55           push     ebp
    // 0x405b0d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x405b10: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x405b14: 8bec         mov      ebp, esp
    // 0x405b16: 6aff         push     -1
    // 0x405b18: 6827684300   push     0x436827
    // 0x405b1d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x405b23: 50           push     eax
    // 0x405b24: 53           push     ebx
    // 0x405b25: 81ec20020000 sub      esp, 0x220
    // 0x405b2b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x405b30: 33c5         xor      eax, ebp
    // 0x405b32: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x405b35: 56           push     esi
    // 0x405b36: 57           push     edi
    // calls: ['0x4235b0', 'dword ptr [0x43a154]', '0x41dea0']
}


// Function at 0x405cc0 — heuristic
void sub_0x405cc0() {
    // 0x405cc0: 55           push     ebp
    // 0x405cc1: 8bec         mov      ebp, esp
    // 0x405cc3: 83e4f8       and      esp, 0xfffffff8
    // 0x405cc6: 83ec68       sub      esp, 0x68
    // 0x405cc9: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x405cce: 33c4         xor      eax, esp
    // 0x405cd0: 89442464     mov      dword ptr [esp + 0x64], eax
    // 0x405cd4: 56           push     esi
    // 0x405cd5: 8bf1         mov      esi, ecx
    // 0x405cd7: ba303f4400   mov      edx, 0x443f30
    // 0x405cdc: 89742404     mov      dword ptr [esp + 4], esi
    // 0x405ce0: 8d4c240c     lea      ecx, [esp + 0xc]
    // 0x405ce4: 57           push     edi
    // 0x405ce5: 89742408     mov      dword ptr [esp + 8], esi
    // 0x405ce9: e812feffff   call     0x405b00
    // calls: ['0x405b00', 'dword ptr [0x43a174]', '0x421dd4']
}


// Function at 0x405e1c — heuristic32
void sub_0x405e1c() {
    // 0x405e1c: 55           push     ebp
    // 0x405e1d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x405e20: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x405e24: 8bec         mov      ebp, esp
    // 0x405e26: 6aff         push     -1
    // 0x405e28: 680b694300   push     0x43690b
    // 0x405e2d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x405e33: 50           push     eax
    // 0x405e34: 53           push     ebx
    // 0x405e35: 81ec60010000 sub      esp, 0x160
    // 0x405e3b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x405e40: 33c5         xor      eax, ebp
    // 0x405e42: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x405e45: 56           push     esi
    // 0x405e46: 57           push     edi
    // calls: ['dword ptr [0x43a1a0]', '0x401520', '0x41dea0']
}


// Function at 0x4069ac — heuristic32
void sub_0x4069ac() {
    // 0x4069ac: 55           push     ebp
    // 0x4069ad: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x4069b0: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x4069b4: 8bec         mov      ebp, esp
    // 0x4069b6: 6aff         push     -1
    // 0x4069b8: 6868694300   push     0x436968
    // 0x4069bd: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x4069c3: 50           push     eax
    // 0x4069c4: 53           push     ebx
    // 0x4069c5: 81ec98000000 sub      esp, 0x98
    // 0x4069cb: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4069d0: 33c5         xor      eax, ebp
    // 0x4069d2: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x4069d5: 56           push     esi
    // 0x4069d6: 57           push     edi
    // calls: ['0x41c940', '0x423030', '0x41e0b0']
}


// Function at 0x40717c — heuristic32
void sub_0x40717c() {
    // 0x40717c: 55           push     ebp
    // 0x40717d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x407180: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x407184: 8bec         mov      ebp, esp
    // 0x407186: 6aff         push     -1
    // 0x407188: 68e3694300   push     0x4369e3
    // 0x40718d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x407193: 50           push     eax
    // 0x407194: 53           push     ebx
    // 0x407195: 81ecb8000000 sub      esp, 0xb8
    // 0x40719b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x4071a0: 33c5         xor      eax, ebp
    // 0x4071a2: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x4071a5: 56           push     esi
    // 0x4071a6: 57           push     edi
    // calls: ['0x41c940', '0x423030', '0x41e0b0']
}


// Function at 0x4077fc — heuristic32
void sub_0x4077fc() {
    // 0x4077fc: 55           push     ebp
    // 0x4077fd: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x407800: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x407804: 8bec         mov      ebp, esp
    // 0x407806: 6aff         push     -1
    // 0x407808: 68416a4300   push     0x436a41
    // 0x40780d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x407813: 50           push     eax
    // 0x407814: 53           push     ebx
    // 0x407815: b890110000   mov      eax, 0x1190
    // 0x40781a: e821e60200   call     0x435e40
    // 0x40781f: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x407824: 33c5         xor      eax, ebp
    // 0x407826: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x407829: 56           push     esi
    // calls: ['0x435e40', '0x4235b0', 'dword ptr [0x43a27c]']
}


// Function at 0x407e70 — heuristic
void sub_0x407e70() {
    // 0x407e70: 55           push     ebp
    // 0x407e71: 8bec         mov      ebp, esp
    // 0x407e73: 6aff         push     -1
    // 0x407e75: 68cf6a4300   push     0x436acf
    // 0x407e7a: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x407e80: 50           push     eax
    // 0x407e81: 81ec18010000 sub      esp, 0x118
    // 0x407e87: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x407e8c: 33c5         xor      eax, ebp
    // 0x407e8e: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x407e91: 53           push     ebx
    // 0x407e92: 56           push     esi
    // 0x407e93: 57           push     edi
    // 0x407e94: 50           push     eax
    // 0x407e95: 8d45f4       lea      eax, [ebp - 0xc]
    // calls: ['0x403aa0', '0x403aa0', '0x403aa0']
}


// Function at 0x40836c — heuristic32
void sub_0x40836c() {
    // 0x40836c: 55           push     ebp
    // 0x40836d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x408370: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x408374: 8bec         mov      ebp, esp
    // 0x408376: 6aff         push     -1
    // 0x408378: 683c6b4300   push     0x436b3c
    // 0x40837d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x408383: 50           push     eax
    // 0x408384: 53           push     ebx
    // 0x408385: 81eca8020000 sub      esp, 0x2a8
    // 0x40838b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x408390: 33c5         xor      eax, ebp
    // 0x408392: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x408395: 56           push     esi
    // 0x408396: 57           push     edi
    // calls: ['0x4235b0', 'dword ptr [0x43a164]', '0x41dea0']
}


// Function at 0x40880c — heuristic32
void sub_0x40880c() {
    // 0x40880c: 55           push     ebp
    // 0x40880d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x408810: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x408814: 8bec         mov      ebp, esp
    // 0x408816: 6aff         push     -1
    // 0x408818: 68966b4300   push     0x436b96
    // 0x40881d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x408823: 50           push     eax
    // 0x408824: 53           push     ebx
    // 0x408825: 81ecd4020000 sub      esp, 0x2d4
    // 0x40882b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x408830: 33c5         xor      eax, ebp
    // 0x408832: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x408835: 56           push     esi
    // 0x408836: 50           push     eax
    // calls: ['0x41dea0', '0x408360', '0x41e610']
}


// Function at 0x408c3c — heuristic32
void sub_0x408c3c() {
    // 0x408c3c: 55           push     ebp
    // 0x408c3d: 8b6b04       mov      ebp, dword ptr [ebx + 4]
    // 0x408c40: 896c2404     mov      dword ptr [esp + 4], ebp
    // 0x408c44: 8bec         mov      ebp, esp
    // 0x408c46: 6aff         push     -1
    // 0x408c48: 68286c4300   push     0x436c28
    // 0x408c4d: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x408c53: 50           push     eax
    // 0x408c54: 53           push     ebx
    // 0x408c55: 81ecb80d0000 sub      esp, 0xdb8
    // 0x408c5b: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x408c60: 33c5         xor      eax, ebp
    // 0x408c62: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x408c65: 56           push     esi
    // 0x408c66: 57           push     edi
    // calls: ['dword ptr [0x43a448]', 'dword ptr [0x43a278]', '0x40a780']
}


// Function at 0x409b00 — heuristic
void sub_0x409b00() {
    // 0x409b00: 55           push     ebp
    // 0x409b01: 8bec         mov      ebp, esp
    // 0x409b03: 6aff         push     -1
    // 0x409b05: 687b6c4300   push     0x436c7b
    // 0x409b0a: 64a100000000 mov      eax, dword ptr fs:[0]
    // 0x409b10: 50           push     eax
    // 0x409b11: 81ec70020000 sub      esp, 0x270
    // 0x409b17: a140b04400   mov      eax, dword ptr [0x44b040]
    // 0x409b1c: 33c5         xor      eax, ebp
    // 0x409b1e: 8945ec       mov      dword ptr [ebp - 0x14], eax
    // 0x409b21: 53           push     ebx
    // 0x409b22: 56           push     esi
    // 0x409b23: 57           push     edi
    // 0x409b24: 50           push     eax
    // 0x409b25: 8d45f4       lea      eax, [ebp - 0xc]
    // calls: ['ebx', '0x4235b0', '0x403aa0']
}
