import random
import pefile
import sys

DECRYPTER = [
    [ 0xe8, 0x00, 0x00, 0x00, 0x00 ],           # call 5
    [ 0x5a ],                                   # pop edx
    [ 0x83, 0xea, 0x06 ],                       # sub edx, 0x6
    [ 0x89, 0xd1 ],                             # mov ecx, edx
    [ 0x81, 0xe9, 0x11, 0x11, 0x11, 0x11 ],     # sub ecx, 0x11111111 
    [ 0x89, 0xc8 ],                             # mov eax, ecx
    [ 0x05, 0x22, 0x22, 0x22, 0x22 ],           # add eax, 0x22222222
    [ 0x81, 0x31, 0x33, 0x33, 0x33, 0x33 ],     # loop: xor dword [ecx], 0x33333333
    [ 0x39, 0xd1, 0x7d, 0x05 ],                 # cmp ecx, edx      jge out ; can't separate these
    [ 0x83, 0xc1, 0x04 ],                       # add ecx, 4
    [ 0xeb, 0xf1 ],                             # jmp loop
    [ 0xff, 0xe0 ]                              # out: jmp eax
]

JMP_OFFSETS = [
    [ 0x21, 5 ],
    [ 0x26, -15 ]
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

def mutate(length, entry, key):
    decrypter = DECRYPTER
    jmp_offsets = JMP_OFFSETS

    length = length - 1
    
    # replace length, entry point and key values
    decrypter[4] = decrypter[4][:2] + [(0xff & (length >> (8 * x))) for x in range(4)] + decrypter[4][2 + 4:]
    decrypter[6] = decrypter[6][:1] + [(0xff & (entry >> (8 * x))) for x in range(4)] + decrypter[6][1 + 4:]
    decrypter[7] = decrypter[7][:2] + [(0xff & (key >> (8 * x))) for x in range(4)] + decrypter[7][2 + 4:]

    # start inserting goop
    for i in range(4):
        cruft = random.choice(CRUFT)
        # Start at 1 so we know where out "call 5" is going to be
        # TODO: work around this by juggling the sub operation later on
        insert_index = random.randint(1, len(decrypter))
        insert_offset = reduce(lambda a, x: a + len(x), decrypter[:insert_index], 0)
        
        # Now we need to wriggle the values and offsets for our JMPS
        # so we don't go missing once we insert the cruft
        for offset in jmp_offsets:
            current_jmp_target = offset[0] + offset[1] + 1

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
            final[offset[0]] = offset[1]
        else:
            final[offset[0]] = offset[1] & 0xff

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
    print('USAGE: {0} TARGET')
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
    """
    print('\nSections:')
    target_section = None
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

    print('')
    print('Targetting section: ' + target_section.Name)
    print('Space available   : {0} bytes'.format(target_section.SizeOfRawData - target_section.Misc_VirtualSize))
    
    # TODO: bail, or expand section if we don't have enough space

    random.seed()
    key = random.randint(0, 0xffffffff)
    length = target_section.Misc_VirtualSize
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint - target_section.VirtualAddress
    
    print('Key               : {0:#010x}'.format(key))
    print('Length            : {0:#x}'.format(length))
    print('Entry Offset      : {0:#010x}'.format(entry))
    
    shellcode = mutate(length, entry, key)
    
    # Stuff new code into the back of the section
    file_offset = target_section.PointerToRawData + target_section.Misc_VirtualSize
    pe.set_bytes_at_offset(file_offset, str(shellcode))
    
    # Update the Entry point
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = target_section.VirtualAddress + target_section.Misc_VirtualSize
        
    # And now 'encrypt' the existing code
    buffer = bytearray(target_section.get_data())
    key_index = 0
    buffer_index = 0
    for buffer_index in xrange(target_section.Misc_VirtualSize):
        buffer[buffer_index] ^= (key >> (key_index * 8)) & 0xff
        key_index = (key_index + 1) % 4
        
    pe.set_bytes_at_offset(target_section.PointerToRawData, str(buffer))
    
    # Update the section size
    target_section.Misc_VirtualSize += len(shellcode)
    
    # Mark the section as writable
    target_section.Characteristics |= pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']
    
    # Strip relocations, since it tweaks the code as it's loaded to account 
    # for the base addresses and this will break our encryption
    pe.FILE_HEADER.Characteristics |= pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_RELOCS_STRIPPED']
    
    pe.write(filename = '{0}.{1:08x}.exe'.format(target_file, key))
    