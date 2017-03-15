import random
import pefile
import sys

encode_int32 = lambda x: [(0xff & (x >> (8 * i))) for i in range(4)]
twos_comp = lambda x: x - (1 << 32)

def mutate(length, entry, key, shellcode):
    decrypter = shellcode.get_shellcode(length, entry, key)
    jmp_offsets = shellcode.JMP_OFFSETS
    
    # start inserting goop
    for i in range(100):
        cruft = random.choice(shellcode.CRUFT)
        
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
    
    if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        print('64-bit PE+')
        import shellcode64 as shellcode
    else:
        print('32-bit PE')
        import shellcode32 as shellcode
    
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
    
    shellcode = mutate(length, entry, key, shellcode)
    
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
    