# hmmz

A simple proof-of-concept win32 crypter.

## Sounds hardcore

Yeah, it brings us right up-to-date with the latest in 1988 Bulgarian 
technology.

## So how does it work?

Magic.

## No, really

It finds the code section of the executable, XORs every dword with the same 
random 32 bits, mutates the decryptor by adding instructions that do nothing,
adds that to the end of the code section and then changes the program's entry
point to the start of the decryptor.

The code section has its permissions changed at runtime so that it's writable.
Most of the shellcode is actually there to track down kernel32 and 
VirtualProtect.

Import tables and everything else remain untouched, so fingerprinting is still 
very simple. I made this because I wanted to see if I could. If you're 
actually trusting it to protect your code from detection then you're an idiot 
and deserve to be v&.

## Dependencies

[pefile](https://github.com/erocarrera/pefile)

## Side effects

The crypted binary is marked as non-relocatable, since the address fudging 
that happens when the binary is loaded makes the decryption break. Future 
plans are either to undo-decrypt-redo at runtime, or write my own loader.

## To do

- Make sure we're using the right section (the one containing the entry point)
- More cruft
- Works on 32 and 64 executables, but only tested properly on Win7.
- Find a way around the ASLR issue
- Support for crypting DLLs
- Anti-reversing features
