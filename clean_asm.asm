.code

PUBLIC DisableWP
PUBLIC EnableWP

DisableWP PROC
    mov rax, cr0
    and rax, 0FFFFFFFFFFFEFFFFh
    mov cr0, rax
    ret
DisableWP ENDP

EnableWP PROC
    mov rax, cr0
    or rax, 0000000000010000h
    mov cr0, rax
    ret
EnableWP ENDP

END
