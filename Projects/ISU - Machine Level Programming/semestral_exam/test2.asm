%include "rw32-2018.inc"

section .data
    ; zde budou vase data

section .text
_main:
    push ebp
    mov ebp, esp
    
    mov al,25
    and ax, 25 ;al=25
    or al, -97 ;al=-97
    xchg al, dl
    rol ax, 8
    xor al, dl
    sar al, 4 ;al = -7
        
    pop ebp
    ret