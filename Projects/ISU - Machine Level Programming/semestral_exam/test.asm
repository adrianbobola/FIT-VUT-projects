%include "rw32-2018.inc"

section .data
    ; zde budou vase data

section .text
_main:
    push ebp
    mov ebp, esp
    
    mov al, 84
    mov bl, 9
    mov cl, 5
    
    mul cl ;ax = 420
    add ah, bl ;  617 100
    mov dl, 100 
    div dl ; ax = 6171
    inc ax
    add al, ah ; al = 52
    sub al, bl
    cmp al, bl
    cmp al, -85 ;
    jae hop1
    add al, -128 ;
    
  hop1: ; al = -85
        
    pop ebp
    ret