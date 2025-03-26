;int getMax(ESI, ECX)
; - vstup:  - ESI: ukazatel na zacatek pole
;           - ECX: pocet prvku pole
; - vystup: - EAX: hodnota maxima se zn.
;Fce musi zachovat obsah vsech registru
%include "rw32-2018.inc"
section .data
    pole dd 12,33,42,1,0,52,-1,129
section .text
_main:
    push ebp
    mov ebp, esp
    
    mov esi, pole
    mov ecx, 8
    call getMax
    call WriteInt32

    pop ebp
    ret
getMax:
    push ebp
    mov ebp, esp
    push ecx
    push esi
    
    mov esi, [ebp+12]
    mov ecx, [ebp+8]
    mov eax, -1
  .for:
    dec ecx
    cmp eax, [esi+ecx*4]
    jg .forend
    mov eax, [esi+ecx*4]
  .forend:
    cmp ecx, 0
    je .end
    jmp .for
  .end:
    pop esi
    pop ecx
    ret 8
  