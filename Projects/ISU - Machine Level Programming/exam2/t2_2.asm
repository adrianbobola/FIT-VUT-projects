; od pola A odecte hodnotu x a ulozi do pola B
;int subX(int *pA, unsigned int N, int x, int *pB)
; - vstup:  - pA: ukazatel na zacatek pole
;           - N: pocet prvku pole
;           - x: hodnota x
;           - pB: ukazatel na zacatek pole
; - vystup: - EAX=0: bez chyby
;           - EAX=-1: neplatne pA (pA=0)
;           - EAX=-2: neplatne pB (pB=0)
;Fce musi zachovat obsah vsech registru
%include "rw32-2018.inc"
section .data
    pA dd 12, 23, 42, 1, 0, 52, -1, 129
    pB dd 0, 0, 1, 0, 0, 0, 0, 0, 0
    N dd 8
    x dd 10
section .text
_main:
    push ebp
    mov ebp, esp
    mov eax, [x]
    mov ebx, [N]
    push pB
    push eax
    push ebx
    push pA
    
    call subx
    add esp, 16
    call WriteInt32
    
    pop ebp
    ret
  subx:
    push ebp
    mov ebp, esp
    push ebx
    push edx
    push ecx
    mov ebx, [ebp+8]
    mov edx, [ebp+20]
    mov ecx, [ebp+12] ;x=[ebp+16]
    
    mov eax, -1
    cmp ebx, 0
    je .error
    
    mov eax, -2
    cmp edx, 0
    je .error
      
      .for:
        dec ecx
        mov eax, [ebx + ecx*4]
        sub eax, [ebp+16]
        mov [edx + ecx*4], eax
        
        cmp eax, 0
        je .end
        jmp .for
      .end:
        mov eax, 0
      .error:
        pop ecx
        pop edx
        pop ebx
        pop ebp
        ret
    