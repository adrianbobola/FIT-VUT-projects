; Naprogramujte funkci, která v poli 32bitových èísel bez znaménka pA nalezne minimum a vrátí jeho hodnotu
; v registru EAX. Délka pole je dána parametrem N.
;
; Funkci jsou pøedávány parametry na zásobníku v poøadí od posledního k prvnímu (zprava doleva), parametry ze 
; zásobníku uklízí volající a výsledek funkce se vrací v registru EAX (konvence jazyka C).
;
; unsigned int task22(const unsigned int *pA, int N)
;
; Vstup:
;   pA: ukazatel na zaèátek pole 32bitových prvkù bez znaménka
;    N: poèet prvkù pole pA (32bitové èíslo se znaménkem)
;
; Výstup:
;   EAX = 0, když je pA neplatný ukazatel (tj. pA == 0) nebo N <= 0
;   EAX = hodnota 32bitového minima bez znaménka.
;
; Dùležité:
;   Funkce musí zachovat obsah všech registrù, kromì registru EAX a pøíznakového registru.
;
%include "rw32-2018.inc"
section .data
    pA dd 12, 23, 42, 1, 0, 52, -1, 129
    N dd 22
section .text
_main:
    push ebp
    mov ebp, esp
    
    mov ecx, [N]
    mov esi, pA
    
    push ecx
    push esi
    
    call findMin
    call WriteInt32 
         
    pop esi 
    pop ecx                    
    pop ebp
    ret
  
findMin:
    push ebp
    mov ebp, esp
    
    push ecx
    push ebx
    xor ecx, ecx
    xor ebx, ebx
    
    mov ebx, [ebp+8] ;ebx = pA
    mov ecx, [ebp+12];ecx = N
    
    mov eax, 0
    cmp ebx, 0 ;pA == 0
    je end
    cmp ecx, 0 ;pA < 0
    jb end
    mov eax,[ebx+ecx*4]
    
  for:
    dec ecx
    cmp eax, [ebx+ecx*4]
    jb forend
    mov eax, 129
  
  forend:
    cmp ecx, 0
    je end
    jmp for
    
  end:
    pop ebx
    pop ecx
    pop ebp
    ret