;--- Úkol 3 ---
;
; Naprogramujte funkci 'unsigned char* task23(int N)', která vypoèítá Padovanovu 
; posloupnost N 8bitových èísel bez znaménka. Funkce má jako vstupní parametr
; poèet prvkù posloupnosti v ECX (32bitová hodnota se znaménkem) a vrací v EAX 
; ukazatel na pole, které alokujete funkcí 'malloc', a do kterého uložíte
; jednotlivé prvky posloupnosti.
;
; Padovanova posloupnost je definována takto:
;
;   P(0) = 1, P(1) = 1, P(2) = 1, P(n) = P(n-2) + P(n-3)
;
; Funkci 'malloc' importujte makrem CEXTERN:
;
;   CEXTERN  malloc
;
; Funkce 'malloc' je definována takto: 
;
;   void* malloc(size_t N)
;     * N je poèet bytù, které mají být alokovány (32bitové èíslo bez znaménka)
;     * funkce vrací v EAX ukazatel (32bitové èíslo bez znaménka)
;     * funkce mùže zmìnit obsah registrù ECX a EDX
;
; Vstup:
;   * ECX = poèet prvkù pole (32bitové èíslo se znaménkem)
;
; Výstup:
;   * EAX = 0, pokud bude N <= 0 (tj. nic nealokujete a vrátíte hodnotu EAX = NULL = 0),
;   * jinak v EAX vrátíte ukazatel na pole 8bitových prvkù bez znaménka reprezentujících Padovanovu posloupnost
;
; Dùležité:
;   * Funkce musí zachovat obsah všech registrù, kromì registru EAX a pøíznakového registru.
;   * Funkce 'malloc' mùže zmìnit obsah registrù ECX a EDX => pokud je používáte, schovejte si je.
;
; Hodnocení: až 6 b.
;

task23:
    push ebp
    mov ebp, esp
    push ecx
    push eax  
    push edx
    xor eax, eax  
    CEXTERN  malloc
  
    mov eax, 0
    mov ecx, [ebp + 8] ;ecx = param N
    
    cmp ecx, 0 ; N<=0
    jl end
    cmp ecx, 1 ;vysledok = 1, ukonci rekurziu
    je one
    
    push dword ecx
    call malloc
    add esp, 4
    ;mov [buffer], eax
    
    dec ecx ; inak rekurzivne volanie funkcie s n-1
    call task23 
    
  one:
    mov eax, 1
    
  end:   
    pop edx 
    pop eax
    pop ecx
    pop ebp
    ret
