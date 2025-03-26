%include "rw32-2018.inc"

section .data

section .text
_main:
    push ebp
    mov ebp, esp

    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    
    mov eax, __float32__(0.0)
    push eax
    mov ebx, __float32__(-6400.0)
    push ebx
    mov eax, __float32__(0.0)
    push eax
    ; push pError   [ebp + 16]
    ; push y= 10    [ebp + 12]
    ; push x= 5     [ebp + 8]
    call task32
    pop ebp
    ret
    
task32: 
    push ebp
    mov ebp, esp 
    push eax
    
    mov eax, __float32__(4.325)
    push eax ;dword[ebp-8]
    mov eax, __float32__(17.0)
    push eax ;dword[ebp-12]
    
    fld dword[ebp + 8]      
    fadd dword[ebp + 12]     
    fsub dword[ebp - 8]
    fabs
    fdiv dword[ebp - 12]  ;st0= abs(x+y-4.325)/17
    
    fldpi ;st0=pi
    fld1 
    fadd st0 ;st0=2, st1=pi
    fmulp st1 ;st0=st1*st0
    fmul dword[ebp + 8];st0=2*pi*x 
    fld1
    fadd st0
    fadd st0 ;st0=4
    fxch st1
    fsubp st1
    fsin ;st0=sin(4 - 2*pi*x)
    fxch st1
    faddp st1 ;st0=A
    
    fld dword[ebp+12] 
    fldz ; st0 = 0, st1 = y
    fcomip
    jnc nula
    
    fsqrt
    fld dword[ebp+8]
    faddp st1 ; st0=B | st1=A
    
    fldz
    fcomip
    je nula
    fdiv ; st0=f(x,y)
    jmp skip
   nula:
    mov dword [errorCode], 1
    push dword  0b1111111110000000000000000000000
    fld dword[ebp-16]
    add esp, 12
    jmp end
   skip:
    mov dword [errorCode], 0
    add esp, 8
   end:
    mov esp, ebp
    pop ebp
    ret
