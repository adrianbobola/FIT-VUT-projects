task21:
    repe cmpsw
    je zhodne
    mov eax, 0
    jmp end
  zhodne:
    mov eax, 1
    jmp end
  end:
    ret   
    
task22:
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
    mov eax, [ebx+ecx*4]
  
  forend:
    cmp ecx, 0
    je end
    jmp for
    
  end:
    pop ebx
    pop ecx
    pop ebp
    ret
    
    
  