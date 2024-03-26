.686

.MODEL FLAT

.code

?strnstr@@YIPADKPBXK0@Z proc
	jecxz @retz8
	cmp ecx,[esp + 4]
	jb @retz8
	push edi
	push esi
	push ebx
	push ebp
	mov ebx,[esp + 20]
	mov ebp,[esp + 24]
	mov edi,edx
	mov al,[ebp]
	inc ebp
	dec ebx
	sub ecx,ebx
@@1:
	repne scasb
	jne @@2
	mov esi,ebp
	mov edx,edi
	push ecx
	mov ecx,ebx
	test ecx,ecx
	repe cmpsb
	pop ecx
	je @@2
	mov edi,edx
	jmp @@1
@@2:
	mov eax,edi
	cmovne eax,ecx
	pop ebp
	pop ebx
	pop esi
	pop edi
	ret 8
?strnstr@@YIPADKPBXK0@Z endp

@retz8 proc
	xor eax,eax
	ret 8
@retz8 endp

end