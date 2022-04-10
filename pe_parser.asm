LoadPeFile proc CurrentStdcallNotation uses cdi filename:ptr byte, pe:ptr byte, filesize:cword

	local comp64:cword
	local comp64_2:cword
	
	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
    mov cdi, [pe]
    assume cdi: ptr PeParser

    mov cax, [filename]
    mov [cdi].filename, cax
    ; права
    invoke sc_CreateFileA, [filename], GENERIC_READ or GENERIC_WRITE or GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov [cdi].fd, cax
    .if [cdi].fd == INVALID_HANDLE_VALUE
        ;invoke PrintLastErrorMessage
        ;invoke crt_puts, $CTA0 ("Error open file\n")
        xor cax, cax
        ret
    .endif
    
    .if [filesize]
        mov cax, [filesize]
        mov [cdi].filesize, cax
    .else
        invoke sc_GetFileSize, [cdi].fd, 0
        mov [cdi].filesize, cax
    .endif
    
	mov ccx, [cdi].fd
	mov cdx, [cdi].filesize
	mov [comp64], ccx
	mov [comp64_2], cdx
    invoke sc_CreateFileMappingA, [comp64], 0, PAGE_EXECUTE_READWRITE, 0, [comp64_2], 0
    mov [cdi].mapd, cax
    .if [cdi].mapd == 0
        invoke sc_CloseHandle, [cdi].fd
        ;invoke crt_puts, $CTA0 ("Error create fie mapping\n")
        xor cax, cax
        ret
    .endif
    
	; маппинг в память
	mov ccx, [cdi].mapd
    invoke sc_MapViewOfFile, ccx, FILE_MAP_READ or FILE_MAP_WRITE or 20h, 0, 0, 0
    mov [cdi].mem, cax
    .if [cdi].mem == 0
        invoke sc_CloseHandle, [cdi].mapd
        invoke sc_CloseHandle, [cdi].fd
        ;invoke crt_puts, $CTA0 ("Error mapping file\n")
        xor cax, cax
        ret
    .endif

	; указатель на заголовок PE
	mov cdx, [pe]
	mov cax, [cdx].PeParser.mem
	mov [cdx].PeParser.doshead, cax
	
	movzx eax, word ptr [cax].IMAGE_DOS_HEADER.e_magic
	.if eax != IMAGE_DOS_SIGNATURE
		invoke UnloadPeFile, addr [pe]
		xor cax, cax
		ret
	.endif
	
	; указатель на NT заголовок
	mov cdx, [pe]
	mov cax, [cdx].PeParser.mem
	mov cdx, [cdx].PeParser.doshead
	lea cdx, [cdx].IMAGE_DOS_HEADER.e_lfanew
	mov edx, dword ptr [cdx]
	add cax, cdx
	mov cdx, [pe]
	mov [cdx].PeParser.nthead, cax
	mov eax, dword ptr [cax]
	
	.if eax != IMAGE_NT_SIGNATURE
		invoke UnloadPeFile, addr [pe]
		xor cax, cax
		ret
	.endif
	
	; определение формата РЕ
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	lea cax, [cax].IMAGE_OPTIONAL_HEADER.Magic
	movzx cax, word ptr [cax]
	
	ifdef _WIN64
		.if ax != IMAGE_NT_OPTIONAL_HDR64_MAGIC
	else
		.if ax != IMAGE_NT_OPTIONAL_HDR32_MAGIC
	endif
		xor eax, eax
		ret
	.endif
	
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	mov cdx, [pe]
	mov cdx, [cdx].PeParser.nthead
	lea cdx, [cdx].IMAGE_NT_HEADERS.FileHeader
	lea cdx, [cdx].IMAGE_FILE_HEADER.SizeOfOptionalHeader
	movzx ecx, word ptr [cdx]
	add cax, ccx
	mov cdx, [pe]
	mov [cdx].PeParser.sections, cax
	
	mov cdx, [pe]
	mov cdx, [cdx].PeParser.nthead
	lea cdx, [cdx].IMAGE_NT_HEADERS.FileHeader
	movzx eax, word ptr [cdx].IMAGE_FILE_HEADER.NumberOfSections
	mov cdx, [pe]
	mov [cdx].PeParser.countSec, eax
    ;invoke ParsePeFileHeader, [cdi].mem, [pe]
    ; .if !cax
        ; invoke sc_UnmapViewOfFile, [cdi].mem
        ; invoke sc_CloseHandle, [cdi].mapd
        ; invoke sc_CloseHandle, [cdi].fd
        ; xor cax, cax
        ; ret
    ; .endif
    
    mov cax, 1
    ret    

LoadPeFile endp

UnloadPeFile proc CurrentStdcallNotation pe:cword

	ifdef _WIN64 
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

	mov cax, cword ptr [pe]
	mov cdx, [cax].PeParser.mem
	invoke sc_UnmapViewOfFile, cdx
	
	mov cax, cword ptr [pe]
	mov cdx, [cax].PeParser.fd
	invoke sc_CloseHandle, cdx
	
	mov cax, cword ptr [pe]
	mov cdx, [cax].PeParser.mapd
	invoke sc_CloseHandle, cdx
	
	ret
	
UnloadPeFile endp

;
; Возвращает файловое смещение по RVA.
;
RvaToOffset proc CurrentStdcallNotation uses ccx cdx cdi rva:cword, pe:cword
	local currentSection:cword
	local numberOfSections:dword
	
	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
	mov cdx, [pe]
	mov cax, [cdx].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	mov eax, [cax].IMAGE_OPTIONAL_HEADER.SizeOfImage
	mov eax, eax
	
	; if (rva > SizeOfImage) return 0;
	.if [rva] > cax
		mov cax, 0
		ret
	.endif
	
	
	mov cdx, [pe]
	mov cdi, [cdx].PeParser.sections
	mov ecx, [cdx].PeParser.countSec
	mov [numberOfSections], ecx
	
	xor ecx, ecx
	.while ecx != [numberOfSections]
	
        xor cax, cax
		mov eax, ecx
		imul cax, IMAGE_SIZEOF_SECTION_HEADER
		add cax, cdi
		mov [currentSection], cax
		
		xor cdx, cdx
		mov edx, [cax].IMAGE_SECTION_HEADER.Misc.VirtualSize
		mov eax, [cax].IMAGE_SECTION_HEADER.VirtualAddress
		add cdx, cax

		.if [rva] >= cax && [rva] <= cdx
		;if [rva] >= VirtualAddress && [rva] <= VirtualSize + VirtualAddress
			;return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
			mov cax, [rva]
			mov cdx, [currentSection]
			mov edi, [edx].IMAGE_SECTION_HEADER.VirtualAddress
			sub cax, cdi
			mov edi, [edx].IMAGE_SECTION_HEADER.PointerToRawData
			add cax, cdi
			ret

		.endif

		inc ecx
    .endw
	
	xor cax, cax
	ret
RvaToOffset endp