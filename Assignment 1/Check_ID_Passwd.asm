; Checking Student ID and Password 
; Name: Gia Huy Tran
; Student ID: 104224749
; Unit Code: CYB80003
; Last Modified: 20-05-2025
; Description: This program checks the validity of a user ID and password.
; Testing credentials
; userID: S104224749
; Password: Test1234@

.686
.MODEL FLAT, STDCALL
.STACK 4096

INCLUDE Irvine32.inc

BufSize      = 30               ; Max password length for validation
XorKeyValue  = 7Ah              ; Fixed XOR key from Week 5 logic

.DATA
msgInvalidID   BYTE "Invalid User ID. Please enter S followed by a number between 100000000 and 109000000.", 13, 10, 0
promptID       BYTE "Enter your User ID (e.g., S104224749): ", 0
promptPass     BYTE "Enter your password (max 30 characters): ", 0
msgTooLong     BYTE "Password too long. Possible intrusion attempt.", 13, 10, 0
msgSuccess     BYTE "Login successful.", 13, 10, 0
msgNamenEmailPromptSuccess     BYTE "Successfully save Name and Email.", 13, 10, 0
msgFailure     BYTE "Login failed. Incorrect credentials.", 13, 10, 0
msgFileError   BYTE "Could not open password file.", 13, 10, 0
msgTooMany    BYTE "Too many failed attempts. Exiting...",13,10,0
attempts      DWORD 0
promptName     BYTE "Enter your full name: ", 0
promptEmail    BYTE "Enter your email: ", 0
labelName      BYTE "Name: ", 0
labelEmail     BYTE "Email: ", 0

; Buffers
courseCode BYTE "CYB80003", 0
semesterCode BYTE "202501", 0
colon BYTE ":", 0
endMarker BYTE "::", 13, 10, 0
nameInput        BYTE 64 DUP(0)
emailInput       BYTE 64 DUP(0)
userIDInput     BYTE 32 DUP(0)
passwordInput   BYTE 80 DUP(0)       ; read buffer
passwordHex     BYTE BufSize * 2 + 1 DUP(0)

fileUserID      BYTE 32 DUP(0)
filePasswordHex BYTE BufSize * 2 + 1 DUP(0)
fileBuffer      BYTE 256 DUP(0)

filename        BYTE "passwd", 0
fileHandle      DWORD ?
passwordLen     DWORD ?
xorKey          BYTE XorKeyValue

.CODE

;******************************************************************
;    WriteStringToFile procedure
;    Writes a null-terminated string to an open file
;    Input: EDX = offset of string, ECX = length computed inside
;    Uses: EAX = file handle, modifies EAX, ECX, EDX, ESI
;******************************************************************
WriteStringToFile PROC
    push eax
    push ecx
    push edx
    push esi

    mov esi, edx
    xor ecx, ecx
countLen:
    cmp byte ptr [esi + ecx], 0
    je writeNow
    inc ecx
    jmp countLen
writeNow:
    mov eax, fileHandle
    mov edx, esi
    call WriteToFile

    pop esi
    pop edx
    pop ecx
    pop eax
    ret
WriteStringToFile ENDP

;******************************************************************
;    main procedure
;    Orchestrates user login flow: prompts, validation, encryption,
;    file I/O and prompts for name/email on success
;    Uses: various buffers and procedures from Irvine32.inc
;******************************************************************
main PROC

    ; Prompt for user ID and validate format
CheckUserIDs:
    mov edx, OFFSET promptID
    call WriteString
    mov edx, OFFSET userIDInput
    mov ecx, SIZEOF userIDInput
    call ReadString

    ; Check length is exactly 10 (1 letter + 9 digits)
    mov esi, OFFSET userIDInput
    mov ecx, 0
countLoop:
    mov al, [esi]
    cmp al, 0
    je checkLength
    inc ecx
    inc esi
    jmp countLoop
checkLength:
    cmp ecx, 10
    jne showInvalidID

    
    ; Check first character is 'S'
    mov al, [userIDInput]
    cmp al, 'S'
    jne showInvalidID

    ; Check numeric part is 9 digits long and in range
    ; Convert ASCII to integer
    lea esi, userIDInput + 1   ; Skip 'S'
    xor eax, eax               ; result = 0
    mov ecx, 9
validateDigits:
    mov bl, [esi]
    sub bl, '0'
    cmp bl, 9
    ja showInvalidID            ; not a digit
    imul eax, eax, 10
    movzx edx, bl
    add eax, edx
    inc esi
    loop validateDigits
    cmp eax, 100000000
    jb showInvalidID
    cmp eax, 109000000
    ja showInvalidID

    jmp CheckPasswd

showInvalidID:
    mov edx, OFFSET msgInvalidID
    call WriteString
    jmp CheckUserIDs

CheckPasswd:

; Prompt for password
    mov edx, OFFSET promptPass
    call WriteString
    mov edx, OFFSET passwordInput
    mov ecx, SIZEOF passwordInput
    call ReadString

    ; Check password length (must not exceed BufSize)
    mov passwordLen, eax
    cmp eax, BufSize
    jbe CheckEncryptrdPasswd
    ; If too long, treat as intrusion attempt
    mov edx, OFFSET msgTooLong
    call WriteString
    call Crlf
    call WaitMsg
    exit

CheckEncryptrdPasswd:

    ; Encrypt password input to hex
    mov esi, OFFSET passwordInput
    mov edi, OFFSET passwordHex
    movzx ebx, xorKey
    mov ecx, passwordLen
encLoop:
    mov al, [esi]
    xor al, bl
    call ByteToHex
    mov [edi], ah
    inc edi
    mov [edi], al
    inc edi
    inc esi
    loop encLoop
    mov BYTE PTR [edi], 0

    ; Open and read password file
    mov edx, OFFSET filename
    call OpenInputFile
    cmp eax, -1
    je fileError
    mov fileHandle, eax

    mov eax, fileHandle
    mov edx, OFFSET fileBuffer
    mov ecx, SIZEOF fileBuffer
    call ReadFromFile
    mov eax, fileHandle    ; restore handle before closing
    call CloseFile

    
        
    ; Parse user ID from fileBuffer
    mov esi, OFFSET fileBuffer
    mov edi, OFFSET fileUserID
parseID:
    mov al, [esi]
    cmp al, 0
    je compareFail
    cmp al, ':'
    je doneID
    mov [edi], al
    inc esi
    inc edi
    jmp parseID
doneID:
    mov BYTE PTR [edi], 0
    inc esi

    ; Parse password hex from fileBuffer
    mov edi, OFFSET filePasswordHex
parsePass:
    mov al, [esi]
    cmp al, 0
    je compareFail
    cmp al, ':'
    je donePass
    mov [edi], al
    inc esi
    inc edi
    jmp parsePass
donePass:
    mov BYTE PTR [edi], 0

    ; Compare user ID
    mov esi, OFFSET userIDInput
    mov edi, OFFSET fileUserID
compareID:
    mov al, [esi]
    mov bl, [edi]
    cmp al, bl
    jne compareFail
    cmp al, 0
    je comparePass
    inc esi
    inc edi
    jmp compareID

comparePass:
    mov esi, OFFSET passwordHex
    mov edi, OFFSET filePasswordHex
compareHex:
    mov al, [esi]
    mov bl, [edi]
    cmp al, bl
    jne compareFail
    cmp al, 0
    je loginSuccess
    inc esi
    inc edi
    jmp compareHex

loginSuccess:
    mov edx, OFFSET msgSuccess
    call WriteString

    ; Save full user info after successful login
    mov edx, OFFSET filename
    call CreateOutputFile
    cmp eax, INVALID_HANDLE_VALUE    ; ensure file opened
    je fileError
    mov fileHandle, eax
    

    mov edx, OFFSET userIDInput
    call WriteStringToFile
    mov edx, OFFSET colon
    call WriteStringToFile

    mov edx, OFFSET passwordHex
    call WriteStringToFile
    mov edx, OFFSET colon
    call WriteStringToFile

    mov edx, OFFSET courseCode
    call WriteStringToFile
    mov edx, OFFSET colon
    call WriteStringToFile

    mov edx, OFFSET semesterCode
    call WriteStringToFile
    mov edx, OFFSET colon
    call WriteStringToFile

    mov edx, OFFSET promptName
    call WriteString
    mov edx, OFFSET nameInput
    mov ecx, SIZEOF nameInput
    call ReadString

    mov edx, OFFSET nameInput
    call WriteStringToFile
    mov edx, OFFSET colon
    call WriteStringToFile

    mov edx, OFFSET promptEmail
    call WriteString
    mov edx, OFFSET emailInput
    mov ecx, SIZEOF emailInput
    call ReadString

    mov edx, OFFSET emailInput
    call WriteStringToFile
    mov edx, OFFSET endMarker
    call WriteStringToFile
    call CloseFile
    mov edx, OFFSET msgNamenEmailPromptSuccess
    call WriteString
    call Crlf
    mov eax, fileHandle
    call Crlf
    call WaitMsg
    exit

compareFail:
    mov edx, OFFSET msgFailure
    call WriteString
    call Crlf
    ; increment and check attempts
    inc DWORD PTR [attempts]
    mov eax, DWORD PTR [attempts]
    cmp eax, 3
    jae tooMany
    jmp CheckUserIDs
    call Crlf
    call WaitMsg
    exit

tooMany:
    mov edx, OFFSET msgTooMany
    call WriteString
    call Crlf
    call WaitMsg
    exit

fileError:
    mov edx, OFFSET msgFileError
    call WriteString
    call Crlf
    call WaitMsg
    exit

main ENDP

; ===== Byte to Hex Conversion =====
;******************************************************************
;    ByteToHex procedure
;    Converts a byte in AL to two ASCII hex characters
;    Input: AL = byte to convert
;    Output: AH = high nibble ASCII, AL = low nibble ASCII
;    Clobbers EBX
;******************************************************************
ByteToHex PROC
    push ebx
    mov bl, al
    shr al, 4
    call NibbleToHex
    mov ah, al
    mov al, bl
    and al, 0Fh
    call NibbleToHex
    pop ebx
    ret
ByteToHex ENDP

;******************************************************************
;    NibbleToHex procedure
;    Converts a 4-bit value in AL to ASCII hex digit
;    Input: AL = 0-15
;    Output: AL = '0'-'9' or 'A'-'F'
;******************************************************************
NibbleToHex PROC
    cmp al, 9
    jbe digit
    add al, 7
digit:
    add al, '0'
    ret
NibbleToHex ENDP

END main
