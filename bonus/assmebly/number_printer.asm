section .data
    num_format db "%ld", 10, 0   ; Format string for printing numbers with a newline
    num_buffer db 20, 0          ; Buffer to store the number as a string (up to 20 characters)

section .text
global _start

_start:
    xor rsi, rsi                 ; Initialize loop counter to 0

print_loop:
    mov rax, rsi                 ; Move loop counter to rax
    lea rdi, [num_buffer]        ; Load the address of the number buffer
    call itoa                    ; Convert rax to a string

    ; Calculate the length of the string
    mov rax, rdi                 ; rdi contains the address of the string
    call strlen

    ; Write the string to stdout
    mov rax, 1                   ; Syscall number for sys_write
    mov rdi, 1                   ; File descriptor for stdout
    lea rdx, [num_buffer]        ; Load the address of the string to print
    syscall

    inc rsi                      ; Increment the counter

    cmp rsi, 10000               ; Compare the counter with 10,000
    jle print_loop               ; Jump back to the loop if less than or equal

exit:
    mov rax, 60                  ; Syscall number for sys_exit
    xor rdi, rdi                 ; Exit status 0
    syscall

itoa:
    push rax                      ; Preserve registers
    push rdi
    push rdx

    mov rdi, rdx                 ; rdi points to the end of the buffer
    mov rcx, 10                  ; Set rcx to 10 (decimal)
    mov byte [rdi], 0            ; Null-terminate the string

itoa_loop:
    dec rdi
    xor rdx, rdx                 ; Clear any previous remainder
    div rcx                      ; Divide rax by 10
    add dl, '0'                  ; Convert the remainder to ASCII
    mov [rdi], dl                ; Store the ASCII character
    test rax, rax
    jnz itoa_loop

    pop rdx                       ; Restore registers
    pop rdi
    pop rax
    ret

strlen:
    push rax                      ; Preserve registers

    xor rax, rax                 ; Initialize length to 0
    xor rcx, rcx                 ; Initialize index to 0

strlen_loop:
    mov al, byte [rdi + rcx]     ; Load the next byte from the string
    test al, al                  ; Check if it's the null terminator
    jz strlen_done
    inc rax                       ; Increment the length
    inc rcx                       ; Increment the index
    jmp strlen_loop

strlen_done:
    pop rax                       ; Restore registers
    ret