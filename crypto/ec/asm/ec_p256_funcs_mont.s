##############################################################################
#                                                                            # 
#  Copyright (c) 2013, Intel Corporation                                     #   
#                                                                            # 
#  All rights reserved.                                                      # 
#                                                                            # 
#  Redistribution and use in source and binary forms, with or without        # 
#  modification, are permitted provided that the following conditions are    # 
#  met:                                                                      # 
#                                                                            # 
#  #  Redistributions of source code must retain the above copyright         # 
#     notice, this list of conditions and the following disclaimer.          # 
#                                                                            # 
#  #  Redistributions in binary form must reproduce the above copyright      # 
#     notice, this list of conditions and the following disclaimer in the    # 
#     documentation and/or other materials provided with the                 # 
#     distribution.                                                          # 
#                                                                            # 
#  #  Neither the name of the Intel Corporation nor the names of its         # 
#     contributors may be used to endorse or promote products derived from   # 
#     this software without specific prior written permission.               # 
#                                                                            # 
#                                                                            # 
#  THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION ""AS IS"" AND ANY          # 
#  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE         # 
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR        # 
#  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR            # 
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,     # 
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,       # 
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR        # 
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    # 
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      # 
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        # 
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              # 
#                                                                            # 
##############################################################################
#                                                                            # 
#  Developers and authors:                                                   # 
#  Shay Gueron (1, 2), and Vlad Krasnov (1)                                  # 
#  (1) Intel Corporation, Israel Development Center                          # 
#  (2) University of Haifa                                                   # 
#  Reference:                                                                # 
#  S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with# 
#                           256 Bit Primes"                                  # 
#                                                                            # 
##############################################################################
 
# Constant time access reduction table, contains 8 values
.align 64
.LPolyTable:
#            0*P                 -1*P                -2*P                -3*P                -4*P                -5*P                -6*P                -7*P
.quad 0x0000000000000000, 0x0000000000000001, 0x0000000000000002, 0x0000000000000003, 0x0000000000000004, 0x0000000000000005, 0x0000000000000006, 0x0000000000000007
.quad 0x0000000000000000, 0xffffffff00000000, 0xfffffffe00000000, 0xfffffffd00000000, 0xfffffffc00000000, 0xfffffffb00000000, 0xfffffffa00000000, 0xfffffff900000000
.quad 0x0000000000000000, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
.quad 0x0000000000000000, 0x00000000fffffffe, 0x00000001fffffffd, 0x00000002fffffffc, 0x00000003fffffffb, 0x00000004fffffffa, 0x00000005fffffff9, 0x00000006fffffff8
.quad 0x0000000000000000, 0xffffffffffffffff, 0xfffffffffffffffe, 0xfffffffffffffffd, 0xfffffffffffffffc, 0xfffffffffffffffb, 0xfffffffffffffffa, 0xfffffffffffffff9

# The polynomial
.align 64
.Lpoly:
.quad 0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001

# 2^512 mod P precomputed for NIST P256 polynomial
.LRR:
.quad 0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd

################################################################################
# void p256_lshift_small(uint64_t res[4], uint64_t a[4], int amount);
.align 64
.globl p256_lshift_small
p256_lshift_small:

.set res, %rdi
.set a_ptr, %rsi

.set a0, %r8
.set a1, %r9
.set a2, %r10
.set a3, %r11

.set t0, %rax
.set t1, %rdx

    xor     t0, t0
    movzx   %dl, %rcx

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3

    shld    %cl, a3, t0
    shld    %cl, a2, a3
    shld    %cl, a1, a2
    shld    %cl, a0, a1
    shl     %cl, a0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    add     64*0(t0, t1), a0
    adc     64*1(t0, t1), a1
    adc     64*2(t0, t1), a2
    adc     64*3(t0, t1), a3
     
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret

################################################################################
# void p256_mul_by_2(uint64_t res[4], uint64_t a[4]);
.align 64
.globl p256_mul_by_2
p256_mul_by_2:

.set res, %rdi
.set a_ptr, %rsi

.set a0, %r8
.set a1, %r9
.set a2, %r10
.set a3, %r11

.set t0, %rax
.set t1, %rdx

    xor     t0, t0

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3

    shld    $1, a3, t0
    shld    $1, a2, a3
    shld    $1, a1, a2
    shld    $1, a0, a1
    shl     $1, a0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    add     64*0(t0, t1), a0
    adc     64*1(t0, t1), a1
    adc     64*2(t0, t1), a2
    adc     64*3(t0, t1), a3
     
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret
################################################################################
# void p256_mul_by_4(uint64_t res[4], uint64_t a[4]);
.align 64
.globl p256_mul_by_4
p256_mul_by_4:
    xor     t0, t0

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3

    shld    $2, a3, t0
    shld    $2, a2, a3
    shld    $2, a1, a2
    shld    $2, a0, a1
    shl     $2, a0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    add     64*0(t0, t1), a0
    adc     64*1(t0, t1), a1
    adc     64*2(t0, t1), a2
    adc     64*3(t0, t1), a3
     
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret
################################################################################
# void p256_mul_by_8(uint64_t res[4], uint64_t a[4]);
.align 64
.globl p256_mul_by_8
p256_mul_by_8:

    xor     t0, t0

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3

    shld    $3, a3, t0
    shld    $3, a2, a3
    shld    $3, a1, a2
    shld    $3, a0, a1
    shl     $3, a0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    add     64*0(t0, t1), a0
    adc     64*1(t0, t1), a1
    adc     64*2(t0, t1), a2
    adc     64*3(t0, t1), a3
     
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret
################################################################################
# void p256_mul_by_3(uint64_t res[4], uint64_t a[4]);
.align 64
.globl p256_mul_by_3
p256_mul_by_3:
    xor     t0, t0

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3

    shld    $1, a3, t0
    shld    $1, a2, a3
    shld    $1, a1, a2
    shld    $1, a0, a1
    shl     $1, a0
    
    add     8*0(a_ptr), a0
    adc     8*1(a_ptr), a1
    adc     8*2(a_ptr), a2
    adc     8*3(a_ptr), a3
    adc     $0, t0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    add     64*0(t0, t1), a0
    adc     64*1(t0, t1), a1
    adc     64*2(t0, t1), a2
    adc     64*3(t0, t1), a3
         
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret
################################################################################
# void p256_add(uint64_t res[4], uint64_t a[4], uint64_t b[4]);
.align 64
.globl p256_add
p256_add:

.set res, %rdi
.set a_ptr, %rsi
.set b_ptr, %rdx

.set a0, %r8
.set a1, %r9
.set a2, %r10
.set a3, %r11

.set t0, %rax
.set t1, %rcx

    xor     t0, t0

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3
    
    add     8*0(b_ptr), a0
    adc     8*1(b_ptr), a1
    adc     8*2(b_ptr), a2
    adc     8*3(b_ptr), a3
    adc     $0, t0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    add     64*0(t0, t1), a0
    adc     64*1(t0, t1), a1
    adc     64*2(t0, t1), a2
    adc     64*3(t0, t1), a3
     
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret
################################################################################
# void p256_sub(uint64_t res[4], uint64_t a[4], uint64_t b[4]);
.align 64
.globl p256_sub
p256_sub:

    xor     t0, t0

    mov     8*0(a_ptr), a0
    mov     8*1(a_ptr), a1
    mov     8*2(a_ptr), a2
    mov     8*3(a_ptr), a3
    
    sub     8*0(b_ptr), a0
    sbb     8*1(b_ptr), a1
    sbb     8*2(b_ptr), a2
    sbb     8*3(b_ptr), a3
    adc     $0, t0
    
    shl     $3, t0
    lea     .LPolyTable(%rip), t1
    
    sub     64*0(t0, t1), a0
    sbb     64*1(t0, t1), a1
    sbb     64*2(t0, t1), a2
    sbb     64*3(t0, t1), a3
     
    mov     a0, 8*0(res)
    mov     a1, 8*1(res)
    mov     a2, 8*2(res)
    mov     a3, 8*3(res)

    ret

################################################################################
# void p256_mul_montl(
#   uint64_t res[4],
#   uint64_t a[4],
#   uint64_t b[4]);

.align 64
.globl p256_mul_montl
p256_mul_montl:

.set res, %rdi
.set a_ptr, %rsi
.set b_in, %rdx

.set acc0, %r8
.set acc1, %r9
.set acc2, %r10
.set acc3, %r11
.set acc4, %r12
.set acc5, %r13
.set acc6, %r14
.set acc7, %r15

.set t0, %rcx
.set t1, %rbp
.set b_ptr, %rbx

.set t2, %rbx
.set t3, %rdx
.set t4, %rax

    push    %rbp
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    
    mov b_in, b_ptr
    
    xor acc5, acc5
    ############################################################################
    # Multiply a by b[0]
    mov 8*0(b_ptr), %rax    
    mulq    8*0(a_ptr)
    mov %rax, acc0
    mov %rdx, acc1
    
    mov 8*0(b_ptr), %rax    
    mulq    8*1(a_ptr)
    add %rax, acc1
    adc $0, %rdx
    mov %rdx, acc2
    
    mov 8*0(b_ptr), %rax    
    mulq    8*2(a_ptr)
    add %rax, acc2
    adc $0, %rdx
    mov %rdx, acc3
    
    mov 8*0(b_ptr), %rax    
    mulq    8*3(a_ptr)
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, acc4
    ############################################################################
    # First reduction step
    # Basically now we want to multiply acc[0] by p256, and add the result to the acc
    # Due to the special form of p256 we do some optimizations
    mov acc0, t1
    
    # acc[0] x p256[0] = acc[0] x 2^64 - acc[0]
    xor %rax, %rax
    mov acc0, t0
    sub acc0, %rax
    sbb $0, t0
    add %rax, acc0
    adc $0, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc1
    adc $0, %rdx
    xor t0, t0
    add %rax, acc1
    
    # acc[0] x p256[2] = 0
    adc %rdx, acc2
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc %rdx, acc4
    adc $0, acc5
    ############################################################################
    # Multiply by b[1]
    mov 8*1(b_ptr), %rax
    mulq    8*0(a_ptr)
    add %rax, acc1
    adc $0, %rdx
    mov %rdx, t0    
    
    mov 8*1(b_ptr), %rax
    mulq    8*1(a_ptr)
    add t0, acc2
    adc $0, %rdx
    add %rax, acc2
    adc $0, %rdx
    mov %rdx, t0
    
    mov 8*1(b_ptr), %rax
    mulq    8*2(a_ptr)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, t0
    
    mov 8*1(b_ptr), %rax
    mulq    8*3(a_ptr)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc %rdx, acc5
    adc $0, acc0
    ############################################################################
    # Second reduction step   
    mov acc1, t1    
    xor %rax, %rax
    mov acc1, t0
    sub acc1, %rax
    sbb $0, t0
    add %rax, acc1
    adc $0, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc2
    adc $0, %rdx
    xor t0, t0
    add %rax, acc2
    adc %rdx, acc3 
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc %rdx, acc5
    adc $0, acc0
    ############################################################################
    # Multiply by b[2]
    mov 8*2(b_ptr), %rax
    mulq    8*0(a_ptr)
    add %rax, acc2
    adc $0, %rdx
    mov %rdx, t0    
    
    mov 8*2(b_ptr), %rax
    mulq    8*1(a_ptr)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, t0
    
    mov 8*2(b_ptr), %rax
    mulq    8*2(a_ptr)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc $0, %rdx
    mov %rdx, t0
    
    mov 8*2(b_ptr), %rax
    mulq    8*3(a_ptr)
    add t0, acc5
    adc $0, %rdx
    add %rax, acc5
    adc %rdx, acc0
    adc $0, acc1
    ############################################################################
    # Third reduction step   
    mov acc2, t1    
    xor %rax, %rax
    mov acc2, t0
    sub acc2, %rax
    sbb $0, t0
    add %rax, acc2
    adc $0, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    xor t0, t0
    add %rax, acc3
    adc %rdx, acc4
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc5
    adc $0, %rdx
    add %rax, acc5
    adc %rdx, acc0
    adc $0, acc1
    ############################################################################
    # Multiply by b[3]
    mov 8*3(b_ptr), %rax
    mulq    8*0(a_ptr)
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, t0    
    
    mov 8*3(b_ptr), %rax
    mulq    8*1(a_ptr)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc $0, %rdx
    mov %rdx, t0
    
    mov 8*3(b_ptr), %rax
    mulq    8*2(a_ptr)
    add t0, acc5
    adc $0, %rdx
    add %rax, acc5
    adc $0, %rdx
    mov %rdx, t0
    
    mov 8*3(b_ptr), %rax
    mulq    8*3(a_ptr)
    add t0, acc0
    adc $0, %rdx
    add %rax, acc0
    adc %rdx, acc1
    adc $0, acc2
    ############################################################################
    # Final reduction step   
    mov acc3, t1  
  
    xor %rax, %rax
    mov acc3, t0
    sub acc3, %rax
    sbb $0, t0
    add %rax, acc3
    adc $0, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    xor t0, t0
    add %rax, acc4
    adc %rdx, acc5
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc0
    adc $0, %rdx
    add %rax, acc0
    adc %rdx, acc1
    adc $0, acc2
    ############################################################################    
    mov 0*8+.Lpoly(%rip), t0
    mov 1*8+.Lpoly(%rip), t1
    mov 2*8+.Lpoly(%rip), t2
    mov 3*8+.Lpoly(%rip), t3

    mov acc4, t4
    mov acc5, acc3
    mov acc0, acc6
    mov acc1, acc7
    
    sub t0, t4
    sbb t1, acc3
    sbb t2, acc6
    sbb t3, acc7
    sbb $0, acc2
    
    cmovnc t4, acc4
    cmovnc acc3, acc5
    cmovnc acc6, acc0
    cmovnc acc7, acc1
    
    mov acc4, 8*0(res)
    mov acc5, 8*1(res)
    mov acc0, 8*2(res)
    mov acc1, 8*3(res)
bail:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp

    ret
################################################################################
# void p256_sqr_montl(
#   uint64_t res[4],
#   uint64_t a[4]);

# we optimize the square according to S.Gueron and V.Krasnov, "Speeding up Big-Number Squaring"
.align 64
.globl p256_sqr_montl
p256_sqr_montl:

    push    %rbp
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    
    mov     8*0(a_ptr), t2
    
    mov     8*1(a_ptr), %rax
    mulq    t2
    mov     %rax, acc1
    mov     %rdx, acc2
    mov     8*2(a_ptr), %rax
    mulq    t2
    add     %rax, acc2
    adc     $0, %rdx
    mov     %rdx, acc3
    mov     8*3(a_ptr), %rax
    mulq    t2
    add     %rax, acc3
    adc     $0, %rdx
    mov     %rdx, acc4
    #################################
    mov     8*1(a_ptr), t2
    
    mov     8*2(a_ptr), %rax
    mulq    t2
    add     %rax, acc3
    adc     $0, %rdx
    mov     %rdx, t1
    mov     8*3(a_ptr), %rax
    mulq    t2
    add     %rax, acc4
    adc     $0, %rdx
    add     t1, acc4
    adc     $0, %rdx
    mov     %rdx, acc5
    #################################
    mov     8*2(a_ptr), t2
    
    mov     8*3(a_ptr), %rax
    mulq    t2
    add     %rax, acc5
    adc     $0, %rdx
    mov     %rdx, acc6
    xor     acc7, acc7
    
    shld    $1, acc6, acc7
    shld    $1, acc5, acc6
    shld    $1, acc4, acc5
    shld    $1, acc3, acc4
    shld    $1, acc2, acc3
    shld    $1, acc1, acc2
    shl     $1, acc1
      
    mov     8*0(a_ptr), %rax
    mulq    %rax
    mov     %rax, acc0
    mov     %rdx, t0

    mov     8*1(a_ptr), %rax
    mulq    %rax
    add     t0, acc1
    adc     %rax, acc2
    adc	    $0, %rdx
    mov     %rdx, t0

    mov     8*2(a_ptr), %rax
    mulq    %rax
    add     t0, acc3
    adc     %rax, acc4
    adc     $0, %rdx
    mov     %rdx, t0

    mov     8*3(a_ptr), %rax
    mulq    %rax
    add     t0, acc5
    adc     %rax, acc6
    adc     %rdx, acc7
    
    #########################################
    # Now the reduction
    # First iteration
    mov acc0, t1

    xor %rax, %rax
    mov acc0, t0
    sub acc0, %rax
    sbb $0, t0
    add %rax, acc0
    adc $0, t0
    mov t1, %rax
    
    mulq 1*8+.Lpoly(%rip)
    add t0, acc1
    adc $0, %rdx
    xor t0, t0
    add %rax, acc1
    adc %rdx, acc2
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc %rdx, acc4
    adc $0, acc0
    #########################################
    # Second iteration
    mov acc1, t1    
    xor %rax, %rax
    mov acc1, t0
    sub acc1, %rax
    sbb $0, t0
    add %rax, acc1
    adc $0, t0

    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc2
    adc $0, %rdx
    xor t0, t0
    add %rax, acc2
    adc %rdx, acc3 
    adc $0, t0
        
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc %rdx, acc0
    adc $0, acc1
    ##########################################
    # Third iteration
    mov acc2, t1    
    xor %rax, %rax
    mov acc2, t0
    sub acc2, %rax
    sbb $0, t0
    add %rax, acc2
    adc $0, t0    

    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    xor t0, t0
    add %rax, acc3
    adc %rdx, acc4 
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc0
    adc $0, %rdx
    add %rax, acc0
    adc %rdx, acc1
    adc $0, acc2
    ########################################### 
    # Last iteration
    mov acc3, t1    
    xor %rax, %rax
    mov acc3, t0
    sub acc3, %rax
    sbb $0, t0
    add %rax, acc3
    adc $0, t0    

    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    xor t0, t0
    add %rax, acc4
    adc %rdx, acc0 
    adc $0, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc1
    adc $0, %rdx
    add %rax, acc1
    adc %rdx, acc2
    adc $0, acc3
    ############################################
    # Add the rest of the acc
    add acc5, acc0
    adc acc6, acc1
    adc acc7, acc2
    adc $0, acc3
    
    mov 0*8+.Lpoly(%rip), t0
    mov 1*8+.Lpoly(%rip), t1
    mov 2*8+.Lpoly(%rip), t2
    mov 3*8+.Lpoly(%rip), t3
    
    mov acc4, t4
    mov acc0, acc5
    mov acc1, acc6
    mov acc2, acc7
    
    sub t0, t4
    sbb t1, acc5
    sbb t2, acc6
    sbb t3, acc7
    sbb $0, acc3
    
    cmovnc t4, acc4
    cmovnc acc5, acc0
    cmovnc acc6, acc1
    cmovnc acc7, acc2
    
    
    mov acc4, 8*0(res)
    mov acc0, 8*1(res)
    mov acc1, 8*2(res)
    mov acc2, 8*3(res)
    
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp

    ret

################################################################################
# void p256_mont_back(
#   uint64_t res[4],
#   uint64_t in[4]);
# This one performs Montgomery multiplication by 1, so we only need the reduction
.set res, %rdi
.set in_ptr, %rsi

.set acc0, %r8
.set acc1, %r9
.set acc2, %r10
.set acc3, %r11
.set acc4, %r12

.set t0, %rcx
.set t1, %rsi

.align 64
.globl p256_mont_back
p256_mont_back:

    push    %r12
    mov 8*0(in_ptr), acc0
    mov 8*1(in_ptr), acc1
    mov 8*2(in_ptr), acc2
    mov 8*3(in_ptr), acc3
    
    mov acc0, t1
    mov acc0, %rax
    mulq 0*8+.Lpoly(%rip)
    add %rax, acc0
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc1
    adc $0, %rdx
    add %rax, acc1
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 2*8+.Lpoly(%rip)
    add t0, acc2
    adc $0, %rdx
    add %rax, acc2
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, acc4
    
    mov acc1, t1    
    mov acc1, %rax
    mulq 0*8+.Lpoly(%rip)
    add %rax, acc1
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc2
    adc $0, %rdx
    add %rax, acc2
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 2*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc %rdx, acc0
    adc $0, acc1

    mov acc2, t1    
    mov acc2, %rax
    mulq 0*8+.Lpoly(%rip)
    add %rax, acc2
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc3
    adc $0, %rdx
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 2*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc0
    adc $0, %rdx
    add %rax, acc0
    adc %rdx, acc1
    adc $0, acc2
     
    mov acc3, t1    
    mov acc3, %rax
    mulq 0*8+.Lpoly(%rip)
    add %rax, acc3
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 1*8+.Lpoly(%rip)
    add t0, acc4
    adc $0, %rdx
    add %rax, acc4
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 2*8+.Lpoly(%rip)
    add t0, acc0
    adc $0, %rdx
    add %rax, acc0
    adc $0, %rdx
    mov %rdx, t0
    
    mov t1, %rax
    mulq 3*8+.Lpoly(%rip)
    add t0, acc1
    adc $0, %rdx
    add %rax, acc1
    adc %rdx, acc2
    sbb $0, acc3
    
    mov 0*8+.Lpoly(%rip), t0
    mov 1*8+.Lpoly(%rip), t1
    mov 2*8+.Lpoly(%rip), %rax
    mov 3*8+.Lpoly(%rip), %rdx
    
    and acc3, t0
    and acc3, t1
    and acc3, %rax
    and acc3, %rdx
    
    sub t0, acc4
    sbb t1, acc0
    sbb %rax, acc1
    sbb %rdx, acc2
    
    mov acc4, 8*0(res)
    mov acc0, 8*1(res)
    mov acc1, 8*2(res)
    mov acc2, 8*3(res)
    
    pop %r12
    ret

################################################################################
# void p256_to_mont(
#   uint64_t res[4],
#   uint64_t in[4]);
.align 64
.globl p256_to_mont
p256_to_mont:

    lea     .LRR(%rip), %rdx
    call    p256_mul_montl
    ret
################################################################################


################################################################################
# void p256_mul_montx(
#   uint64_t res[4],
#   uint64_t a[4],
#   uint64_t b[4]);
.align 64
.globl p256_mul_montx
p256_mul_montx:
.set res, %rdi
.set a_ptr, %rsi
.set b_in, %rdx

.set acc0, %r8
.set acc1, %r9
.set acc2, %r10
.set acc3, %r11
.set acc4, %r12
.set acc5, %r13
.set acc6, %r14
.set acc7, %r15

.set t0, %rcx
.set t1, %rbp
.set b_ptr, %rbx

.set t2, %rbx
.set t3, %rdx
.set t4, %rax

    push    %rbp
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    
    mov b_in, b_ptr
    
    ############################################################################
    # Multiply by b[0]
    xor     %rdx, %rdx
    mov     8*0(b_ptr), %rdx    
    
    mulx    8*0(a_ptr), acc0, acc1     
    mulx    8*1(a_ptr), t0, acc2
    add     t0, acc1     
    mulx    8*2(a_ptr), t0, acc3
    adc     t0, acc2    
    mulx    8*3(a_ptr), t0, acc4
    adc     t0, acc3
    adc     $0, acc4    
    ############################################################################
    # First reduction step
    xor     acc5, acc5
    mov     acc0, %rdx
    
    mulx    0*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc0
    adox    t1, acc1
    
    mulx    1*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc1
    adox    t1, acc2
    
    mulx    2*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc2
    adox    t1, acc3
    
    mulx    3*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    adcx    acc5, acc4
    adox    acc5, acc5
    adc     $0, acc5
    ############################################################################
    # Multiply by b[1]
    xor     acc0, acc0
    mov     8*1(b_ptr), %rdx
    
    mulx    8*0(a_ptr), t0, t1
    adcx    t0, acc1
    adox    t1, acc2
    
    mulx    8*1(a_ptr), t0, t1
    adcx    t0, acc2
    adox    t1, acc3
    
    mulx    8*2(a_ptr), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    8*3(a_ptr), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    
    adcx    acc0, acc5
    adox    acc0, acc0
    adc     $0, acc0
    ############################################################################
    # Second reduction step
    mov     acc1, %rdx
    xor     t0, t0
    
    mulx    0*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc1
    adox    t1, acc2
    
    mulx    1*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc2
    adox    t1, acc3
    
    mulx    2*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    3*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    
    adcx    acc1, acc5
    adox    acc1, acc0
    
    adcx    acc1, acc0
    ############################################################################
    # Multiply by b[2]
    mov     8*2(b_ptr), %rdx
    
    mulx    8*0(a_ptr), t0, t1
    adcx    t0, acc2
    adox    t1, acc3
    
    mulx    8*1(a_ptr), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    8*2(a_ptr), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    
    mulx    8*3(a_ptr), t0, t1
    adcx    t0, acc5
    adox    t1, acc0
    
    adcx    acc1, acc0
    adox    acc1, acc1
    
    adc     $0, acc1
    ############################################################################
    # Third reduction step
    mov     acc2, %rdx
    xor     t0, t0
    
    mulx    0*8+.Lpoly(%rip), t0, t1
    adox    t0, acc2
    adox    t1, acc3
    
    mulx    1*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    2*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    
    mulx    3*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc5
    adox    t1, acc0
    
    adcx    acc2, acc0
    adox    acc2, acc1
    
    adcx    acc2, acc1
    ############################################################################
    # Multiply by b[3]
    mov     8*3(b_ptr), %rdx
    
    mulx    8*0(a_ptr), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    8*1(a_ptr), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    
    mulx    8*2(a_ptr), t0, t1
    adcx    t0, acc5
    adox    t1, acc0
    
    mulx    8*3(a_ptr), t0, t1
    adcx    t0, acc0
    adox    t1, acc1
    
    adcx    acc2, acc1
    adox    acc2, acc2
    adc     $0, acc2
    ############################################################################
    # Third reduction step
    mov     acc3, %rdx
    xor     t0, t0
    
    mulx    0*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    1*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    
    mulx    2*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc5
    adox    t1, acc0
    
    mulx    3*8+.Lpoly(%rip), t0, t1
    adcx    t0, acc0
    adox    t1, acc1
    
    adcx    acc3, acc1
    adox    acc3, acc2
    adcx    acc3, acc2
    ############################################################################
    # Conditionless subtraction of P if required    
    mov 0*8+.Lpoly(%rip), t0
    mov 1*8+.Lpoly(%rip), t1
    mov 2*8+.Lpoly(%rip), t2
    mov 3*8+.Lpoly(%rip), t3

    mov acc4, t4
    mov acc5, acc3
    mov acc0, acc6
    mov acc1, acc7
    
    sub t0, t4
    sbb t1, acc3
    sbb t2, acc6
    sbb t3, acc7
    sbb $0, acc2
    
    cmovnc t4, acc4
    cmovnc acc3, acc5
    cmovnc acc6, acc0
    cmovnc acc7, acc1
    
    mov acc4, 8*0(res)
    mov acc5, 8*1(res)
    mov acc0, 8*2(res)
    mov acc1, 8*3(res)
    
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp

    ret
################################################################################
# void p256_sqr_montx(
#   uint64_t res[4],
#   uint64_t a[4]);
.align 64
.globl p256_sqr_montx
p256_sqr_montx:

    push    %rbp
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    
	mov     8*0(a_ptr), %rdx
    
    mulx    8*1(a_ptr), acc1, acc2

    mulx    8*2(a_ptr), t0, acc3
    add     t0, acc2
    
    mulx    8*3(a_ptr), t0, acc4
    adc     t0, acc3
    adc     $0, acc4
    #################################
    mov     8*1(a_ptr), %rdx
    xor     acc5, acc5
    
    mulx    8*2(a_ptr), t0, t1
    adcx    t0, acc3
    adox    t1, acc4
    
    mulx    8*3(a_ptr), t0, t1
    adcx    t0, acc4
    adox    t1, acc5
    adc     $0, acc5
    #################################
    mov     8*2(a_ptr), %rdx
    
    mulx    8*3(a_ptr), t0, acc6
    add     t0, acc5
    adc     $0, acc6
    xor     acc7, acc7
    
    shld    $1, acc6, acc7
    shld    $1, acc5, acc6
    shld    $1, acc4, acc5
    shld    $1, acc3, acc4
    shld    $1, acc2, acc3
    shld    $1, acc1, acc2
    shl     $1, acc1
    
    xor     acc0, acc0
	mov     8*0(a_ptr), %rdx
    mulx    %rdx, acc0, t1
    adcx    t1, acc1
	mov     8*1(a_ptr), %rdx
    mulx    %rdx, t0, t1
    adcx    t0, acc2
    adcx    t1, acc3
	mov     8*2(a_ptr), %rdx
    mulx    %rdx, t0, t1
    adcx    t0, acc4
    adcx    t1, acc5
	mov     8*3(a_ptr), %rdx
    mulx    %rdx, t0, t1
    adcx    t0, acc6
    adcx    t1, acc7
    
    # reduction step 1
    mov acc0, %rdx
    xor t0, t0
        
    mulx 0*8+.Lpoly(%rip), t0, t1
    adcx t0, acc0
    adox t1, acc1
    
    mulx 1*8+.Lpoly(%rip), t0, t1
    adcx t0, acc1
    adox t1, acc2
    
    mulx 2*8+.Lpoly(%rip), t0, t1
    adcx t0, acc2
    adox t1, acc3
    
    mulx 3*8+.Lpoly(%rip), t0, t1
    adcx t0, acc3
    adox t1, acc0
    
    adc  $0, acc0
    
    # reduction step 2
    mov acc1, %rdx
    xor t0, t0
    
    mulx 0*8+.Lpoly(%rip), t0, t1
    adcx t0, acc1
    adox t1, acc2
    
    mulx 1*8+.Lpoly(%rip), t0, t1
    adcx t0, acc2
    adox t1, acc3
    
    mulx 2*8+.Lpoly(%rip), t0, t1
    adcx t0, acc3
    adox t1, acc0
    
    mulx 3*8+.Lpoly(%rip), t0, t1
    adcx t0, acc0
    adox t1, acc1
    
    adc  $0, acc1
    
    # reduction step 3
    mov acc2, %rdx
    xor t0, t0
    
    mulx 0*8+.Lpoly(%rip), t0, t1
    adcx t0, acc2
    adox t1, acc3
    
    mulx 1*8+.Lpoly(%rip), t0, t1
    adcx t0, acc3
    adox t1, acc0
    
    mulx 2*8+.Lpoly(%rip), t0, t1
    adcx t0, acc0
    adox t1, acc1
    
    mulx 3*8+.Lpoly(%rip), t0, t1
    adcx t0, acc1
    adox t1, acc2
    
    adc  $0, acc2
    
    # reduction step 4
    mov acc3, %rdx
    xor t0, t0
    
    mulx 0*8+.Lpoly(%rip), t0, t1
    adcx t0, acc3
    adox t1, acc0
    
    mulx 1*8+.Lpoly(%rip), t0, t1
    adcx t0, acc0
    adox t1, acc1
    
    mulx 2*8+.Lpoly(%rip), t0, t1
    adcx t0, acc1
    adox t1, acc2
    
    mulx 3*8+.Lpoly(%rip), t0, t1
    adcx t0, acc2
    adox t1, acc3
    
    adc  $0, acc3
    
    xor t4, t4
    
    add acc4, acc0
    adc acc5, acc1
    adc acc6, acc2
    adc acc7, acc3
    adc $0, t4
    
    mov 0*8+.Lpoly(%rip), t0
    mov 1*8+.Lpoly(%rip), t1
    mov 2*8+.Lpoly(%rip), t2
    mov 3*8+.Lpoly(%rip), t3
    
    
    mov acc0, acc4
    mov acc1, acc5
    mov acc2, acc6
    mov acc3, acc7
    
    sub t0, acc4
    sbb t1, acc5
    sbb t2, acc6
    sbb t3, acc7
    sbb $0, t4
    
    cmovnc acc4, acc0
    cmovnc acc5, acc1
    cmovnc acc6, acc2
    cmovnc acc7, acc3
    
    mov acc0, 8*0(res)
    mov acc1, 8*1(res)
    mov acc2, 8*2(res)
    mov acc3, 8*3(res)
    
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp

    ret
