#ifndef EGALITO_ELF_RISCV_ELF_H
#define EGALITO_ELF_RISCV_ELF_H

/* Mainline glibc doesn't have the RISC-V relocation information yet, so if
    it's not present, define it. */

#if defined(ARCH_RISCV) && !defined(R_RISCV_NONE)

/* RISC-V relocations.  */
#define R_RISCV_NONE          0
#define R_RISCV_32            1
#define R_RISCV_64            2
#define R_RISCV_RELATIVE      3
#define R_RISCV_COPY          4
#define R_RISCV_JUMP_SLOT     5
#define R_RISCV_TLS_DTPMOD32  6
#define R_RISCV_TLS_DTPMOD64  7
#define R_RISCV_TLS_DTPREL32  8
#define R_RISCV_TLS_DTPREL64  9
#define R_RISCV_TLS_TPREL32  10
#define R_RISCV_TLS_TPREL64  11

#endif

#endif
