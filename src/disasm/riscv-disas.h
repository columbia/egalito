/*
 * RISC-V Disassembler
 *
 * Copyright (c) 2016-2017 Michael Clark <michaeljclark@mac.com>
 * Copyright (c) 2017-2018 SiFive, Inc.
 * Copyright (c) 2018 Kent Williams-King <ethereal@ethv.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef RISCV_DISASSEMBLER_H
#define RISCV_DISASSEMBLER_H

#ifdef ARCH_RISCV

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>

/* types */

typedef uint64_t rv_inst;
typedef uint16_t rv_opcode;

/* enums */

typedef enum {
    rv32,
    rv64,
    rv128
} rv_isa;

typedef enum {
    rv_rm_rne = 0,
    rv_rm_rtz = 1,
    rv_rm_rdn = 2,
    rv_rm_rup = 3,
    rv_rm_rmm = 4,
    rv_rm_dyn = 7,
} rv_rm;

typedef enum {
    rv_fence_i = 8,
    rv_fence_o = 4,
    rv_fence_r = 2,
    rv_fence_w = 1,
} rv_fence;

typedef enum {
    rv_ireg_zero,
    rv_ireg_ra,
    rv_ireg_sp,
    rv_ireg_gp,
    rv_ireg_tp,
    rv_ireg_t0,
    rv_ireg_t1,
    rv_ireg_t2,
    rv_ireg_s0,
    rv_ireg_s1,
    rv_ireg_a0,
    rv_ireg_a1,
    rv_ireg_a2,
    rv_ireg_a3,
    rv_ireg_a4,
    rv_ireg_a5,
    rv_ireg_a6,
    rv_ireg_a7,
    rv_ireg_s2,
    rv_ireg_s3,
    rv_ireg_s4,
    rv_ireg_s5,
    rv_ireg_s6,
    rv_ireg_s7,
    rv_ireg_s8,
    rv_ireg_s9,
    rv_ireg_s10,
    rv_ireg_s11,
    rv_ireg_t3,
    rv_ireg_t4,
    rv_ireg_t5,
    rv_ireg_t6,

    rv_freg_base = 128,
    rv_freg_ft0 = 128,
    rv_freg_ft1,
    rv_freg_ft2,
    rv_freg_ft3,
    rv_freg_ft4,
    rv_freg_ft5,
    rv_freg_ft6,
    rv_freg_ft7,
    rv_freg_fs0,
    rv_freg_fs1,
    rv_freg_fa0,
    rv_freg_fa1,
    rv_freg_fa2,
    rv_freg_fa3,
    rv_freg_fa4,
    rv_freg_fa5,
    rv_freg_fa6,
    rv_freg_fa7,
    rv_freg_fs2,
    rv_freg_fs3,
    rv_freg_fs4,
    rv_freg_fs5,
    rv_freg_fs6,
    rv_freg_fs7,
    rv_freg_fs8,
    rv_freg_fs9,
    rv_freg_fs10,
    rv_freg_fs11,
    rv_freg_ft8,
    rv_freg_ft9,
    rv_freg_ft10,
    rv_freg_ft11
} rv_reg;

typedef enum {
    rvc_end,
    rvc_rd_eq_ra,
    rvc_rd_eq_x0,
    rvc_rs1_eq_x0,
    rvc_rs2_eq_x0,
    rvc_rs2_eq_rs1,
    rvc_rs1_eq_ra,
    rvc_imm_eq_zero,
    rvc_imm_eq_n1,
    rvc_imm_eq_p1,
    rvc_csr_eq_0x001,
    rvc_csr_eq_0x002,
    rvc_csr_eq_0x003,
    rvc_csr_eq_0xc00,
    rvc_csr_eq_0xc01,
    rvc_csr_eq_0xc02,
    rvc_csr_eq_0xc80,
    rvc_csr_eq_0xc81,
    rvc_csr_eq_0xc82,
} rvc_constraint;

typedef enum {
    rv_codec_illegal,
    rv_codec_none,
    rv_codec_u,
    rv_codec_uj,
    rv_codec_i,
    rv_codec_i_sh5,
    rv_codec_i_sh6,
    rv_codec_i_sh7,
    rv_codec_i_csr,
    rv_codec_s,
    rv_codec_sb,
    rv_codec_r,
    rv_codec_r_m,
    rv_codec_r4_m,
    rv_codec_r_a,
    rv_codec_r_l,
    rv_codec_r_f,
    rv_codec_cb,
    rv_codec_cb_imm,
    rv_codec_cb_sh5,
    rv_codec_cb_sh6,
    rv_codec_ci,
    rv_codec_ci_sh5,
    rv_codec_ci_sh6,
    rv_codec_ci_16sp,
    rv_codec_ci_lwsp,
    rv_codec_ci_ldsp,
    rv_codec_ci_lqsp,
    rv_codec_ci_li,
    rv_codec_ci_lui,
    rv_codec_ci_none,
    rv_codec_ciw_4spn,
    rv_codec_cj,
    rv_codec_cj_jal,
    rv_codec_cl_lw,
    rv_codec_cl_ld,
    rv_codec_cl_lq,
    rv_codec_cr,
    rv_codec_cr_mv,
    rv_codec_cr_jalr,
    rv_codec_cr_jr,
    rv_codec_cs,
    rv_codec_cs_sw,
    rv_codec_cs_sd,
    rv_codec_cs_sq,
    rv_codec_css_swsp,
    rv_codec_css_sdsp,
    rv_codec_css_sqsp,
} rv_codec;

typedef enum {
    rv_op_illegal = 0,
    rv_op_lui = 1,
    rv_op_auipc = 2,
    rv_op_jal = 3,
    rv_op_jalr = 4,
    rv_op_beq = 5,
    rv_op_bne = 6,
    rv_op_blt = 7,
    rv_op_bge = 8,
    rv_op_bltu = 9,
    rv_op_bgeu = 10,
    rv_op_lb = 11,
    rv_op_lh = 12,
    rv_op_lw = 13,
    rv_op_lbu = 14,
    rv_op_lhu = 15,
    rv_op_sb = 16,
    rv_op_sh = 17,
    rv_op_sw = 18,
    rv_op_addi = 19,
    rv_op_slti = 20,
    rv_op_sltiu = 21,
    rv_op_xori = 22,
    rv_op_ori = 23,
    rv_op_andi = 24,
    rv_op_slli = 25,
    rv_op_srli = 26,
    rv_op_srai = 27,
    rv_op_add = 28,
    rv_op_sub = 29,
    rv_op_sll = 30,
    rv_op_slt = 31,
    rv_op_sltu = 32,
    rv_op_xor = 33,
    rv_op_srl = 34,
    rv_op_sra = 35,
    rv_op_or = 36,
    rv_op_and = 37,
    rv_op_fence = 38,
    rv_op_fence_i = 39,
    rv_op_lwu = 40,
    rv_op_ld = 41,
    rv_op_sd = 42,
    rv_op_addiw = 43,
    rv_op_slliw = 44,
    rv_op_srliw = 45,
    rv_op_sraiw = 46,
    rv_op_addw = 47,
    rv_op_subw = 48,
    rv_op_sllw = 49,
    rv_op_srlw = 50,
    rv_op_sraw = 51,
    rv_op_ldu = 52,
    rv_op_lq = 53,
    rv_op_sq = 54,
    rv_op_addid = 55,
    rv_op_sllid = 56,
    rv_op_srlid = 57,
    rv_op_sraid = 58,
    rv_op_addd = 59,
    rv_op_subd = 60,
    rv_op_slld = 61,
    rv_op_srld = 62,
    rv_op_srad = 63,
    rv_op_mul = 64,
    rv_op_mulh = 65,
    rv_op_mulhsu = 66,
    rv_op_mulhu = 67,
    rv_op_div = 68,
    rv_op_divu = 69,
    rv_op_rem = 70,
    rv_op_remu = 71,
    rv_op_mulw = 72,
    rv_op_divw = 73,
    rv_op_divuw = 74,
    rv_op_remw = 75,
    rv_op_remuw = 76,
    rv_op_muld = 77,
    rv_op_divd = 78,
    rv_op_divud = 79,
    rv_op_remd = 80,
    rv_op_remud = 81,
    rv_op_lr_w = 82,
    rv_op_sc_w = 83,
    rv_op_amoswap_w = 84,
    rv_op_amoadd_w = 85,
    rv_op_amoxor_w = 86,
    rv_op_amoor_w = 87,
    rv_op_amoand_w = 88,
    rv_op_amomin_w = 89,
    rv_op_amomax_w = 90,
    rv_op_amominu_w = 91,
    rv_op_amomaxu_w = 92,
    rv_op_lr_d = 93,
    rv_op_sc_d = 94,
    rv_op_amoswap_d = 95,
    rv_op_amoadd_d = 96,
    rv_op_amoxor_d = 97,
    rv_op_amoor_d = 98,
    rv_op_amoand_d = 99,
    rv_op_amomin_d = 100,
    rv_op_amomax_d = 101,
    rv_op_amominu_d = 102,
    rv_op_amomaxu_d = 103,
    rv_op_lr_q = 104,
    rv_op_sc_q = 105,
    rv_op_amoswap_q = 106,
    rv_op_amoadd_q = 107,
    rv_op_amoxor_q = 108,
    rv_op_amoor_q = 109,
    rv_op_amoand_q = 110,
    rv_op_amomin_q = 111,
    rv_op_amomax_q = 112,
    rv_op_amominu_q = 113,
    rv_op_amomaxu_q = 114,
    rv_op_ecall = 115,
    rv_op_ebreak = 116,
    rv_op_uret = 117,
    rv_op_sret = 118,
    rv_op_hret = 119,
    rv_op_mret = 120,
    rv_op_dret = 121,
    rv_op_sfence_vm = 122,
    rv_op_sfence_vma = 123,
    rv_op_wfi = 124,
    rv_op_csrrw = 125,
    rv_op_csrrs = 126,
    rv_op_csrrc = 127,
    rv_op_csrrwi = 128,
    rv_op_csrrsi = 129,
    rv_op_csrrci = 130,
    rv_op_flw = 131,
    rv_op_fsw = 132,
    rv_op_fmadd_s = 133,
    rv_op_fmsub_s = 134,
    rv_op_fnmsub_s = 135,
    rv_op_fnmadd_s = 136,
    rv_op_fadd_s = 137,
    rv_op_fsub_s = 138,
    rv_op_fmul_s = 139,
    rv_op_fdiv_s = 140,
    rv_op_fsgnj_s = 141,
    rv_op_fsgnjn_s = 142,
    rv_op_fsgnjx_s = 143,
    rv_op_fmin_s = 144,
    rv_op_fmax_s = 145,
    rv_op_fsqrt_s = 146,
    rv_op_fle_s = 147,
    rv_op_flt_s = 148,
    rv_op_feq_s = 149,
    rv_op_fcvt_w_s = 150,
    rv_op_fcvt_wu_s = 151,
    rv_op_fcvt_s_w = 152,
    rv_op_fcvt_s_wu = 153,
    rv_op_fmv_x_s = 154,
    rv_op_fclass_s = 155,
    rv_op_fmv_s_x = 156,
    rv_op_fcvt_l_s = 157,
    rv_op_fcvt_lu_s = 158,
    rv_op_fcvt_s_l = 159,
    rv_op_fcvt_s_lu = 160,
    rv_op_fld = 161,
    rv_op_fsd = 162,
    rv_op_fmadd_d = 163,
    rv_op_fmsub_d = 164,
    rv_op_fnmsub_d = 165,
    rv_op_fnmadd_d = 166,
    rv_op_fadd_d = 167,
    rv_op_fsub_d = 168,
    rv_op_fmul_d = 169,
    rv_op_fdiv_d = 170,
    rv_op_fsgnj_d = 171,
    rv_op_fsgnjn_d = 172,
    rv_op_fsgnjx_d = 173,
    rv_op_fmin_d = 174,
    rv_op_fmax_d = 175,
    rv_op_fcvt_s_d = 176,
    rv_op_fcvt_d_s = 177,
    rv_op_fsqrt_d = 178,
    rv_op_fle_d = 179,
    rv_op_flt_d = 180,
    rv_op_feq_d = 181,
    rv_op_fcvt_w_d = 182,
    rv_op_fcvt_wu_d = 183,
    rv_op_fcvt_d_w = 184,
    rv_op_fcvt_d_wu = 185,
    rv_op_fclass_d = 186,
    rv_op_fcvt_l_d = 187,
    rv_op_fcvt_lu_d = 188,
    rv_op_fmv_x_d = 189,
    rv_op_fcvt_d_l = 190,
    rv_op_fcvt_d_lu = 191,
    rv_op_fmv_d_x = 192,
    rv_op_flq = 193,
    rv_op_fsq = 194,
    rv_op_fmadd_q = 195,
    rv_op_fmsub_q = 196,
    rv_op_fnmsub_q = 197,
    rv_op_fnmadd_q = 198,
    rv_op_fadd_q = 199,
    rv_op_fsub_q = 200,
    rv_op_fmul_q = 201,
    rv_op_fdiv_q = 202,
    rv_op_fsgnj_q = 203,
    rv_op_fsgnjn_q = 204,
    rv_op_fsgnjx_q = 205,
    rv_op_fmin_q = 206,
    rv_op_fmax_q = 207,
    rv_op_fcvt_s_q = 208,
    rv_op_fcvt_q_s = 209,
    rv_op_fcvt_d_q = 210,
    rv_op_fcvt_q_d = 211,
    rv_op_fsqrt_q = 212,
    rv_op_fle_q = 213,
    rv_op_flt_q = 214,
    rv_op_feq_q = 215,
    rv_op_fcvt_w_q = 216,
    rv_op_fcvt_wu_q = 217,
    rv_op_fcvt_q_w = 218,
    rv_op_fcvt_q_wu = 219,
    rv_op_fclass_q = 220,
    rv_op_fcvt_l_q = 221,
    rv_op_fcvt_lu_q = 222,
    rv_op_fcvt_q_l = 223,
    rv_op_fcvt_q_lu = 224,
    rv_op_fmv_x_q = 225,
    rv_op_fmv_q_x = 226,
    rv_op_c_addi4spn = 227,
    rv_op_c_fld = 228,
    rv_op_c_lw = 229,
    rv_op_c_flw = 230,
    rv_op_c_fsd = 231,
    rv_op_c_sw = 232,
    rv_op_c_fsw = 233,
    rv_op_c_nop = 234,
    rv_op_c_addi = 235,
    rv_op_c_jal = 236,
    rv_op_c_li = 237,
    rv_op_c_addi16sp = 238,
    rv_op_c_lui = 239,
    rv_op_c_srli = 240,
    rv_op_c_srai = 241,
    rv_op_c_andi = 242,
    rv_op_c_sub = 243,
    rv_op_c_xor = 244,
    rv_op_c_or = 245,
    rv_op_c_and = 246,
    rv_op_c_subw = 247,
    rv_op_c_addw = 248,
    rv_op_c_j = 249,
    rv_op_c_beqz = 250,
    rv_op_c_bnez = 251,
    rv_op_c_slli = 252,
    rv_op_c_fldsp = 253,
    rv_op_c_lwsp = 254,
    rv_op_c_flwsp = 255,
    rv_op_c_jr = 256,
    rv_op_c_mv = 257,
    rv_op_c_ebreak = 258,
    rv_op_c_jalr = 259,
    rv_op_c_add = 260,
    rv_op_c_fsdsp = 261,
    rv_op_c_swsp = 262,
    rv_op_c_fswsp = 263,
    rv_op_c_ld = 264,
    rv_op_c_sd = 265,
    rv_op_c_addiw = 266,
    rv_op_c_ldsp = 267,
    rv_op_c_sdsp = 268,
    rv_op_c_lq = 269,
    rv_op_c_sq = 270,
    rv_op_c_lqsp = 271,
    rv_op_c_sqsp = 272,
    rv_op_nop = 273,
    rv_op_mv = 274,
    rv_op_not = 275,
    rv_op_neg = 276,
    rv_op_negw = 277,
    rv_op_sext_w = 278,
    rv_op_seqz = 279,
    rv_op_snez = 280,
    rv_op_sltz = 281,
    rv_op_sgtz = 282,
    rv_op_fmv_s = 283,
    rv_op_fabs_s = 284,
    rv_op_fneg_s = 285,
    rv_op_fmv_d = 286,
    rv_op_fabs_d = 287,
    rv_op_fneg_d = 288,
    rv_op_fmv_q = 289,
    rv_op_fabs_q = 290,
    rv_op_fneg_q = 291,
    rv_op_beqz = 292,
    rv_op_bnez = 293,
    rv_op_blez = 294,
    rv_op_bgez = 295,
    rv_op_bltz = 296,
    rv_op_bgtz = 297,
    rv_op_ble = 298,
    rv_op_bleu = 299,
    rv_op_bgt = 300,
    rv_op_bgtu = 301,
    rv_op_j = 302,
    rv_op_ret = 303,
    rv_op_jr = 304,
    rv_op_rdcycle = 305,
    rv_op_rdtime = 306,
    rv_op_rdinstret = 307,
    rv_op_rdcycleh = 308,
    rv_op_rdtimeh = 309,
    rv_op_rdinstreth = 310,
    rv_op_frcsr = 311,
    rv_op_frrm = 312,
    rv_op_frflags = 313,
    rv_op_fscsr = 314,
    rv_op_fsrm = 315,
    rv_op_fsflags = 316,
    rv_op_fsrmi = 317,
    rv_op_fsflagsi = 318,
} rv_op;

/* structures */

typedef struct {
    uint64_t  pc;
    uint64_t  inst;
    int32_t   imm;
    uint16_t  op;
    uint8_t   codec;
    uint8_t   rd;
    uint8_t   rs1;
    uint8_t   rs2;
    uint8_t   rs3;
    uint8_t   rm;
    uint8_t   pred;
    uint8_t   succ;
    uint8_t   aq;
    uint8_t   rl;
} rv_decode;

/* functions */

typedef struct {
    enum {
        rv_oper_reg,
        rv_oper_imm,
        rv_oper_mem
    } type;
    union {
        uint8_t reg;
        int32_t imm;
        struct {
            uint8_t basereg;
            int64_t disp;
        } mem;
    } value;
} rv_oper;

typedef struct {
    // IP of instruction
    uint64_t ip;
    // original encoding of instruction
    uint64_t inst;
    // length of instruction in bytes
    uint8_t len;
    // codec
    uint8_t codec;
    // opcode
    uint16_t op;
    // opcode name (as string)
    const char *op_name;

    // op count
    uint8_t oper_count;
    // result operand
    rv_oper oper[8];

    // fence info
    uint8_t pred, succ;

    // rounding mode
    uint8_t rm;
    // atomic control
    uint8_t aq, rl;
} rv_instr;

size_t rv_inst_length(rv_inst inst);
void rv_disasm_inst(char *buf, size_t buflen, rv_isa isa, uint64_t pc, rv_inst inst);

uint8_t rv_disasm_instr(rv_instr *instr, rv_isa isa, uint64_t ip, uint8_t *code,
                     uint64_t code_size);

#endif

#endif
