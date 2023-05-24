## Actual location of the makefile
ROOT_DIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
## Argument for the CLANG compiler
CLANG ?= clang-15
INCLUDES= -I$(ROOT_DIR)/include
# Optimization flags to save space
CFLAGS+= -O2 -g -c -D__KERNEL__ -D__ASM_SYSREG_H \
	 -Wno-unused-value  -Wno-pointer-sign \
	 -Wno-compare-distinct-pointer-types \
	 -Wno-gnu-variable-sized-type-not-at-end \
	 -Wno-address-of-packed-member -Wno-tautological-compare \
	 -Wno-unknown-warning-option -Wnoparentheses-equality

MODEL1_TABLES :=
MODEL1_TABLES+=model1/parser/redirect_l2_pna_parser_scripted.c

MODEL2_TABLES :=
MODEL2_TABLES+=model2/1table/exact/redirect_l2_pna_1t_exact.c
MODEL2_TABLES+=model2/1table/exact/redirect_l2_pna_1t_exact_xdp.c
MODEL2_TABLES+=model2/1table/lpm/redirect_l2_pna_1t_lpm.c
MODEL2_TABLES+=model2/1table/lpm/redirect_l2_pna_1t_lpm_xdp.c
MODEL2_TABLES+=model2/1table/ternary/redirect_l2_pna_1t_ternary.c
MODEL2_TABLES+=model2/1table/ternary/redirect_l2_pna_1t_ternary_xdp.c

MODEL2_TABLES+=model2/2tables/exact/redirect_l2_pna_2t_exact.c
MODEL2_TABLES+=model2/2tables/exact/redirect_l2_pna_2t_exact_xdp.c
MODEL2_TABLES+=model2/2tables/lpm/redirect_l2_pna_2t_lpm.c
MODEL2_TABLES+=model2/2tables/lpm/redirect_l2_pna_2t_lpm_xdp.c
MODEL2_TABLES+=model2/2tables/ternary/redirect_l2_pna_2t_ternary.c
MODEL2_TABLES+=model2/2tables/ternary/redirect_l2_pna_2t_ternary_xdp.c

MODEL2_SEP_PARSER_TABLES :=
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/parser/redirect_l2_pna_parser_ebpf_datapath.c

MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/1table/exact/redirect_l2_pna_1t_exact_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/1table/exact/redirect_l2_pna_1t_exact_xdp_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/1table/lpm/redirect_l2_pna_1t_lpm_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/1table/lpm/redirect_l2_pna_1t_lpm_xdp_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/1table/ternary/redirect_l2_pna_1t_ternary_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/1table/ternary/redirect_l2_pna_1t_ternary_xdp_noparser.c

MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/2tables/exact/redirect_l2_pna_2t_exact_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/2tables/exact/redirect_l2_pna_2t_exact_xdp_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/2tables/lpm/redirect_l2_pna_2t_lpm_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/2tables/lpm/redirect_l2_pna_2t_lpm_xdp_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/2tables/ternary/redirect_l2_pna_2t_ternary_noparser.c
MODEL2_SEP_PARSER_TABLES+=model2_sep_parser/2tables/ternary/redirect_l2_pna_2t_ternary_xdp_noparser.c

MODEL1_OBJS=$(MODEL1_TABLES:.c=.o)

MODEL2_OBJS=$(MODEL2_TABLES:.c=.o)

MODEL2_SEP_PARSER_OBJS=$(MODEL2_SEP_PARSER_TABLES:.c=.o)

all: verify_cmds $(MODEL1_OBJS) $(MODEL2_OBJS) $(MODEL2_SEP_PARSER_OBJS)

$(MODEL1_OBJS): %.o : %.c
	$(CLANG) $(CFLAGS) $(INCLUDES) --target=bpf -mcpu=probe -c $< -o $@

$(MODEL2_OBJS): %.o : %.c
	$(CLANG) $(CFLAGS) $(INCLUDES) --target=bpf -mcpu=probe -c $< -o $@

$(MODEL2_SEP_PARSER_OBJS): %.o : %.c
	$(CLANG) $(CFLAGS) $(INCLUDES) --target=bpf -mcpu=probe -c $< -o $@

model1: verify_cmds $(MODEL1_OBJS)

model2_sep_parser: verify_cmds $(MODEL2_SEP_PARSER_OBJS)

model2: verify_cmds $(MODEL2_OBJS)

clean:
	rm -f $(MODEL2_SEP_PARSER_OBJS) $(MODEL2_OBJS) $(MODEL1_OBJS)

# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: verify_cmds $(CLANG)

verify_cmds: $(CLANG)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else \
			echo "pass verify_cmds:" \
			true; fi; \
	done
