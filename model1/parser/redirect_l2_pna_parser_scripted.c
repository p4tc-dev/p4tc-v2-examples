#include <model1/parser.h>

#include <stdbool.h>

#define IPV4_SRC_ADDR_OFF (96)

extern void bpf_p4tc_set_cookie(u32 cookie) __ksym;

static __always_inline int run_parser(void *pkt_start, void *pkt_end,
				      u32 pkt_len)
{

    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    u16 ipv4_srcAddr_offset = 0;
    u16 ipv4_dstAddr_offset = 0;
    u16 eth_dstAddr_offset = 0;
    u16 eth_srcAddr_offset = 0;
    u16 eth_type_offset = 0;
    struct p4tc_parser_buffer_act_bpf *parser_buff;
    struct p4tc_pkt_meta *pkt_meta;
    unsigned char ebpf_byte;

    {
        goto start;
        parse_ipv4: {
            if (pkt_end < pkt_start + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

            ebpf_packetOffsetInBits += IPV4_SRC_ADDR_OFF;
	    ipv4_srcAddr_offset = ebpf_packetOffsetInBits;
            ebpf_packetOffsetInBits += 32;

	    ipv4_dstAddr_offset = ebpf_packetOffsetInBits;

;
             goto accept;
        }
        start: {
            u16 select_0;

            if (pkt_end < pkt_start + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

	    eth_dstAddr_offset = ebpf_packetOffsetInBits;
            ebpf_packetOffsetInBits += 48;

	    eth_srcAddr_offset = ebpf_packetOffsetInBits;
            ebpf_packetOffsetInBits += 48;

	    eth_type_offset = ebpf_packetOffsetInBits;
	    select_0 = (u16)((load_half(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 16;
;
            if (select_0 == 0x800)goto parse_ipv4;
            if ((select_0 & 0x0) == (0x0 & 0x0))goto accept;
            else goto reject;
        }

        reject: {
            if (ebpf_errorCode == 0) {
                return TC_ACT_SHOT;
            }
            goto accept;
        }

    }

accept:
    return -1;
}

#define XDP_COOKIE 22

SEC("p4tc/tc-parse")
int tc_parse(struct __sk_buff *skb) {

    void *pkt_start = ((void*)(long)skb->data);
    void *pkt_end = ((void*)(long)skb->data_end);
    u32 pkt_len = skb->len;
    int ret;

    ret = run_parser(pkt_start, pkt_end, pkt_len);
    if (ret != -1) {
        return ret;
    }

    return TC_ACT_PIPE;
}

SEC("p4tc/xdp-parse")
int xdp_parse(struct xdp_md *skb) {

    void *pkt_start = ((void*)(long)skb->data);
    void *pkt_end = ((void*)(long)skb->data_end);
    u32 pkt_len = pkt_end - pkt_start;
    int ret;

    ret = run_parser(pkt_start, pkt_end, pkt_len);
    if (ret != -1) {
        return ret;
    }

    bpf_p4tc_set_cookie(XDP_COOKIE);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
