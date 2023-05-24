#include <model2_sep_parser/parser.h>
#include <pna.h>

#include <stdbool.h>

extern void bpf_p4tc_set_cookie(u32 cookie) __ksym;

REGISTER_START()
REGISTER_TABLE(hdr_md_cpumap, BPF_MAP_TYPE_PERCPU_ARRAY, u32, struct hdr_md, 2)
BPF_ANNOTATE_KV_PAIR(hdr_md_cpumap, u32, struct hdr_md)
REGISTER_END()

static __always_inline int run_parser(void *pkt_start, void *pkt_end,
				      u32 pkt_len,
				      struct my_ingress_headers_t *hdr)
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

    struct hdr_md *hdrMd;

    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_zero);
    if (!hdrMd)
        return TC_ACT_SHOT;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    hdr = &(hdrMd->cpumap_hdr);
    {
        goto start;
        parse_ipv4: {
/* extract(hdr->ipv4) */
            if (pkt_end < pkt_start + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

            hdr->ipv4.version = (u8)((load_byte(pkt_start, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
            ebpf_packetOffsetInBits += 4;

            hdr->ipv4.ihl = (u8)((load_byte(pkt_start, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
            ebpf_packetOffsetInBits += 4;

            hdr->ipv4.diffserv = (u8)((load_byte(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 8;

            hdr->ipv4.totalLen = (u16)((load_half(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 16;

            hdr->ipv4.identification = (u16)((load_half(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 16;

            hdr->ipv4.flags = (u8)((load_byte(pkt_start, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
            ebpf_packetOffsetInBits += 3;

            hdr->ipv4.fragOffset = (u16)((load_half(pkt_start, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 13));
            ebpf_packetOffsetInBits += 13;

            hdr->ipv4.ttl = (u8)((load_byte(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 8;

            hdr->ipv4.protocol = (u8)((load_byte(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 8;

            hdr->ipv4.hdrChecksum = (u16)((load_half(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 16;

	    ipv4_srcAddr_offset = ebpf_packetOffsetInBits;
            hdr->ipv4.srcAddr = (u32)((load_word(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 32;

	    ipv4_dstAddr_offset = ebpf_packetOffsetInBits;
            hdr->ipv4.dstAddr = (u32)((load_word(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 32;

            hdr->ipv4.ebpf_valid = 1;

;
             goto accept;
        }
        start: {
/* extract(hdr->ethernet) */
            if (pkt_end < pkt_start + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

	    eth_dstAddr_offset = ebpf_packetOffsetInBits;
            hdr->ethernet.dstAddr = (u64)((load_dword(pkt_start, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
            ebpf_packetOffsetInBits += 48;

	    eth_srcAddr_offset = ebpf_packetOffsetInBits;
            hdr->ethernet.srcAddr = (u64)((load_dword(pkt_start, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
            ebpf_packetOffsetInBits += 48;

	    eth_type_offset = ebpf_packetOffsetInBits;
            hdr->ethernet.etherType = (u16)((load_half(pkt_start, BYTES(ebpf_packetOffsetInBits))));
            ebpf_packetOffsetInBits += 16;

            hdr->ethernet.ebpf_valid = 1;

;
            u16 select_0;
            select_0 = hdr->ethernet.etherType;
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
    struct my_ingress_headers_t *hdr;
    int ret;

    ret = run_parser(pkt_start, pkt_end, pkt_len, hdr);
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
    struct my_ingress_headers_t *hdr;
    int ret;

    ret = run_parser(pkt_start, pkt_end, pkt_len, hdr);
    if (ret != -1) {
        return ret;
    }

    bpf_p4tc_set_cookie(XDP_COOKIE);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
