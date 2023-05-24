#include <ebpf_kernel.h>

#include <stdbool.h>
#include <linux/if_ether.h>
#include <pna.h>
#include <model2_sep_parser/parser.h>

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)

struct p4tc_table_entry_act_bpf_params__local {
        u32 pipeid;
        u32 tblid;
} __attribute__((preserve_access_index));

struct __attribute__((__packed__)) p4tc_table_entry_act_bpf {
        u32 act_id;
        u8 params[124];
};

extern struct p4tc_table_entry_act_bpf *
bpf_xdp_p4tc_tbl_lookup(struct xdp_md *skb,
                        struct p4tc_table_entry_act_bpf_params__local *params,
                        void *key, const u32 key__sz) __ksym;

struct internal_metadata {
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));

#define INGRESS_NH_TABLE_ACT_INGRESS_SEND_NH 1
#define INGRESS_NH_TABLE_ACT_INGRESS_DROP 2

struct ingress_nh_table_key {
    u32 keysz;
    u32 maskid;
    u32 field0; /* hdr.ipv4.srcAddr */
    u32 field1; /* hdr.ipv4.dstAddr */
} __attribute__((aligned(4)));

struct __attribute__((__packed__)) ingress_nh_table_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct __attribute__((__packed__)) {
            u32 port;
            u64 smac;
            u64 dmac;
        } ingress_send_nh;
        struct {
        } ingress_drop;
    } u;
};

REGISTER_START()
REGISTER_TABLE(hdr_md_cpumap, BPF_MAP_TYPE_PERCPU_ARRAY, u32, struct hdr_md, 2)
BPF_ANNOTATE_KV_PAIR(hdr_md_cpumap, u32, struct hdr_md)
REGISTER_END()

static __always_inline int process(struct xdp_md *skb, struct my_ingress_headers_t *hdr, struct pna_global_metadata *compiler_meta__)
{
    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->data_end - skb->data;
    u32 ebpf_input_port = skb->ingress_ifindex;

    struct my_ingress_metadata_t *meta;
    struct hdr_md *hdrMd;

    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_zero);
    if (!hdrMd)
        return XDP_ABORTED;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    hdr = &(hdrMd->cpumap_hdr);
    meta = &(hdrMd->cpumap_usermeta);
    {
        u8 hit;
        {
/* nh_table_0.apply() */
            {
                /* construct key */
                struct p4tc_table_entry_act_bpf_params__local params = {
                        .pipeid = 1,
                        .tblid = 1
                };
                struct ingress_nh_table_key key = {};
                key.keysz = 64;
                key.field0 = htonl(hdr->ipv4.srcAddr);
                key.field1 = htonl(hdr->ipv4.dstAddr);
                struct p4tc_table_entry_act_bpf *act_bpf;
                /* value */
                struct ingress_nh_table_value *value = NULL;
                /* perform lookup */
                act_bpf = bpf_xdp_p4tc_tbl_lookup(skb, &params, &key, sizeof(key));
                value = (struct ingress_nh_table_value *)act_bpf;
                /* Value will never be NULL, but we must check because of the verifier */
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_NH_TABLE_ACT_INGRESS_SEND_NH:
                            {
                                hdr->ethernet.srcAddr = value->u.ingress_send_nh.smac;
                                hdr->ethernet.dstAddr = value->u.ingress_send_nh.dmac;
                                compiler_meta__->egress_port = value->u.ingress_send_nh.port;
                                compiler_meta__->drop = false;
                                hit = 1;
                            }
                            break;
                        case INGRESS_NH_TABLE_ACT_INGRESS_DROP:
                            {
                                compiler_meta__->drop = true;
                            }
                            break;
                        default:
                            return XDP_ABORTED;
                    }
                } else {
                    return XDP_ABORTED;
;
                }
            }
;
        }
    }

    {

        if (compiler_meta__->drop) {
            return XDP_ABORTED;
        }
        int outHeaderLength = 0;
        if (hdr->ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
;        if (hdr->ipv4.ebpf_valid) {
            outHeaderLength += 160;
        }
;
        int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_xdp_adjust_head(skb, -outHeaderOffset);
            if (returnCode) {
                return XDP_ABORTED;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (hdr->ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return XDP_ABORTED;
            }

            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            hdr->ethernet.etherType = bpf_htons(hdr->ethernet.etherType);
            ebpf_byte = ((char*)(&hdr->ethernet.etherType))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.etherType))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
;       if (hdr->ipv4.ebpf_valid) {
           if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
               return XDP_ABORTED;
           }

           ebpf_byte = ((char*)(&hdr->ipv4.version))[0];
           write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
           ebpf_packetOffsetInBits += 4;

           ebpf_byte = ((char*)(&hdr->ipv4.ihl))[0];
           write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
           ebpf_packetOffsetInBits += 4;

           ebpf_byte = ((char*)(&hdr->ipv4.diffserv))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_packetOffsetInBits += 8;

           hdr->ipv4.totalLen = bpf_htons(hdr->ipv4.totalLen);
           ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[1];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
           ebpf_packetOffsetInBits += 16;

           hdr->ipv4.identification = bpf_htons(hdr->ipv4.identification);
           ebpf_byte = ((char*)(&hdr->ipv4.identification))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.identification))[1];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
           ebpf_packetOffsetInBits += 16;

           ebpf_byte = ((char*)(&hdr->ipv4.flags))[0];
           write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
           ebpf_packetOffsetInBits += 3;

           hdr->ipv4.fragOffset = bpf_htons(hdr->ipv4.fragOffset << 3);
           ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[0];
           write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
           write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[1];
           write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
           ebpf_packetOffsetInBits += 13;

           ebpf_byte = ((char*)(&hdr->ipv4.ttl))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_packetOffsetInBits += 8;

           ebpf_byte = ((char*)(&hdr->ipv4.protocol))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_packetOffsetInBits += 8;

           hdr->ipv4.hdrChecksum = bpf_htons(hdr->ipv4.hdrChecksum);
           ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[1];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
           ebpf_packetOffsetInBits += 16;

           hdr->ipv4.srcAddr = htonl(hdr->ipv4.srcAddr);
           ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[1];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[2];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[3];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
           ebpf_packetOffsetInBits += 32;

           hdr->ipv4.dstAddr = htonl(hdr->ipv4.dstAddr);
           ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[0];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[1];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[2];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
           ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[3];
           write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
           ebpf_packetOffsetInBits += 32;

       }
;
    }
    return -1;
}

SEC("p4prog/xdp-ingress")
int xdp_ingress_func(struct xdp_md *skb) {
    struct pna_global_metadata instance = {};
    struct pna_global_metadata *compiler_meta__ = &instance;

    struct hdr_md *hdrMd;
    struct my_ingress_headers_t *hdr;
    int ret = -1;
    ret = process(skb, (struct my_ingress_headers_t *) hdr, compiler_meta__);
    if (ret != -1) {
        return ret;
    }
    return bpf_redirect(compiler_meta__->egress_port, 0);
}

char _license[] SEC("license") = "GPL";
