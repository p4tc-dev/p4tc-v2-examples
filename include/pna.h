#ifndef P4C_PNA_H
#define P4C_PNA_H

#include <stdbool.h>

typedef __u32 PortId_t;
typedef __u64 Timestamp_t;
typedef __u8  ClassOfService_t;
typedef __u16 CloneSessionId_t;
typedef __u32 MulticastGroup_t;
typedef __u16 EgressInstance_t;
typedef __u8  MirrorSlotId_t;
typedef __u16 MirrorSessionId_t;

// Instead of using enum we define ParserError_t as __u8 to save memory.
typedef __u8 ParserError_t;
static const ParserError_t NoError = 0;  /// No error.
static const ParserError_t PacketTooShort = 1;  /// Not enough bits in packet for 'extract'.
static const ParserError_t NoMatch = 2;  /// 'select' expression has no matches.
static const ParserError_t StackOutOfBounds = 3;  /// Reference to invalid element of a header stack.
static const ParserError_t HeaderTooShort = 4;  /// Extracting too many bits into a varbit field.
static const ParserError_t ParserTimeout = 5;  /// Parser execution time limit exceeded.
static const ParserError_t ParserInvalidArgument = 6;  /// Parser operation was called with a value
/// not supported by the implementation

enum PNA_Source_t { FROM_HOST, FROM_NET };

enum MirrorType { NO_MIRROR, PRE_MODIFY, POST_MODIFY };

/*
 * INGRESS data types
 */
struct pna_main_parser_input_metadata_t {
    bool                     recirculated;
    PortId_t                 input_port;    // taken from xdp_md or __sk_buff
} __attribute__((aligned(4)));

struct pna_main_input_metadata_t {
    // All of these values are initialized by the architecture before
    // the Ingress control block begins executing.
    bool                     recirculated;
    Timestamp_t              timestamp;         // taken from bpf helper
    ParserError_t            parser_error;      // local to parser
    ClassOfService_t         class_of_service;  // 0, set in control as global metadata
    PortId_t                 input_port;
} __attribute__((aligned(4)));;

struct pna_main_output_metadata_t {
    // The comment after each field specifies its initial value when the
    // Ingress control block begins executing.
    ClassOfService_t         class_of_service;
} __attribute__((aligned(4)));

/*
 * Opaque struct to be used to share global PNA metadata fields between eBPF program attached to Ingress and Egress.
 * The size of this struct must be less than 32 bytes.
 */
struct pna_global_metadata {
    bool                     recirculated;
    bool             drop; // NOTE(tomasz): no drop field in PNA metadata, so we keep drop state as internal metadata.
    PortId_t         egress_port;
    enum MirrorType  mirror_type;
    MirrorSlotId_t   mirror_slot_id;
    MirrorSessionId_t mirror_session_id;
    /// NOTE (tomasz): two below fields might be optional - they are used to implement https://github.com/p4lang/p4c/tree/main/backends/ebpf/psa#ntk-normal-packet-to-kernel
    __u8             mark;         /// packet mark set by PSA/eBPF programs. Used to differentiate between packets processed by PSA/eBPF from other packets.
    bool             pass_to_kernel;   /// internal metadata, forces sending packet up to kernel stack
} __attribute__((aligned(4)));

// NOTE (tomasz): This struct should be aligned with PNA specs. TBD
struct clone_session_entry {
    __u32 egress_port;
    __u16 instance;
    __u8  class_of_service;
    __u8  truncate;
    __u16 packet_length_bytes;
} __attribute__((aligned(4)));


#endif //P4C_PNA_H
