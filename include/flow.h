/**
 * @file flow.h
 * @brief Core data structures for AegisFlow network flow records.
 *
 * Defines the FlowKey (5-tuple), FlowRecord (all per-flow state),
 * PacketInfo (parsed packet descriptor), and FlowFeatures (computed
 * output vector). All statistics are maintained incrementally using
 * Welford's online algorithm — no packet data is ever retained.
 *
 * AegisFlow — High-Performance CICFlowMeter-Compatible Feature Engine
 * SPDX-License-Identifier: MIT
 */

#ifndef AEGISFLOW_FLOW_H
#define AEGISFLOW_FLOW_H

#include <stdint.h>
#include <sys/time.h>

#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * TCP flag bit masks (RFC 793 / RFC 3168)
 * ========================================================================= */
#define TCP_FLAG_FIN  0x01u
#define TCP_FLAG_SYN  0x02u
#define TCP_FLAG_RST  0x04u
#define TCP_FLAG_PSH  0x08u
#define TCP_FLAG_ACK  0x10u
#define TCP_FLAG_URG  0x20u
#define TCP_FLAG_ECE  0x40u
#define TCP_FLAG_CWR  0x80u

/* =========================================================================
 * Common IP protocol numbers
 * ========================================================================= */
#define PROTO_ICMP  1u
#define PROTO_TCP   6u
#define PROTO_UDP   17u

/* =========================================================================
 * Timeout defaults (seconds)
 * ========================================================================= */
#define FLOW_TIMEOUT_TCP_SEC  120
#define FLOW_TIMEOUT_UDP_SEC  60

/* =========================================================================
 * FlowKey — 5-tuple used as the uthash key
 *
 * NOTE: _pad ensures the struct has no implicit padding bytes so that
 * memcmp-based hashing is deterministic across compilers.
 * ========================================================================= */
typedef struct {
    uint32_t src_ip;    /**< Source IPv4 address (network byte order) */
    uint32_t dst_ip;    /**< Destination IPv4 address (network byte order) */
    uint16_t src_port;  /**< Source port (network byte order) */
    uint16_t dst_port;  /**< Destination port (network byte order) */
    uint8_t  protocol;  /**< IP protocol number (TCP=6, UDP=17, …) */
    uint8_t  _pad[3];   /**< Explicit padding — keeps key deterministic */
} FlowKey;

/* =========================================================================
 * WelfordState — streaming mean + population variance (O(1) per update)
 *
 * Implements Welford's online algorithm.  Call welford_update() once per
 * sample; call welford_finalize() at export time to extract mean / std.
 * ========================================================================= */
typedef struct {
    uint64_t count;  /**< Number of samples seen so far */
    double   mean;   /**< Running mean */
    double   M2;     /**< Running sum of squared deviations from mean */
} WelfordState;

/* =========================================================================
 * DirectionStats — per-direction packet/byte/IAT/length accumulators
 * ========================================================================= */
typedef struct {
    uint64_t     pkt_count;       /**< Number of packets in this direction */
    uint64_t     byte_count;      /**< Total bytes (payload) in this direction */
    uint64_t     header_bytes;    /**< Total transport header bytes */

    WelfordState len_stats;       /**< Online mean/var for packet lengths */
    double       min_len;         /**< Minimum observed packet length */
    double       max_len;         /**< Maximum observed packet length */

    WelfordState iat_stats;       /**< Online mean/var for inter-arrival times */
    double       min_iat;         /**< Minimum observed IAT (µs) */
    double       max_iat;         /**< Maximum observed IAT (µs) */

    struct timeval last_pkt_time; /**< Timestamp of last packet in this direction */
    int          has_last_pkt;    /**< Flag: 0 before first packet seen */
    uint32_t     psh_count;       /**< PSH flags in this direction */
    uint32_t     urg_count;       /**< URG flags in this direction */
    uint32_t     act_data_pkts;   /**< Packets with payload in this direction */
    uint32_t     min_seg_size;    /**< Minimum transport header size */
    uint64_t     bulk_count;      /**< Completed bulk groups in this direction */
    uint64_t     bulk_pkt_total;  /**< Packets across completed bulk groups */
    uint64_t     bulk_byte_total; /**< Bytes across completed bulk groups */
    double       bulk_duration_us;/** Duration across completed bulk groups */
    uint64_t     cur_bulk_pkts;   /**< Current candidate bulk group packets */
    uint64_t     cur_bulk_bytes;  /**< Current candidate bulk group bytes */
    struct timeval cur_bulk_start;/** Current candidate bulk start */
    double       last_len;        /**< Previous packet length in this direction */
} DirectionStats;

/* =========================================================================
 * FlowRecord — complete runtime state for one active flow
 *
 * Layout rules:
 *   - `key` MUST be the first field (uthash requirement)
 *   - `hh` is the uthash intrusive handle
 *   - All statistics are updated in-place; no packets are stored
 * ========================================================================= */
typedef struct FlowRecord {
    /* ── Identity (key must be first for uthash) ── */
    FlowKey        key;

    /* ── Timestamps ── */
    struct timeval first_seen;     /**< Timestamp of first packet */
    struct timeval last_seen;      /**< Timestamp of most recent packet */

    /* ── Directional statistics ── */
    DirectionStats fwd;            /**< Forward direction (same as first pkt) */
    DirectionStats bwd;            /**< Backward direction */

    /* ── Global packet length statistics (fwd + bwd combined) ── */
    WelfordState   pkt_len_stats;
    double         min_pkt_len;
    double         max_pkt_len;

    /* ── Global inter-arrival time statistics ── */
    WelfordState   iat_stats;
    double         min_iat;
    double         max_iat;
    struct timeval last_pkt_time;  /**< Last packet time (any direction) */
    int            has_last_pkt;   /**< Flag: 0 before second packet seen */

    /* ── TCP flag accumulators ── */
    uint32_t       syn_count;
    uint32_t       ack_count;
    uint32_t       rst_count;
    uint32_t       fin_count;
    uint32_t       psh_count;
    uint32_t       urg_count;
    uint32_t       cwr_count;
    uint32_t       ece_count;

    /* ── Protocol (redundant copy for quick access) ── */
    uint8_t        protocol;

    int32_t        init_fwd_win_bytes;
    int32_t        init_bwd_win_bytes;

    WelfordState   active_stats;
    WelfordState   idle_stats;
    double         min_active;
    double         max_active;
    double         min_idle;
    double         max_idle;
    struct timeval active_start;
    struct timeval active_last;
    int            active_initialized;

    /* ── uthash intrusive handle (must be last or at least after key) ── */
    UT_hash_handle hh;
} FlowRecord;

/* =========================================================================
 * PacketInfo — parsed packet descriptor passed from capture to flow engine
 * ========================================================================= */
typedef struct {
    FlowKey        key;           /**< 5-tuple (always stored in fwd direction) */
    struct timeval timestamp;     /**< Capture timestamp */
    uint32_t       payload_len;   /**< IP payload / transport data length */
    uint8_t        tcp_flags;     /**< TCP flags byte (0 for non-TCP) */
    uint8_t        is_fwd;        /**< 1 = forward direction, 0 = backward */
    uint32_t       header_len;    /**< Transport header length in bytes */
    uint16_t       tcp_window;    /**< TCP window size (0 for non-TCP) */
} PacketInfo;

/* =========================================================================
 * FlowFeatures — exported feature vector (CICFlowMeter-compatible)
 *
 * Computed from a completed (closed or timed-out) FlowRecord at export time.
 * All rate features are computed on-the-fly from raw counters + duration.
 * ========================================================================= */
typedef struct {
    /* ── 5-tuple identity ── */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    /* ── Duration (microseconds) ── */
    double   flow_duration_us;

    /* ── Packet counts ── */
    uint64_t total_fwd_packets;
    uint64_t total_bwd_packets;
    uint64_t total_packets;

    /* ── Byte counts ── */
    uint64_t total_len_fwd_pkts;
    uint64_t total_len_bwd_pkts;

    /* ── Packet length statistics (all packets, fwd+bwd) ── */
    double   pkt_len_min;
    double   pkt_len_max;
    double   pkt_len_mean;
    double   pkt_len_std;
    double   pkt_len_var;

    /* ── Rate features ── */
    double   flow_bytes_per_sec;
    double   flow_pkts_per_sec;

    /* ── TCP flag counts ── */
    uint32_t syn_count;
    uint32_t ack_count;
    uint32_t rst_count;
    uint32_t fin_count;
    uint32_t psh_count;
    uint32_t urg_count;
    uint32_t cwr_count;
    uint32_t ece_count;

    /* ── Global IAT ── */
    double   flow_iat_mean;
    double   flow_iat_std;
    double   flow_iat_min;
    double   flow_iat_max;

    /* ── Forward packet length ── */
    double   fwd_pkt_len_mean;
    double   fwd_pkt_len_std;
    double   fwd_pkt_len_min;
    double   fwd_pkt_len_max;

    /* ── Backward packet length ── */
    double   bwd_pkt_len_mean;
    double   bwd_pkt_len_std;
    double   bwd_pkt_len_min;
    double   bwd_pkt_len_max;

    /* ── Forward IAT ── */
    double   fwd_iat_mean;
    double   fwd_iat_std;
    double   fwd_iat_min;
    double   fwd_iat_max;
    double   fwd_iat_total;

    /* ── Backward IAT ── */
    double   bwd_iat_mean;
    double   bwd_iat_std;
    double   bwd_iat_min;
    double   bwd_iat_max;
    double   bwd_iat_total;

    double   flow_iat_total;
    uint32_t fwd_psh_flags;
    uint32_t bwd_psh_flags;
    uint32_t fwd_urg_flags;
    uint32_t bwd_urg_flags;
    uint64_t fwd_header_len;
    uint64_t bwd_header_len;
    double   fwd_pkts_per_sec;
    double   bwd_pkts_per_sec;
    double   down_up_ratio;
    double   pkt_size_avg;
    double   fwd_seg_size_avg;
    double   bwd_seg_size_avg;
    double   fwd_bytes_per_bulk_avg;
    double   fwd_packets_per_bulk_avg;
    double   fwd_bulk_rate_avg;
    double   bwd_bytes_per_bulk_avg;
    double   bwd_packets_per_bulk_avg;
    double   bwd_bulk_rate_avg;
    uint64_t subflow_fwd_packets;
    uint64_t subflow_fwd_bytes;
    uint64_t subflow_bwd_packets;
    uint64_t subflow_bwd_bytes;
    int32_t  init_fwd_win_bytes;
    int32_t  init_bwd_win_bytes;
    uint32_t fwd_act_data_pkts;
    uint32_t fwd_seg_size_min;
    double   active_mean;
    double   active_std;
    double   active_max;
    double   active_min;
    double   idle_mean;
    double   idle_std;
    double   idle_max;
    double   idle_min;
} FlowFeatures;

#ifdef __cplusplus
}
#endif

#endif /* AEGISFLOW_FLOW_H */
