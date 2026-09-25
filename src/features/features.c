/**
 * @file features.c
 * @brief Incremental feature computation engine — Welford + per-packet updates.
 *
 * All operations are O(1) per packet.  No packet data is ever buffered.
 * Population variance (÷N) is used to match CICFlowMeter's implementation.
 *
 * AegisFlow — High-Performance CICFlowMeter-Compatible Feature Engine
 * SPDX-License-Identifier: MIT
 */

#include "aegis_features.h"
#include "utils.h"

#include <math.h>
#include <string.h>
#include <float.h>
#include <stdint.h>

#define CIC_BULK_BOUNDARY_US 1000000LL
#define CIC_ACTIVE_IDLE_THRESHOLD_US 5000000LL
#define CIC_MIN_BULK_PACKETS 4u

/* =========================================================================
 * Welford's Online Algorithm
 * ========================================================================= */

void welford_init(WelfordState *state) {
    state->count = 0;
    state->mean  = 0.0;
    state->M2    = 0.0;
}

void welford_update(WelfordState *state, double value) {
    state->count++;
    double delta  = value - state->mean;
    state->mean  += delta / (double)state->count;
    double delta2 = value - state->mean;
    state->M2    += delta * delta2;
}

void welford_finalize(const WelfordState *state,
                      double *mean,
                      double *variance,
                      double *std_dev) {
    if (mean)     *mean     = state->mean;
    if (variance) *variance = (state->count < 2) ? 0.0 : state->M2 / (double)state->count;
    if (std_dev) {
        double var = (state->count < 2) ? 0.0 : state->M2 / (double)state->count;
        *std_dev = (var > 0.0) ? sqrt(var) : 0.0;
    }
}

/* =========================================================================
 * DirectionStats helpers
 * ========================================================================= */

void direction_stats_init(DirectionStats *ds) {
    memset(ds, 0, sizeof(*ds));
    ds->min_len = DBL_MAX;
    ds->max_len = 0.0;
    ds->min_iat = DBL_MAX;
    ds->max_iat = 0.0;
    ds->min_seg_size = UINT32_MAX;
}

static void direction_bulk_commit(DirectionStats *ds,
                                  const struct timeval *end_ts) {
    if (ds->cur_bulk_pkts >= CIC_MIN_BULK_PACKETS) {
        int64_t duration_us = timeval_diff_usec(&ds->cur_bulk_start, end_ts);
        if (duration_us < 0) duration_us = 0;
        ds->bulk_count++;
        ds->bulk_pkt_total  += ds->cur_bulk_pkts;
        ds->bulk_byte_total += ds->cur_bulk_bytes;
        ds->bulk_duration_us += (double)duration_us;
    }
}

static void direction_bulk_update(DirectionStats *ds, double len,
                                  const struct timeval *ts,
                                  int64_t iat_us) {
    if (iat_us <= CIC_BULK_BOUNDARY_US) {
        if (ds->cur_bulk_pkts == 0) {
            ds->cur_bulk_start = ds->last_pkt_time;
            ds->cur_bulk_pkts = 1;
            ds->cur_bulk_bytes = (uint64_t)ds->last_len;
        }
        ds->cur_bulk_pkts++;
        ds->cur_bulk_bytes += (uint64_t)len;
    } else {
        direction_bulk_commit(ds, &ds->last_pkt_time);
        ds->cur_bulk_start = *ts;
        ds->cur_bulk_pkts = 1;
        ds->cur_bulk_bytes = (uint64_t)len;
    }
}

static void update_active_idle(FlowRecord *record, const struct timeval *ts) {
    if (!record->active_initialized) {
        record->active_start = *ts;
        record->active_last = *ts;
        record->active_initialized = 1;
        return;
    }

    int64_t idle_us = timeval_diff_usec(&record->active_last, ts);
    if (idle_us < 0) idle_us = 0;

    if (idle_us > CIC_ACTIVE_IDLE_THRESHOLD_US) {
        int64_t active_us = timeval_diff_usec(&record->active_start,
                                              &record->active_last);
        if (active_us < 0) active_us = 0;
        double active = (double)active_us;
        double idle = (double)idle_us;

        welford_update(&record->active_stats, active);
        if (active < record->min_active) record->min_active = active;
        if (active > record->max_active) record->max_active = active;

        welford_update(&record->idle_stats, idle);
        if (idle < record->min_idle) record->min_idle = idle;
        if (idle > record->max_idle) record->max_idle = idle;

        record->active_start = *ts;
    }

    record->active_last = *ts;
}

static void bulk_finalize_readonly(const DirectionStats *ds,
                                   uint64_t *bulk_count,
                                   uint64_t *bulk_pkts,
                                   uint64_t *bulk_bytes,
                                   double *bulk_duration_us) {
    *bulk_count = ds->bulk_count;
    *bulk_pkts = ds->bulk_pkt_total;
    *bulk_bytes = ds->bulk_byte_total;
    *bulk_duration_us = ds->bulk_duration_us;

    if (ds->cur_bulk_pkts >= CIC_MIN_BULK_PACKETS) {
        int64_t duration_us = timeval_diff_usec(&ds->cur_bulk_start,
                                                &ds->last_pkt_time);
        if (duration_us < 0) duration_us = 0;
        (*bulk_count)++;
        *bulk_pkts += ds->cur_bulk_pkts;
        *bulk_bytes += ds->cur_bulk_bytes;
        *bulk_duration_us += (double)duration_us;
    }
}

static void extract_bulk_features(const DirectionStats *ds,
                                  double *bytes_per_bulk,
                                  double *pkts_per_bulk,
                                  double *bulk_rate) {
    uint64_t bulk_count, bulk_pkts, bulk_bytes;
    double bulk_duration_us;
    bulk_finalize_readonly(ds, &bulk_count, &bulk_pkts, &bulk_bytes,
                           &bulk_duration_us);

    if (bulk_count > 0) {
        *bytes_per_bulk = (double)bulk_bytes / (double)bulk_count;
        *pkts_per_bulk = (double)bulk_pkts / (double)bulk_count;
    } else {
        *bytes_per_bulk = 0.0;
        *pkts_per_bulk = 0.0;
    }

    if (bulk_duration_us > 0.0) {
        *bulk_rate = (double)bulk_bytes / (bulk_duration_us * 1e-6);
    } else {
        *bulk_rate = 0.0;
    }
}

void direction_stats_update(DirectionStats *ds, double len,
                            const struct timeval *ts) {
    /* ── Packet count + byte count ── */
    ds->pkt_count++;
    ds->byte_count += (uint64_t)len;

    /* ── Packet length statistics ── */
    welford_update(&ds->len_stats, len);
    if (len < ds->min_len) ds->min_len = len;
    if (len > ds->max_len) ds->max_len = len;

    /* ── Inter-arrival time ── */
    if (ds->has_last_pkt) {
        int64_t iat_us = timeval_diff_usec(&ds->last_pkt_time, ts);
        if (iat_us < 0) iat_us = 0; /* clock skew guard */
        double iat = (double)iat_us;

        welford_update(&ds->iat_stats, iat);
        if (iat < ds->min_iat) ds->min_iat = iat;
        if (iat > ds->max_iat) ds->max_iat = iat;
        direction_bulk_update(ds, len, ts, iat_us);
    } else {
        ds->cur_bulk_start = *ts;
        ds->cur_bulk_pkts = 1;
        ds->cur_bulk_bytes = (uint64_t)len;
    }

    ds->last_pkt_time = *ts;
    ds->has_last_pkt  = 1;
    ds->last_len = len;
}

/* =========================================================================
 * Per-packet feature update
 * ========================================================================= */

void features_update(FlowRecord *record, const PacketInfo *pkt) {
    double len = (double)pkt->payload_len;
    const struct timeval *ts = &pkt->timestamp;

    /* ── Timestamps ── */
    record->last_seen = *ts;

    /* ── Direction-specific update ── */
    if (pkt->is_fwd) {
        direction_stats_update(&record->fwd, len, ts);
        record->fwd.header_bytes += pkt->header_len;
        if ((pkt->tcp_flags & TCP_FLAG_PSH) != 0) record->fwd.psh_count++;
        if ((pkt->tcp_flags & TCP_FLAG_URG) != 0) record->fwd.urg_count++;
        if (pkt->payload_len > 0) record->fwd.act_data_pkts++;
        if (pkt->header_len > 0 && pkt->header_len < record->fwd.min_seg_size) {
            record->fwd.min_seg_size = pkt->header_len;
        }
        if (record->init_fwd_win_bytes < 0 && record->key.protocol == PROTO_TCP) {
            record->init_fwd_win_bytes = (int32_t)pkt->tcp_window;
        }
    } else {
        direction_stats_update(&record->bwd, len, ts);
        record->bwd.header_bytes += pkt->header_len;
        if ((pkt->tcp_flags & TCP_FLAG_PSH) != 0) record->bwd.psh_count++;
        if ((pkt->tcp_flags & TCP_FLAG_URG) != 0) record->bwd.urg_count++;
        if (pkt->payload_len > 0) record->bwd.act_data_pkts++;
        if (pkt->header_len > 0 && pkt->header_len < record->bwd.min_seg_size) {
            record->bwd.min_seg_size = pkt->header_len;
        }
        if (record->init_bwd_win_bytes < 0 && record->key.protocol == PROTO_TCP) {
            record->init_bwd_win_bytes = (int32_t)pkt->tcp_window;
        }
    }

    /* ── Global packet length stats (fwd + bwd combined) ── */
    welford_update(&record->pkt_len_stats, len);
    if (len < record->min_pkt_len) record->min_pkt_len = len;
    if (len > record->max_pkt_len) record->max_pkt_len = len;

    /* ── Global inter-arrival time stats ── */
    if (record->has_last_pkt) {
        int64_t iat_us = timeval_diff_usec(&record->last_pkt_time, ts);
        if (iat_us < 0) iat_us = 0;
        double iat = (double)iat_us;

        welford_update(&record->iat_stats, iat);
        if (iat < record->min_iat) record->min_iat = iat;
        if (iat > record->max_iat) record->max_iat = iat;
    }
    record->last_pkt_time = *ts;
    record->has_last_pkt  = 1;
    update_active_idle(record, ts);

    /* ── TCP flag accumulators ── */
    if (pkt->tcp_flags & TCP_FLAG_SYN) record->syn_count++;
    if (pkt->tcp_flags & TCP_FLAG_ACK) record->ack_count++;
    if (pkt->tcp_flags & TCP_FLAG_RST) record->rst_count++;
    if (pkt->tcp_flags & TCP_FLAG_FIN) record->fin_count++;
    if (pkt->tcp_flags & TCP_FLAG_PSH) record->psh_count++;
    if (pkt->tcp_flags & TCP_FLAG_URG) record->urg_count++;
    if (pkt->tcp_flags & TCP_FLAG_CWR) record->cwr_count++;
    if (pkt->tcp_flags & TCP_FLAG_ECE) record->ece_count++;
}

/* =========================================================================
 * Feature vector extraction
 * ========================================================================= */

void features_extract(const FlowRecord *record, FlowFeatures *features) {
    memset(features, 0, sizeof(*features));

    /* ── Identity ── */
    features->src_ip   = record->key.src_ip;
    features->dst_ip   = record->key.dst_ip;
    features->src_port = record->key.src_port;
    features->dst_port = record->key.dst_port;
    features->protocol = record->key.protocol;

    /* ── Duration ── */
    int64_t dur_us = timeval_diff_usec(&record->first_seen, &record->last_seen);
    if (dur_us < 0) dur_us = 0;
    features->flow_duration_us = (double)dur_us;

    /* ── Packet / byte counts ── */
    features->total_fwd_packets  = record->fwd.pkt_count;
    features->total_bwd_packets  = record->bwd.pkt_count;
    features->total_packets      = record->fwd.pkt_count + record->bwd.pkt_count;
    features->total_len_fwd_pkts = record->fwd.byte_count;
    features->total_len_bwd_pkts = record->bwd.byte_count;

    /* ── Global packet length stats ── */
    double pkt_mean, pkt_var, pkt_std;
    welford_finalize(&record->pkt_len_stats, &pkt_mean, &pkt_var, &pkt_std);
    features->pkt_len_mean = pkt_mean;
    features->pkt_len_std  = pkt_std;
    features->pkt_len_var  = pkt_var;
    features->pkt_len_min  = (record->pkt_len_stats.count > 0) ? record->min_pkt_len : 0.0;
    features->pkt_len_max  = record->max_pkt_len;

    /* ── Rate features (computed at export time) ── */
    double dur_sec = features->flow_duration_us * 1e-6;
    if (dur_sec > 0.0) {
        double total_bytes = (double)(record->fwd.byte_count + record->bwd.byte_count);
        double total_pkts  = (double)(record->fwd.pkt_count  + record->bwd.pkt_count);
        features->flow_bytes_per_sec = total_bytes / dur_sec;
        features->flow_pkts_per_sec  = total_pkts  / dur_sec;
        features->fwd_pkts_per_sec   = (double)record->fwd.pkt_count / dur_sec;
        features->bwd_pkts_per_sec   = (double)record->bwd.pkt_count / dur_sec;
    } else {
        features->flow_bytes_per_sec = 0.0;
        features->flow_pkts_per_sec  = 0.0;
        features->fwd_pkts_per_sec   = 0.0;
        features->bwd_pkts_per_sec   = 0.0;
    }

    /* ── TCP flag counts ── */
    features->syn_count = record->syn_count;
    features->ack_count = record->ack_count;
    features->rst_count = record->rst_count;
    features->fin_count = record->fin_count;
    features->psh_count = record->psh_count;
    features->urg_count = record->urg_count;
    features->cwr_count = record->cwr_count;
    features->ece_count = record->ece_count;

    /* ── Global IAT ── */
    double iat_mean, iat_var, iat_std;
    welford_finalize(&record->iat_stats, &iat_mean, &iat_var, &iat_std);
    features->flow_iat_mean = iat_mean;
    features->flow_iat_std  = iat_std;
    features->flow_iat_min  = (record->iat_stats.count > 0) ? record->min_iat : 0.0;
    features->flow_iat_max  = record->max_iat;
    features->flow_iat_total = features->flow_duration_us;

    /* ── Forward packet length ── */
    {
        double mean, var, std;
        welford_finalize(&record->fwd.len_stats, &mean, &var, &std);
        features->fwd_pkt_len_mean = mean;
        features->fwd_pkt_len_std  = std;
        features->fwd_pkt_len_min  = (record->fwd.pkt_count > 0) ? record->fwd.min_len : 0.0;
        features->fwd_pkt_len_max  = record->fwd.max_len;
    }

    /* ── Backward packet length ── */
    {
        double mean, var, std;
        welford_finalize(&record->bwd.len_stats, &mean, &var, &std);
        features->bwd_pkt_len_mean = mean;
        features->bwd_pkt_len_std  = std;
        features->bwd_pkt_len_min  = (record->bwd.pkt_count > 0) ? record->bwd.min_len : 0.0;
        features->bwd_pkt_len_max  = record->bwd.max_len;
    }

    /* ── Forward IAT ── */
    {
        double mean, var, std;
        welford_finalize(&record->fwd.iat_stats, &mean, &var, &std);
        features->fwd_iat_mean = mean;
        features->fwd_iat_std  = std;
        features->fwd_iat_min  = (record->fwd.iat_stats.count > 0) ? record->fwd.min_iat : 0.0;
        features->fwd_iat_max  = record->fwd.max_iat;
        features->fwd_iat_total = features->fwd_iat_mean *
                                  (double)record->fwd.iat_stats.count;
    }

    /* ── Backward IAT ── */
    {
        double mean, var, std;
        welford_finalize(&record->bwd.iat_stats, &mean, &var, &std);
        features->bwd_iat_mean = mean;
        features->bwd_iat_std  = std;
        features->bwd_iat_min  = (record->bwd.iat_stats.count > 0) ? record->bwd.min_iat : 0.0;
        features->bwd_iat_max  = record->bwd.max_iat;
        features->bwd_iat_total = features->bwd_iat_mean *
                                  (double)record->bwd.iat_stats.count;
    }

    features->fwd_psh_flags = record->fwd.psh_count;
    features->bwd_psh_flags = record->bwd.psh_count;
    features->fwd_urg_flags = record->fwd.urg_count;
    features->bwd_urg_flags = record->bwd.urg_count;
    features->fwd_header_len = record->fwd.header_bytes;
    features->bwd_header_len = record->bwd.header_bytes;

    features->down_up_ratio = (record->fwd.pkt_count > 0)
        ? (double)record->bwd.pkt_count / (double)record->fwd.pkt_count
        : 0.0;
    features->pkt_size_avg = (features->total_packets > 0)
        ? (double)(record->fwd.byte_count + record->bwd.byte_count) /
          (double)features->total_packets
        : 0.0;
    features->fwd_seg_size_avg = (record->fwd.pkt_count > 0)
        ? (double)record->fwd.byte_count / (double)record->fwd.pkt_count
        : 0.0;
    features->bwd_seg_size_avg = (record->bwd.pkt_count > 0)
        ? (double)record->bwd.byte_count / (double)record->bwd.pkt_count
        : 0.0;

    extract_bulk_features(&record->fwd,
                          &features->fwd_bytes_per_bulk_avg,
                          &features->fwd_packets_per_bulk_avg,
                          &features->fwd_bulk_rate_avg);
    extract_bulk_features(&record->bwd,
                          &features->bwd_bytes_per_bulk_avg,
                          &features->bwd_packets_per_bulk_avg,
                          &features->bwd_bulk_rate_avg);

    features->subflow_fwd_packets = record->fwd.pkt_count;
    features->subflow_fwd_bytes = record->fwd.byte_count;
    features->subflow_bwd_packets = record->bwd.pkt_count;
    features->subflow_bwd_bytes = record->bwd.byte_count;
    features->init_fwd_win_bytes = record->init_fwd_win_bytes;
    features->init_bwd_win_bytes = record->init_bwd_win_bytes;
    features->fwd_act_data_pkts = record->fwd.act_data_pkts;
    features->fwd_seg_size_min = (record->fwd.min_seg_size == UINT32_MAX)
        ? 0u
        : record->fwd.min_seg_size;

    {
        WelfordState active = record->active_stats;
        double active_min = (active.count > 0) ? record->min_active : 0.0;
        double active_max = record->max_active;

        if (record->active_initialized) {
            int64_t active_us = timeval_diff_usec(&record->active_start,
                                                  &record->active_last);
            if (active_us < 0) active_us = 0;
            double active_val = (double)active_us;
            welford_update(&active, active_val);
            if (active.count == 1 || active_val < active_min) active_min = active_val;
            if (active_val > active_max) active_max = active_val;
        }

        double mean, var, std;
        welford_finalize(&active, &mean, &var, &std);
        features->active_mean = mean;
        features->active_std = std;
        features->active_min = (active.count > 0) ? active_min : 0.0;
        features->active_max = (active.count > 0) ? active_max : 0.0;
    }

    {
        double mean, var, std;
        welford_finalize(&record->idle_stats, &mean, &var, &std);
        features->idle_mean = mean;
        features->idle_std = std;
        features->idle_min = (record->idle_stats.count > 0) ? record->min_idle : 0.0;
        features->idle_max = (record->idle_stats.count > 0) ? record->max_idle : 0.0;
    }
}
