/**
 * @file json_exporter.c
 * @brief cJSON-based JSON flow exporter for AegisFlow.
 *
 * Serialises FlowFeatures (computed from a closed FlowRecord) into a
 * JSON object whose keys match CICFlowMeter's field names.
 *
 * AegisFlow — High-Performance CICFlowMeter-Compatible Feature Engine
 * SPDX-License-Identifier: MIT
 */

#include "exporter.h"
#include "aegis_features.h"
#include "utils.h"

#include <cJSON.h>
#include <arpa/inet.h>
#include <math.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Helper: add a double to a JSON object, gracefully handling inf/NaN
 * ========================================================================= */
static void json_add_double(cJSON *obj, const char *key, double val) {
    /* cJSON encodes NaN/Inf as null; replace with 0 for safety */
    if (!isfinite(val)) val = 0.0;
    cJSON_AddNumberToObject(obj, key, val);
}

/* =========================================================================
 * Serialise FlowRecord → heap-allocated JSON string
 * ========================================================================= */
char *json_exporter_serialize(const FlowRecord *record, const FlowKey *key) {
    /* ── Extract feature vector ── */
    FlowFeatures f;
    features_extract(record, &f);

    /* ── Format IP addresses ── */
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    utils_ipv4_to_str(f.src_ip, src_ip_str, sizeof(src_ip_str));
    utils_ipv4_to_str(f.dst_ip, dst_ip_str, sizeof(dst_ip_str));

    UNUSED(key); /* key is embedded in features via record->key */

    /* ── Build cJSON object ── */
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    /* Identity */
    cJSON_AddStringToObject(root, "src_ip",   src_ip_str);
    cJSON_AddStringToObject(root, "dst_ip",   dst_ip_str);
    cJSON_AddNumberToObject(root, "src_port", ntohs(f.src_port));
    cJSON_AddNumberToObject(root, "dst_port", ntohs(f.dst_port));
    cJSON_AddNumberToObject(root, "protocol", f.protocol);

    /* Flow duration */
    json_add_double(root, "flow_duration", f.flow_duration_us);

    /* Packet counts */
    cJSON_AddNumberToObject(root, "total_fwd_packets",  (double)f.total_fwd_packets);
    cJSON_AddNumberToObject(root, "total_bwd_packets",  (double)f.total_bwd_packets);
    cJSON_AddNumberToObject(root, "total_packets",      (double)f.total_packets);

    /* Byte counts */
    cJSON_AddNumberToObject(root, "total_length_fwd_pkts", (double)f.total_len_fwd_pkts);
    cJSON_AddNumberToObject(root, "total_length_bwd_pkts", (double)f.total_len_bwd_pkts);

    /* Packet length stats */
    json_add_double(root, "pkt_length_min",  f.pkt_len_min);
    json_add_double(root, "pkt_length_max",  f.pkt_len_max);
    json_add_double(root, "pkt_length_mean", f.pkt_len_mean);
    json_add_double(root, "pkt_length_std",  f.pkt_len_std);
    json_add_double(root, "pkt_length_variance", f.pkt_len_var);

    /* Rate features */
    json_add_double(root, "flow_bytes_per_sec", f.flow_bytes_per_sec);
    json_add_double(root, "flow_pkts_per_sec",  f.flow_pkts_per_sec);
    json_add_double(root, "fwd_pkts_per_sec",   f.fwd_pkts_per_sec);
    json_add_double(root, "bwd_pkts_per_sec",   f.bwd_pkts_per_sec);

    /* TCP flags */
    cJSON_AddNumberToObject(root, "syn_flag_count", f.syn_count);
    cJSON_AddNumberToObject(root, "ack_flag_count", f.ack_count);
    cJSON_AddNumberToObject(root, "rst_flag_count", f.rst_count);
    cJSON_AddNumberToObject(root, "fin_flag_count", f.fin_count);
    cJSON_AddNumberToObject(root, "psh_flag_count", f.psh_count);
    cJSON_AddNumberToObject(root, "urg_flag_count", f.urg_count);
    cJSON_AddNumberToObject(root, "cwe_flag_count", f.cwr_count);
    cJSON_AddNumberToObject(root, "ece_flag_count", f.ece_count);

    /* Flow IAT */
    json_add_double(root, "flow_iat_total", f.flow_iat_total);
    json_add_double(root, "flow_iat_mean", f.flow_iat_mean);
    json_add_double(root, "flow_iat_std",  f.flow_iat_std);
    json_add_double(root, "flow_iat_min",  f.flow_iat_min);
    json_add_double(root, "flow_iat_max",  f.flow_iat_max);

    /* Forward packet length */
    json_add_double(root, "fwd_pkt_length_mean", f.fwd_pkt_len_mean);
    json_add_double(root, "fwd_pkt_length_std",  f.fwd_pkt_len_std);
    json_add_double(root, "fwd_pkt_length_min",  f.fwd_pkt_len_min);
    json_add_double(root, "fwd_pkt_length_max",  f.fwd_pkt_len_max);

    /* Backward packet length */
    json_add_double(root, "bwd_pkt_length_mean", f.bwd_pkt_len_mean);
    json_add_double(root, "bwd_pkt_length_std",  f.bwd_pkt_len_std);
    json_add_double(root, "bwd_pkt_length_min",  f.bwd_pkt_len_min);
    json_add_double(root, "bwd_pkt_length_max",  f.bwd_pkt_len_max);

    /* Forward IAT */
    json_add_double(root, "fwd_iat_total", f.fwd_iat_total);
    json_add_double(root, "fwd_iat_mean", f.fwd_iat_mean);
    json_add_double(root, "fwd_iat_std",  f.fwd_iat_std);
    json_add_double(root, "fwd_iat_min",  f.fwd_iat_min);
    json_add_double(root, "fwd_iat_max",  f.fwd_iat_max);

    /* Backward IAT */
    json_add_double(root, "bwd_iat_total", f.bwd_iat_total);
    json_add_double(root, "bwd_iat_mean", f.bwd_iat_mean);
    json_add_double(root, "bwd_iat_std",  f.bwd_iat_std);
    json_add_double(root, "bwd_iat_min",  f.bwd_iat_min);
    json_add_double(root, "bwd_iat_max",  f.bwd_iat_max);

    /* Extended CICFlowMeter features */
    cJSON_AddNumberToObject(root, "fwd_psh_flags", f.fwd_psh_flags);
    cJSON_AddNumberToObject(root, "bwd_psh_flags", f.bwd_psh_flags);
    cJSON_AddNumberToObject(root, "fwd_urg_flags", f.fwd_urg_flags);
    cJSON_AddNumberToObject(root, "bwd_urg_flags", f.bwd_urg_flags);
    cJSON_AddNumberToObject(root, "fwd_header_length", (double)f.fwd_header_len);
    cJSON_AddNumberToObject(root, "bwd_header_length", (double)f.bwd_header_len);
    json_add_double(root, "down_up_ratio", f.down_up_ratio);
    json_add_double(root, "avg_packet_size", f.pkt_size_avg);
    json_add_double(root, "avg_fwd_segment_size", f.fwd_seg_size_avg);
    json_add_double(root, "avg_bwd_segment_size", f.bwd_seg_size_avg);
    cJSON_AddNumberToObject(root, "fwd_header_length_dup", (double)f.fwd_header_len);
    json_add_double(root, "fwd_avg_bytes_bulk", f.fwd_bytes_per_bulk_avg);
    json_add_double(root, "fwd_avg_packets_bulk", f.fwd_packets_per_bulk_avg);
    json_add_double(root, "fwd_avg_bulk_rate", f.fwd_bulk_rate_avg);
    json_add_double(root, "bwd_avg_bytes_bulk", f.bwd_bytes_per_bulk_avg);
    json_add_double(root, "bwd_avg_packets_bulk", f.bwd_packets_per_bulk_avg);
    json_add_double(root, "bwd_avg_bulk_rate", f.bwd_bulk_rate_avg);
    cJSON_AddNumberToObject(root, "subflow_fwd_packets", (double)f.subflow_fwd_packets);
    cJSON_AddNumberToObject(root, "subflow_fwd_bytes", (double)f.subflow_fwd_bytes);
    cJSON_AddNumberToObject(root, "subflow_bwd_packets", (double)f.subflow_bwd_packets);
    cJSON_AddNumberToObject(root, "subflow_bwd_bytes", (double)f.subflow_bwd_bytes);
    cJSON_AddNumberToObject(root, "init_fwd_win_bytes", f.init_fwd_win_bytes);
    cJSON_AddNumberToObject(root, "init_bwd_win_bytes", f.init_bwd_win_bytes);
    cJSON_AddNumberToObject(root, "fwd_act_data_pkts", f.fwd_act_data_pkts);
    cJSON_AddNumberToObject(root, "fwd_seg_size_min", f.fwd_seg_size_min);
    json_add_double(root, "active_mean", f.active_mean);
    json_add_double(root, "active_std", f.active_std);
    json_add_double(root, "active_max", f.active_max);
    json_add_double(root, "active_min", f.active_min);
    json_add_double(root, "idle_mean", f.idle_mean);
    json_add_double(root, "idle_std", f.idle_std);
    json_add_double(root, "idle_max", f.idle_max);
    json_add_double(root, "idle_min", f.idle_min);

    /* ── Serialise to string ── */
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return json_str;  /* caller must free() */
}

/* =========================================================================
 * ExportFn-compatible writer
 * ========================================================================= */
void json_exporter_write(const FlowRecord *record,
                         const FlowKey    *key,
                         void             *ctx) {
    FILE *fp = ctx ? (FILE *)ctx : stdout;

    char *json_str = json_exporter_serialize(record, key);
    if (!json_str) {
        LOG_ERROR("json_exporter_serialize returned NULL (OOM?)");
        return;
    }

    fputs(json_str, fp);
    fputc('\n', fp);
    fflush(fp);

    free(json_str);
}
