/**
 * @file csv_exporter.c
 * @brief CSV flow exporter for AegisFlow.
 *
 * Produces CICFlowMeter-compatible CSV output: one header line followed
 * by one data line per completed flow.  Column order matches CICFlowMeter's
 * default output for direct compatibility with ML pipelines trained on
 * CICIDS datasets.
 *
 * AegisFlow — High-Performance CICFlowMeter-Compatible Feature Engine
 * SPDX-License-Identifier: MIT
 */

#include "exporter.h"
#include "aegis_features.h"
#include "utils.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * CSV column header (CICFlowMeter-compatible ordering)
 * ========================================================================= */
static const char *CSV_HEADER =
    "Src IP,Dst IP,Src Port,Dst Port,Protocol,"
    "Flow Duration,"
    "Total Fwd Packet,Total Bwd packets,Total Packets,"
    "Total Length of Fwd Packet,Total Length of Bwd Packet,"
    "Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std,Packet Length Variance,"
    "Flow Bytes/s,Flow Packets/s,Fwd Packets/s,Bwd Packets/s,"
    "SYN Flag Count,ACK Flag Count,RST Flag Count,"
    "FIN Flag Count,PSH Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
    "Flow IAT Total,Flow IAT Mean,Flow IAT Std,Flow IAT Min,Flow IAT Max,"
    "Fwd Packet Length Mean,Fwd Packet Length Std,Fwd Packet Length Min,Fwd Packet Length Max,"
    "Bwd Packet Length Mean,Bwd Packet Length Std,Bwd Packet Length Min,Bwd Packet Length Max,"
    "Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Min,Fwd IAT Max,"
    "Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Min,Bwd IAT Max,"
    "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,"
    "Fwd Header Length,Bwd Header Length,Down/Up Ratio,Average Packet Size,"
    "Fwd Segment Size Avg,Bwd Segment Size Avg,"
    "Fwd Header Length.1,"
    "Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,"
    "Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,"
    "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,"
    "FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,Fwd Seg Size Min,"
    "Active Mean,Active Std,Active Max,Active Min,"
    "Idle Mean,Idle Std,Idle Max,Idle Min";

/* =========================================================================
 * Helper: safely print a double (emit 0 for inf/nan)
 * ========================================================================= */
static inline void fprint_double(FILE *fp, double v) {
    if (!isfinite(v)) v = 0.0;
    fprintf(fp, "%.6f", v);
}

/* =========================================================================
 * Public API
 * ========================================================================= */

void csv_exporter_write_header(FILE *fp) {
    if (!fp) fp = stdout;
    fputs(CSV_HEADER, fp);
    fputc('\n', fp);
    fflush(fp);
}

void csv_exporter_write(const FlowRecord *record,
                        const FlowKey    *key,
                        void             *ctx) {
    FILE *fp = ctx ? (FILE *)ctx : stdout;
    UNUSED(key);

    /* ── Extract feature vector ── */
    FlowFeatures f;
    features_extract(record, &f);

    /* ── Format IP addresses ── */
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    utils_ipv4_to_str(f.src_ip, src_ip_str, sizeof(src_ip_str));
    utils_ipv4_to_str(f.dst_ip, dst_ip_str, sizeof(dst_ip_str));

    /* ── Write CSV row ── */
    /* Identity */
    fprintf(fp, "%s,%s,%u,%u,%u,",
            src_ip_str, dst_ip_str,
            (unsigned)ntohs(f.src_port),
            (unsigned)ntohs(f.dst_port),
            (unsigned)f.protocol);

    /* Flow duration */
    fprint_double(fp, f.flow_duration_us); fputc(',', fp);

    /* Packet counts */
    fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
            f.total_fwd_packets, f.total_bwd_packets, f.total_packets);

    /* Byte counts */
    fprintf(fp, "%" PRIu64 ",%" PRIu64 ",",
            f.total_len_fwd_pkts, f.total_len_bwd_pkts);

    /* Packet length stats */
    fprint_double(fp, f.pkt_len_min);  fputc(',', fp);
    fprint_double(fp, f.pkt_len_max);  fputc(',', fp);
    fprint_double(fp, f.pkt_len_mean); fputc(',', fp);
    fprint_double(fp, f.pkt_len_std);  fputc(',', fp);
    fprint_double(fp, f.pkt_len_var);  fputc(',', fp);

    /* Rate features */
    fprint_double(fp, f.flow_bytes_per_sec); fputc(',', fp);
    fprint_double(fp, f.flow_pkts_per_sec);  fputc(',', fp);
    fprint_double(fp, f.fwd_pkts_per_sec);   fputc(',', fp);
    fprint_double(fp, f.bwd_pkts_per_sec);   fputc(',', fp);

    /* TCP flags */
    fprintf(fp, "%u,%u,%u,%u,%u,%u,%u,%u,",
            f.syn_count, f.ack_count, f.rst_count,
            f.fin_count, f.psh_count, f.urg_count,
            f.cwr_count, f.ece_count);

    /* Flow IAT */
    fprint_double(fp, f.flow_iat_total); fputc(',', fp);
    fprint_double(fp, f.flow_iat_mean); fputc(',', fp);
    fprint_double(fp, f.flow_iat_std);  fputc(',', fp);
    fprint_double(fp, f.flow_iat_min);  fputc(',', fp);
    fprint_double(fp, f.flow_iat_max);  fputc(',', fp);

    /* Forward packet length */
    fprint_double(fp, f.fwd_pkt_len_mean); fputc(',', fp);
    fprint_double(fp, f.fwd_pkt_len_std);  fputc(',', fp);
    fprint_double(fp, f.fwd_pkt_len_min);  fputc(',', fp);
    fprint_double(fp, f.fwd_pkt_len_max);  fputc(',', fp);

    /* Backward packet length */
    fprint_double(fp, f.bwd_pkt_len_mean); fputc(',', fp);
    fprint_double(fp, f.bwd_pkt_len_std);  fputc(',', fp);
    fprint_double(fp, f.bwd_pkt_len_min);  fputc(',', fp);
    fprint_double(fp, f.bwd_pkt_len_max);  fputc(',', fp);

    /* Forward IAT */
    fprint_double(fp, f.fwd_iat_total); fputc(',', fp);
    fprint_double(fp, f.fwd_iat_mean); fputc(',', fp);
    fprint_double(fp, f.fwd_iat_std);  fputc(',', fp);
    fprint_double(fp, f.fwd_iat_min);  fputc(',', fp);
    fprint_double(fp, f.fwd_iat_max);  fputc(',', fp);

    /* Backward IAT */
    fprint_double(fp, f.bwd_iat_total); fputc(',', fp);
    fprint_double(fp, f.bwd_iat_mean); fputc(',', fp);
    fprint_double(fp, f.bwd_iat_std);  fputc(',', fp);
    fprint_double(fp, f.bwd_iat_min);  fputc(',', fp);
    fprint_double(fp, f.bwd_iat_max);  fputc(',', fp);

    fprintf(fp, "%u,%u,%u,%u,",
            f.fwd_psh_flags, f.bwd_psh_flags,
            f.fwd_urg_flags, f.bwd_urg_flags);
    fprintf(fp, "%" PRIu64 ",%" PRIu64 ",",
            f.fwd_header_len, f.bwd_header_len);
    fprint_double(fp, f.down_up_ratio);      fputc(',', fp);
    fprint_double(fp, f.pkt_size_avg);       fputc(',', fp);
    fprint_double(fp, f.fwd_seg_size_avg);   fputc(',', fp);
    fprint_double(fp, f.bwd_seg_size_avg);   fputc(',', fp);
    fprintf(fp, "%" PRIu64 ",", f.fwd_header_len);

    fprint_double(fp, f.fwd_bytes_per_bulk_avg);   fputc(',', fp);
    fprint_double(fp, f.fwd_packets_per_bulk_avg); fputc(',', fp);
    fprint_double(fp, f.fwd_bulk_rate_avg);        fputc(',', fp);
    fprint_double(fp, f.bwd_bytes_per_bulk_avg);   fputc(',', fp);
    fprint_double(fp, f.bwd_packets_per_bulk_avg); fputc(',', fp);
    fprint_double(fp, f.bwd_bulk_rate_avg);        fputc(',', fp);

    fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
            f.subflow_fwd_packets, f.subflow_fwd_bytes,
            f.subflow_bwd_packets, f.subflow_bwd_bytes);
    fprintf(fp, "%" PRId32 ",%" PRId32 ",%" PRIu32 ",%" PRIu32 ",",
            f.init_fwd_win_bytes, f.init_bwd_win_bytes,
            f.fwd_act_data_pkts, f.fwd_seg_size_min);

    fprint_double(fp, f.active_mean); fputc(',', fp);
    fprint_double(fp, f.active_std);  fputc(',', fp);
    fprint_double(fp, f.active_max);  fputc(',', fp);
    fprint_double(fp, f.active_min);  fputc(',', fp);
    fprint_double(fp, f.idle_mean);   fputc(',', fp);
    fprint_double(fp, f.idle_std);    fputc(',', fp);
    fprint_double(fp, f.idle_max);    fputc(',', fp);
    fprint_double(fp, f.idle_min);

    fputc('\n', fp);
    fflush(fp);
}

/* =========================================================================
 * ExporterChain implementation
 * ========================================================================= */

void exporter_chain_init(ExporterChain *chain) {
    chain->count = 0;
    for (int i = 0; i < AEGIS_MAX_EXPORTERS; i++) {
        chain->fns[i]  = NULL;
        chain->ctxs[i] = NULL;
    }
}

int exporter_chain_add(ExporterChain *chain, ExportFn fn, void *ctx) {
    if (chain->count >= AEGIS_MAX_EXPORTERS) {
        LOG_WARN("ExporterChain full (max=%d)", AEGIS_MAX_EXPORTERS);
        return -1;
    }
    chain->fns[chain->count]  = fn;
    chain->ctxs[chain->count] = ctx;
    chain->count++;
    return 0;
}

void exporter_chain_dispatch(const FlowRecord *record,
                             const FlowKey    *key,
                             void             *ctx) {
    ExporterChain *chain = (ExporterChain *)ctx;
    for (int i = 0; i < chain->count; i++) {
        if (chain->fns[i]) {
            chain->fns[i](record, key, chain->ctxs[i]);
        }
    }
}
