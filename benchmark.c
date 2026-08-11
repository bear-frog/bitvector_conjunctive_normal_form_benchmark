#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "bitvec_engine.h"

#define ETHERTYPE_IP     0x0800
#define IPPROTO_TCP      6
#define PROTO_SHIFT      17
#define PROTO_PORT_MASK  0x7ffff
#define PACK_PROTO_PORT(proto, port) (((proto) << PROTO_SHIFT | (port)) & PROTO_PORT_MASK)
#define PORT_MAX         65536
#define ANY_PORT         PORT_MAX
#define OLD_ANY_PORT     (65537 - 1)

typedef void lookup_cache_t;
struct bhs_hdr { uint16_t ether_type; uint8_t Protocol; uint32_t ip_src; uint32_t ip_dst; uint16_t sport; union { uint16_t dport; } dp; };
struct net_packet { int indev; struct bhs_hdr bhs; };
typedef struct { bve_ctx_t clsf; bitvec_t *inter[10]; void *ref; int actions[120000]; } acl_engine_t;

int g_engine_idx = 0;
acl_engine_t g_acl_engine[1];

// 비트벡터 전역 변수
bitvec_t *g_vec_inter, *g_vec_sip, *g_vec_dip, *g_vec_sport_exact, *g_vec_sport_any, *g_vec_dport_exact, *g_vec_dport_any;

// Search 함수 Mocking (기업/프로젝트 종속적인 네이밍 제거)
bitvec_t *lookup_src_ip_vector(int layer, uint32_t ip, void *ref, void *opt) { return g_vec_sip; }
bitvec_t *lookup_dst_ip_vector(int layer, uint32_t ip, void *ref, void *opt) { return g_vec_dip; }
bitvec_t *lookup_src_port_vector(int layer, int proto_port, void *ref, void *opt) {
    int port = proto_port & PROTO_PORT_MASK;
    return (port == ANY_PORT || port == OLD_ANY_PORT) ? g_vec_sport_any : g_vec_sport_exact;
}
bitvec_t *lookup_dst_port_vector(int layer, int proto_port, void *ref, void *opt) {
    int port = proto_port & PROTO_PORT_MASK;
    return (port == ANY_PORT || port == OLD_ANY_PORT) ? g_vec_dport_any : g_vec_dport_exact;
}

// ----------------------------------------------------------------------------
// [구버전] Exact 1번 + ANY 1번 (총 2회)
// ----------------------------------------------------------------------------
int EvaluatePacket_Legacy(struct net_packet *pPacket, lookup_cache_t *cache, int tid) {
    int ret, single_ret, any_ret, def_action = 0, proto = 0, proto_port;
    int sport_any_flag = 1, dport_any_flag = 1;
    bitvec_t *bvs[5];
    acl_engine_t *obj = &g_acl_engine[g_engine_idx];

    bvs[0] = obj->inter[pPacket->indev];
    bvs[1] = lookup_src_ip_vector(0, pPacket->bhs.ip_src, obj->ref, NULL);
    bvs[2] = lookup_dst_ip_vector(0, pPacket->bhs.ip_dst, obj->ref, NULL);

    proto_port = (proto << 17 | pPacket->bhs.sport) & 0x7ffff;
    bvs[3] = lookup_src_port_vector(0, proto_port, obj->ref, NULL);
    if (!bvs[3]) {
        proto_port = (proto << 17 | OLD_ANY_PORT) & 0x7ffff;
        bvs[3] = lookup_src_port_vector(0, proto_port, obj->ref, NULL);
        sport_any_flag = 0;
    }
    proto_port = (proto << 17 | pPacket->bhs.dp.dport) & 0x7ffff;
    bvs[4] = lookup_dst_port_vector(0, proto_port, obj->ref, NULL);
    if (!bvs[4]) {
        proto_port = (proto << 17 | OLD_ANY_PORT) & 0x7ffff;
        bvs[4] = lookup_dst_port_vector(0, proto_port, obj->ref, NULL);
        dport_any_flag = 0;
    }

    single_ret = bve_match_exact(&obj->clsf, bvs, 5);

    if (sport_any_flag) bvs[3] = lookup_src_port_vector(0, (proto << 17 | OLD_ANY_PORT) & 0x7ffff, obj->ref, NULL);
    if (dport_any_flag) bvs[4] = lookup_dst_port_vector(0, (proto << 17 | OLD_ANY_PORT) & 0x7ffff, obj->ref, NULL);
    
    any_ret = bve_match_exact(&obj->clsf, bvs, 5);

    if (single_ret < 0) ret = any_ret;
    else if (any_ret < 0) ret = single_ret;
    else if (single_ret < any_ret) ret = single_ret;
    else ret = any_ret;

    return (ret != -1) ? obj->actions[ret] : def_action;
}

// ----------------------------------------------------------------------------
// [신버전] CNF 병합 처리 (단일 패스 1회)
// ----------------------------------------------------------------------------
int EvaluatePacket_Optimized(struct net_packet *pPacket, lookup_cache_t *cache, int tid) {
    int ret, def_action = 0, proto = 0, proto_port, proto_any_port, proto_any_port_cnt;
    bitvec_t *bvs[3], *sp_ex = NULL, *sp_any = NULL, *dp_ex = NULL, *dp_any = NULL;
    bitvec_or_group_t port_groups[2];
    acl_engine_t *obj = &g_acl_engine[g_engine_idx];

    bvs[0] = obj->inter[pPacket->indev];
    bvs[1] = lookup_src_ip_vector(0, pPacket->bhs.ip_src, obj->ref, NULL);
    bvs[2] = lookup_dst_ip_vector(0, pPacket->bhs.ip_dst, obj->ref, NULL);

    proto_any_port = PACK_PROTO_PORT(proto, ANY_PORT);
    
    proto_port = PACK_PROTO_PORT(proto, pPacket->bhs.sport);
    sp_ex = lookup_src_port_vector(0, proto_port, obj->ref, NULL);
    sp_any = lookup_src_port_vector(0, proto_any_port, obj->ref, NULL);

    proto_port = PACK_PROTO_PORT(proto, pPacket->bhs.dp.dport);
    dp_ex = lookup_dst_port_vector(0, proto_port, obj->ref, NULL);
    dp_any = lookup_dst_port_vector(0, proto_any_port, obj->ref, NULL);

    proto_any_port_cnt = 0;
    if (sp_ex) port_groups[0].bvs[proto_any_port_cnt++] = sp_ex;
    if (sp_any) port_groups[0].bvs[proto_any_port_cnt++] = sp_any;
    port_groups[0].count = proto_any_port_cnt;

    proto_any_port_cnt = 0;
    if (dp_ex) port_groups[1].bvs[proto_any_port_cnt++] = dp_ex;
    if (dp_any) port_groups[1].bvs[proto_any_port_cnt++] = dp_any;
    port_groups[1].count = proto_any_port_cnt;

    ret = bve_match_cnf(&obj->clsf, bvs, 3, port_groups, 2);

    return (ret != -1) ? obj->actions[ret] : def_action;
}

// ----------------------------------------------------------------------------
// 타이머 & 메인
// ----------------------------------------------------------------------------
static inline double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + (ts.tv_nsec * 1e-9);
}

int main(void) {
    acl_engine_t *obj = &g_acl_engine[0];
    struct net_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // mock.rule 파일 파싱 및 로드
    FILE *fp = fopen("mock.rule", "r");
    if (!fp) {
        perror("mock.rule 파일을 찾을 수 없습니다.");
        return 1;
    }

    int MAX_RULES = 120000;
    bve_init_context(&obj->clsf, MAX_RULES);
    g_vec_inter       = bve_alloc_vector(&obj->clsf);
    g_vec_sip         = bve_alloc_vector(&obj->clsf);
    g_vec_dip         = bve_alloc_vector(&obj->clsf);
    g_vec_sport_exact = bve_alloc_vector(&obj->clsf);
    g_vec_sport_any   = bve_alloc_vector(&obj->clsf);
    g_vec_dport_exact = bve_alloc_vector(&obj->clsf);
    g_vec_dport_any   = bve_alloc_vector(&obj->clsf);
    obj->inter[0]     = g_vec_inter;

    char line[256];
    int mode = 0;
    int rule_idx = 0;
    uint32_t p_sip = 0, p_dip = 0, r_sip, r_dip, r_sport, r_dport;
    uint16_t p_sport = 0, p_dport = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "[PACKET]", 8) == 0) { mode = 1; continue; }
        if (strncmp(line, "[RULES]", 7) == 0)  { mode = 2; continue; }
        if (line[0] == '\n' || line[0] == '#') continue;

        if (mode == 1) {
            sscanf(line, "%u,%u,%hu,%hu", &p_sip, &p_dip, &p_sport, &p_dport);
            pkt.indev = 0;
            pkt.bhs.ether_type = ETHERTYPE_IP;
            pkt.bhs.Protocol = IPPROTO_TCP;
            pkt.bhs.ip_src = p_sip;
            pkt.bhs.ip_dst = p_dip;
            pkt.bhs.sport = p_sport;
            pkt.bhs.dp.dport = p_dport;
        } else if (mode == 2) {
            sscanf(line, "%u,%u,%u,%u", &r_sip, &r_dip, &r_sport, &r_dport);

            // 인터페이스는 모두 매칭 통과라고 가정
            bve_set_bit(&obj->clsf, &g_vec_inter, rule_idx);

            // 패킷과 매칭되는 룰셋에만 비트 세팅
            if (r_sip == p_sip) bve_set_bit(&obj->clsf, &g_vec_sip, rule_idx);
            if (r_dip == p_dip) bve_set_bit(&obj->clsf, &g_vec_dip, rule_idx);

            if (r_sport == p_sport)  bve_set_bit(&obj->clsf, &g_vec_sport_exact, rule_idx);
            if (r_sport == ANY_PORT) bve_set_bit(&obj->clsf, &g_vec_sport_any, rule_idx);

            if (r_dport == p_dport)  bve_set_bit(&obj->clsf, &g_vec_dport_exact, rule_idx);
            if (r_dport == ANY_PORT) bve_set_bit(&obj->clsf, &g_vec_dport_any, rule_idx);

            rule_idx++;
        }
    }
    fclose(fp);

    volatile int dummy = 0;
    double start, end;

    // ---------------------------------------------------
    // [추가] 웜업(Warm-up) 구간
    // CPU 클럭을 최고조로 올리고 분기 예측기를 안정화합니다.
    // ---------------------------------------------------
    printf("[*] 웜업(Warm-up) 진행 중... (CPU 상태 안정화)\n");
    for (int i = 0; i < 1000000; i++) {
        dummy += EvaluatePacket_Legacy(&pkt, NULL, 0);
        dummy += EvaluatePacket_Optimized(&pkt, NULL, 0);
    }

    // ---------------------------------------------------
    // [수정] 반복 횟수 10배 증가 (200만 -> 2000만)
    // ---------------------------------------------------
    const int ITERATIONS = 20000000; 

    printf("[*] 외부 파일 데이터 기반 벤치마크 (로드된 룰: %d, 패킷 반복: %d)\n", rule_idx, ITERATIONS);
    printf("---------------------------------------------------\n");

    // 구버전 로직 측정
    start = get_time_sec();
    for (int i = 0; i < ITERATIONS; i++) dummy += EvaluatePacket_Legacy(&pkt, NULL, 0);
    end = get_time_sec();
    double old_time = end - start;

    printf("[구버전 로직 - 2회 검색]\n");
    printf(" - 소요 시간 : %.4f sec\n", old_time);
    printf(" - 처리 속도 : %.2f Mpps\n\n", (ITERATIONS / old_time) / 1e6);

    // 신버전 로직 측정
    start = get_time_sec();
    for (int i = 0; i < ITERATIONS; i++) dummy += EvaluatePacket_Optimized(&pkt, NULL, 0);
    end = get_time_sec();
    double new_time = end - start;

    printf("[신버전(최적화) 로직 - 1회 CNF 검색]\n");
    printf(" - 소요 시간 : %.4f sec\n", new_time);
    printf(" - 처리 속도 : %.2f Mpps\n\n", (ITERATIONS / new_time) / 1e6);

    printf("===================================================\n");
    printf("=> 결과: 신버전 로직이 구버전 대비 %.1f%% 빠름.\n", ((old_time - new_time) / old_time) * 100);
    printf("===================================================\n");

    return 0;
}
