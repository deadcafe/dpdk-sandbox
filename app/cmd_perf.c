
#include <papi.h>

#include "eng_cmd.h"
#include "eng_cli.h"
#include "eng_thread.h"
#include "eng_log.h"
#include "app_modules.h"

struct cmd_perf_arg_s {
    union {
        struct {
            float rtime;
            float ptime;
            float ipc;
            long long ins;
        } inst;

        struct {
            unsigned nb;
            int events[3];
            long long counters[3];
        } low;
    };
} __attribute__((packed));

/****************************************************************************
 * CMD handler
 ****************************************************************************/
static int
perf_inst_handler(struct eng_cmd_s *cmd)
{
    struct cmd_perf_arg_s *arg = (struct cmd_perf_arg_s *) cmd->data;
    int ret = PAPI_ipc(&arg->inst.rtime, &arg->inst.ptime,
                       &arg->inst.ins, &arg->inst.ipc);

    ENG_DEBUG(TASKCMD, "end: ret:%d ipc:%0.3f ins:%lld",
              ret, arg->inst.ipc, arg->inst.ins);
    return ret;
}

static int
perf_events_start_handler(struct eng_cmd_s *cmd)
{
    struct cmd_perf_arg_s *arg = (struct cmd_perf_arg_s *) cmd->data;
    int ret;

    ENG_DEBUG(TASKCMD, "statrt: nb:%u", arg->low.nb);
    if (arg->low.nb == 0 || arg->low.nb > RTE_DIM(arg->low.events)) {
        ret = -EINVAL;
    } else {
        ret = PAPI_start_counters(arg->low.events, arg->low.nb);
    }
    ENG_DEBUG(TASKCMD, "end: ret:%d", ret);
    return ret;
}

static int
perf_events_stop_handler(struct eng_cmd_s *cmd)
{
    struct cmd_perf_arg_s *arg = (struct cmd_perf_arg_s *) cmd->data;
    int ret = PAPI_stop_counters(arg->low.counters, arg->low.nb);

    ENG_DEBUG(TASKCMD, "end: ret:%d", ret);
    return ret;
}


#define PERF_INST		"PerfInstruction"
#define PERF_EVENTS_START	"PerfEventsStart"
#define PERF_EVENTS_STOP	"PerfEventsStop"

int
cmd_perf_init(void)
{
    ENG_ERR(TASKCMD, "start");

    int ret;

    ret = eng_cmd_register(PERF_INST, perf_inst_handler);
    ret |= eng_cmd_register(PERF_EVENTS_START, perf_events_start_handler);
    ret |= eng_cmd_register(PERF_EVENTS_STOP, perf_events_stop_handler);

    ENG_ERR(TASKCMD, "end:%d", ret);
    return ret;
}

/****************************************************************************
 * CLI code
 ****************************************************************************/
struct event_s {
    int code;
    const char *name;
    const char *desc;
};

static int
perf_counter(FILE *fp,
             unsigned thread_id,
             unsigned sec,
             const struct event_s *events,
             long long *counters,
             unsigned nb)
{
    int ret;
    struct cmd_perf_arg_s arg;

    memset(&arg, 0, sizeof(arg));

    if (!nb || nb > RTE_DIM(arg.low.events) || !events)
        return -EINVAL;

    arg.low.nb = nb;
    for (unsigned i = 0; i < nb; i++)
        arg.low.events[i] = events[i].code;

    ret = eng_cmd_request(thread_id, PERF_EVENTS_START, &arg, sizeof(arg));
    if (!ret) {
        sleep(sec);
        ret = eng_cmd_request(thread_id, PERF_EVENTS_STOP, &arg, sizeof(arg));
        if (!ret) {
             for (unsigned i = 0; i< nb; i++) {
                 fprintf(fp, "%s (%s): %lld ",
                         events[i].name, events[i].desc, arg.low.counters[i]);
                if (counters)
                    counters[i] =  arg.low.counters[i];
            }
            fprintf(fp, "\n");
        }
    }
    return ret;
}

static int
perf_ipc(FILE *fp,
         unsigned th_id,
         int sec)
{
    const struct event_s events[] = {
        { PAPI_TOT_INS, "TOT_INS", "", },
        { PAPI_TOT_CYC, "TOT_CYC", "", },
        { PAPI_REF_CYC, "REF_CYC", "", },
    };
    long long val[RTE_DIM(events)];

    ENG_DEBUG(TASKCMD, "start");

    int ret = perf_counter(fp, th_id, sec, events, val, RTE_DIM(events));
    if (!ret)
        fprintf(fp, "ipc:%0.3f\n", (float) val[0] / (float) val[1]);

    ENG_DEBUG(TASKCMD, "end:%d", ret);
    return ret;
}

static int
perf_cache1(FILE *fp,
            unsigned th_id,
            int sec)
{
    const struct event_s events[] = {
        { PAPI_L1_DCM, "L1_DCM", "", },
        { PAPI_L2_DCM, "L2_DCM", "", },
    };

    ENG_DEBUG(TASKCMD, "start");

    int ret = perf_counter(fp, th_id, sec, events, NULL, RTE_DIM(events));

    ENG_DEBUG(TASKCMD, "end:%d", ret);
    return ret;
}

static int
perf_cache2(FILE *fp,
            unsigned th_id,
            int sec)
{
    const struct event_s events[] = {
        { PAPI_L2_DCH, "L2_DCH", "", },
        { PAPI_L2_DCM, "L2_DCM", "", },
        //        { PAPI_L3_TCA, "L3_TCA", },
        //        { PAPI_L1_DCM, "L1_DCM", },
    };
    long long val[RTE_DIM(events)];

    ENG_DEBUG(TASKCMD, "start");

    int ret = perf_counter(fp, th_id, sec, events, val, RTE_DIM(events));
    if (!ret)
        fprintf(fp, "L2 hit rate:%0.3f\n", (float) val[0] / (float) (val[0] + val[1]));

    ENG_DEBUG(TASKCMD, "end:%d", ret);
    return ret;
}

static int
perf_tlb(FILE *fp,
         unsigned th_id,
         int sec)
{
    const struct event_s events[] = {
        { PAPI_TLB_DM, "TLB_DM", "", },
        { PAPI_TLB_IM, "TLB_IM", "", },
    };

    ENG_DEBUG(TASKCMD, "start");

    int ret = perf_counter(fp, th_id, sec, events, NULL, RTE_DIM(events));

    ENG_DEBUG(TASKCMD, "end:%d", ret);
    return ret;
}

static int
perf_all(FILE *fp,
         unsigned th_id,
         int sec)
{
    const struct event_s events[] = {
        { PAPI_L1_DCM,  "PAPI_L1_DCM",  "L1 data cache misses", },
        { PAPI_L1_ICM,  "PAPI_L1_ICM",  "L1 instruction cache misses", },
        { PAPI_L1_TCM,  "PAPI_L1_TCM",  "L1 cache misses", },
        { PAPI_L1_LDM,  "PAPI_L1_LDM",  "L1 load misses", },
        { PAPI_L1_STM,  "PAPI_L1_STM",  "L1 store misses", },
        { PAPI_L1_DCH,  "PAPI_L1_DCH",  "L1 data cache hits", },
        { PAPI_L1_DCA,  "PAPI_L1_DCA",  "L1 data cache accesses", },
        { PAPI_L1_DCR,  "PAPI_L1_DCR",  "L1 data cache reads", },
        { PAPI_L1_DCW,  "PAPI_L1_DCW",  "L1 data cache writes", },
        { PAPI_L1_ICH,  "PAPI_L1_ICH",  "L1 instruction cache hits", },
        { PAPI_L1_ICA,  "PAPI_L1_ICA",  "L1 instruction cache accesses", },
        { PAPI_L1_ICR,  "PAPI_L1_ICR",  "L1 instruction cache reads", },
        { PAPI_L1_ICW,  "PAPI_L1_ICW",  "L1 instruction cache writes", },
        { PAPI_L1_TCH,  "PAPI_L1_TCH",  "L1 total cache hits", },
        { PAPI_L1_TCA,  "PAPI_L1_TCA",  "L1 total cache accesses", },
        { PAPI_L1_TCR,  "PAPI_L1_TCR",  "L1 total cache reads", },
        { PAPI_L1_TCW,  "PAPI_L1_TCW",  "L1 total cache writes", },

        { PAPI_L2_DCM,  "PAPI_L2_DCM",  "L2 data cache misses", },
        { PAPI_L2_ICM,  "PAPI_L2_ICM",  "L2 instruction cache misses", },
        { PAPI_L2_TCM,  "PAPI_L2_TCM",  "L2 cache misses", },
        { PAPI_L2_LDM,  "PAPI_L2_LDM",  "L2 load misses", },
        { PAPI_L2_STM,  "PAPI_L2_STM",  "L2 store misses", },
        { PAPI_L2_DCH,  "PAPI_L2_DCH",  "L2 data cache hits", },
        { PAPI_L2_DCA,  "PAPI_L2_DCA",  "L2 data cache accesses", },
        { PAPI_L2_DCR,  "PAPI_L2_DCR",  "L2 data cache reads", },
        { PAPI_L2_DCW,  "PAPI_L2_DCW",  "L2 data cache writes", },
        { PAPI_L2_ICH,  "PAPI_L2_ICH",  "L2 instruction cache hits", },
        { PAPI_L2_ICA,  "PAPI_L2_ICA",  "L2 instruction cache accesses", },
        { PAPI_L2_ICR,  "PAPI_L2_ICR",  "L2 instruction cache reads", },
        { PAPI_L2_ICW,  "PAPI_L2_ICW",  "L2 instruction cache writes", },
        { PAPI_L2_TCH,  "PAPI_L2_TCH",  "L2 total cache hits", },
        { PAPI_L2_TCA,  "PAPI_L2_TCA",  "L2 total cache accesses", },
        { PAPI_L2_TCR,  "PAPI_L2_TCR",  "L2 total cache reads", },
        { PAPI_L2_TCW,  "PAPI_L2_TCW",  "L2 total cache writes", },

        { PAPI_L3_DCM,  "PAPI_L3_DCM",  "L3 data cache misses", },
        { PAPI_L3_ICM,  "PAPI_L3_ICM",  "L3 instruction cache misses", },
        { PAPI_L3_TCM,  "PAPI_L3_TCM",  "L3 cache misses", },
        { PAPI_L3_LDM,  "PAPI_L3_LDM",  "L3 load misses", },
        { PAPI_L3_STM,  "PAPI_L3_STM",  "L3 store misses", },
        { PAPI_L3_DCH,  "PAPI_L3_DCH",  "L3 data cache hits", },
        { PAPI_L3_DCA,  "PAPI_L3_DCA",  "L3 data cache accesses", },
        { PAPI_L3_DCR,  "PAPI_L3_DCR",  "L3 data cache reads", },
        { PAPI_L3_DCW,  "PAPI_L3_DCW",  "L3 data cache writes", },
        { PAPI_L3_ICH,  "PAPI_L3_ICH",  "L3 instruction cache hits", },
        { PAPI_L3_ICA,  "PAPI_L3_ICA",  "L3 instruction cache accesses", },
        { PAPI_L3_ICR,  "PAPI_L3_ICR",  "L3 instruction cache reads", },
        { PAPI_L3_ICW,  "PAPI_L3_ICW",  "L3 instruction cache writes", },
        { PAPI_L3_TCH,  "PAPI_L3_TCH",  "L3 total cache hits", },
        { PAPI_L3_TCA,  "PAPI_L3_TCA",  "L3 total cache accesses", },
        { PAPI_L3_TCR,  "PAPI_L3_TCR",  "L3 total cache read", },
        { PAPI_L3_TCW,  "PAPI_L3_TCW",  "L3 total cache writes", },

        { PAPI_CA_SNP,  "PAPI_CA_SNP",  "Requests for a snoop", },
        { PAPI_CA_SHR,  "PAPI_CA_SHR",  "Requests for exclusive access to shared cache line", },
        { PAPI_CA_CLN,  "PAPI_CA_CLN",  "Requests for exclusive access to clean cache line", },
        { PAPI_CA_INV,  "PAPI_CA_INV",  "Requests for cache line invalidation", },
        { PAPI_CA_ITV,  "PAPI_CA_ITV",  "Requests for cache line intervention", },

        { PAPI_TLB_DM,  "PAPI_TLB_DM",  "Data translation lookaside buffer misses", },
        { PAPI_TLB_IM,  "PAPI_TLB_IM",  "Instruction translation lookaside buffer misses", },
        { PAPI_TLB_TL,  "PAPI_TLB_TL",  "Total translation lookaside buffer misses", },
        { PAPI_TLB_SD,  "PAPI_TLB_SD",  "Translation lookaside buffer shootdowns", },

        { PAPI_FMA_INS, "PAPI_FMA_INS", "FMA instructions completed", },
        { PAPI_TOT_IIS, "PAPI_TOT_IIS", "Instructions issued", },
        { PAPI_TOT_INS, "PAPI_TOT_INS", "Instructions completed", },
        { PAPI_INT_INS, "PAPI_INT_INS", "Integer instructions", },
        { PAPI_FP_INS,  "PAPI_FP_INS",  "Floating point instructions", },
        { PAPI_LD_INS,  "PAPI_LD_INS",  "Load instructions", },
        { PAPI_SR_INS,  "PAPI_SR_INS",  "Store instructions", },
        { PAPI_BR_INS,  "PAPI_BR_INS",  "Branch instructions", },
        { PAPI_VEC_INS, "PAPI_VEC_INS", "Vector/SIMD instructions", },
        { PAPI_LST_INS, "PAPI_LST_INS", "Load/store instructions completed", },
        { PAPI_SYC_INS, "PAPI_SYC_INS", "Synchronization instructions completed", },
        { PAPI_FML_INS, "PAPI_FML_INS", "Floating point multiply instructions", },
        { PAPI_FAD_INS, "PAPI_FAD_INS", "Floating point add instructions", },
        { PAPI_FDV_INS, "PAPI_FDV_INS", "Floating point divide instructions", },
        { PAPI_FSQ_INS, "PAPI_FSQ_INS", "Floating point square root instructions", },
        { PAPI_FNV_INS, "PAPI_FNV_INS", "Floating point inverse instructions", },
        { PAPI_FP_OPS,  "PAPI_FP_OPS",  "Floating point operations", },
        { PAPI_SP_OPS,  "PAPI_SP_OPS",  "Floating point operations(single)", },
        { PAPI_DP_OPS,  "PAPI_DP_OPS",  "Floating point operations(double)", },
        { PAPI_VEC_SP,  "PAPI_VEC_SP",  "Single precision vector", },
        { PAPI_VEC_DP,  "PAPI_VEC_DP",  "Double precision vector", },

        { PAPI_BRU_IDL, "PAPI_BRU_IDL", "Cycles branch units are idle", },
        { PAPI_FXU_IDL, "PAPI_FXU_IDL", "Cycles integer units are idle", },
        { PAPI_FPU_IDL, "PAPI_FPU_IDL", "Cycles floating point units are idle", },
        { PAPI_LSU_IDL, "PAPI_LSU_IDL", "Cycles load/store units are idle", },

        { PAPI_RES_STL, "PAPI_RES_STL", "Cycles stalled on any resource", },
        { PAPI_FP_STAL, "PAPI_FP_STAL", "Cycles the FP unit(s) are stalled", },
        { PAPI_TOT_CYC, "PAPI_TOT_CYC", "Total cycles", },
        { PAPI_REF_CYC, "PAPI_REF_CYC", "Reference clock cycles", },

        { PAPI_BTAC_M,  "PAPI_BTAC_M",  "Branch target address cache misses", },
        { PAPI_PRF_DM,  "PAPI_PRF_DM",  "Data prefetch cache misses", },
        { PAPI_CSR_FAL, "PAPI_CSR_FAL", "Failed store conditional instructions", },
        { PAPI_CSR_SUC, "PAPI_CSR_SUC", "Successful store conditional instructions", },
        { PAPI_CSR_TOT, "PAPI_CSR_TOT", "Total store conditional instructions", },
        { PAPI_MEM_SCY, "PAPI_MEM_SCY", "Cycles Stalled Waiting for memory accesses", },
        { PAPI_MEM_RCY, "PAPI_MEM_RCY", "Cycles Stalled Waiting for memory Reads", },
        { PAPI_MEM_WCY, "PAPI_MEM_WCY", "Cycles Stalled Waiting for memory writes", },
        { PAPI_STL_ICY, "PAPI_STL_ICY", "Cycles with no instruction issue", },
        { PAPI_FUL_ICY, "PAPI_FUL_ICY", "Cycles with maximum instruction issue", },
        { PAPI_STL_CCY, "PAPI_STL_CCY", "Cycles with no instructions completed", },
        { PAPI_FUL_CCY, "PAPI_FUL_CCY", "Cycles with maximum instructions completed", },
        { PAPI_HW_INT,  "PAPI_HW_INT",  "Hardware interrupts", },
        { PAPI_BR_UCN,  "PAPI_BR_UCN",  "Unconditional branch instructions", },
        { PAPI_BR_CN,   "PAPI_BR_CN",   "Conditional branch instructions", },
        { PAPI_BR_TKN,  "PAPI_BR_TKN",  "Conditional branch instructions taken", },
        { PAPI_BR_NTK,  "PAPI_BR_NTK",  "Conditional branch instructions not taken", },
        { PAPI_BR_MSP,  "PAPI_BR_MSP",  "Conditional branch instructions mispredicted", },
        { PAPI_BR_PRC,  "PAPI_BR_PRC",  "Conditional branch instructions correctly predicted", },

    };

    ENG_DEBUG(TASKCMD, "start");

    for (unsigned i = 0;i < RTE_DIM(events); i++)
        perf_counter(fp, th_id, sec, &events[i], NULL, 1);

    ENG_DEBUG(TASKCMD, "end");
    return 0;
}

enum eng_cli_cmd_type_e {
    CMD_INVALID = -1,

    CMD_PERF_IPC,
    CMD_PERF_CACHE1,
    CMD_PERF_CACHE2,
    CMD_PERF_TLB,
    CMD_PERF_ALL,

    NB_CMDs,
};

static const struct eng_cli_cmd_info_s CliInfos[NB_CMDs] = {
    [CMD_PERF_IPC]    = { "ipc",    "{--thread ID | --core ID} [--second TIME]", },
    [CMD_PERF_CACHE1] = { "cache1", "{--thread ID | --core ID} [--second TIME]", },
    [CMD_PERF_CACHE2] = { "cache2", "{--thread ID | --core ID} [--second TIME]", },
    [CMD_PERF_TLB]    = { "tlb",    "{--thread ID | --core ID} [--second TIME]", },
    [CMD_PERF_ALL]    = { "all",    "{--thread ID | --core ID} [--second TIME]", },
};
/* constructor */
ENG_GENERATE_CLI(Perf, "perf", CliInfos, cli_perf);

static const struct option LongOptions[] = {
    { "cmd",      required_argument, NULL, 'c', },
    { "help",     no_argument,       NULL, 'h', },
    { "thread",   required_argument, NULL, 't', },
    { "core",     required_argument, NULL, 'o', },
    { "second",   required_argument, NULL, 's', },
    { NULL,       0,                 NULL, 0,   },
};

static int
cli_perf(int ac,
         char *av[])
{
    int opt, index;
    int err = 0;
    enum eng_cli_cmd_type_e cmd = CMD_INVALID;
    unsigned thread_id = -1;
    int sec = 1;

    while ((opt = getopt_long(ac, av, "c:t:o:s:h",
                              LongOptions, &index)) != EOF && !err) {
        switch (opt) {
        case 'c':       /* cmd */
            cmd = eng_cli_get_cmd_type(optarg);
            break;

        case 'h':       /* Help */
            CMD_USAGE(Perf);
            return 0;

        case 't':
            thread_id = atoi(optarg);
            break;

        case 'o':
            thread_id = eng_lcore2thread(atoi(optarg));
            break;

        case 's':
            sec = atoi(optarg);
            break;

        default:
            err = -EINVAL;
            break;
        }
    }

    if (!eng_thread_is_valid(thread_id)) {
        fprintf(eng_stdout, "invalid thread_id:%u\n", thread_id);
        err = -EINVAL;
    }
    if (sec < 0) {
        fprintf(eng_stdout, "invalid seconde:%d\n", sec);
        err = -EINVAL;
    }

    if (!err) {
        switch (cmd) {
        case CMD_PERF_IPC:
            err = perf_ipc(eng_stdout, thread_id, sec);
            break;

        case CMD_PERF_CACHE1:
            err = perf_cache1(eng_stdout, thread_id, sec);
            break;

        case CMD_PERF_CACHE2:
            err = perf_cache2(eng_stdout, thread_id, sec);
            break;

        case CMD_PERF_TLB:
            err = perf_tlb(eng_stdout, thread_id, sec);
            break;

        case CMD_PERF_ALL:
            err = perf_all(eng_stdout, thread_id, sec);
            break;

        case CMD_INVALID:
        default:
            fprintf(eng_stdout, "invalid cmd:%d\n", cmd);
            err = -EINVAL;
            break;
        }
    }
    if (err) {
        char buff[80];

        fprintf(eng_stdout, "%s\n", strerror_r(-(err), buff, sizeof(buff)));
        CMD_USAGE(Perf);
    }
    return 0;
}

