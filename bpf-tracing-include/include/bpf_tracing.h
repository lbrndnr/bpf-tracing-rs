#ifndef __BPF_TRACING_RS_H__
#define __BPF_TRACING_RS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum log_level {
    BPF_LOG_LEVEL_OFF=0,
    BPF_LOG_LEVEL_ERROR,
    BPF_LOG_LEVEL_WARN,
    BPF_LOG_LEVEL_INFO,
    BPF_LOG_LEVEL_DEBUG,
    BPF_LOG_LEVEL_TRACE,
};

#ifndef BPF_LOG_LEVEL
#define BPF_LOG_LEVEL BPF_LOG_LEVEL_OFF
#endif

enum tracing_event_type {
    TRACING_EVENT_TYPE_MSG = 0,
    TRACING_EVENT_TYPE_SPAN_START,
    TRACING_EVENT_TYPE_SPAN_END,
};

#define BPF_TRACING_STR_LEN 100

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1000);
} bpf_tracing_events SEC(".maps");

#ifdef BPF_LOG_FILE_INFO
struct bpf_tracing_event {
    __u8 level;
    __u8 kind;
    __u16 cpu;
    char msg[BPF_TRACING_STR_LEN];
    char file[BPF_TRACING_STR_LEN];
    __u32 line;
};

#define BPF_TRACING_EMIT_EVENT(lvl, ty, fmt, ...)                     \
    do {                                                              \
        struct bpf_tracing_event *event;                              \
        event = bpf_ringbuf_reserve(&bpf_tracing_events, sizeof(*event), 0);      \
        if (!event) {                                                 \
            break;                                                    \
        }                                                             \
        event->level = (__u8)(lvl);                                   \
        event->kind = (__u8)(ty);                                     \
        event->cpu = (__u16)(bpf_get_smp_processor_id);               \
        BPF_SNPRINTF(event->msg, BPF_TRACING_STR_LEN, fmt, ##__VA_ARGS__); \
        BPF_SNPRINTF(event->file, BPF_TRACING_STR_LEN, "%s", __FILE__);  \
        event->line = (__u32)__LINE__;                                \
        bpf_ringbuf_submit(event, 0);                                 \
    } while (0)
#else
struct bpf_tracing_event {
    __u8 level;
    __u8 kind;
    __u16 _pad;
    char msg[BPF_TRACING_STR_LEN];
};

#define BPF_TRACING_EMIT_EVENT(lvl, ty, fmt, ...)                     \
    do {                                                              \
        struct bpf_tracing_event *event;                              \
        event = bpf_ringbuf_reserve(&bpf_tracing_events, sizeof(*event), 0);      \
        if (!event) {                                                 \
            break;                                                    \
        }                                                             \
        event->level = (__u8)(lvl);                                   \
        event->kind = (__u8)(ty);                                     \
        BPF_SNPRINTF(event->msg, BPF_TRACING_STR_LEN, fmt, ##__VA_ARGS__); \
        bpf_ringbuf_submit(event, 0);                                 \
    } while (0)
#endif

#if BPF_LOG_LEVEL == BPF_LOG_LEVEL_OFF
    #define bpf_end_span(fmt, ...) (0)
#else
    #define bpf_end_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_OFF, TRACING_EVENT_TYPE_SPAN_END, "")
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_ERROR
    #define bpf_error(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_ERROR, TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_error_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_ERROR, TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_error(fmt, ...) (0)
    #define bpf_start_error_span(fmt, ...) (0)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_WARN
    #define bpf_warn(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_WARN, TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_warn_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_WARN, TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_warn(fmt, ...) (0)
    #define bpf_start_warn_span(fmt, ...) (0)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_INFO
    #define bpf_info(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_INFO, TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_info_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_INFO, TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_info(fmt, ...) (0)
    #define bpf_start_info_span(fmt, ...) (0)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_DEBUG
    #define bpf_debug(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_DEBUG, TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_debug_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_DEBUG, TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_debug(fmt, ...) (0)
    #define bpf_start_debug_span(fmt, ...) (0)
#endif

#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_TRACE
    #define bpf_trace(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_TRACE, TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_trace_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_LOG_LEVEL_TRACE, TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_trace(fmt, ...) (0)
    #define bpf_start_trace_span(fmt, ...) (0)
#endif

#endif // __BPF_TRACING_RS_H__
