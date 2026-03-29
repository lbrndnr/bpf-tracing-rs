#ifndef __BPF_TRACING_RS_H__
#define __BPF_TRACING_RS_H__

#define BPF_LOG_LEVEL_NONE 0
#define BPF_LOG_LEVEL_ERROR 1
#define BPF_LOG_LEVEL_WARN 2
#define BPF_LOG_LEVEL_INFO 3
#define BPF_LOG_LEVEL_DEBUG 4
#define BPF_LOG_LEVEL_TRACE 5

#ifdef BPF_LOG_LEVEL

    #if BPF_LOG_LEVEL == BPF_LOG_LEVEL_ERROR
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(...) (0)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(...) (0)
        #define bpf_start_warn_span(...) (0)
        #define bpf_start_error_span(fmt, ...) bpf_printk("[>ERROR] " fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_printk("[<] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_WARN
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(...) (0)
        #define bpf_start_warn_span(fmt, ...) bpf_printk("[>WARN] " fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_printk("[>ERROR] " fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_printk("[<] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_INFO
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(fmt, ...) bpf_printk("[>INFO] " fmt, ##__VA_ARGS__)
        #define bpf_start_warn_span(fmt, ...) bpf_printk("[>WARN] " fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_printk("[>ERROR] " fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_printk("[<] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_DEBUG
        #define bpf_trace(...) (0)
        #define bpf_debug(fmt, ...) bpf_printk("[DEBUG] " fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(fmt, ...) bpf_printk("[>DEBUG] " fmt, ##__VA_ARGS__)
        #define bpf_start_info_span(fmt, ...) bpf_printk("[>INFO] " fmt, ##__VA_ARGS__)
        #define bpf_start_warn_span(fmt, ...) bpf_printk("[>WARN] " fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_printk("[>ERROR] " fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_printk("[<] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_TRACE
        #define bpf_trace(fmt, ...) bpf_printk("[TRACE] " fmt, ##__VA_ARGS__)
        #define bpf_debug(fmt, ...) bpf_printk("[DEBUG] " fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(fmt, ...) bpf_printk("[>TRACE] " fmt, ##__VA_ARGS__)
        #define bpf_start_debug_span(fmt, ...) bpf_printk("[>DEBUG] " fmt, ##__VA_ARGS__)
        #define bpf_start_info_span(fmt, ...) bpf_printk("[>INFO] " fmt, ##__VA_ARGS__)
        #define bpf_start_warn_span(fmt, ...) bpf_printk("[>WARN] " fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_printk("[>ERROR] " fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_printk("[<] " fmt, ##__VA_ARGS__)
    #else
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(...) (0)
        #define bpf_error(...) (0)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(...) (0)
        #define bpf_start_warn_span(...) (0)
        #define bpf_start_error_span(...) (0)
        #define bpf_end_span(...) (0)
    #endif

#else

#define bpf_trace(...) (0)
#define bpf_debug(...) (0)
#define bpf_info(...) (0)
#define bpf_warn(...) (0)
#define bpf_error(...) (0)

#define bpf_start_trace_span(...) (0)
#define bpf_start_debug_span(...) (0)
#define bpf_start_info_span(...) (0)
#define bpf_start_warn_span(...) (0)
#define bpf_start_error_span(...) (0)
#define bpf_end_span(...) (0)

#endif

#endif // __BPF_TRACING_RS_H__
