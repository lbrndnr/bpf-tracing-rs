#ifndef __BPF_TRACING_RS_H__
#define __BPF_TRACING_RS_H__

#define BPF_LOG_LEVEL_NONE 0
#define BPF_LOG_LEVEL_ERROR 1
#define BPF_LOG_LEVEL_WARN 2
#define BPF_LOG_LEVEL_INFO 3
#define BPF_LOG_LEVEL_DEBUG 4
#define BPF_LOG_LEVEL_TRACE 5

#ifdef BPF_LOG_LEVEL

    #ifdef BPF_LOG_FILE_INFO
        #define bpf_print_rich(level, fmt, ...) bpf_printk("[%s|%s:%d] " fmt, level, __FILE__, __LINE__, ##__VA_ARGS__)
    #else
        #define bpf_print_rich(level, fmt, ...) bpf_printk("[%s] " fmt, level, ##__VA_ARGS__)
    #endif

    #if BPF_LOG_LEVEL == BPF_LOG_LEVEL_ERROR
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(...) (0)
        #define bpf_error(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(...) (0)
        #define bpf_start_warn_span(...) (0)
        #define bpf_start_error_span(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_print_rich("<", fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_WARN
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(...) (0)
        #define bpf_start_warn_span(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_print_rich("<", fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_INFO
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(fmt, ...) bpf_print_rich("INFO", fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(...) (0)
        #define bpf_start_info_span(fmt, ...) bpf_print_rich("INFO", fmt, ##__VA_ARGS__)
        #define bpf_start_warn_span(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_print_rich("<", fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_DEBUG
        #define bpf_trace(...) (0)
        #define bpf_debug(fmt, ...) bpf_print_rich("DEBUG", fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_print_rich("INFO", fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(...) (0)
        #define bpf_start_debug_span(fmt, ...) bpf_print_rich("DEBUG", fmt, ##__VA_ARGS__)
        #define bpf_start_info_span(fmt, ...) bpf_print_rich("INFO", fmt, ##__VA_ARGS__)
        #define bpf_start_warn_span(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_print_rich("<", fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == BPF_LOG_LEVEL_TRACE
        #define bpf_trace(fmt, ...) bpf_print_rich("TRACE", fmt, ##__VA_ARGS__)
        #define bpf_debug(fmt, ...) bpf_print_rich("DEBUG", fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_print_rich("INFO", fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)

        #define bpf_start_trace_span(fmt, ...) bpf_print_rich("TRACE", fmt, ##__VA_ARGS__)
        #define bpf_start_debug_span(fmt, ...) bpf_print_rich("DEBUG", fmt, ##__VA_ARGS__)
        #define bpf_start_info_span(fmt, ...) bpf_print_rich("INFO", fmt, ##__VA_ARGS__)
        #define bpf_start_warn_span(fmt, ...) bpf_print_rich("WARN", fmt, ##__VA_ARGS__)
        #define bpf_start_error_span(fmt, ...) bpf_print_rich("ERROR", fmt, ##__VA_ARGS__)
        #define bpf_end_span(fmt, ...) bpf_print_rich("<", fmt, ##__VA_ARGS__)
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
