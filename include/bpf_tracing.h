#ifndef __BPF_TRACING_H__
#define __BPF_TRACING_H__

#ifdef BPF_LOG_LEVEL
    #if BPF_LOG_LEVEL == 0
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(...) (0)
        #define bpf_error(...) (0)
    #elif BPF_LOG_LEVEL == 1
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(...) (0)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 2
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 3
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 4
        #define bpf_trace(...) (0)
        #define bpf_debug(fmt, ...) bpf_printk("[DEBUG] " fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 5
        #define bpf_trace(fmt, ...) bpf_printk("[TRACE] " fmt, ##__VA_ARGS__)
        #define bpf_debug(fmt, ...) bpf_printk("[DEBUG] " fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)
    #endif
#else
    #define bpf_trace(...) (0)
    #define bpf_debug(...) (0)
    #define bpf_info(...) (0)
    #define bpf_warn(...) (0)
    #define bpf_error(...) (0)
#endif

#endif // __BPF_TRACING_H__
