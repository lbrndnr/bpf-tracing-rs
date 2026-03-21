#ifndef __BPFLOG_H__
#define __BPFLOG_H__

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
        #define bpf_error(fmt, ...) bpf_printk("[bpflog error] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 2
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(...) (0)
        #define bpf_warn(fmt, ...) bpf_printk("[bpflog warn] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[bpflog error] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 3
        #define bpf_trace(...) (0)
        #define bpf_debug(...) (0)
        #define bpf_info(fmt, ...) bpf_printk("[bpflog info] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[bpflog warn] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[bpflog error] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 4
        #define bpf_trace(...) (0)
        #define bpf_debug(fmt, ...) bpf_printk("[bpflog debug] " fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_printk("[bpflog info] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[bpflog warn] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[bpflog error] " fmt, ##__VA_ARGS__)
    #elif BPF_LOG_LEVEL == 5
        #define bpf_trace(fmt, ...) bpf_printk("[bpflog trace] " fmt, ##__VA_ARGS__)
        #define bpf_debug(fmt, ...) bpf_printk("[bpflog debug] " fmt, ##__VA_ARGS__)
        #define bpf_info(fmt, ...) bpf_printk("[bpflog info] " fmt, ##__VA_ARGS__)
        #define bpf_warn(fmt, ...) bpf_printk("[bpflog warn] " fmt, ##__VA_ARGS__)
        #define bpf_error(fmt, ...) bpf_printk("[bpflog error] " fmt, ##__VA_ARGS__)
    #endif
#else
    #define bpf_trace(...) (0)
    #define bpf_debug(...) (0)
    #define bpf_info(...) (0)
    #define bpf_warn(...) (0)
    #define bpf_error(...) (0)
#endif

#endif // __BPFLOG_H__
