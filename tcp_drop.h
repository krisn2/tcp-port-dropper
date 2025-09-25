#ifndef __TCP_DROP_H__
#define __TCP_DROP_H__

#include <linux/types.h>

// Map key structure
struct port_key {
    __u32 port;
};

// Map value structure  
struct port_value {
    __u64 packet_count;
    __u64 drop_count;
};

// Configuration structure
struct config {
    __u32 target_port;
    __u32 enabled;
};

#define MAX_PORTS 1024

#endif /* __TCP_DROP_H__ */
