#include <linux/types.h>
#include <traffic_logger.h>

#define BUFFER_SIZE 1000

// struct circ_buffer {
//     struct packet_info *buffer[BUFFER_SIZE];
//     atomic_t head;
//     atomic_t tail;
// }