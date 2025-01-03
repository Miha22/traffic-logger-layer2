#include <linux/types.h>
#include <traffic_logger.h>

#define BUF_SIZE 1000
#define BATCH_SIZE 100

struct ring_buffer {
    void *buffer[BUF_SIZE];
    uint32_t head;
    uint32_t tail;
};