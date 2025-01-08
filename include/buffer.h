#include <traffic_logger.h>

struct ring_buffer {
    void *buffer[BUF_SIZE];
    signed long int head;
    uint32_t tail;
};