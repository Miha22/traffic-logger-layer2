#include <traffic_logger.h>

#define BUF_SIZE 1000
#define BATCH_SIZE 100

struct ring_buffer {
    void *buffer[BUF_SIZE];
    signed long int head;//yes long
    uint32_t tail;//yes uint
};