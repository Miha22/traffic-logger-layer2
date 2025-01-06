#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/fs.h>

#include <traffic_logger.h>

#define DUMP_PERIOD 10000