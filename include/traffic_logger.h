#include <linux/rhashtable.h>
#include <linux/etherdevice.h> 

struct mac_info {
	uint32_t key;
    char mac_s[ETH_ALEN];
	struct rhash_head linkage;
	uint32_t counter;
	refcount_t ref;
	struct rcu_head rcu_read;
};