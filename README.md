## Ethernet layer 2 traffic logger
A linux kernel module that:

- intercepts all network packets (regardless of the protocol - including IP, IPv6, ARP, etc.) that come through any of the ethernet interfaces before they are processed by the network protocol code
- accumulates information about the number of packets received from each unique mac address by storing in a hash table, where the mac address is used as the key
>after "inspecting" the received packet, the normal kernel packet processing should continue (the packet should not be dropped)
- makes the stored information available in the /proc file system file
- once every 10 seconds the accumulated information is deleted and the accounting is restarted
>if the entry corresponding to the mac address of the received package is already in the hash table, then processing must be done without acquiring any locks
- works correctly on a multiprocessor system

### Features
- Uses Netfilter hook with **NFPROTO_NETDEV** protocol family flag to capture "non-IP traffic" - Layer 2 traffic at incoming state with specified **NF_NETDEV_INGRESS** flag, which will include the IP traffic implicitly. 

- I started testing with popular ethernet protocols:
```
static int32_t whitelist_proto[65536] = {
    [ETH_P_IP] = 1,
    [ETH_P_IPV6] = 1,
    [ETH_P_ARP] = 1,
    [ETH_P_RARP] = 1,
    [ETH_P_MPLS_UC] = 1,
    [ETH_P_BATMAN] = 1,
    [ETH_P_LLDP] = 1,
};
```
#### **[UPD. 23.12.2024]**
Later I might consider checking eth_hdr's protocol **ETH_P_ALL** to capture all ethernet procols and loggin them, but that might overwhelm the system. There is a need to decrease the load by filtering out irrelevant protocols traffic such as loopback frames, slow protocol frames, 802 vlan frames, experimental, deprecated etc. 

### Prerequisites
- ```apt-get install raspberrypi-kernel-headers linux-headers-$(uname -r)```

### Build
- ```make``` - creates build directory with .ko module
- ```make clean```- removes build direcory and supplementary meta files.