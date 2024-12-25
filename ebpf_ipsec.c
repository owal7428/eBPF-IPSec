// ebpf_ipsec.c
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800     /* Internet Protocol packet */
#define IP_PROTOCOL_UDP 17  /* UDP Protocol */
#define UDP_PORT 12345      /* Target UDP port */

#define P 23
#define G 5

static __u8 keys_generated = 0;
static __u8 first_received = 0;

static __u32 private_key = 0;
static __u32 public_key = 0;
static __u32 other_key = 0;
static __u32 shared_key = 0;

static __u32 num_ingress = 0;
static __u32 num_egress = 0;

// Get pseudo-random number for private key
static __always_inline __u32 generate_private_key(struct __sk_buff *ctx) 
{
    return (bpf_ktime_get_ns() % 1000) + 1;
    //return 5;
}

// Function to calculate G^PK % P
static __always_inline __u32 calc_exponent(__u32 base, __u32 mod, __u32 exp) 
{
    __u32 result = 1;

    while (exp > 0) 
    {
        if (exp % 2 == 1) 
        {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

/// @tchook {"ifindex":2, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process UDP packets
    if (ip->protocol != IP_PROTOCOL_UDP)
        return TC_ACT_OK;
    
    // Parse UDP header
    udp = (struct udphdr *)((__u8 *)ip + (ip->ihl * 4));
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    // Only look at packets from or to port 12345
    if (udp->dest != bpf_htons(UDP_PORT) && udp->source != bpf_htons(UDP_PORT))
        return TC_ACT_OK;
    
    num_ingress += 1;
    
    // Get UDP payload
    void *payload = (void *)(udp + 1);
    if (payload >= data_end)
        return TC_ACT_OK;
    
    __u16 udp_len = bpf_ntohs(udp->len) - sizeof(*udp);

    if (first_received == 0)
    {
        first_received = 1;
        bpf_probe_read_kernel(&other_key, sizeof(other_key), payload);
        bpf_printk("Received public key: %u", other_key);

        if (other_key != 0 && private_key != 0)
        {
            shared_key = calc_exponent(other_key, P, private_key);
            bpf_printk("Shared key: %u", shared_key);
        }   
    }
    else
    {
        if (payload + udp_len > data_end)
            return TC_ACT_OK;

        bpf_printk("Direction: Ingress, payload len: %d, Message: %s", udp_len - 1, payload);
        bpf_printk("Number of ingresses: %u", num_ingress);

        // Put decrypted message into the payload
        for (int i = 0; i < 20; i++)
        {
            if ((payload + i) >= data_end || (i >= udp_len))
                break;
            
            __u8 *curret_char = (__u8*)(payload) + i;
            
            *curret_char ^= (shared_key >> (8 * (i % sizeof(shared_key)))) & 0xFF;
        }

        bpf_printk("Received Unencrypted Message: %s", payload);
    }

    return TC_ACT_OK;
}

/// @tchook {"ifindex":2, "attach_point":"BPF_TC_EGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process UDP packets
    if (ip->protocol != IP_PROTOCOL_UDP)
        return TC_ACT_OK;
    
    // Parse UDP header
    udp = (struct udphdr *)((__u8 *)ip + (ip->ihl * 4));
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    // Only look at packets from or to port 12345
    if (udp->dest != bpf_htons(UDP_PORT) && udp->source != bpf_htons(UDP_PORT))
        return TC_ACT_OK;
    
    num_egress += 1;
    
    // Get UDP payload
    void *payload = (void *)(udp + 1);
    if (payload >= data_end)
        return TC_ACT_OK;
    
    __u16 udp_len = bpf_ntohs(udp->len) - sizeof(*udp);

    __u8 message[64] = {};

    if (keys_generated == 0)
    {
        keys_generated = 1;
        private_key = generate_private_key(ctx);
        public_key = calc_exponent(G, P, private_key);

        bpf_printk("Generated keys-> Private:%u, Public:%u", private_key, public_key);

        memcpy(message, &public_key, sizeof(public_key));

        if (payload + sizeof(public_key) <= data_end) 
        {
            // Replace the payload with the public key
            bpf_skb_store_bytes(ctx, (unsigned long)payload - (unsigned long)data, message, sizeof(public_key), 0);
            bpf_printk("Replaced message with public key: %u", public_key);
        } 
        else 
        {
            bpf_printk("Not enough space in the payload to insert public key.");
            keys_generated = 0;
        }

        if (other_key != 0 && private_key != 0)
        {
            shared_key = calc_exponent(other_key, P, private_key);
            bpf_printk("Shared key: %u", shared_key);
        }
    }
    else
    {
        if (payload + udp_len > data_end)
            return TC_ACT_OK;

        bpf_printk("Direction: Egress, payload len: %d, Message: %s", udp_len - 1, payload);
        bpf_printk("Number of egresses: %u", num_egress);

        // Put encrypted message into the payload

        for (int i = 0; i < 20; i++)
        {
            if ((payload + i) >= data_end || (i >= udp_len))
                break;
            
            __u8 *curret_char = (__u8*)(payload) + i;
            
            *curret_char ^= (shared_key >> (8 * (i % sizeof(shared_key)))) & 0xFF;
        }

        bpf_printk("Sending Encrypted Message: %s", payload);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
