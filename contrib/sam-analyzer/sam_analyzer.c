// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Aggregator Module (SAM) Packet Analyzer
 * 
 * Real-time packet analysis and monitoring for Microsoft Surface devices
 * running Linux. This module provides deep inspection of SAM communication
 * protocols for debugging and development purposes.
 *
 * Author: Jakub Komosa
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/ring_buffer.h>
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/rculist.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>

#define SAM_ANALYZER_VERSION "1.0.0"
#define SAM_PACKET_MAX_SIZE 256
#define SAM_RING_BUFFER_SIZE (1024 * 1024) // 1MB per CPU
#define SAM_HASH_BITS 8

/* SAM packet types based on linux-surface documentation */
enum sam_packet_type {
    SAM_PKT_TYPE_CMD = 0x01,
    SAM_PKT_TYPE_ACK = 0x02,
    SAM_PKT_TYPE_NAK = 0x04,
    SAM_PKT_TYPE_EVENT = 0x08,
    SAM_PKT_TYPE_DATA = 0x10,
};

/* SAM packet structure for analysis */
struct sam_packet {
    ktime_t timestamp;
    enum sam_packet_type type;
    u8 target_category;
    u8 target_id;
    u8 command_id;
    u16 sequence;
    u32 payload_len;
    u8 payload[SAM_PACKET_MAX_SIZE];
    u32 latency_ns; /* Response latency for commands */
};

/* Per-CPU statistics */
struct sam_analyzer_stats {
    u64 packets_captured;
    u64 packets_dropped;
    u64 total_bytes;
    u64 cmd_packets;
    u64 event_packets;
    u64 errors;
    ktime_t last_packet_time;
};

/* Command tracking for latency measurement */
struct sam_cmd_tracker {
    struct hlist_node node;
    u16 sequence;
    ktime_t sent_time;
    u8 target_category;
    u8 command_id;
    struct rcu_head rcu;
};

/* Main analyzer structure */
struct sam_analyzer {
    struct dentry *debugfs_root;
    struct ring_buffer *buffer;
    struct mutex config_lock;
    spinlock_t stats_lock;
    
    /* Per-CPU stats */
    struct sam_analyzer_stats __percpu *stats;
    
    /* Command tracking hash table */
    DECLARE_HASHTABLE(cmd_tracker, SAM_HASH_BITS);
    spinlock_t tracker_lock;
    
    /* Configuration */
    bool enabled;
    bool capture_payload;
    u32 filter_mask;
    
    /* Workqueue for deferred processing */
    struct workqueue_struct *wq;
    struct work_struct process_work;
    
    /* Kprobes for hooking into SAM functions */
    struct kprobe kp_send;
    struct kprobe kp_recv;
};

static struct sam_analyzer *analyzer;

/* Ring buffer operations */
static int sam_rb_write(struct sam_packet *pkt)
{
    struct ring_buffer_event *event;
    struct sam_packet *entry;
    int cpu = get_cpu();
    
    event = ring_buffer_lock_reserve(analyzer->buffer, sizeof(*pkt));
    if (!event) {
        this_cpu_inc(analyzer->stats->packets_dropped);
        put_cpu();
        return -ENOBUFS;
    }
    
    entry = ring_buffer_event_data(event);
    memcpy(entry, pkt, sizeof(*pkt));
    ring_buffer_unlock_commit(analyzer->buffer, event);
    
    this_cpu_inc(analyzer->stats->packets_captured);
    this_cpu_add(analyzer->stats->total_bytes, pkt->payload_len);
    
    put_cpu();
    return 0;
}

/* Latency tracking for command-response pairs */
static void track_command(struct sam_packet *pkt)
{
    struct sam_cmd_tracker *tracker;
    unsigned long flags;
    
    tracker = kmalloc(sizeof(*tracker), GFP_ATOMIC);
    if (!tracker)
        return;
    
    tracker->sequence = pkt->sequence;
    tracker->sent_time = pkt->timestamp;
    tracker->target_category = pkt->target_category;
    tracker->command_id = pkt->command_id;
    
    spin_lock_irqsave(&analyzer->tracker_lock, flags);
    hash_add_rcu(analyzer->cmd_tracker, &tracker->node, tracker->sequence);
    spin_unlock_irqrestore(&analyzer->tracker_lock, flags);
}

static u32 match_response(struct sam_packet *pkt)
{
    struct sam_cmd_tracker *tracker;
    u32 latency = 0;
    unsigned long flags;
    
    rcu_read_lock();
    hash_for_each_possible_rcu(analyzer->cmd_tracker, tracker, node, pkt->sequence) {
        if (tracker->sequence == pkt->sequence) {
            latency = ktime_to_ns(ktime_sub(pkt->timestamp, tracker->sent_time));
            
            spin_lock_irqsave(&analyzer->tracker_lock, flags);
            hash_del_rcu(&tracker->node);
            spin_unlock_irqrestore(&analyzer->tracker_lock, flags);
            
            kfree_rcu(tracker, rcu);
            break;
        }
    }
    rcu_read_unlock();
    
    return latency;
}

/* Kprobe handlers for intercepting SAM communication */
static int sam_send_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct sam_packet pkt = {0};
    void *data = (void *)regs->si; /* Assuming data pointer in RSI */
    
    if (!analyzer->enabled)
        return 0;
    
    pkt.timestamp = ktime_get();
    pkt.type = SAM_PKT_TYPE_CMD;
    
    /* Extract packet details from registers/memory */
    if (probe_kernel_read(&pkt.target_category, data, 1) ||
        probe_kernel_read(&pkt.command_id, data + 1, 1) ||
        probe_kernel_read(&pkt.sequence, data + 2, 2)) {
        this_cpu_inc(analyzer->stats->errors);
        return 0;
    }
    
    /* Capture payload if enabled */
    if (analyzer->capture_payload) {
        pkt.payload_len = min_t(u32, regs->dx, SAM_PACKET_MAX_SIZE);
        if (probe_kernel_read(pkt.payload, data + 4, pkt.payload_len)) {
            this_cpu_inc(analyzer->stats->errors);
            return 0;
        }
    }
    
    track_command(&pkt);
    sam_rb_write(&pkt);
    this_cpu_inc(analyzer->stats->cmd_packets);
    
    return 0;
}

static int sam_recv_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct sam_packet pkt = {0};
    void *data = (void *)regs->si;
    
    if (!analyzer->enabled)
        return 0;
    
    pkt.timestamp = ktime_get();
    
    /* Determine packet type from response */
    u8 type_byte;
    if (probe_kernel_read(&type_byte, data, 1)) {
        this_cpu_inc(analyzer->stats->errors);
        return 0;
    }
    
    if (type_byte & 0x80)
        pkt.type = SAM_PKT_TYPE_EVENT;
    else if (type_byte & 0x40)
        pkt.type = SAM_PKT_TYPE_ACK;
    else
        pkt.type = SAM_PKT_TYPE_DATA;
    
    /* Extract packet details */
    if (probe_kernel_read(&pkt.sequence, data + 2, 2)) {
        this_cpu_inc(analyzer->stats->errors);
        return 0;
    }
    
    /* Match with sent command for latency calculation */
    if (pkt.type == SAM_PKT_TYPE_ACK || pkt.type == SAM_PKT_TYPE_DATA) {
        pkt.latency_ns = match_response(&pkt);
    }
    
    sam_rb_write(&pkt);
    
    if (pkt.type == SAM_PKT_TYPE_EVENT)
        this_cpu_inc(analyzer->stats->event_packets);
    
    return 0;
}

/* Debugfs interface for user-space interaction */
static int sam_stats_show(struct seq_file *m, void *v)
{
    struct sam_analyzer_stats total = {0};
    int cpu;
    
    for_each_possible_cpu(cpu) {
        struct sam_analyzer_stats *stats = per_cpu_ptr(analyzer->stats, cpu);
        total.packets_captured += stats->packets_captured;
        total.packets_dropped += stats->packets_dropped;
        total.total_bytes += stats->total_bytes;
        total.cmd_packets += stats->cmd_packets;
        total.event_packets += stats->event_packets;
        total.errors += stats->errors;
    }
    
    seq_printf(m, "SAM Packet Analyzer Statistics\n");
    seq_printf(m, "==============================\n");
    seq_printf(m, "Version: %s\n", SAM_ANALYZER_VERSION);
    seq_printf(m, "Status: %s\n", analyzer->enabled ? "Enabled" : "Disabled");
    seq_printf(m, "Packets Captured: %llu\n", total.packets_captured);
    seq_printf(m, "Packets Dropped: %llu\n", total.packets_dropped);
    seq_printf(m, "Total Bytes: %llu\n", total.total_bytes);
    seq_printf(m, "Command Packets: %llu\n", total.cmd_packets);
    seq_printf(m, "Event Packets: %llu\n", total.event_packets);
    seq_printf(m, "Errors: %llu\n", total.errors);
    
    return 0;
}

static int sam_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, sam_stats_show, NULL);
}

static const struct file_operations sam_stats_fops = {
    .open = sam_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static ssize_t sam_enable_write(struct file *file, const char __user *buf,
                                size_t count, loff_t *ppos)
{
    char val;
    
    if (get_user(val, buf))
        return -EFAULT;
    
    mutex_lock(&analyzer->config_lock);
    analyzer->enabled = (val == '1');
    mutex_unlock(&analyzer->config_lock);
    
    return count;
}

static ssize_t sam_enable_read(struct file *file, char __user *buf,
                               size_t count, loff_t *ppos)
{
    char val = analyzer->enabled ? '1' : '0';
    
    if (*ppos != 0)
        return 0;
    
    if (put_user(val, buf))
        return -EFAULT;
    
    *ppos = 1;
    return 1;
}

static const struct file_operations sam_enable_fops = {
    .read = sam_enable_read,
    .write = sam_enable_write,
};

/* Module initialization */
static int __init sam_analyzer_init(void)
{
    int ret;
    
    pr_info("SAM Analyzer: Initializing version %s\n", SAM_ANALYZER_VERSION);
    
    analyzer = kzalloc(sizeof(*analyzer), GFP_KERNEL);
    if (!analyzer)
        return -ENOMEM;
    
    /* Initialize structures */
    mutex_init(&analyzer->config_lock);
    spin_lock_init(&analyzer->stats_lock);
    spin_lock_init(&analyzer->tracker_lock);
    hash_init(analyzer->cmd_tracker);
    
    /* Allocate per-CPU stats */
    analyzer->stats = alloc_percpu(struct sam_analyzer_stats);
    if (!analyzer->stats) {
        ret = -ENOMEM;
        goto err_free_analyzer;
    }
    
    /* Create ring buffer */
    analyzer->buffer = ring_buffer_alloc(SAM_RING_BUFFER_SIZE, RB_FL_OVERWRITE);
    if (!analyzer->buffer) {
        ret = -ENOMEM;
        goto err_free_stats;
    }
    
    /* Create workqueue */
    analyzer->wq = create_singlethread_workqueue("sam_analyzer");
    if (!analyzer->wq) {
        ret = -ENOMEM;
        goto err_free_buffer;
    }
    
    /* Setup debugfs */
    analyzer->debugfs_root = debugfs_create_dir("sam_analyzer", NULL);
    if (!analyzer->debugfs_root) {
        ret = -ENOENT;
        goto err_destroy_wq;
    }
    
    debugfs_create_file("stats", 0444, analyzer->debugfs_root, NULL, &sam_stats_fops);
    debugfs_create_file("enable", 0644, analyzer->debugfs_root, NULL, &sam_enable_fops);
    debugfs_create_bool("capture_payload", 0644, analyzer->debugfs_root, 
                       &analyzer->capture_payload);
    debugfs_create_x32("filter_mask", 0644, analyzer->debugfs_root, 
                      &analyzer->filter_mask);
    
    /* Register kprobes */
    analyzer->kp_send.symbol_name = "ssam_request_write_data";
    ret = register_kprobe(&analyzer->kp_send);
    if (ret < 0) {
        pr_warn("SAM Analyzer: Failed to register send kprobe: %d\n", ret);
        /* Continue anyway - module can still be useful for stats */
    }
    
    analyzer->kp_recv.symbol_name = "ssam_request_read_data";
    ret = register_kprobe(&analyzer->kp_recv);
    if (ret < 0) {
        pr_warn("SAM Analyzer: Failed to register recv kprobe: %d\n", ret);
    }
    
    pr_info("SAM Analyzer: Successfully initialized\n");
    return 0;

err_destroy_wq:
    destroy_workqueue(analyzer->wq);
err_free_buffer:
    ring_buffer_free(analyzer->buffer);
err_free_stats:
    free_percpu(analyzer->stats);
err_free_analyzer:
    kfree(analyzer);
    return ret;
}

static void __exit sam_analyzer_exit(void)
{
    struct sam_cmd_tracker *tracker;
    struct hlist_node *tmp;
    int bkt;
    
    pr_info("SAM Analyzer: Shutting down\n");
    
    /* Disable capturing */
    analyzer->enabled = false;
    
    /* Unregister kprobes */
    unregister_kprobe(&analyzer->kp_send);
    unregister_kprobe(&analyzer->kp_recv);
    
    /* Clean up debugfs */
    debugfs_remove_recursive(analyzer->debugfs_root);
    
    /* Clean up tracking hash table */
    hash_for_each_safe(analyzer->cmd_tracker, bkt, tmp, tracker, node) {
        hash_del(&tracker->node);
        kfree(tracker);
    }
    
    /* Free resources */
    destroy_workqueue(analyzer->wq);
    ring_buffer_free(analyzer->buffer);
    free_percpu(analyzer->stats);
    kfree(analyzer);
    
    pr_info("SAM Analyzer: Shutdown complete\n");
}

module_init(sam_analyzer_init);
module_exit(sam_analyzer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Komosa");
MODULE_DESCRIPTION("Surface Aggregator Module Packet Analyzer");
MODULE_VERSION(SAM_ANALYZER_VERSION);
