# SAM Analyzer

Kernel module for analyzing Surface Aggregator Module (SAM) communication on Surface devices. Uses kprobes to intercept SAM packets and track latencies without modifying the kernel.

## 🎯 Key Features

### Advanced Kernel Programming Techniques Demonstrated

- **Lock-Free Ring Buffers**: Per-CPU ring buffer implementation for high-throughput, low-latency packet capture
- **RCU (Read-Copy-Update)**: Lock-free synchronization for command tracking hash table
- **Kprobes**: Dynamic kernel instrumentation to hook into SAM communication functions
- **Per-CPU Statistics**: Cache-efficient statistics collection using percpu variables
- **Debugfs Interface**: Clean user-kernel interface for configuration and monitoring
- **Work Queues**: Deferred processing for heavy analysis tasks
- **Memory Barriers & Atomics**: Proper synchronization primitives for multi-core systems

### Functional Capabilities

- **Real-time Packet Capture**: Zero-copy packet capture with minimal performance impact
- **Latency Analysis**: Automatic command-response pairing with nanosecond precision timing
- **Category Filtering**: Hardware-accelerated filtering by SAM device category
- **Payload Inspection**: Optional deep packet inspection with configurable depth
- **Performance Statistics**: Per-CPU statistics aggregation with cache line optimization
- **Event Tracking**: Asynchronous event monitoring and categorization

## 📊 Architecture

```
┌─────────────────────────────────────────────────────┐
│                   User Space                         │
│  ┌──────────────┐        ┌──────────────┐          │
│  │ sam_monitor  │◄──────►│   debugfs    │          │
│  │   (Python)   │        │  interface   │          │
│  └──────────────┘        └──────────────┘          │
├─────────────────────────────────────────────────────┤
│                   Kernel Space                       │
│  ┌──────────────────────────────────────┐          │
│  │         SAM Analyzer Module          │          │
│  │  ┌──────────┐    ┌──────────────┐  │          │
│  │  │ Kprobes  │───►│ Ring Buffer  │  │          │
│  │  └──────────┘    └──────────────┘  │          │
│  │  ┌──────────┐    ┌──────────────┐  │          │
│  │  │  Stats   │───►│ Hash Table   │  │          │
│  │  │ (percpu) │    │   (RCU)      │  │          │
│  │  └──────────┘    └──────────────┘  │          │
│  └──────────────────────────────────────┘          │
│              ▲               ▲                      │
│              │               │                      │
│  ┌───────────┴──┐     ┌─────┴──────────┐          │
│  │ ssam_request │     │ ssam_request   │          │
│  │ _write_data  │     │ _read_data     │          │
│  └──────────────┘     └────────────────┘          │
└─────────────────────────────────────────────────────┘
```

## 🚀 Installation

### Prerequisites
- Linux kernel headers (linux-headers package)
- Surface kernel with SAM support (linux-surface)
- Python 3.6+ (for monitoring tool)
- Root access for module loading

### Building
```bash
make
sudo insmod sam_analyzer.ko
```

## Usage

The Python monitor script provides the easiest interface:

```bash
sudo ./sam_monitor.py --enable --monitor
```

Options:
- `--payload` - capture full packet payloads
- `--filter <category>` - filter by device (Keyboard, Touchpad, Power, etc.)
- `--latency` - show latency statistics
- `--dump <file>` - save raw trace

You can also control it directly via debugfs:
```bash
# Manual control via debugfs
echo 1 > /sys/kernel/debug/sam_analyzer/enable
cat /sys/kernel/debug/sam_analyzer/stats
echo 1 > /sys/kernel/debug/sam_analyzer/capture_payload
echo 0x100 > /sys/kernel/debug/sam_analyzer/filter_mask
```
### Lock-Free Ring Buffer Implementation
The module uses per-CPU ring buffers with lock-free write operations:
```c
struct ring_buffer_event *event;
event = ring_buffer_lock_reserve(buffer, size);
// Write data
ring_buffer_unlock_commit(buffer, event);
```

### RCU-Protected Command Tracking
Command-response pairs are tracked using RCU for lock-free reads:
```c
hash_for_each_possible_rcu(cmd_tracker, tracker, node, sequence) {
    if (tracker->sequence == sequence) {
        // Calculate latency
        latency = ktime_to_ns(ktime_sub(now, tracker->sent_time));
    }
}
```

### Kprobe Dynamic Instrumentation
The module dynamically instruments SAM functions without kernel modification:
```c
kprobe.symbol_name = "ssam_request_write_data";
register_kprobe(&kprobe);
```


## Performance

Uses about 1MB memory per CPU core. Overhead is minimal - typically under 0.5% CPU with negligible latency impact.

## Notes

This is mainly useful for debugging SAM driver issues or understanding how Surface devices communicate. The kprobe approach means you don't need a patched kernel, but it does depend on the internal function names staying the same.

