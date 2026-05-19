# PcapConstrictorBPF

PcapConstrictorBPF is an experimental Linux TC eBPF packet recorder that
captures traffic into classic PCAP files and applies a small subset of
TLS/QUIC-aware constriction during live capture.

It is related to
[PcapConstrictor](https://github.com/AlexeyVasilev/PcapConstrictor), but it is
not intended to replace it. The main PcapConstrictor project remains the more
robust offline PCAP/PCAPNG constriction tool. PcapConstrictorBPF is narrower
and more educational: it is useful for learning TC hooks, verifier-friendly BPF
parsing, BPF maps, ring buffers, and adaptive capture policy.

For practical Linux live capture, use
[PcapConstrictorAFPacket](https://github.com/AlexeyVasilev/PcapConstrictorAFPacket).
PcapConstrictorBPF is intentionally limited by eBPF verifier constraints and
should be understood as a research project rather than the main
recommended live recorder.

## Status

Experimental / research-oriented project. The recorder is functional on Linux
and demonstrates TC eBPF-based adaptive capture, BPF maps, verifier-friendly
packet parsing, and runtime policy configuration. It intentionally implements a
much narrower policy than PcapConstrictor and
PcapConstrictorAFPacket.

## Project family

| Project | Role | Use when |
|---|---|---|
| [PcapConstrictor](https://github.com/AlexeyVasilev/PcapConstrictor) | Main offline PCAP/PCAPNG constriction tool | You already have capture files and want the richest policy support, including TLS final_only/stream/bulk, QUIC, PCAPNG, reinflate/restore, checksum policies, stats, and decision logs. |
| [PcapConstrictorAFPacket](https://github.com/AlexeyVasilev/PcapConstrictorAFPacket) | Linux AF_PACKET live recorder | You want practical Linux live capture with userspace PcapConstrictor-style policy. Supports TLS final_only and QUIC CID-aware short-header constriction, but not TLS stream/bulk. |
| [PcapConstrictorWinPacket](https://github.com/AlexeyVasilev/PcapConstrictorWinPacket) | Windows Npcap/libpcap live recorder | You want practical Windows live capture with Npcap and similar policy scope to AFPacket. Supports TLS final_only and QUIC known-DCID constriction, but not TLS stream/bulk. |
| [PcapConstrictorBPF](https://github.com/AlexeyVasilev/PcapConstrictorBPF) | Experimental Linux TC eBPF recorder | You want a research eBPF project demonstrating TC hooks, BPF maps, verifier-friendly parsing, and a much smaller live-capture policy subset. |

## Current capabilities

- TC ingress and egress capture on Linux.
- Classic PCAP output.
- Runtime policy configuration through `config.ini`.
- Capture up to compile-time `MAX_CAPTURE_LEN=4096`.
- Correct PCAP length semantics:
  - `incl_len = captured bytes`
  - `orig_len = original skb length`
- Simple TLS AppData constriction:
  - TCP/443 only
  - the TLS record must start at the TCP payload offset
  - complete or partial single TLS Application Data records are supported
  - `cap_len = payload_off + encrypted_snaplen`
- QUIC support:
  - UDP/443 Long Header detection
  - DCID/SCID learning
  - flow-aware CID state using a canonical IPv4 UDP 4-tuple
  - Short Header matching by expected directional DCID
  - matched Short Header constriction
  - `cap_len = payload_off + max(quic_short_header_keep_packet_bytes, 1 + matched_dcid_len)`
- Aggregate shutdown stats.

Compared with the AF_PACKET and offline projects, TLS reduction here is much
smaller and QUIC support is narrower. That is expected: the BPF path favors
simple verifier-friendly parsing over deep continuation handling.

## Limitations / non-goals

- Linux only.
- Requires root or equivalent capabilities such as `CAP_NET_ADMIN`.
- Uses TC `clsact` hooks.
- Experimental, verifier-friendly eBPF implementation.
- Not the recommended practical live recorder.
- BPF verifier constraints intentionally limit policy depth and protocol
  handling.
- QUIC flow state is currently IPv4-focused.
- No QUIC decryption.
- No QUIC frame parsing.
- No QUIC `NEW_CONNECTION_ID` tracking.
- No QUIC migration support.
- No TCP stream reassembly.
- No multi-record TLS constriction in BPF.
- TLS support is intentionally limited to simple AppData records at TCP payload
  start.
- TLS continuation handling is intentionally much narrower than
  PcapConstrictor and PcapConstrictorAFPacket.
- QUIC handling is intentionally narrower than PcapConstrictor and
  PcapConstrictorAFPacket.
- Large packets are capped by `MAX_CAPTURE_LEN=4096` in the current build.
- Cleanup removes the `clsact` qdisc and therefore the TC filters attached to
  it on that interface. That is acceptable for this demo project, but should be
  used carefully on real systems.

## Architecture

```text
TC ingress/egress hook
    -> BPF metadata parser
    -> TLS/QUIC policy decision
    -> ringbuf event
    -> user-space PCAP writer
```

Main BPF maps:

- `capture_config`: runtime capture policy
- `capture_stats`: aggregate counters
- `quic_cids`: learned QUIC CID diagnostics
- `quic_flows`: QUIC flow state for directional CID matching
- scratch maps used to keep the BPF stack verifier-friendly

This repository is a good fit if you want to study how a TC eBPF design is put
together end to end: attach points, BPF maps, ring buffer events, compact
metadata parsing, and policy decisions that stay within verifier constraints.

## Build

The current repository builds through the provided `Makefile`:

```sh
make
```

The build flow uses:

- `bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h`
- `clang -g -O2 -target bpf -D__TARGET_ARCH_x86 ... -c src/tcpcap.bpf.c`
- `bpftool gen skeleton src/tcpcap.bpf.o > src/tcpcap.skel.h`
- `cc -g -O2 ... src/tcpcap.c -o tcpcap ...`

Expected dependencies:

- `clang` with BPF target support
- `libbpf`
- `bpftool`
- Linux headers and a BPF-capable kernel
- `tc` / `iproute2`
- `libelf` and `zlib`

## Tested environment

Developed and tested on Ubuntu in a VirtualBox Linux VM with a BPF-capable
kernel, `clang`, `bpftool`, `libbpf`, and `iproute2` / `tc`. Other kernels or
toolchains may require small adjustments.

## Usage

Default capture:

```sh
sudo ./tcpcap enp0s3 out.pcap
```

Capture with config:

```sh
sudo ./tcpcap enp0s3 out.pcap --config config.example.ini
```

Cleanup:

```sh
sudo ./tcpcap enp0s3 --cleanup
```

Inspect TC state:

```sh
sudo tc qdisc show dev enp0s3
sudo tc filter show dev enp0s3 ingress
sudo tc filter show dev enp0s3 egress
```

## Configuration

Runtime policy is loaded from `config.ini` into `pcapc_capture_config`.
[`config.example.ini`](config.example.ini)
shows the supported format.

Supported keys:

### `[capture]`

- `default_snaplen`
- `max_capture_len`

### `[tls]`

- `encrypted_snaplen`

### `[quic]`

- `short_header_keep_packet_bytes`
- `require_dcid_match`
- `allow_short_header_without_known_dcid`

Notes:

- `require_dcid_match` is currently fixed to `true` in the BPF policy.
- `allow_short_header_without_known_dcid` is currently fixed to `false`.
- Those keys are included for policy clarity and future compatibility.
- Capture values cannot exceed the current build limit `MAX_CAPTURE_LEN=4096`.
- The config surface matches the current BPF-supported feature subset; it does
  not expose TLS stream/bulk modes or PCAPNG output because those are outside
  the scope of this recorder.

## Shutdown stats

On shutdown the recorder prints compact aggregate counters. Common counters
include:

- `events_total`
- `events_submitted`
- `reason_tcp`
- `reason_udp`
- `reason_tls_app_data`
- `reason_quic_long`
- `reason_quic_short_candidate`
- `tcp_443`
- `udp_443`
- `quic_long`
- `quic_cid_learned`
- `quic_cid_update`
- `quic_flow_learned`
- `quic_flow_update`
- `quic_short_flow_match`
- `quic_short_constricted`

Notes:

- `reason_quic_short_candidate` currently means a flow-aware matched QUIC Short
  Header.
- `quic_short_constricted` counts matched Short Header packets that were
  actually shortened.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Alexey Vasilev.
