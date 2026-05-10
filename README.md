# PcapConstrictorBPF

PcapConstrictorBPF is an experimental Linux TC eBPF packet recorder that
captures traffic into classic PCAP files and applies a small subset of
TLS/QUIC-aware constriction during live capture.

It is related to
[PcapConstrictor](https://github.com/AlexeyVasilev/PcapConstrictor), but it is
not intended to replace it. The main PcapConstrictor project remains the more
robust offline PCAP/PCAPNG constriction tool. PcapConstrictorBPF is narrower
and more educational: it is useful for learning TC hooks, verifier-friendly BPF
parsing, BPF maps, and adaptive capture policy.

## Status

Experimental project. The recorder is functional on Linux and
demonstrates TC eBPF-based adaptive capture, BPF maps, verifier-friendly packet
parsing, and runtime policy configuration. It intentionally implements a
narrower policy than PcapConstrictor.

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

## Limitations / non-goals

- Linux only.
- Requires root or equivalent capabilities such as `CAP_NET_ADMIN`.
- Uses TC `clsact` hooks.
- Experimental, verifier-friendly eBPF implementation.
- QUIC flow state is currently IPv4-focused.
- No QUIC decryption.
- No QUIC frame parsing.
- No QUIC `NEW_CONNECTION_ID` tracking.
- No QUIC migration support.
- No TCP stream reassembly.
- No multi-record TLS constriction in BPF.
- TLS support is intentionally limited to simple AppData records at TCP payload
  start.
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
sudo ./tcpcap enp0s3 out.pcap --config config.ini
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

## Relationship to PcapConstrictor

This repository is intentionally narrower and more experimental than
PcapConstrictor. It is a good vehicle for exploring eBPF, TC hooks, verifier
constraints, BPF maps, and adaptive live capture policy. For robust offline
PCAP/PCAPNG constriction and richer protocol handling, use
[PcapConstrictor](https://github.com/AlexeyVasilev/PcapConstrictor).

## License

Apache License 2.0. See [LICENSE](LICENSE).
