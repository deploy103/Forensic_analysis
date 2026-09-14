# Playbook: PCAP/PCAPNG

## 1. Scope and input identification

Applies to classic `libpcap` files (magic `0xA1B2C3D4`/`0xA1B23C4D` little-endian, or the
byte-swapped big-endian forms) and `pcapng` files (Section Header Block magic `0x0A0D0D0A`
followed by byte-order magic `0x1A2B3C4D`). `bin/fpcap` (`lib/pyforensic/triage/pcap.py`)
detects both natively via `struct` -- no `tshark`/`tcpdump` binary is required.

## 2. Evidence read-only principle

`bin/fpcap` only ever `os.pread`s the evidence file through a read-only fd opened by
`common.open_input_safely`; it never writes to the capture. Reassembled streams/objects are
written only under `workspace/extracted/`, never back into the capture file.

## 3. Initial observations

1. `sha256sum` the evidence file and compare against the manifest.
2. `bin/fpcap cases/<case>/evidence/<file> --json` -- reports link type, snaplen, packet count,
   total captured bytes, first/last timestamp (classic pcap) or block-type histogram and
   link types (pcapng), and a `truncated` warning if a record/block claims more bytes than
   remain in the file.
3. Compare `packet_count`/`total_captured_bytes` against the evidence file's own size as a
   sanity check before trusting any downstream tool's parse of the same file.

## 4. Hypothesis branching

- `truncated: true` -> the capture was cut mid-record; note the exact offset in the warning
  and treat everything after it as unrecoverable without a repair tool -- do not assume data
  loss further upstream too.
- Unusual `linktype` (not Ethernet/`1`) -> the capture may be raw IP, loopback, or a
  non-Ethernet link; decode accordingly rather than assuming an Ethernet header is present.
- High packet count concentrated in a narrow time range -> possible flood/beacon traffic;
  isolate by timestamp range before inspecting payloads.
- `decryption_secrets` blocks present in pcapng -> TLS keys may be embedded in the capture
  itself; that is a stronger lead than trying to break TLS externally.

## 5. Stop conditions

- `bin/fpcap` intentionally has no protocol dissector; do not hand-roll a byte-level TCP/HTTP
  reassembler in this project when a proper dissector is what is actually needed -- escalate
  to the remote server (`docs/server-contract.md`) for `tshark`/`wireshark`-class tooling
  instead of reinventing it under time pressure.
- If a display-filter-equivalent search over payload bytes finds nothing after covering every
  packet once, stop and re-examine the hypothesis rather than repeating the same scan.

## 6. Exact commands

```bash
bin/fpcap cases/<case>/evidence/<file> --json
bin/flag-scan cases/<case>/evidence/<file> --json
```

If `tshark` is confirmed present via `bin/tool-inventory` (it is not, on the reference host):

```bash
bin/log-command <case> -- tshark -r cases/<case>/evidence/<file> -q -z io,phs
bin/log-command <case> -- tshark -r cases/<case>/evidence/<file> --export-objects http,cases/<case>/workspace/extracted
```

## 7. Workspace output location

Any reconstructed stream or exported object goes under `cases/<case>/workspace/extracted/`.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/extracted/<object> --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to specific packet numbers/stream identifiers and the exact filter or
reconstruction command that produced the artifact:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/workspace/extracted/<object> \
  --locator '{"packet_numbers": [12, 13, 14]}' --transformation "TCP stream reassembly" --log-id <log-id>
```

## 10. Failure fallback

If native `bin/fpcap` triage plus a `bin/flag-scan` pass over the raw capture find nothing, and
no dissector is available locally, escalate to the remote `forensic` server for `tshark`-class
protocol dissection rather than attempting a hand-written dissector for an unfamiliar protocol.
