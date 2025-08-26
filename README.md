# zkstat.py

Small CLI to inspect **Circom/SnarkJS artifacts**: `.wtns` (witness) and `.zkey` (proving key).  
Focus: **zero-bit/byte histograms** and **zero-point counts**, streamed (memory-light).

---

## What it computes

### WTNS (`*.wtns`)
- Reads header (`FS` in bytes, `witness_len`).
- Streams witness values (section #2) and outputs:
    - **Per-bit zero counts**: length `FS*8` (bit index = `byte*8 + bit`).
    - **Per-byte zero counts**: length `FS`.

### ZKEY (`*.zkey`)
- Parses container sections `(id, length, offset)` with common labels:
  `HEADER, VK_ALPHA1, VK_BETA1, VK_BETA2, VK_GAMMA2, VK_DELTA1, VK_DELTA2, IC, A, B1, B2, H, L`.
- For each section, if payload size is divisible by a **block**:
    - **G1 block** = `2*FS` bytes, **G2 block** = `4*FS` bytes.
    - Count **candidates** (`payload/block`) and how many are **all‑zero** (treated as ∞).
- Optional: **per‑byte zero histogram** inside G1/G2 blocks for each section.

Everything is streamed via `mmap`; no full-file loads.

---

## Commands

```bash
# Witness: bit/byte zero histograms
python3 zkstat.py wtns-stats circuit.wtns --out out/wtns --plot

# ZKey: section sizes + zero-point counts (and sort by zeroes)
python3 zkstat.py zkey-stats circuit_final.zkey --fs-bytes 32 --out out/zkey --sort

# ZKey: also write per-section per-byte histograms (CSV/JSON; PNG with --plot)
python3 zkstat.py zkey-stats circuit_final.zkey --fs-bytes 32 --out out/zkey --hist --plot

# ZKey: dump sample indices of zero G1/G2 blocks (+hexdump files)
python3 zkstat.py zkey-stats circuit_final.zkey --fs-bytes 32 --out out/zkey --dump-g1 6 --limit 5 --hexdump
python3 zkstat.py zkey-stats circuit_final.zkey --fs-bytes 32 --out out/zkey --dump-g2 7 --limit 5 --hexdump

# One-shot over a tarball (extract + run stats)
python3 zkstat.py scan-tgz artifacts.tgz --out out
```

Flags:
- `--fs-bytes` (default `32` for BN254)
- `--sort` (sort sections by zero-points, then size)
- `--hist` (per‑byte zero histogram per section for G1/G2 shapes)
- `--plot` (PNG charts alongside CSV/JSON)
- `--dump-g1 N` / `--dump-g2 N` (dump zero-block indices for section `N`)
- `--limit K` (limit number of dumped indices; default 10)
- `--hexdump` (write hexdump samples of dumped blocks into `--out`)

---

## Outputs (by command)

### `wtns-stats`
- `wtns_summary.json` — FS, witness_len, sections, totals.
- `wtns_zero_bits.csv` — `bit_index, zero_count, zero_ratio`.
- `wtns_zero_bytes.csv` — `byte_index, zero_count, zero_ratio`.
- `wtns_zero_bits_hist.png` (with `--plot`).

### `zkey-stats`
- `zkey_summary.json` — sections + zero-point stats.
- `zkey_sections.csv` — `section_id, label, payload_bytes, offset`.
- `zkey_zero_points.csv` — per section: candidates/zero‑points for G1/G2.
- With `--hist`: `zkey_sec{ID}_{g1|g2}_zero_bytes.{json,csv}` (+ `*_hist.png` with `--plot`).
- With dumps: `sample_{g1|g2}_iXXXXXXXX.hex` for selected indices.

---

## Sanity checks (quick)
- For BN254 (`FS=32`): G1/G2 blocks are 64/128 bytes; section sizes should divide evenly for vectors.
- In WTNS bit histogram, the **two MSBs** should be ~100% zero (254‑bit modulus).
- Use dumps + hexdumps to confirm reported zero blocks are truly all‑zero bytes.

---

## Notes / assumptions
- “Zero point” = **all‑zero bytes** (common for uncompressed ∞ in snarkjs/rapidsnark). If your encoding differs, adjust the rule.
- Labels are conventional; exact semantics can vary. For precise vector sizes, mirror rapidsnark’s header parsing.

MIT License.
