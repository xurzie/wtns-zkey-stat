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

---

## Testing

```bash
python3 - <<'PY'
import json, mmap
z = "aadhaar-verifier_58662f0cdc3f108b430bab374605b6f3_final.zkey"
meta = json.load(open("out/zkey/zkey_summary.json"))
# section 7 = large G2, first 5 zero indices selected
sec_id = 7
fs = meta["field_size_bytes_used"]; G2 = fs*4
off = next(s["offset"] for s in meta["sections"] if s["id"]==sec_id)
g2cand = next(r for r in meta["zero_points_by_section"] if r["section_id"]==sec_id)["g2_candidates"]

with open(z, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
    found = 0
    for i in range(g2cand):
        blk = mm[off+i*G2 : off+(i+1)*G2]
        if blk.count(0) == G2:
            print("zero@i=", i)
            found += 1
            if found >= 5: break
PY
```
It will print several __i__ indices where the block is zero. Check the specific block in hexdump:

```bash
# substitute your offset (off), size (128) and i from the output above:
OFF=<offset_sec7>            # from zkey_summary.json for section_id=7
I=<index_from_script>
Z="aadhaar-verifier_58662f0cdc3f108b430bab374605b6f3_final.zkey"

# look at 128 bytes of this block - they should all be 00
dd if="$Z" bs=1 skip=$((OFF + I*128)) count=128 2>/dev/null | hexdump -C
```

One python shot, hexdump block __i=4__ section __7__

```bash
python3 - <<'PY'
import json, mmap

def hexdump(b, base=0):
    """Print b bytes as hexdump; base is the base offset."""
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        print(
            f"{base+i:08x}: "
            + ' '.join(f"{x:02x}" for x in chunk).ljust(47)
            + "  |"
            + ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
            + "|"
        )

# --- params you may tweak ---
ZKEY = "aadhaar-verifier_58662f0cdc3f108b430bab374605b6f3_final.zkey"
SECTION_ID = 7   # VK_DELTA2 (G2) in this cace
BLOCK_INDEX = 4  # which block to check
# ----------------------------

meta = json.load(open("out/zkey/zkey_summary.json"))
sec  = next(s for s in meta["sections"] if s["id"] == SECTION_ID)
fs   = meta["field_size_bytes_used"]
BLK  = fs * 4  # G2 = 4*FS; для G1 было бы fs*2

off = sec["offset"] + BLOCK_INDEX * BLK

with open(ZKEY, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
    b = mm[off : off + BLK]  # one G2 block by index
    print("all-zero?", b.count(0) == BLK, "offset=", off)
    hexdump(b, base=off)
PY
```

MIT License.
