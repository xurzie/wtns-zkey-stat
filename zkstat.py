#!/usr/bin/env python3

from __future__ import annotations
import argparse, csv, io, os, struct, mmap, json, math, pathlib, sys, tarfile
from typing import Dict, Any, List, Tuple, Optional

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def write_json(path: str, data: Any):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def write_csv(path: str, headers: List[str], rows: List[List[Any]]):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)

def format_section_id(sec_id: int) -> str:
    known = {
        1: 'HEADER',
        2: 'VK_ALPHA1 (G1)',
        3: 'VK_BETA1 (G1)',
        4: 'VK_BETA2 (G2)',
        5: 'VK_GAMMA2 (G2)',
        6: 'VK_DELTA1 (G1)',
        7: 'VK_DELTA2 (G2)',
        8: 'IC (G1 vec)',
        9: 'A (G1 vec)',
        10:'B1 (G1 vec)',
        11:'B2 (G2 vec)',
        12:'H (G1 vec)',
        13:'L (G1 vec)',
    }
    return known.get(sec_id, f'SEC_{sec_id}')

def hexdump(b: bytes, base_off: int = 0) -> str:
    out_lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexs = ' '.join(f'{x:02x}' for x in chunk)
        asci = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        out_lines.append(f"{base_off+i:08x}: {hexs:<47}  |{asci}|")
    return '\n'.join(out_lines)

class ZkeyStats:
    def __init__(self, version: int, n_sections: int, sections: List[Dict[str, Any]], fs_bytes_guess: int):
        self.version = version
        self.n_sections = n_sections
        self.sections = sections
        self.fs_bytes_guess = fs_bytes_guess
        self.zero_points_by_section: List[Dict[str, Any]] = []

    def to_json(self) -> Dict[str, Any]:
        return {
            "format": "zkey",
            "version": self.version,
            "n_sections": self.n_sections,
            "sections": self.sections,
            "field_size_bytes_guess": self.fs_bytes_guess,
            "zero_points_by_section": self.zero_points_by_section,
        }

def parse_zkey_header(mm: mmap.mmap) -> ZkeyStats:
    if mm.read(4) != b"zkey":
        raise ValueError("Not a .zkey file (magic mismatch)")
    version = struct.unpack('<I', mm.read(4))[0]
    n_sections = struct.unpack('<I', mm.read(4))[0]
    sections_meta: List[Dict[str, Any]] = []
    for _ in range(n_sections):
        sec_id = struct.unpack('<I', mm.read(4))[0]
        sec_len = struct.unpack('<Q', mm.read(8))[0]
        off = mm.tell()
        sections_meta.append({"id": int(sec_id), "label": format_section_id(sec_id),
                              "length": int(sec_len), "offset": int(off)})
        mm.seek(off + sec_len)
    return ZkeyStats(version, n_sections, sections_meta, fs_bytes_guess=32)

def count_zero_points_in_sections(mm: mmap.mmap, zstats: ZkeyStats, fs_bytes: int, sort_sections: bool):
    G1 = fs_bytes * 2
    G2 = fs_bytes * 4
    rows: List[Dict[str, Any]] = []

    for meta in zstats.sections:
        off = meta["offset"]; length = meta["length"]
        sec_id = meta["id"]; label = meta["label"]
        g1_n = length // G1 if G1 and length % G1 == 0 else 0
        g2_n = length // G2 if G2 and length % G2 == 0 else 0

        g1_zero = 0
        if g1_n > 0:
            for _, blkdata in iter_blocks(mm, off, length, G1):
                if blkdata.count(0) == G1:
                    g1_zero += 1

        g2_zero = 0
        if g2_n > 0:
            for _, blkdata in iter_blocks(mm, off, length, G2):
                if blkdata.count(0) == G2:
                    g2_zero += 1

        rows.append({
            "section_id": sec_id, "label": label, "payload_bytes": length,
            "g1_candidates": g1_n, "g1_zero_points": g1_zero,
            "g2_candidates": g2_n, "g2_zero_points": g2_zero,
        })

    if sort_sections:
        rows.sort(key=lambda r: (r["g1_zero_points"] + r["g2_zero_points"], r["payload_bytes"]), reverse=True)
    zstats.zero_points_by_section = rows

def dump_zero_indices(mm: mmap.mmap, section_meta: Dict[str, Any], fs_bytes: int, space: str, limit: Optional[int] = None):
    assert space in ("g1", "g2")
    blk = fs_bytes*2 if space == "g1" else fs_bytes*4
    off = section_meta["offset"]; length = section_meta["length"]
    if length % blk != 0:
        return ([], blk)
    mm.seek(off); data = mm.read(length)
    n = length // blk
    out = []
    for i in range(n):
        if data[i*blk:(i+1)*blk].count(0) == blk:
            out.append(i)
            if limit is not None and len(out) >= limit:
                break
    return out, blk

def iter_blocks(mm: mmap.mmap, off: int, length: int, blk: int):
    """
    Sequentially yield (i, bytes) for blocks of size `blk` inside [off, off+length).
    Uses mmap to avoid extra copies; still reads into bytes per block.
    """
    mm.seek(off)
    n = length // blk
    for i in range(n):
        chunk = mm.read(blk)
        if len(chunk) != blk:
            break
        yield i, chunk

def compute_zero_byte_histogram_for_section(mm: mmap.mmap, meta: Dict[str, Any], blk: int):
    off = meta["offset"]; length = meta["length"]
    if length % blk != 0 or blk <= 0:
        return None
    counts = [0]*blk
    total = 0
    for _, chunk in iter_blocks(mm, off, length, blk):
        total += 1
        # count zeros at each byte position
        for j, b in enumerate(chunk):
            if b == 0:
                counts[j] += 1
    return {"block_bytes": blk, "blocks": total, "zero_byte_counts": counts,
            "zero_byte_ratio": [c/max(1,total) for c in counts]}

def plot_zero_byte_histogram(outdir: str, sec_id: int, space: str, counts: list):
    try:
        import matplotlib.pyplot as plt
    except Exception as e:
        print(f"[warn] matplotlib not available, skip plotting: {e}", file=sys.stderr)
        return
    xs = list(range(len(counts))); ys = [int(c) for c in counts]
    plt.figure(); plt.bar(xs, ys)
    plt.title(f"Section {sec_id} zero-bytes per position ({space})")
    plt.xlabel("Byte index in block"); plt.ylabel("Zero count")
    out = os.path.join(outdir, f"zkey_sec{sec_id}_{space}_zero_bytes_hist.png")
    plt.savefig(out, dpi=160, bbox_inches="tight"); plt.close()

def plot_zkey_zero_points(outdir: str, rows: List[Dict[str, Any]]):
    try:
        import matplotlib.pyplot as plt
    except Exception as e:
        print(f"[warn] matplotlib not available, skip plotting: {e}", file=sys.stderr)
        return
    vals = [r["g1_zero_points"] + r["g2_zero_points"] for r in rows]
    plt.figure(); plt.bar(range(len(vals)), vals)
    plt.title("ZKEY: zero points per section"); plt.xlabel("Section # (order)"); plt.ylabel("Zero points")
    out = os.path.join(outdir, "zkey_zero_points_hist.png")
    plt.savefig(out, dpi=160, bbox_inches="tight"); plt.close()

def cmd_scan_tgz(args):
    tgz = pathlib.Path(args.file).expanduser().resolve()
    outdir = pathlib.Path(args.out).resolve() if args.out else pathlib.Path.cwd() / "out"
    outdir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tgz, "r:gz") as tf:
        members = tf.getmembers()
        zkey_members = [m for m in members if m.isfile() and m.name.lower().endswith(".zkey")]

        results = {}
        extracted_paths: List[str] = []

        for m in zkey_members:
            target = outdir / os.path.basename(m.name)
            with tf.extractfile(m) as rf, open(target, "wb") as wf:
                wf.write(rf.read())
            extracted_paths.append(str(target))

        for p in extracted_paths:
            if p.endswith(".zkey"):
                with open(p, 'rb') as fh, mmap.mmap(fh.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    zst = parse_zkey_header(mm)
                    fs = fs_guess if fs_guess else zst.fs_bytes_guess
                    count_zero_points_in_sections(mm, zst, fs_bytes=fs, sort_sections=True)
                summary = zst.to_json()
                summary["field_size_bytes_used"] = fs
                results[os.path.basename(p)] = summary
                sub = outdir / (os.path.basename(p) + ".out"); sub.mkdir(exist_ok=True)
                write_json(str(sub / "zkey_summary.json"), summary)
                zp = zst.zero_points_by_section
                zp_rows = [[r["section_id"], r["label"], r["payload_bytes"], r["g1_candidates"],
                            r["g1_zero_points"], r["g2_candidates"], r["g2_zero_points"]] for r in zp]
                write_csv(str(sub / "zkey_zero_points.csv"),
                          ["section_id","label","payload_bytes","g1_candidates",
                           "g1_zero_points","g2_candidates","g2_zero_points"], zp_rows)
                sec_rows = [[s["id"], s["label"], s["length"], s["offset"]] for s in zst.sections]
                write_csv(str(sub / "zkey_sections.csv"),
                          ["section_id","label","payload_bytes","offset"], sec_rows)

        write_json(str(outdir / "scan_summary.json"), results)
        print(json.dumps({"out": str(outdir), "files": list(results.keys())}, indent=2))

def cmd_zkey_stats(args):
    p = pathlib.Path(args.file).expanduser().resolve()
    outdir = pathlib.Path(args.out).resolve() if args.out else None
    if outdir: outdir.mkdir(parents=True, exist_ok=True)

    with open(p, 'rb') as fh, mmap.mmap(fh.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
        zstats = parse_zkey_header(mm)
        fs = args.fs_bytes if args.fs_bytes else zstats.fs_bytes_guess
        count_zero_points_in_sections(mm, zstats, fs_bytes=fs, sort_sections=args.sort)

        # Optional dumps of zero indices
        dumps = {}
        by_id = {s["id"]: s for s in zstats.sections}

        # Optional per-section byte-position histograms
        persec = {}
        if args.hist and outdir:
            for meta in zstats.sections:
                sec_id = meta["id"]
                # G1-shaped
                h1 = compute_zero_byte_histogram_for_section(mm, meta, fs*2)
                if h1:
                    persec.setdefault(sec_id, {})["g1"] = h1
                    # write CSV/JSON + plot
                    write_json(str(outdir / f"zkey_sec{sec_id}_g1_zero_bytes.json"), h1)
                    rows = [[i, c, h1["zero_byte_ratio"][i]] for i, c in enumerate(h1["zero_byte_counts"])]
                    write_csv(str(outdir / f"zkey_sec{sec_id}_g1_zero_bytes.csv"), ["byte_index","zero_count","zero_ratio"], rows)
                    if args.plot:
                        plot_zero_byte_histogram(str(outdir), sec_id, "g1", h1["zero_byte_counts"])
                # G2-shaped
                h2 = compute_zero_byte_histogram_for_section(mm, meta, fs*4)
                if h2:
                    persec.setdefault(sec_id, {})["g2"] = h2
                    write_json(str(outdir / f"zkey_sec{sec_id}_g2_zero_bytes.json"), h2)
                    rows = [[i, c, h2["zero_byte_ratio"][i]] for i, c in enumerate(h2["zero_byte_counts"])]
                    write_csv(str(outdir / f"zkey_sec{sec_id}_g2_zero_bytes.csv"), ["byte_index","zero_count","zero_ratio"], rows)
                    if args.plot:
                        plot_zero_byte_histogram(str(outdir), sec_id, "g2", h2["zero_byte_counts"])

        if args.dump_g1 is not None:
            sec = by_id.get(args.dump_g1)
            if sec:
                idxs, blk = dump_zero_indices(mm, sec, fs, "g1", args.limit)
                dumps["g1"] = {"section_id": args.dump_g1, "block_bytes": blk, "indices": idxs}
                if args.hexdump and outdir and idxs:
                    for i in idxs:
                        off = sec["offset"] + i*blk
                        mm.seek(off); data = mm.read(blk)
                        with open(outdir / f"sample_g1_i{i:08d}.hex", "w", encoding="utf-8") as wf:
                            wf.write(hexdump(data, base_off=off))
        if args.dump_g2 is not None:
            sec = by_id.get(args.dump_g2)
            if sec:
                idxs, blk = dump_zero_indices(mm, sec, fs, "g2", args.limit)
                dumps["g2"] = {"section_id": args.dump_g2, "block_bytes": blk, "indices": idxs}
                if args.hexdump and outdir and idxs:
                    for i in idxs:
                        off = sec["offset"] + i*blk
                        mm.seek(off); data = mm.read(blk)
                        with open(outdir / f"sample_g2_i{i:08d}.hex", "w", encoding="utf-8") as wf:
                            wf.write(hexdump(data, base_off=off))

    summary = zstats.to_json()
    summary["field_size_bytes_used"] = args.fs_bytes or zstats.fs_bytes_guess
    if 'dumps' in locals():
        summary["zero_indices_dump"] = dumps

    print(json.dumps(summary, indent=2))

    if outdir:
        write_json(str(outdir / "zkey_summary.json"), summary)
        sec_rows = [[s["id"], s["label"], s["length"], s["offset"]] for s in zstats.sections]
        write_csv(str(outdir / "zkey_sections.csv"), ["section_id","label","payload_bytes","offset"], sec_rows)
        zp = zstats.zero_points_by_section
        zp_rows = [[r["section_id"], r["label"], r["payload_bytes"], r["g1_candidates"],
                    r["g1_zero_points"], r["g2_candidates"], r["g2_zero_points"]] for r in zp]
        write_csv(str(outdir / "zkey_zero_points.csv"),
                  ["section_id","label","payload_bytes","g1_candidates",
                   "g1_zero_points","g2_candidates","g2_zero_points"], zp_rows)
        if args.plot:
            plot_zkey_zero_points(str(outdir), zstats.zero_points_by_section)

# ----------------------------
# CLI
# ----------------------------

def main():
    ap = argparse.ArgumentParser(description="Quick stats for .wtns and .zkey files")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_z = sub.add_parser("zkey-stats", help="Parse zkey sections and count zero points per section (heuristic)")
    ap_z.add_argument("file", help="Path to .zkey file")
    ap_z.add_argument("--fs-bytes", type=int, default=32, help="Field element byte length (default 32 for BN254)")
    ap_z.add_argument("--out", help="Directory to write CSV/JSON/plots")
    ap_z.add_argument("--plot", action="store_true", help="Also emit PNG histograms (requires matplotlib)")
    ap_z.add_argument("--sort", action="store_true", help="Sort sections by (zero_points, size) desc in outputs")
    ap_z.add_argument("--hist", action="store_true", help="Compute per-section zero-byte histograms (writes CSV/JSON; with --plot also PNG)")
    ap_z.add_argument("--dump-g1", type=int, help="Section id to dump indices of zero G1 blocks (64B for FS=32)")
    ap_z.add_argument("--dump-g2", type=int, help="Section id to dump indices of zero G2 blocks (128B for FS=32)")
    ap_z.add_argument("--limit", type=int, default=10, help="Max number of indices/hexdumps to include in dump")
    ap_z.add_argument("--hexdump", action="store_true", help="Write hexdump samples of dumped blocks into --out dir")
    ap_z.set_defaults(func=cmd_zkey_stats)

    ap_s = sub.add_parser("scan-tgz", help="Scan a .tgz/.tar.gz with .zkey files and emit stats for each")
    ap_s.add_argument("file", help="Path to .tgz or .tar.gz")
    ap_s.add_argument("--out", help="Directory to place extracted files and stats (default ./out)")
    ap_s.set_defaults(func=cmd_scan_tgz)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
