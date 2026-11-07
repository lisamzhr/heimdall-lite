#!/usr/bin/env python3
"""Build a labelled flow-feature table from a CTU-13 .binetflow file.
Usage: python ml/prepare.py data/ctu13/capture20110812.binetflow data/ctu13/feat_44.parquet
"""
import sys
import numpy as np
import pandas as pd

src, dst = sys.argv[1], sys.argv[2]
cats = {c: "category" for c in ["Proto", "SrcAddr", "DstAddr", "Dir", "State", "Label"]}
df = pd.read_csv(
    src, skipinitialspace=True, low_memory=False,
    usecols=["StartTime", "Dur", "Proto", "SrcAddr", "Sport", "Dir", "DstAddr",
             "Dport", "State", "TotPkts", "TotBytes", "SrcBytes", "Label"],
    dtype={**cats, "Sport": "string", "Dport": "string"},
)
print("flows read:", len(df))

# Behaviour per source host over one-minute windows, computed on ALL flows
df["minute"] = df["StartTime"].str.slice(0, 16)
g = df.groupby(["SrcAddr", "minute"], observed=True)
df["win_dst"] = g["DstAddr"].transform("nunique")
df["win_flows"] = g["DstAddr"].transform("size")

# Labels: From-Botnet = 1, Normal = 0, everything else (Background...) dropped
lab = df["Label"].astype(str)
df["y"] = np.where(lab.str.contains("From-Botnet"), 1,
                   np.where(lab.str.contains("Normal"), 0, -1))
df = df[df["y"] >= 0].copy()


def port_bucket(s):
    p = pd.to_numeric(s.astype(object), errors="coerce").to_numpy(dtype="float64")
    return np.select([np.isnan(p), p < 1024, p < 49152], [-1, 0, 1], default=2)


tcp = df["Proto"].astype(str) == "tcp"
st = df["State"].astype(str)
f = pd.DataFrame({
    "dur": df["Dur"], "pkts": df["TotPkts"], "bytes": df["TotBytes"],
    "src_bytes": df["SrcBytes"], "dst_bytes": df["TotBytes"] - df["SrcBytes"],
    "bytes_per_pkt": df["TotBytes"] / df["TotPkts"].clip(lower=1),
    "src_ratio": df["SrcBytes"] / df["TotBytes"].clip(lower=1),
    "proto_tcp": tcp.astype(int),
    "proto_udp": (df["Proto"].astype(str) == "udp").astype(int),
    "proto_icmp": (df["Proto"].astype(str) == "icmp").astype(int),
    "sport_bucket": port_bucket(df["Sport"]),
    "dport_bucket": port_bucket(df["Dport"]),
    "dir_uni": df["Dir"].astype(str).str.strip().isin(["->", "<-"]).astype(int),
    "win_dst": df["win_dst"], "win_flows": df["win_flows"],
})
for ch in "SAFRP":
    f["st_" + ch] = (st.str.contains(ch) & tcp).astype(int)
f = f.replace([np.inf, -np.inf], 0).fillna(0)
f["y"] = df["y"].astype(int)
f["src"] = df["SrcAddr"].astype(str)
f["minute"] = df["minute"]
f.to_parquet(dst)

print(f["y"].value_counts().rename({1: "botnet", 0: "normal"}).to_string())
print("features:", [c for c in f.columns if c not in ("y", "src", "minute")])
print("saved", dst, f.shape)
