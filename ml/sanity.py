#!/usr/bin/env python3
"""Sanity checks: simple-threshold baseline, no-port model, false-positive hosts."""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score

D = "data/ctu13/"
s42 = pd.read_parquet(D + "feat_42.parquet")
s44 = pd.read_parquet(D + "feat_44.parquet")
META = ["y", "src", "minute"]
ALL = [c for c in s42.columns if c not in META]


def pr(y, yhat):
    return (precision_score(y, yhat, zero_division=0), recall_score(y, yhat, zero_division=0))


print("== 1. Single-threshold baseline (no ML) ==")
for name, tr, te in [("42->44", s42, s44), ("44->42", s44, s42)]:
    for col in ["win_dst", "win_flows"]:
        cands = np.unique(np.quantile(tr[col], np.linspace(0.01, 0.99, 99)))
        t = max(cands, key=lambda c: f1_score(tr["y"], (tr[col] >= c).astype(int), zero_division=0))
        p, r = pr(te["y"], (te[col] >= t).astype(int))
        print(f"{name} {col}>={t:.0f}: precision={p:.3f} recall={r:.3f}")

print("\n== 2. Random Forest without ports and behaviour features ==")
FEATS = [c for c in ALL if c not in ("sport_bucket", "dport_bucket", "win_dst", "win_flows")]
for name, tr, te in [("42->44", s42, s44), ("44->42", s44, s42)]:
    m = RandomForestClassifier(n_estimators=100, max_depth=20, min_samples_leaf=2,
                               class_weight="balanced", n_jobs=-1, random_state=42).fit(tr[FEATS], tr["y"])
    p, r = pr(te["y"], m.predict(te[FEATS]))
    print(f"{name}: precision={p:.3f} recall={r:.3f}")

print("\n== 3. Hosts behind the host-level numbers (42->44, all features) ==")
m = RandomForestClassifier(n_estimators=100, max_depth=20, min_samples_leaf=2,
                           class_weight="balanced", n_jobs=-1, random_state=42).fit(s42[ALL], s42["y"])
t = s44.assign(pred=m.predict(s44[ALL]))
print("hosts with botnet-labelled flows (flows):")
print(t[t.y == 1].src.value_counts().head(5).to_string())
print("normal hosts with the most flows predicted botnet (predicted / total flows):")
fp = t[t.y == 0].groupby("src").agg(pred=("pred", "sum"), flows=("pred", "size"))
print(fp.sort_values("pred", ascending=False).head(4).to_string())
