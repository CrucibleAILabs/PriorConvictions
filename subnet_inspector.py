#!/usr/bin/env python3
"""
subnet_inspector.py -- a "home inspector" for a Bittensor subnet slot.

Run this BEFORE you buy, lease, or inherit an existing subnet. It reads live
chain state and reports the ways the slot can be taken away from you, held
hostage, or drained -- the class of problem you cannot see from the dashboard
and cannot undo after the transfer.

What it looks at:

  OWNERSHIP        Who owns the slot today, whether the on-chain conviction
                   takeover gate is already open, what it would cost an
                   attacker in TAO to seize ownership, and whether the seller
                   still holds levers (proxies, pending coldkey swap, a lease).

  OVERHANG         Every alpha holder it can attribute, clustered into
                   entities using proxy, identity, childkey, portfolio and
                   auto-stake evidence. Answers: does someone other than the
                   owner hold more alpha than the owner does?

  CAPTURE          Where emission actually lands, who holds validator permits
                   and weight-setting power, who is squatting UIDs, and which
                   childkeys are quietly redirecting stake.

  MECHANICS        Hyperparameters, pool depth, exit slippage, registration
                   posture, dead validators.

Usage:
    python subnet_inspector.py 4
    python subnet_inspector.py 38 --buyer 5Grw...  --price 25000
    python subnet_inspector.py 4 --deep --json sn4_inspection.json
    python subnet_inspector.py 38 --report sn38.txt        plain-English report
    python subnet_inspector.py --from-json sn4.json --report sn4.txt

Nothing here signs, stakes, or transacts. It is read-only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import sys
import textwrap
import time
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any, Iterable, Optional

import bittensor as bt
from bittensor._generated import storage as st

getcontext().prec = 50

RAO = 1_000_000_000
U64_MAX = 2**64 - 1
U16_MAX = 65535
TAO_WEIGHT = 0.18          # chain's root-stake discount inside total_stake
BLOCK_SECONDS = 12.0

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def amt(x: Any) -> float:
    """Normalize a chain amount (Balance, rao int, SafeFloat dict) to whole units."""
    if x is None:
        return 0.0
    if hasattr(x, "rao"):
        return x.rao / RAO
    if isinstance(x, dict) and "mantissa" in x:
        return float(safe_float(x))
    if isinstance(x, (int,)):
        return x / RAO
    return float(x)


def safe_float(d: dict) -> Decimal:
    """Decode the runtime's SafeFloat/FixedU128 {mantissa, exponent} shape."""
    if d is None:
        return Decimal(0)
    if isinstance(d, dict) and "mantissa" in d:
        return Decimal(int(d["mantissa"])) * (Decimal(10) ** int(d["exponent"]))
    return Decimal(str(d))


def pct(x: float, total: float) -> float:
    return 100.0 * x / total if total else 0.0


def short(ss58: Optional[str], n: int = 6) -> str:
    if not ss58:
        return "-"
    return f"{ss58[:n]}..{ss58[-4:]}"


def blocks_to_human(blocks: int) -> str:
    if blocks is None:
        return "-"
    secs = abs(blocks) * BLOCK_SECONDS
    days = secs / 86400
    if days >= 1:
        return f"{days:,.1f}d"
    if secs >= 3600:
        return f"{secs/3600:,.1f}h"
    return f"{secs/60:,.0f}min"


def fmt(x: float, dp: int = 2) -> str:
    return f"{x:,.{dp}f}"


def human(x: float) -> str:
    """Compact magnitude for table cells."""
    if x is None:
        return "-"
    a = abs(x)
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if a >= div:
            return f"{x/div:,.2f}{suf}"
    return f"{x:,.2f}" if a >= 1 else f"{x:.4f}"


class Union:
    """Union-find over ss58 strings."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for x in list(self.parent):
            out[self.find(x)].append(x)
        return out


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Holder:
    coldkey: str
    alpha: float = 0.0
    by_hotkey: dict = field(default_factory=dict)   # hotkey -> alpha
    owns_hotkeys: list = field(default_factory=list)
    uids: list = field(default_factory=list)
    emission: float = 0.0
    identity: Optional[str] = None


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------

class Inspector:
    def __init__(self, client, netuid: int, args) -> None:
        self.c = client
        self.netuid = netuid
        self.args = args
        self.block: int = 0
        self.block_hash: Optional[str] = None
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.d: dict[str, Any] = {}          # raw collected state
        self.holders: dict[str, Holder] = {}
        self.clusters: list[dict] = []
        self.coverage: dict[str, Any] = {}

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)

    def add(self, code, severity, title, detail, **evidence) -> None:
        self.findings.append(Finding(code, severity, title, detail, evidence))

    # -- raw chain state ---------------------------------------------------

    async def collect(self) -> None:
        c, nid = self.c, self.netuid
        self.block = await c.block()
        try:
            self.block_hash = await c._block_hash(self.block)
        except Exception:
            self.block_hash = None

        exists = await c.query(st.SubtensorModule.NetworksAdded, [nid], block=self.block)
        if not exists:
            raise SystemExit(f"subnet {nid} does not exist at block {self.block}")

        say(f"reading subnet {nid} at block {self.block:,}")
        phase("chain state", 3)

        t_stage = time.time()
        mg = await c.subnets.metagraph(nid, block=self.block, commitments=False)
        say(f"metagraph in {time.time()-t_stage:.1f}s ({len(mg.neurons)} uids)")
        step(note=f"{len(mg.neurons)} uids")
        self.d["mg"] = mg
        hks = [n.hotkey for n in mg.neurons]
        self.d["hotkeys"] = hks

        (
            hyper, conv, sid, leases, crowdloans, total_alpha, price,
            owner_ck, owner_hk, registered_at, emission_enabled,
            subnet_tao, alpha_in, alpha_out, protocol_alpha, volume, locked_tao,
            owner_cut_g, max_uids, reg_this_interval, burn,
        ) = await asyncio.gather(
            c.subnets.subnet_hyperparameters(nid, block=self.block),
            c.locks.subnet_convictions(nid, block=self.block),
            c.subnets.subnet_identity(nid, block=self.block),
            c.leasing.leases(block=self.block),
            c.leasing.crowdloans(block=self.block),
            c.staking.total_alpha_staked(nid, block=self.block),
            c.prices.alpha_price(nid, block=self.block),
            c.query(st.SubtensorModule.SubnetOwner, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetOwnerHotkey, [nid], block=self.block),
            c.query(st.SubtensorModule.NetworkRegisteredAt, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetEmissionEnabled, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetTAO, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetAlphaIn, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetAlphaOut, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetProtocolAlpha, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetVolume, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetLocked, [nid], block=self.block),
            c.query(st.SubtensorModule.SubnetOwnerCut, block=self.block),
            c.query(st.SubtensorModule.MaxAllowedUids, [nid], block=self.block),
            c.query(st.SubtensorModule.RegistrationsThisInterval, [nid], block=self.block),
            c.subnets.burn(nid, block=self.block),
        )

        say(f"subnet state in {time.time()-t_stage:.1f}s")
        step()
        self.d.update(
            hyper=hyper or {}, conv=conv or {}, subnet_identity=sid,
            leases=leases or [], crowdloans=crowdloans or [],
            total_alpha=amt(total_alpha), price=_price(price),
            owner_ck=owner_ck, owner_hk=owner_hk,
            registered_at=int(registered_at or 0),
            emission_enabled=bool(emission_enabled),
            subnet_tao=amt(subnet_tao), alpha_in=amt(alpha_in),
            alpha_out=amt(alpha_out), protocol_alpha=amt(protocol_alpha),
            volume=amt(volume), locked_tao=amt(locked_tao),
            owner_cut=(owner_cut_g or 0) / U16_MAX,
            max_uids=int(max_uids or 0),
            regs_this_interval=int(reg_this_interval or 0),
            burn=amt(burn),
        )

        # per-hotkey subnet state, one RPC per item
        pairs = [[h, nid] for h in hks]
        tha, ths, children, parents, pending, ck_take, takes = await asyncio.gather(
            c.query_batch(st.SubtensorModule.TotalHotkeyAlpha, pairs, block=self.block),
            c.query_batch(st.SubtensorModule.TotalHotkeySharesV2, pairs, block=self.block),
            c.query_batch(st.SubtensorModule.ChildKeys, pairs, block=self.block),
            c.query_batch(st.SubtensorModule.ParentKeys, pairs, block=self.block),
            c.query_batch(st.SubtensorModule.PendingChildKeys, [[nid, h] for h in hks], block=self.block),
            c.query_batch(st.SubtensorModule.ChildkeyTake, pairs, block=self.block),
            c.query_batch(st.SubtensorModule.Delegates, [[h] for h in hks], block=self.block),
        )
        say(f"per-hotkey state in {time.time()-t_stage:.1f}s")
        step(note=f"{len(hks)} registered hotkeys")
        self.d["registered_alpha"] = {h: amt(v) for h, v in zip(hks, tha)}
        self.d["shares"] = {h: safe_float(v) for h, v in zip(hks, ths)}
        self.d["children"] = {h: (v or []) for h, v in zip(hks, children)}
        self.d["parents"] = {h: (v or []) for h, v in zip(hks, parents)}
        self.d["pending_children"] = {h: v for h, v in zip(hks, pending) if v and v[0]}
        self.d["childkey_take"] = {h: (v or 0) / U16_MAX for h, v in zip(hks, ck_take)}
        self.d["delegate_take"] = {h: (v or 0) / U16_MAX for h, v in zip(hks, takes)}

        await self.discover_pools()
        await self.scan_holders()
        await self.enrich_holders()

    async def discover_pools(self) -> None:
        """Find every hotkey holding alpha on this subnet, registered or not.

        The metagraph only lists hotkeys that hold a UID here. Alpha can sit on
        any hotkey on any subnet, so a position staged on an unregistered hotkey
        is invisible to the metagraph -- and that is exactly where someone
        accumulating quietly would put it. TotalHotkeyAlpha is the chain's own
        index of (hotkey, netuid) -> alpha; walking it costs about half a minute
        and makes the cap table authoritative instead of indicative.
        """
        c, nid = self.c, self.netuid
        if self.args.fast:
            self.d["tha"] = {h: a for h, a in self.d["registered_alpha"].items() if a > 0}
            self.d["offregister_alpha"] = None
            return

        t0 = time.time()
        # The index scan is one long paged read, and a public endpoint will
        # refuse it outright under load. Refusal is not a reason to lose the
        # whole run: retry with the endpoint's own backoff, and if it still
        # will not serve the index, fall back to the registered hotkeys and
        # say so, so the coverage section reports what was missed.
        pools: dict[str, float] = {}
        scanned = 0
        phase("hotkey index")
        for attempt in range(self.args.retries + 1):
            pools, scanned = {}, 0
            try:
                res = await c._substrate.raw.query_map(
                    "SubtensorModule", "TotalHotkeyAlpha", [],
                    block_hash=self.block_hash, page_size=1000,
                )
                async for key, val in res:
                    scanned += 1
                    if key[1] == nid and val:
                        pools[key[0]] = amt(val)
                    if scanned % 2000 == 0:
                        step(completed=scanned, note=f"{len(pools)} pools here")
                break
            except Exception as e:
                if attempt >= self.args.retries or not _throttled(e):
                    self.notes.append(
                        f"hotkey index scan unavailable ({e.__class__.__name__}): falling back "
                        f"to registered hotkeys, so off-register alpha is not measured")
                    say("endpoint refused the hotkey index scan; falling back to "
                        "registered hotkeys only")
                    self.d["tha"] = {h: a for h, a in self.d["registered_alpha"].items() if a > 0}
                    self.d["offregister_alpha"] = None
                    return
                wait = _retry_after(e) * (attempt + 1) + 2.0 * attempt
                say(f"endpoint throttled the hotkey index scan, retrying in {wait:.0f}s")
                await asyncio.sleep(wait)
        self.d["tha"] = pools
        registered = set(self.d["hotkeys"])
        off = {h: a for h, a in pools.items() if h not in registered}
        self.d["offregister_alpha"] = sum(off.values())
        self.d["offregister_hotkeys"] = sorted(off.items(), key=lambda kv: -kv[1])

        missing = [h for h in pools if h not in self.d["shares"]]
        for i in range(0, len(missing), 200):
            part = missing[i: i + 200]
            got = await c.query_batch(st.SubtensorModule.TotalHotkeySharesV2,
                                      [[h, nid] for h in part], block=self.block)
            self.d["shares"].update({h: safe_float(v) for h, v in zip(part, got)})

        say(f"{len(pools)} hotkeys hold alpha here ({len(off)} of them unregistered, "
            f"{fmt(self.d['offregister_alpha'])} alpha) · {scanned:,} index rows in "
            f"{time.time()-t0:.0f}s")

    # -- holder discovery --------------------------------------------------

    async def scan_holders(self) -> None:
        """Attribute subnet alpha down to coldkeys.

        Alpha on a subnet lives in the AlphaV2 map keyed (hotkey, coldkey,
        netuid) as *shares* of a hotkey's pool. We walk it per hotkey, biggest
        stake first, converting shares to alpha with that hotkey's share/alpha
        totals. Popular delegates have tens of thousands of nominators across
        every subnet, so each prefix walk is capped -- whatever the cap leaves
        behind is reported as unattributed rather than silently dropped.
        """
        c, nid = self.c, self.netuid
        tha = self.d["tha"]
        staked = self.d["total_alpha"] or 1.0

        # A holder inside a pool can never hold more than the pool does, so a
        # pool below the materiality line cannot hide anyone who matters. That
        # turns "we ran out of budget" into a hard bound on what we could have
        # missed, which is the only honest way to report a partial scan.
        material = self.args.materiality * staked
        ranked = sorted((h for h, x in tha.items() if x > 0), key=lambda h: -tha[h])
        expand = [h for h in ranked if tha[h] >= material]
        unexpanded = [h for h in ranked if tha[h] < material]
        budget = self.args.row_budget
        floor = 2000

        raw = c._substrate.raw
        per_hk: dict[str, dict[str, float]] = {}
        truncated: dict[str, float] = {}
        skipped: list[tuple[str, float]] = []
        t0 = time.time()
        rows_read = 0
        deadline = t0 + self.args.max_scan_seconds
        pool_total = sum(tha[h] for h in expand) or 1.0

        rows_live = 0        # counts pages as they land, for the progress note

        async def walk(hk: str, cap: Optional[int]):
            # public endpoints meter paged storage scans; back off and retry
            # rather than silently dropping a pool from the cap table
            nonlocal rows_live
            for attempt in range(self.args.retries + 1):
                try:
                    res = await raw.query_map(
                        "SubtensorModule", "AlphaV2", [hk],
                        block_hash=self.block_hash, page_size=1000, max_results=cap,
                    )
                    rows = []
                    async for key, val in res:
                        rows.append((key, val))
                        rows_live += 1
                        if rows_live % 2000 == 0:
                            step(0, note=f"{rows_live:,} rows")
                    return rows, not res._exhausted
                except Exception as e:
                    if attempt >= self.args.retries or not _throttled(e):
                        raise
                    await asyncio.sleep(_retry_after(e) * (attempt + 1))
            raise RuntimeError("unreachable")

        def absorb(hk: str, rows) -> float:
            total_shares = self.d["shares"].get(hk) or Decimal(0)
            pool_alpha = tha[hk]
            share_of: dict[str, float] = {}
            per_hk[hk] = share_of
            if total_shares <= 0 or pool_alpha <= 0:
                return 0.0
            seen = 0.0
            for key, val in rows:
                ck, key_nid = key[0], key[1]
                if key_nid != nid:
                    continue
                alpha = float(safe_float(val) / total_shares) * pool_alpha
                if alpha <= 0:
                    continue
                share_of[ck] = share_of.get(ck, 0.0) + alpha
                seen += alpha
            return seen

        async def sweep(targets: list[tuple[str, Optional[int]]], label: str) -> None:
            nonlocal rows_read
            wave = max(1, self.args.concurrency)
            phase(label, len(targets))
            for i in range(0, len(targets), wave):
                if time.time() > deadline:
                    skipped.extend((h, tha[h]) for h, _ in targets[i:])
                    self.note(
                        f"holder scan hit its {self.args.max_scan_seconds:.0f}s budget with "
                        f"{len(targets) - i} material pools unread")
                    return
                batch = targets[i: i + wave]

                async def tracked(hk: str, cap: Optional[int]):
                    try:
                        return await walk(hk, cap)
                    finally:
                        step(1)

                got = await asyncio.gather(*[tracked(h, cap) for h, cap in batch],
                                           return_exceptions=True)
                for (hk, _cap), res in zip(batch, got):
                    if isinstance(res, Exception):
                        skipped.append((hk, tha[hk]))
                        self.note(
                        f"pool {short(hk)} ({human(tha[hk])} alpha) unreadable: "
                        + ("endpoint throttled the scan" if _throttled(res)
                           else str(res)[:100]))
                        continue
                    rows, was_cut = res
                    rows_read += len(rows)
                    seen = absorb(hk, rows)
                    if was_cut:
                        truncated[hk] = max(0.0, tha[hk] - seen)
                    else:
                        truncated.pop(hk, None)
                done = min(i + wave, len(targets))
                attributed = sum(sum(v.values()) for v in per_hk.values())
                step(0, note=f"{pct(attributed, staked):.0f}% attributed · {rows_read:,} rows")
                if (i // wave) % 5 == 0 or done == len(targets):
                    say(f"  {label} {done}/{len(targets)} pools · "
                        f"{pct(attributed, staked):.0f}% attributed · "
                        f"{rows_read:,} rows · {time.time()-t0:.0f}s")
                await asyncio.sleep(0.1)      # stay under the endpoint's scan budget

        def cap_for(hk: str) -> Optional[int]:
            if self.args.deep:
                return None
            return max(floor, int(budget * tha[hk] / pool_total))

        say(f"expanding {len(expand)} pools at or above the materiality line "
            f"({fmt(material)} alpha); {len(unexpanded)} smaller pools bounded, not read")
        await sweep([(h, cap_for(h)) for h in expand], "stake scan")

        # follow-up rounds: unspent budget goes to pools that got cut off or
        # were refused, largest shortfall first
        for _round in range(2):
            pendingp = dict(truncated)
            pendingp.update({h: a for h, a in skipped})
            if not pendingp or self.args.deep or time.time() >= deadline:
                break
            left = budget - rows_read
            if left <= floor:
                break
            skipped.clear()
            before = rows_read
            unseen_total = sum(pendingp.values()) or 1.0
            order = sorted(pendingp.items(), key=lambda kv: -kv[1])
            await sweep([(h, max(floor, int(left * u / unseen_total)) + (cap_for(h) or 0))
                         for h, u in order], "deep-dive")
            if rows_read == before:
                self.note("follow-up pass made no progress; the endpoint is refusing "
                                  "further storage scans")
                break

        for hk, share_of in per_hk.items():
            for ck, alpha in share_of.items():
                h = self.holders.setdefault(ck, Holder(coldkey=ck))
                h.alpha += alpha
                h.by_hotkey[hk] = h.by_hotkey.get(hk, 0.0) + alpha
        attributed = sum(sum(v.values()) for v in per_hk.values())

        truncated_list = sorted(truncated.items(), key=lambda kv: -kv[1])
        # the largest position that could still be hiding from us: the biggest
        # pool we never opened, the biggest shortfall in one we only half-read,
        # and (in --fast) all the alpha sitting on pools we never discovered
        undiscovered = max(0.0, staked - sum(tha.values()))
        if undiscovered > 0:
            self.note(f"{fmt(undiscovered)} alpha sits on hotkeys this run never enumerated"
                      + (" (--fast skips the hotkey index, so off-register positions are "
                         "invisible)" if self.args.fast else ""))
        hidden_bound = max(
            [tha[h] for h in unexpanded] +
            [u for _, u in truncated_list] +
            [a for _, a in skipped] + [undiscovered, 0.0])
        self.d["hidden_bound"] = hidden_bound
        self.d["unexpanded_alpha"] = sum(tha[h] for h in unexpanded)

        self.coverage = {
            "attributed_alpha": attributed,
            "staked_alpha_total": self.d["total_alpha"],
            "attributed_pct": pct(attributed, self.d["total_alpha"]),
            "truncated_hotkeys": [{"hotkey": h, "unseen_alpha": a} for h, a in truncated_list],
            "skipped_hotkeys": [{"hotkey": h, "alpha": a} for h, a in skipped],
            "scan_seconds": round(time.time() - t0, 1),
            "rows_read": rows_read,
            "deep": bool(self.args.deep),
            "pools_expanded": len(expand),
            "pools_below_materiality": len(unexpanded),
            "materiality_alpha": material,
            "largest_possible_hidden_holder": hidden_bound,
            "alpha_on_undiscovered_pools": undiscovered,
        }
        say(f"attributed {fmt(attributed)} / {fmt(self.d['total_alpha'])} alpha "
            f"({self.coverage['attributed_pct']:.1f}%) across {len(self.holders):,} coldkeys "
            f"in {self.coverage['scan_seconds']}s")

    # -- per-coldkey enrichment for the shortlist --------------------------

    async def enrich_holders(self) -> None:
        c, nid = self.c, self.netuid
        mg = self.d["mg"]

        # every coldkey that owns a UID counts as a candidate even with no alpha
        for n in mg.neurons:
            h = self.holders.setdefault(n.coldkey, Holder(coldkey=n.coldkey))
            h.owns_hotkeys.append(n.hotkey)
            h.uids.append(n.uid)
            h.emission += amt(n.emission)
        for extra in ([self.d["owner_ck"]] + list(self.args.watch or [])):
            if extra:
                self.holders.setdefault(extra, Holder(coldkey=extra))

        ranked = sorted(self.holders.values(), key=lambda h: -h.alpha)
        keep = {h.coldkey for h in ranked[: self.args.candidates]}
        keep |= {h.coldkey for h in self.holders.values() if h.uids}
        keep.add(self.d["owner_ck"])
        keep |= set(self.args.watch or [])
        if self.args.buyer:
            keep.add(self.args.buyer)
        keep.discard(None)
        cands = sorted(keep)
        self.d["candidates"] = cands
        say(f"profiling {len(cands)} candidate coldkeys for entity clustering")
        phase("profiling", len(cands))

        idents, proxies, autostake, balances = await asyncio.gather(
            c.query_batch(st.SubtensorModule.IdentitiesV2, [[x] for x in cands], block=self.block),
            c.query_batch(st.Proxy.Proxies, [[x] for x in cands], block=self.block),
            c.query_batch(st.SubtensorModule.AutoStakeDestination, [[x, nid] for x in cands], block=self.block),
            c.balances.get_many(cands, block=self.block),
        )
        self.d["identity"] = {ck: (v or {}).get("name") or None for ck, v in zip(cands, idents)}
        self.d["proxies"] = {
            ck: [p["delegate"] for p in (v[0] if v else [])] for ck, v in zip(cands, proxies)
        }
        self.d["proxy_detail"] = {ck: (v[0] if v else []) for ck, v in zip(cands, proxies)}
        self.d["autostake"] = {ck: v for ck, v in zip(cands, autostake) if v}
        self.d["free_tao"] = {ck: amt(v) for ck, v in (balances or {}).items()}

        for ck in cands:
            if ck in self.holders:
                self.holders[ck].identity = self.d["identity"].get(ck)

        # cross-subnet portfolios -- the strongest cheap fingerprint for
        # "these five wallets are one desk"
        ports: dict[str, list] = {}
        chunk = 40
        for i in range(0, len(cands), chunk):
            part = cands[i: i + chunk]
            try:
                got = await c.staking.stake_for_coldkeys(part, block=self.block)
                ports.update(got or {})
                step(len(part), note="cross-subnet portfolios")
            except Exception as e:
                self.notes.append(f"portfolio batch failed: {e}")
        self.d["portfolios"] = {
            ck: sorted({(p.netuid, p.hotkey) for p in pos}) for ck, pos in ports.items()
        }

        # ownership of every hotkey a candidate stakes to (links nominators to operators)
        all_hk = {hk for h in self.holders.values() for hk in h.by_hotkey}
        all_hk |= set(self.d["hotkeys"]) | set(self.d["tha"])
        all_hk = sorted(all_hk)
        owners = await c.query_batch(st.SubtensorModule.Owner, [[h] for h in all_hk], block=self.block)
        self.d["hotkey_owner"] = {h: o for h, o in zip(all_hk, owners)}

        # seller-side levers on the owner coldkey
        try:
            self.d["owner_swap"] = await c.balances.coldkey_swap_announcement(
                self.d["owner_ck"], block=self.block)
        except Exception:
            self.d["owner_swap"] = None


def _price(p: Any) -> float:
    if isinstance(p, dict):
        for k in ("price", "tao_per_alpha", "alpha_price"):
            if k in p:
                return float(amt(p[k]) if hasattr(p[k], "rao") else p[k])
        return 0.0
    return float(amt(p) if hasattr(p, "rao") else p or 0.0)


_RETRY_RE = __import__("re").compile(r"retry_after_ms'?:?\s*'?(\d+)")


def _throttled(e: Exception) -> bool:
    t = str(e).lower()
    return "work limit" in t or "retry_after" in t or "traffic policy" in t or "too many" in t


def _retry_after(e: Exception, default: float = 1.0) -> float:
    m = _RETRY_RE.search(str(e))
    return (int(m.group(1)) / 1000.0) if m else default


def say(msg: str) -> None:
    if PROG is not None and PROG.p is not None:
        PROG.log(f"  · {msg}")
    else:
        print(f"  · {msg}", file=sys.stderr)


# --------------------------------------------------------------------------
# progress display
#
# A run is minutes of one paged scan after another, and the log lines alone do
# not say whether it is working or wedged. This adds a bar per phase over the
# top of the existing log: lines scroll above the bar instead of fighting it.
# It turns itself off when stderr is not a terminal, so redirected output is
# byte-identical to what it was before.
# --------------------------------------------------------------------------

PHASES = ["chain state", "hotkey index", "stake scan", "profiling", "clustering", "analysis"]


class RunProgress:
    def __init__(self, netuid: int, enabled: bool = True) -> None:
        self.enabled = bool(enabled) and sys.stderr.isatty()
        self.netuid = netuid
        self.p = None
        self.overall = None
        self.task = None
        self.done: set[str] = set()

    def __enter__(self) -> "RunProgress":
        if not self.enabled:
            return self
        try:
            from rich.console import Console
            from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                                       MofNCompleteColumn, TimeElapsedColumn)
        except Exception:
            self.enabled = False
            return self
        self.p = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=26, complete_style="cyan", finished_style="cyan"),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[note]}"),
            TimeElapsedColumn(),
            console=Console(stderr=True),
            refresh_per_second=8,
        )
        self.p.start()
        self.overall = self.p.add_task(f"subnet {self.netuid}", total=len(PHASES), note="")
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def phase(self, name: str, total: Optional[float] = None) -> None:
        if not self.p:
            return
        if self.task is not None:
            self.p.remove_task(self.task)
        if name in PHASES and name not in self.done:
            self.done.add(name)
            self.p.update(self.overall, completed=len(self.done),
                          description=f"subnet {self.netuid} · {name}")
        self.task = self.p.add_task(name, total=total, note="")

    def step(self, n: float = 1, note: Optional[str] = None,
             completed: Optional[float] = None, total: Optional[float] = None) -> None:
        if not self.p or self.task is None:
            return
        fields: dict = {}
        if note is not None:
            fields["note"] = note
        if total is not None:
            fields["total"] = total
        if completed is not None:
            self.p.update(self.task, completed=completed, **fields)
        else:
            self.p.update(self.task, advance=n, **fields)

    def log(self, msg: str) -> None:
        if self.p:
            self.p.console.print(msg, highlight=False, markup=False)
        else:
            print(msg, file=sys.stderr)

    def close(self) -> None:
        if not self.p:
            return
        if self.task is not None:
            self.p.remove_task(self.task)
            self.task = None
        self.p.update(self.overall, completed=len(PHASES))
        self.p.stop()
        self.p = None


PROG: Optional[RunProgress] = None


def phase(name: str, total: Optional[float] = None) -> None:
    if PROG is not None:
        PROG.phase(name, total)


def step(n: float = 1, **kw) -> None:
    if PROG is not None:
        PROG.step(n, **kw)


# --------------------------------------------------------------------------
# provenance -- where a wallet came from
#
# Everything else in this tool reads one block. That is enough to see what a
# wallet holds and not enough to see whether two wallets are one hand: a desk
# splitting a position leaves its fingerprint in history, not in state.
#
# Three facts per coldkey, all cheap to read against an archive node:
#
#   created   binary search System.Account -- `providers` flips 0 -> 1 at the
#             block the account was first funded. ~24 reads over 9M blocks.
#   funder    the Balances.Transfer in that block's events that endowed it.
#   staked    binary search the stake map for the first block this coldkey
#             held alpha on the subnet. Older runtimes call it Alpha, newer
#             ones AlphaV2, and a position migrated between them reads zero on
#             the old map -- so both are probed at every block.
#
# The funder alone proves little: an exchange hot wallet funds thousands of
# unrelated people. Its nonce says which kind of wallet it is -- a personal
# key signs tens of transactions, an exchange signs hundreds of thousands --
# and the evidence is weighted by that, so exchange-funded wallets do not get
# clustered into one entity on the strength of sharing Binance.
# --------------------------------------------------------------------------

# How close together two wallets appeared, and what that is worth. A burst --
# accounts created a minute apart, in sequence -- is a different claim from
# two accounts that happened to appear the same afternoon, so the weight is
# graded by tightness rather than by a single cutoff. Staking is graded more
# loosely: a desk batches wallet creation because it is tedious, then spreads
# the buys, which is exactly the shape SN 38 turned out to have.
PROV_CREATED_WEIGHTS = ((60, 5.0), (300, 3.0), (1_800, 1.5))
PROV_STAKED_WEIGHTS = ((300, 3.0), (5_000, 1.5))
PROV_PERSONAL_NONCE = 1_000
PROV_EXCHANGE_NONCE = 50_000


def _prov_cache_path() -> Path:
    return Path.home() / ".cache" / "subnet_inspector" / "provenance.json"


def _load_prov_cache() -> dict:
    try:
        return json.loads(_prov_cache_path().read_text())
    except Exception:
        return {}


def _save_prov_cache(cache: dict) -> None:
    try:
        p = _prov_cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cache, indent=1, default=str))
    except Exception:
        pass


def _nonzero(v: Any) -> bool:
    if not v:
        return False
    if isinstance(v, dict):
        return any(bool(x) for x in v.values())
    return bool(v)


class Provenance:
    """Historical reads against an archive node, cached by coldkey.

    Creation blocks and funders never change, so a hit in the cache costs
    nothing and a second run on the same wallets is free.
    """

    def __init__(self, client, args, head: int) -> None:
        self.c = client
        self.args = args
        self.head = head
        self.pace = args.provenance_pace
        self.cache = _load_prov_cache()
        self.reads = 0
        self._hashes: dict[int, str] = {}     # block hashes are immutable
        self._stake_map = "AlphaV2"           # last map that answered

    async def _read(self, coro_factory, tries: int = 5):
        for attempt in range(tries):
            try:
                self.reads += 1
                out = await coro_factory()
                await asyncio.sleep(self.pace)
                return out
            except Exception as e:
                if attempt >= tries - 1 or not _throttled(e):
                    raise
                await asyncio.sleep(max(_retry_after(e), 2.0) * (attempt + 1))

    async def _account(self, ck: str, block: int) -> Optional[dict]:
        return await self._read(
            lambda: self.c.query(st.System.Account, [ck], block=block))

    @staticmethod
    def _exists(acc: Optional[dict]) -> bool:
        if not acc:
            return False
        d = acc.get("data") or {}
        return bool(acc.get("providers") or acc.get("consumers")
                    or d.get("free") or d.get("reserved"))

    async def creation_block(self, ck: str) -> Optional[int]:
        """First block at which this coldkey existed on chain."""
        if not self._exists(await self._account(ck, self.head)):
            return None
        lo, hi = 1, self.head
        while lo < hi:
            mid = (lo + hi) // 2
            if self._exists(await self._account(ck, mid)):
                hi = mid
            else:
                lo = mid + 1
        return lo

    async def endowment(self, ck: str, block: int) -> tuple[Optional[str], float]:
        """Who paid for the account, and how much, at the block it appeared."""
        try:
            evs = await self._read(
                lambda: self.c.query(st.System.Events, [], block=block))
        except Exception:
            return None, 0.0
        for e in evs or []:
            at = e.get("attributes") or {}
            if (e.get("module_id") == "Balances" and e.get("event_id") == "Transfer"
                    and at.get("to") == ck):
                return at.get("from"), amt(at.get("amount") or 0)
        return None, 0.0

    async def nonce(self, ck: str) -> int:
        acc = await self._account(ck, self.head)
        return int((acc or {}).get("nonce") or 0)

    async def _block_hash(self, block: int) -> str:
        if block not in self._hashes:
            self._hashes[block] = await self._read(lambda: self.c._block_hash(block))
        return self._hashes[block]

    async def _staked(self, hk: str, ck: str, netuid: int, block: int) -> bool:
        """Did this coldkey hold alpha here at this block?

        The map was renamed mid-history, so both names are tried -- but the
        one that answered last time is tried first, which costs one read per
        probe instead of two everywhere except at the migration boundary.
        """
        bh = await self._block_hash(block)
        raw = self.c._substrate.raw
        order = ([self._stake_map] +
                 [n for n in ("AlphaV2", "Alpha") if n != self._stake_map])
        for name in order:
            try:
                v = await self._read(
                    lambda n=name: raw.query("SubtensorModule", n, [hk, ck, netuid],
                                             block_hash=bh))
            except Exception as e:
                if "not found" in str(e).lower():
                    continue          # this runtime predates that storage map
                raise
            if _nonzero(v):
                self._stake_map = name      # remember only what actually answered
                return True
        return False

    async def first_stake(self, hk: str, ck: str, netuid: int,
                          lo: int) -> Optional[int]:
        """First block this coldkey held alpha on the subnet through `hk`."""
        hi = self.head
        if not await self._staked(hk, ck, netuid, hi):
            return None
        lo = max(lo, 1)
        while lo < hi:
            mid = (lo + hi) // 2
            if await self._staked(hk, ck, netuid, mid):
                hi = mid
            else:
                lo = mid + 1
        return lo

    async def trace(self, ck: str, hotkey: Optional[str], netuid: int) -> dict:
        key = f"{ck}"
        row = dict(self.cache.get(key) or {})
        if "created" not in row:
            blk = await self.creation_block(ck)
            row["created"] = blk
            if blk:
                funder, funded = await self.endowment(ck, blk)
                row["funder"] = funder
                row["funded_tao"] = funded
                try:
                    row["created_at"] = str(await self._read(
                        lambda: self.c.timestamp(block=blk)))
                except Exception:
                    row["created_at"] = None
        stake_key = f"stake:{netuid}:{hotkey}"
        if hotkey and stake_key not in row and row.get("created"):
            try:
                row[stake_key] = await self.first_stake(hotkey, ck, netuid,
                                                        row["created"])
            except Exception:
                row[stake_key] = None
        self.cache[key] = row
        return row


def _provenance_targets(insp: "Inspector", limit: int) -> list[str]:
    """Which wallets are worth the historical reads.

    Every member of a tight size band -- the shape that provenance exists to
    resolve -- then the largest holders, until the budget runs out.
    """
    single = [cl for cl in insp.clusters if cl["size"] == 1 and not cl["is_owner"]
              and cl["alpha"] > 0]
    single.sort(key=lambda cl: -cl["alpha"])
    picked: list[str] = []
    k = 0
    while k < len(single):
        j = k + 1
        while j < len(single) and single[k]["alpha"] <= single[j]["alpha"] * 1.35:
            j += 1
        if j - k >= 3:
            picked.extend(cl["members"][0] for cl in single[k:j])
        k = j
    for cl in single:
        if len(picked) >= limit:
            break
        if cl["members"][0] not in picked:
            picked.append(cl["members"][0])
    return picked[:limit]


async def trace_provenance(insp: "Inspector") -> None:
    """Fill insp.d['provenance'] for the wallets worth tracing."""
    args = insp.args
    targets = _provenance_targets(insp, args.provenance_max)
    if not targets:
        return
    prov: dict[str, dict] = {}
    url = args.history_network
    say(f"tracing the origin of {len(targets)} wallets on {url}")
    phase("provenance", len(targets))
    async with bt.Client(network=url) as hc:
        head = await hc.block()
        p = Provenance(hc, args, head)
        for ck in targets:
            hk = None
            h = insp.holders.get(ck)
            if h and h.by_hotkey:
                hk = max(h.by_hotkey.items(), key=lambda kv: kv[1])[0]
            try:
                prov[ck] = await p.trace(ck, hk, insp.netuid)
                prov[ck]["hotkey"] = hk
            except Exception as e:
                insp.note(f"provenance for {short(ck)} failed: {str(e)[:80]}")
            step(1, note=f"{p.reads:,} historical reads")

        # one hop up: an exchange between two wallets means nothing, but two
        # funders paid by the same wallet is the link the exchange was hiding
        funders = {r.get("funder") for r in prov.values() if r.get("funder")}
        funders = {f for f in funders if f not in prov}
        if funders and len(funders) <= args.provenance_max:
            phase("funder trace", len(funders))
            for f in sorted(funders):
                try:
                    row = await p.trace(f, None, insp.netuid)
                    row["nonce"] = await p.nonce(f)
                    prov[f] = row
                except Exception as e:
                    insp.note(f"funder trace {short(f)} failed: {str(e)[:80]}")
                step(1, note=f"{p.reads:,} historical reads")
        _save_prov_cache(p.cache)
        say(f"provenance: {p.reads:,} historical reads, "
            f"{sum(1 for r in prov.values() if r.get('created'))} wallets dated")
    insp.d["provenance"] = prov


# --------------------------------------------------------------------------
# entity clustering
# --------------------------------------------------------------------------

LINK_THRESHOLD = 5.0


class Clusterer:
    """Group coldkeys that behave like one entity.

    No single on-chain fact proves common control, so evidence is weighted and
    accumulated: shared proxy delegates, identical published identity, childkey
    delegation, rare shared hotkeys, near-identical cross-subnet portfolios,
    shared auto-stake destinations, and evenly-split positions. Pairs whose
    evidence clears LINK_THRESHOLD get merged.
    """

    def __init__(self, insp: "Inspector") -> None:
        self.i = insp
        self.links: dict[frozenset, list[tuple[float, str]]] = defaultdict(list)

    def link(self, a: str, b: str, w: float, why: str) -> None:
        if a and b and a != b:
            self.links[frozenset((a, b))].append((w, why))

    def run(self) -> list[dict]:
        i = self.i
        cands = [c for c in i.d["candidates"] if c]
        cset = set(cands)

        self._proxies(cands, cset)
        self._identity(cands)
        self._hotkey_ownership(cands, cset)
        self._shared_hotkeys(cands)
        self._portfolios(cands)
        self._autostake(cands)
        self._childkeys(cset)
        self._even_split(cands)
        self._provenance(cands)

        uf = Union()
        # every holder gets a node, so the cap table and the concentration
        # numbers cover the whole book -- only the clustering evidence is
        # limited to the profiled candidates
        for ck in cands:
            uf.find(ck)
        for ck in i.holders:
            uf.find(ck)
        merged: dict[frozenset, list[tuple[float, str]]] = {}
        for pair, ev in self.links.items():
            total = sum(w for w, _ in ev)
            if total >= LINK_THRESHOLD:
                a, b = tuple(pair)
                uf.union(a, b)
                merged[pair] = ev

        out = []
        for root, members in uf.groups().items():
            out.append(self._summarize(members, merged))
        out.sort(key=lambda c: -c["alpha"])
        return out

    # -- evidence sources --------------------------------------------------

    def _proxies(self, cands, cset) -> None:
        by_delegate: dict[str, list[str]] = defaultdict(list)
        for ck in cands:
            for dg in self.i.d["proxies"].get(ck, []):
                by_delegate[dg].append(ck)
                if dg in cset:
                    self.link(ck, dg, 5.0, f"{short(ck)} grants proxy rights to {short(dg)}")
        for dg, cks in by_delegate.items():
            if len(cks) < 2:
                continue
            w = 5.0 if len(cks) <= 8 else 1.0
            for a in range(len(cks)):
                for b in range(a + 1, len(cks)):
                    self.link(cks[a], cks[b], w, f"share proxy delegate {short(dg)}")

    def _provenance(self, cands) -> None:
        """Common origin: who paid for the wallet, and when it appeared.

        Timing is the load-bearing signal. Two wallets created an hour apart
        and staked into the same subnet an hour apart are either one desk or
        a coincidence that has to happen twice; a shared funder only carries
        weight when the funder looks like a person rather than an exchange.
        """
        prov = self.i.d.get("provenance") or {}
        if not prov:
            return
        rows = {ck: prov[ck] for ck in cands if ck in prov and prov[ck].get("created")}

        by_funder: dict[str, list[str]] = defaultdict(list)
        for ck, r in rows.items():
            if r.get("funder"):
                by_funder[r["funder"]].append(ck)
        for f, cks in by_funder.items():
            if len(cks) < 2:
                continue
            nonce = int((prov.get(f) or {}).get("nonce") or 0)
            if nonce and nonce >= PROV_EXCHANGE_NONCE:
                w, how = 1.0, f"both funded from {short(f)}, an exchange-scale wallet " \
                              f"({nonce:,} txs) -- weak on its own"
            elif nonce and nonce < PROV_PERSONAL_NONCE:
                w, how = 5.0, f"both funded from {short(f)}, a personal wallet ({nonce:,} txs)"
            else:
                w, how = 3.0, f"both funded from {short(f)}"
            for a in range(len(cks)):
                for b in range(a + 1, len(cks)):
                    self.link(cks[a], cks[b], w, how)

        # funders that were themselves paid by the same wallet
        by_grandparent: dict[str, list[str]] = defaultdict(list)
        for ck, r in rows.items():
            gp = (prov.get(r.get("funder")) or {}).get("funder")
            if gp:
                by_grandparent[gp].append(ck)
        for gp, cks in by_grandparent.items():
            if len(cks) < 2 or len({rows[c].get("funder") for c in cks}) < 2:
                continue
            for a in range(len(cks)):
                for b in range(a + 1, len(cks)):
                    self.link(cks[a], cks[b], 3.0,
                              f"their funders were both paid by {short(gp)}")

        cks = sorted(rows)
        for a in range(len(cks)):
            for b in range(a + 1, len(cks)):
                x, y = rows[cks[a]], rows[cks[b]]
                gap = abs((x["created"] or 0) - (y["created"] or 0))
                w = next((w for lim, w in PROV_CREATED_WEIGHTS if gap <= lim), 0.0)
                if w:
                    # bucketed wording, so a five-wallet group contributes one
                    # line of evidence instead of ten near-identical ones; the
                    # exact blocks are in the provenance section
                    lim = next(lim for lim, ww in PROV_CREATED_WEIGHTS if ww == w)
                    self.link(cks[a], cks[b], w,
                              f"created within {blocks_to_human(lim)} of each other"
                              + (" in a sequential burst" if lim <= 60 else ""))
                sx = next((v for k, v in x.items() if k.startswith("stake:") and v), None)
                sy = next((v for k, v in y.items() if k.startswith("stake:") and v), None)
                if sx and sy:
                    sgap = abs(sx - sy)
                    w = next((w for lim, w in PROV_STAKED_WEIGHTS if sgap <= lim), 0.0)
                    if w:
                        lim = next(l for l, ww in PROV_STAKED_WEIGHTS if ww == w)
                        self.link(cks[a], cks[b], w,
                                  f"first staked here within {blocks_to_human(lim)} "
                                  f"of each other")

    def _identity(self, cands) -> None:
        by_name: dict[str, list[str]] = defaultdict(list)
        for ck in cands:
            nm = (self.i.d["identity"].get(ck) or "").strip().lower()
            if nm:
                by_name[nm].append(ck)
        for nm, cks in by_name.items():
            for a in range(len(cks)):
                for b in range(a + 1, len(cks)):
                    self.link(cks[a], cks[b], 5.0, f"identical on-chain identity '{nm}'")

    def _hotkey_ownership(self, cands, cset) -> None:
        owner = self.i.d["hotkey_owner"]
        tha = self.i.d["tha"]
        for ck in cands:
            h = self.i.holders.get(ck)
            if not h:
                continue
            for hk, alpha in h.by_hotkey.items():
                op = owner.get(hk)
                if not op or op == ck or op not in cset:
                    continue
                pool = tha.get(hk, 0.0)
                share = alpha / pool if pool else 0.0
                if share >= 0.75:
                    self.link(ck, op, 3.0, f"{short(ck)} funds {share:.0%} of {short(op)}'s hotkey {short(hk)}")
                elif share >= 0.25:
                    self.link(ck, op, 1.5, f"{short(ck)} funds {share:.0%} of {short(op)}'s hotkey {short(hk)}")

    def _shared_hotkeys(self, cands) -> None:
        by_hk: dict[str, list[str]] = defaultdict(list)
        for ck in cands:
            h = self.i.holders.get(ck)
            if not h:
                continue
            for hk in h.by_hotkey:
                by_hk[hk].append(ck)
        for hk, cks in by_hk.items():
            n = len(cks)
            if n < 2:
                continue
            w = 2.0 if n <= 4 else (1.0 if n <= 8 else 0.0)
            if not w:
                continue
            for a in range(n):
                for b in range(a + 1, n):
                    self.link(cks[a], cks[b], w, f"both stake to seldom-used hotkey {short(hk)} ({n} holders)")

    def _portfolios(self, cands) -> None:
        ports = {ck: set(self.i.d["portfolios"].get(ck) or ()) for ck in cands}
        big = [ck for ck in cands if len(ports[ck]) >= 3]
        for a in range(len(big)):
            for b in range(a + 1, len(big)):
                A, B = ports[big[a]], ports[big[b]]
                inter = A & B
                if not inter:
                    continue
                jac = len(inter) / len(A | B)
                if jac >= 0.7:
                    self.link(big[a], big[b], 3.0,
                              f"cross-subnet portfolios {jac:.0%} identical ({len(inter)} shared positions)")
                elif jac >= 0.5 and len(inter) >= 5:
                    self.link(big[a], big[b], 2.0,
                              f"cross-subnet portfolios {jac:.0%} similar ({len(inter)} shared positions)")

    def _autostake(self, cands) -> None:
        by_dest: dict[str, list[str]] = defaultdict(list)
        for ck in cands:
            dest = self.i.d["autostake"].get(ck)
            if dest:
                by_dest[dest].append(ck)
        for dest, cks in by_dest.items():
            if 2 <= len(cks) <= 5:
                for a in range(len(cks)):
                    for b in range(a + 1, len(cks)):
                        self.link(cks[a], cks[b], 2.0, f"same auto-stake destination {short(dest)}")

    def _childkeys(self, cset) -> None:
        owner = self.i.d["hotkey_owner"]
        for parent, kids in self.i.d["children"].items():
            for _prop, child in kids or []:
                a, b = owner.get(parent), owner.get(child)
                if a in cset and b in cset:
                    self.link(a, b, 2.0, f"childkey delegation {short(parent)} -> {short(child)}")

    def _even_split(self, cands) -> None:
        floor = 0.001 * max(self.i.d["total_alpha"], 1.0)
        vals = [(ck, self.i.holders[ck].alpha) for ck in cands
                if ck in self.i.holders and self.i.holders[ck].alpha >= floor]
        vals.sort(key=lambda x: x[1])
        n = len(vals)
        i0 = 0
        while i0 < n:
            j = i0 + 1
            while j < n and vals[j][1] <= vals[i0][1] * 1.005:
                j += 1
            group = vals[i0:j]
            if len(group) >= 3:
                for a in range(len(group)):
                    for b in range(a + 1, len(group)):
                        self.link(group[a][0], group[b][0], 1.0,
                                  f"{len(group)} wallets hold within 0.5% of the same amount")
            i0 = j

    # -- summary -----------------------------------------------------------

    def _summarize(self, members: list[str], merged: dict) -> dict:
        i = self.i
        mg = i.d["mg"]
        mset = set(members)
        alpha = sum(i.holders[m].alpha for m in members if m in i.holders)
        uids = [n for n in mg.neurons if n.coldkey in mset]
        emission = sum(amt(n.emission) for n in uids)
        permits = [n for n in uids if n.validator_permit]
        cons = sum(amt(n.total_stake) for n in permits)
        by_size = sorted(members, key=lambda m: -(i.holders[m].alpha if m in i.holders else 0.0))
        names = sorted({i.d["identity"].get(m) for m in members if i.d["identity"].get(m)})
        owner_name = i.d["identity"].get(i.d["owner_ck"])
        if i.d["owner_ck"] in mset:
            label = owner_name or "subnet owner"
        else:
            label = next((i.d["identity"].get(m) for m in by_size if i.d["identity"].get(m)),
                         short(by_size[0]) if by_size else "?")
        hotkeys = sorted({hk for m in members if m in i.holders for hk in i.holders[m].by_hotkey}
                         | {n.hotkey for n in uids})
        # conviction belongs to whoever owns the hotkey it is locked on, not to
        # everyone who happens to stake through that hotkey
        owned_hk = {hk for hk in hotkeys if i.d["hotkey_owner"].get(hk) in mset}
        conv_rows = [r for r in i.d["conv"].get("hotkeys", []) if r.get("hotkey") in owned_hk]
        why = []
        for pair, ev in merged.items():
            if pair <= mset:
                why.extend(w for _, w in ev)
        return {
            "members": by_size,
            "size": len(members),
            "alpha": alpha,
            "identities": names,
            "label": label,
            "uids": sorted(n.uid for n in uids),
            "validator_permits": len(permits),
            "consensus_stake": cons,
            "emission_per_epoch": emission,
            "hotkeys": hotkeys,
            "owned_hotkeys": sorted(owned_hk),
            "conviction_alpha": sum(amt(r.get("conviction_alpha")) for r in conv_rows),
            "locked_alpha": sum(amt(r.get("locked_alpha")) for r in conv_rows),
            "is_owner": i.d["owner_ck"] in mset,
            "evidence": sorted(set(why))[:12],
            "free_tao": sum(i.d["free_tao"].get(m, 0.0) for m in members),
        }


# --------------------------------------------------------------------------
# market math
# --------------------------------------------------------------------------

async def tao_to_buy_alpha(c, netuid: int, target_alpha: float, block: int,
                           alpha_in: float, tao_in: float) -> Optional[float]:
    """TAO needed to pull `target_alpha` out of the subnet pool, fees included."""
    if target_alpha <= 0:
        return 0.0
    if target_alpha >= alpha_in * 0.995:
        return None                                   # pool cannot supply it
    est = tao_in * target_alpha / (alpha_in - target_alpha)
    lo, hi = est * 0.4, est * 4.0
    try:
        for _ in range(18):
            mid = (lo + hi) / 2
            q = await c.prices.quote_stake(netuid, mid, block=block)
            if amt(q.alpha) < target_alpha:
                lo = mid
            else:
                hi = mid
        return hi
    except Exception:
        return est


async def exit_impact(c, netuid: int, alpha: float, block: int,
                      alpha_in: float, tao_in: float, spot: float) -> dict:
    """What happens to the pool if a holder sells its whole position."""
    out = {"alpha": alpha}
    tao_out = None
    try:
        q = await c.prices.quote_unstake(netuid, alpha, block=block)
        tao_out = amt(q.tao)
    except Exception:
        pass
    if tao_out is None:
        k = alpha_in * tao_in
        tao_out = tao_in - k / (alpha_in + alpha) if alpha_in else 0.0
    price_after = (tao_in - tao_out) / (alpha_in + alpha) if (alpha_in + alpha) else 0.0
    out["tao_out"] = tao_out
    out["spot_value"] = alpha * spot
    out["realized_vs_spot"] = (tao_out / (alpha * spot) - 1.0) if (alpha and spot) else 0.0
    out["price_after"] = price_after
    out["price_drawdown"] = (1.0 - price_after / spot) if spot else 0.0
    return out


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

async def analyze(insp: Inspector) -> None:
    i, c, nid = insp, insp.c, insp.netuid
    d = i.d
    mg = d["mg"]
    conv = d["conv"]
    spot = d["price"] or (d["subnet_tao"] / d["alpha_in"] if d["alpha_in"] else 0.0)
    d["spot"] = spot

    owner_ck = d["owner_ck"]
    owner_cluster = next((cl for cl in i.clusters if cl["is_owner"]), None)
    rivals = [cl for cl in i.clusters if not cl["is_owner"]]
    top_rival = rivals[0] if rivals else None

    # ---- 1. the conviction takeover gate --------------------------------
    thr = amt(conv.get("threshold_alpha"))
    eligible = amt(conv.get("eligible_alpha"))
    change_at = conv.get("ownership_changeable_at_block")
    open_in = (change_at - i.block) if change_at else None
    d["takeover"] = {"threshold_alpha": thr, "eligible_alpha": eligible,
                     "changeable_at_block": change_at, "blocks_until_open": open_in}

    seize_cost = await tao_to_buy_alpha(c, nid, thr, i.block, d["alpha_in"], d["subnet_tao"])
    d["takeover"]["tao_to_seize"] = seize_cost

    if change_at is not None and open_in is not None and open_in <= 0:
        i.add("TAKEOVER_WINDOW_OPEN", "CRITICAL",
              "Conviction takeover of this subnet is live right now",
              f"The chain reassigns subnet ownership to whichever single hotkey's conviction "
              f"exceeds 18% of eligible alpha ({fmt(thr)} alpha here). This subnet passed the "
              f"age gate at block {change_at:,}, {blocks_to_human(-open_in)} ago, so the "
              f"mechanism is armed. Buying alpha and locking it is enough to take the slot from "
              f"you; on current pool depth that costs about "
              f"{'more TAO than the pool can supply' if seize_cost is None else fmt(seize_cost) + ' TAO'}.",
              threshold_alpha=thr, tao_to_seize=seize_cost, changeable_at_block=change_at)
    elif change_at is not None:
        i.add("TAKEOVER_WINDOW_PENDING", "MEDIUM",
              f"Conviction takeover becomes possible in {blocks_to_human(open_in)}",
              f"At block {change_at:,} the subnet clears the ~1 year age gate and any hotkey "
              f"holding conviction above {fmt(thr)} alpha (18% of eligible) can take ownership. "
              f"Budget for the defense before then, not after.",
              threshold_alpha=thr, blocks_until_open=open_in, tao_to_seize=seize_cost)

    owner_conv = amt(next((r for r in conv.get("hotkeys", []) if r.get("is_owner")), {}).get("conviction_alpha"))
    d["owner_conviction"] = owner_conv
    if thr:
        ratio = owner_conv / thr
        if ratio < 0.5 and change_at is not None:
            i.add("OWNER_CONVICTION_WEAK", "HIGH" if (open_in or 1) <= 0 else "MEDIUM",
                  f"Owner conviction is only {ratio:.0%} of the takeover threshold",
                  f"The current owner has {fmt(owner_conv)} alpha of conviction against a "
                  f"{fmt(thr)} alpha threshold. Conviction is the only defense against the "
                  f"ownership-change mechanism, and it has to be locked and then matured -- you "
                  f"cannot buy it the day an attacker moves.",
                  owner_conviction=owner_conv, threshold=thr)

    for row in conv.get("hotkeys", []):
        if row.get("is_owner"):
            continue
        p = row.get("pct_of_threshold") or 0
        if p >= 0.5:
            i.add("RIVAL_CONVICTION", "CRITICAL" if p >= 1 else "HIGH",
                  f"Non-owner hotkey {short(row['hotkey'])} sits at {p:.0%} of the takeover threshold",
                  f"This hotkey is actively accumulating conviction and is not the subnet owner. "
                  f"At 100% it becomes the owner. blocks_to_threshold={row.get('blocks_to_threshold')}",
                  **{k: (amt(v) if hasattr(v, 'rao') else v) for k, v in row.items()})

    # a rival that already holds enough alpha only has to lock it
    if thr:
        for cl in rivals[:5]:
            if cl["alpha"] >= thr:
                i.add("RIVAL_CAN_SEIZE_NOW", "CRITICAL",
                      f"{cl['label']} already holds more alpha than the takeover threshold",
                      f"{cl['label']} controls {fmt(cl['alpha'])} alpha across {cl['size']} "
                      f"coldkey(s) -- above the {fmt(thr)} alpha conviction threshold. They do not "
                      f"need to buy anything; concentrating and locking what they already hold "
                      f"is enough to take ownership once the age gate is open.",
                      cluster=cl["label"], alpha=cl["alpha"], threshold=thr,
                      members=cl["members"])

    # ---- 2. alpha overhang ----------------------------------------------
    owner_alpha = owner_cluster["alpha"] if owner_cluster else 0.0
    d["owner_alpha"] = owner_alpha
    if top_rival and top_rival["alpha"] > owner_alpha:
        i.add("ALPHA_OVERHANG", "CRITICAL" if top_rival["alpha"] > 2 * max(owner_alpha, 1) else "HIGH",
              f"{top_rival['label']} holds more alpha than the subnet owner",
              f"{top_rival['label']} controls {fmt(top_rival['alpha'])} alpha "
              f"({pct(top_rival['alpha'], d['alpha_out']):.1f}% of circulating) across "
              f"{top_rival['size']} coldkey(s), against the owner's {fmt(owner_alpha)}. "
              f"Whoever holds the largest position sets the terms: they can dump into your "
              f"launch, vote your emissions, or simply name a price for not doing so. This is "
              f"the single most common way an inherited slot turns into a hostage situation.",
              rival=top_rival["label"], rival_alpha=top_rival["alpha"],
              owner_alpha=owner_alpha, members=top_rival["members"],
              evidence=top_rival["evidence"])

    for cl in rivals[:3]:
        if cl["size"] >= 3 and cl["alpha"] >= 0.02 * max(d["alpha_out"], 1):
            i.add("SYBIL_CLUSTER", "HIGH",
                  f"{cl['size']} wallets appear to be one entity holding {pct(cl['alpha'], d['alpha_out']):.1f}% of alpha",
                  f"These coldkeys are linked by: " + "; ".join(cl["evidence"][:4]) +
                  ". Read as one position, not as several independent holders.",
                  members=cl["members"], alpha=cl["alpha"], evidence=cl["evidence"])

    # Wallets sitting in a tight size band, each below the radar on its own.
    # On-chain evidence cannot prove they are one desk -- that needs funding
    # history -- but the shape is worth naming, because it is what a split
    # position looks like from the outside.
    band = sorted((cl for cl in rivals
                   if cl["size"] == 1 and cl["alpha"] >= 0.0025 * max(d["alpha_out"], 1)),
                  key=lambda cl: -cl["alpha"])
    groups = []
    k = 0
    while k < len(band):
        j = k + 1
        while j < len(band) and band[k]["alpha"] <= band[j]["alpha"] * 1.35:
            j += 1
        if j - k >= 3:
            groups.append(band[k:j])
        k = j
    floor_alpha = max(0.05 * max(d["alpha_out"], 1), 0.25 * max(owner_alpha, 1))
    groups = [g for g in groups if sum(x["alpha"] for x in g) >= floor_alpha]
    groups.sort(key=lambda g: -sum(x["alpha"] for x in g))
    for grp in groups[:2]:
        tot = sum(g["alpha"] for g in grp)
        shared = set.intersection(*[set(g["hotkeys"]) for g in grp])
        i.add("SPLIT_PATTERN", "HIGH" if tot > max(owner_alpha, 1) else "MEDIUM",
              f"{len(grp)} unlinked wallets hold near-identical positions "
              f"({human(grp[-1]['alpha'])}-{human(grp[0]['alpha'])} alpha each)",
              f"Together they hold {fmt(tot)} alpha, "
              f"{pct(tot, max(d['alpha_out'], 1)):.1f}% of circulating and "
              f"{tot / max(owner_alpha, 1e-9):.1f}x the owner's position"
              + (f", all staked through the same hotkey {short(sorted(shared)[0])}"
                 if shared else "")
              + ". Sizing this close is either coincidence or one position deliberately "
                "split below the level that draws attention. Chain state cannot tell you "
                "which -- ask for the funding history of these coldkeys before you close, "
                "and price the deal as if it is one holder.",
              wallets=[g["members"][0] for g in grp],
              each=[g["alpha"] for g in grp], combined=tot,
              shared_hotkeys=sorted(shared))

    # what the rivals control if they ever agree with each other
    combined = sum(cl["alpha"] for cl in rivals[:5])
    d["top5_rival_alpha"] = combined
    if thr and combined >= thr and rivals:
        i.add("COALITION_RISK", "HIGH",
              f"The top 5 non-owner holders together clear the takeover threshold",
              f"{fmt(combined)} alpha across the five largest outside positions, against a "
              f"{fmt(thr)} alpha threshold and the owner's {fmt(owner_alpha)}. They do not have "
              f"to be one entity today -- they only have to agree once. Any deal you sign should "
              f"assume they can, because the payoff for coordinating is the subnet itself.",
              combined=combined, threshold=thr, owner_alpha=owner_alpha,
              holders=[cl["label"] for cl in rivals[:5]])

    top10 = sum(cl["alpha"] for cl in i.clusters[:10])
    hhi = sum((pct(cl["alpha"], max(d["alpha_out"], 1)) / 100) ** 2 for cl in i.clusters)
    d["hhi"] = hhi
    d["top10_share"] = pct(top10, max(d["alpha_out"], 1))
    if hhi > 0.25:
        i.add("CONCENTRATION", "HIGH" if hhi > 0.4 else "MEDIUM",
              f"Alpha ownership is highly concentrated (HHI {hhi:.2f})",
              f"Top 10 entities hold {d['top10_share']:.1f}% of circulating alpha. A concentrated "
              f"cap table means price, emissions, and governance all move on a handful of decisions "
              f"you do not control.",
              hhi=hhi, top10_share=d["top10_share"])

    off = d.get("offregister_alpha")
    if off and d["alpha_out"]:
        off_pct = pct(off, d["alpha_out"])
        top_off = d.get("offregister_hotkeys", [])[:5]
        if off_pct >= 10:
            i.add("OFF_REGISTER_ALPHA", "HIGH" if off_pct >= 25 else "MEDIUM",
                  f"{off_pct:.1f}% of circulating alpha sits on hotkeys with no UID here",
                  f"{fmt(off)} alpha is held on {len(d.get('offregister_hotkeys', []))} hotkeys "
                  f"that are not registered on this subnet, so none of it shows up in the "
                  f"metagraph or on any dashboard built from it. Largest: "
                  + ", ".join(f"{short(h)} ({human(a)})" for h, a in top_off)
                  + ". Positions are staged off-register when the holder does not want to be "
                    "counted; treat this as the part of the cap table the seller may not have "
                    "shown you.",
                  offregister_alpha=off, offregister_pct=off_pct,
                  top=[{"hotkey": h, "alpha": a} for h, a in top_off])

    # ---- 3. exit / dump risk --------------------------------------------
    if top_rival and top_rival["alpha"] > 0:
        imp = await exit_impact(c, nid, top_rival["alpha"], i.block,
                                d["alpha_in"], d["subnet_tao"], spot)
        d["top_rival_exit"] = imp
        if imp["price_drawdown"] >= 0.25:
            i.add("EXIT_PRESSURE", "HIGH" if imp["price_drawdown"] >= 0.5 else "MEDIUM",
                  f"{top_rival['label']} exiting would take the alpha price down {imp['price_drawdown']:.0%}",
                  f"Selling {fmt(top_rival['alpha'])} alpha into a pool holding "
                  f"{fmt(d['subnet_tao'])} TAO realizes about {fmt(imp['tao_out'])} TAO and leaves "
                  f"the price at {imp['price_after']:.6f} (from {spot:.6f}). That is the size of "
                  f"the threat they can hold over you, and the size of the hole you would be "
                  f"buying into.",
                  **{k: v for k, v in imp.items()})

    depth_ratio = d["subnet_tao"] / max(d["alpha_out"] * spot, 1e-9) if spot else 0
    d["depth_ratio"] = depth_ratio
    if depth_ratio < 0.15:
        i.add("SHALLOW_POOL", "MEDIUM",
              f"Pool depth is thin relative to circulating alpha ({depth_ratio:.0%})",
              f"{fmt(d['subnet_tao'])} TAO backs {fmt(d['alpha_out'])} alpha of circulating "
              f"supply. Small sells move the price a lot, which makes the token easy to attack "
              f"and hard to defend.",
              subnet_tao=d["subnet_tao"], alpha_out=d["alpha_out"], depth_ratio=depth_ratio)

    # ---- 4. emission capture --------------------------------------------
    total_emis = sum(amt(n.emission) for n in mg.neurons) or 1.0
    for cl in sorted(rivals, key=lambda c: -c["emission_per_epoch"])[:3]:
        share = pct(cl["emission_per_epoch"], total_emis)
        if share >= 15:
            i.add("EMISSION_CAPTURE", "HIGH" if share >= 30 else "MEDIUM",
                  f"{cl['label']} captures {share:.1f}% of subnet emission",
                  f"{len(cl['uids'])} UID{'' if len(cl['uids']) == 1 else 's'} owned by this "
                  f"entity earn{'s' if len(cl['uids']) == 1 else ''} "
                  f"{fmt(cl['emission_per_epoch'], 4)} alpha per epoch. Every epoch "
                  f"you own this subnet, you are funding them.",
                  cluster=cl["label"], emission_share=share, uids=cl["uids"])

    permits = [n for n in mg.neurons if n.validator_permit]
    total_cons = sum(amt(n.total_stake) for n in permits) or 1.0
    d["validator_count"] = len(permits)
    for cl in i.clusters[:5]:
        share = pct(cl["consensus_stake"], total_cons)
        if share >= 34 and not cl["is_owner"]:
            i.add("VALIDATOR_CONTROL", "CRITICAL" if share >= 50 else "HIGH",
                  f"{cl['label']} controls {share:.1f}% of validator stake weight",
                  f"With {cl['validator_permits']} permitted validator"
                  f"{'' if cl['validator_permits'] == 1 else 's'} and "
                  f"{human(cl['consensus_stake'])} of stake weight, this entity can steer consensus "
                  f"weights -- which decides which miners earn. Above 50% they decide it outright, "
                  f"including the ability to zero out anyone you bring in.",
                  cluster=cl["label"], stake_share=share, permits=cl["validator_permits"])

    # ---- 5. childkeys ----------------------------------------------------
    if d["pending_children"]:
        rows = []
        for hk, (kids, cooldown) in d["pending_children"].items():
            rows.append({"hotkey": hk, "cooldown_block": cooldown,
                         "children": [{"child": ch, "proportion": p / U64_MAX} for p, ch in kids]})
        i.add("PENDING_CHILDKEYS", "HIGH",
              f"{len(rows)} pending childkey change(s) waiting out cooldown",
              "Childkey proposals already submitted will apply automatically after their "
              "cooldown, redirecting stake weight to hotkeys chosen before you took over. "
              "Check every one of these before signing anything -- they are the cheapest booby "
              "trap to leave behind in a subnet you are selling.",
              pending=rows)

    outbound = []
    for hk, kids in d["children"].items():
        for prop, child in kids or []:
            if child not in set(d["hotkeys"]):
                outbound.append({"parent": hk, "child": child, "proportion": prop / U64_MAX,
                                 "parent_alpha": d["tha"].get(hk, 0.0)})
    if outbound:
        big = [o for o in outbound if o["proportion"] >= 0.5 and o["parent_alpha"] > 0]
        if big:
            i.add("CHILDKEY_EXPORT", "MEDIUM",
                  f"{len(big)} hotkey(s) delegate most of their stake weight off-subnet",
                  "Stake weight registered here is being inherited by hotkeys that are not "
                  "registered on this subnet, so the influence it buys is exercised elsewhere.",
                  links=big)

    # ---- 6. seller-side levers ------------------------------------------
    lease = next((l for l in d["leases"] if l.get("netuid") == nid), None)
    if lease:
        end = lease.get("end_block")
        until = "perpetuity" if not end else f"block {end:,}"
        i.add("LEASE_ACTIVE", "CRITICAL",
              "This subnet is subject to an on-chain lease",
              f"Lease {lease.get('id')} pays {lease.get('emissions_share')}% of owner emissions to "
              f"{short(lease.get('beneficiary'))} until {until}. Whatever the seller tells you "
              f"about owner revenue, this comes out first, and it is enforced by the chain rather "
              f"than by agreement.",
              lease=lease)

    owner_proxies = d["proxy_detail"].get(owner_ck) or []
    dangerous = [p for p in owner_proxies
                 if p.get("proxy_type") in ("Any", "NonTransfer", "Governance", "Owner", "SwapHotkey")]
    if dangerous:
        i.add("OWNER_PROXY_RIGHTS", "HIGH",
              f"The owner coldkey has {len(dangerous)} powerful proxy delegation(s) outstanding",
              "Third parties can sign as the subnet owner. These survive the sale unless the "
              "seller removes them; ask for them to be cleared as a closing condition, and "
              "re-check on chain after transfer.",
              proxies=dangerous)

    if d.get("owner_swap"):
        i.add("OWNER_COLDKEY_SWAP_PENDING", "HIGH",
              "The owner coldkey has a pending coldkey-swap announcement",
              f"A swap is scheduled: {d['owner_swap']}. The key you are negotiating with may not "
              f"be the key that controls the subnet when the deal closes.",
              swap=d["owner_swap"])

    # ---- 7. slot mechanics ----------------------------------------------
    hp = d["hyper"]
    if not d["emission_enabled"]:
        i.add("EMISSION_DISABLED", "CRITICAL",
              "Root has disabled TAO emission for this subnet",
              "SubnetEmissionEnabled is 0: the subnet earns no share of network emission "
              "regardless of how it performs, and only root can turn it back on.",
              )
    if hp.get("subnet_is_active") is False:
        i.add("SUBNET_INACTIVE", "HIGH", "Subnet is not active",
              "The subnet has never been started (or has been stopped), so it is not yet "
              "producing emissions.")
    if hp.get("registration_allowed") is False:
        i.add("REGISTRATION_CLOSED", "MEDIUM", "Registration is closed",
              "New miners and validators cannot register until the owner re-opens it. Fine if "
              "deliberate, a problem if you plan to bring your own operators in on day one.")
    if hp.get("owner_cut_auto_lock_enabled") is False and (open_in is not None and open_in <= 0):
        i.add("OWNER_CUT_NOT_AUTOLOCKED", "MEDIUM",
              "Owner emissions are not auto-locked into conviction",
              "owner_cut_auto_lock_enabled is off while the takeover window is open, so the "
              "owner cut accrues as liquid alpha instead of building the conviction that defends "
              "the slot. Turning it on is the cheapest defense available to you.")
    imm = hp.get("immunity_period") or 0
    if imm > 72000:
        i.add("LONG_IMMUNITY", "LOW",
              f"Immunity period is {imm:,} blocks ({blocks_to_human(imm)})",
              "Long immunity means squatted UIDs cannot be deregistered for a long time after "
              "registration.")

    cutoff = max(int(hp.get("activity_cutoff") or 0), 5 * int(hp.get("tempo") or 360))
    stale = [n for n in permits if (i.block - int(n.last_update or 0)) > cutoff]
    if stale and permits:
        i.add("STALE_VALIDATORS", "LOW",
              f"{len(stale)}/{len(permits)} permitted validators have not set weights recently",
              "Validators holding permits but not setting weights still absorb dividends while "
              "contributing nothing to consensus.",
              uids=[n.uid for n in stale])

    # UID squatting -- a cluster holding the register keeps you from seating
    # your own miners without paying registration burn to displace them
    for cl in i.clusters[:5]:
        if cl["is_owner"] or not cl["uids"]:
            continue
        share = pct(len(cl["uids"]), max(mg.num_uids, 1))
        if share >= 15:
            i.add("UID_SQUAT", "HIGH" if share >= 30 else "MEDIUM",
                  f"{cl['label']} occupies {share:.0f}% of the UID register",
                  f"{len(cl['uids'])} of {mg.num_uids} UIDs belong to this entity. Seats are "
                  f"finite: every one they hold is one you have to buy back at the registration "
                  f"burn ({fmt(d['burn'], 3)} TAO each, {fmt(len(cl['uids']) * d['burn'])} TAO "
                  f"in total) and wait out immunity for.",
                  cluster=cl["label"], uid_share=share, uids=cl["uids"])

    # consensus bought with root TAO rather than with this subnet's alpha
    tao_weighted = sum(amt(n.tao_stake) * TAO_WEIGHT for n in permits)
    root_share = pct(tao_weighted, total_cons)
    d["root_consensus_share"] = root_share
    if root_share >= 50:
        i.add("ROOT_DRIVEN_CONSENSUS", "MEDIUM" if root_share < 70 else "HIGH",
              f"{root_share:.0f}% of validator weight comes from root TAO, not from subnet alpha",
              f"Consensus on this subnet is decided mostly by root stakers, who hold no alpha "
              f"exposure and therefore no stake in the subnet's price or direction. Winning over "
              f"alpha holders will not be enough to control your own weights; you have to court "
              f"root validators too, and they can be re-pointed at any time.",
              root_share=root_share)

    if permits and hp.get("max_validators") and len(permits) >= int(hp["max_validators"]):
        i.add("VALIDATOR_SLOTS_FULL", "LOW",
              "Every validator permit slot is taken",
              f"{len(permits)}/{hp['max_validators']} permits are in use, so your own validator "
              f"has to out-stake an incumbent to get one.")

    # ---- 8. attribution honesty -----------------------------------------
    cov = i.coverage
    bound = d.get("hidden_bound", 0.0)
    unattributed = max(0.0, d["total_alpha"] - cov["attributed_alpha"])
    if bound > 0:
        bound_pct = pct(bound, max(d["alpha_out"], 1))
        sev = ("HIGH" if (thr and bound >= thr) else
               "MEDIUM" if bound >= 0.25 * max(owner_alpha, 1) else "INFO")
        i.add("HIDDEN_HOLDER_BOUND", sev,
              f"A holder of up to {human(bound)} alpha ({bound_pct:.1f}% of circulating) could "
              f"still be hiding from this scan",
              f"{cov['pools_expanded']} stake pools were expanded down to individual coldkeys; "
              f"{cov['pools_below_materiality']} smaller ones were bounded rather than read, and "
              f"{len(cov['truncated_hotkeys'])} large ones were only partly read. No holder can "
              f"exceed the pool it sits in, so {human(bound)} alpha is the ceiling on anything "
              f"this report missed"
              + (" -- which is above the takeover threshold, so this scan is not conclusive "
                 "about who can seize the subnet. Re-run with --deep, a lower --materiality, "
                 "or against your own node before you rely on it."
                 if (thr and bound >= thr) else
                 " -- large enough to reorder the cap table above, so treat the ranking as "
                 "indicative and finish the scan against your own node before closing."
                 if bound >= 0.25 * max(owner_alpha, 1) else
                 " -- comfortably below the positions that decide control here.")
              + f" Attribution reached {cov['attributed_pct']:.1f}% of staked alpha "
                f"({fmt(unattributed)} alpha unread).",
              **{k: v for k, v in cov.items() if not isinstance(v, list)})

    # ---- 9. what defense costs ------------------------------------------
    buyer_alpha = 0.0
    if i.args.buyer:
        bc = next((cl for cl in i.clusters if i.args.buyer in cl["members"]), None)
        buyer_alpha = bc["alpha"] if bc else 0.0
    need_parity = max(0.0, (top_rival["alpha"] if top_rival else 0.0) - max(owner_alpha, buyer_alpha))
    d["defense"] = {
        "alpha_for_parity_with_top_rival": need_parity,
        "tao_for_parity": await tao_to_buy_alpha(c, nid, need_parity, i.block, d["alpha_in"], d["subnet_tao"])
        if need_parity > 0 else 0.0,
        "alpha_for_takeover_immunity": max(0.0, thr - owner_conv),
        "tao_for_takeover_immunity": await tao_to_buy_alpha(
            c, nid, max(0.0, thr - owner_conv), i.block, d["alpha_in"], d["subnet_tao"])
        if thr > owner_conv else 0.0,
    }


# --------------------------------------------------------------------------
# grading + rendering
# --------------------------------------------------------------------------

GRADE_WEIGHT = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}


def grade(findings: list[Finding]) -> tuple[str, int]:
    score = sum(GRADE_WEIGHT[f.severity] for f in findings)
    if score >= 80:
        return "F", score
    if score >= 45:
        return "D", score
    if score >= 25:
        return "C", score
    if score >= 10:
        return "B", score
    return "A", score


def render(insp: Inspector) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    d, mg = insp.d, insp.d["mg"]
    con = Console(width=max(112, Console().width))
    g, score = grade(insp.findings)
    sym = getattr(mg, "symbol", "") or "α"
    name = getattr(mg, "name", None) or (d.get("subnet_identity") or {}).get("subnet_name") or "?"

    head = (
        f"[bold]subnet {insp.netuid}[/] · [bold]{name}[/] {sym}\n"
        f"block {insp.block:,} · registered at {d['registered_at']:,} "
        f"({blocks_to_human(insp.block - d['registered_at'])} old)\n"
        f"owner coldkey {d['owner_ck']}\n"
        f"owner hotkey  {d['owner_hk']}"
    )
    con.print(Panel(head, title="SUBNET INSPECTION", border_style="blue", box=box.ROUNDED))

    grade_style = {"A": "bold green", "B": "green", "C": "yellow",
                   "D": "bold red", "F": "bold white on red"}[g]
    crit = sum(1 for f in insp.findings if f.severity == "CRITICAL")
    high = sum(1 for f in insp.findings if f.severity == "HIGH")
    con.print(Panel(
        f"[{grade_style}]  GRADE {g}  [/]   risk score {score}   "
        f"[bold red]{crit} critical[/] · [red]{high} high[/] · "
        f"{len(insp.findings)} findings total",
        border_style=grade_style.split()[-1] if g != "F" else "red", box=box.HEAVY))

    # --- market / pool -----------------------------------------------------
    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="dim", no_wrap=True)
    t.add_column(justify="right")
    t.add_row("alpha price", f"{d['spot']:.6f} τ")
    t.add_row("pool TAO reserve", f"{human(d['subnet_tao'])} τ")
    t.add_row("pool alpha reserve", f"{human(d['alpha_in'])} {sym}")
    t.add_row("circulating alpha", f"{human(d['alpha_out'])} {sym}")
    t.add_row("staked alpha", f"{human(d['total_alpha'])} {sym}")
    t.add_row("market cap (spot)", f"{human(d['alpha_out'] * d['spot'])} τ")
    t.add_row("root share of consensus", f"{d.get('root_consensus_share', 0):.0f}%")
    t.add_row("owner cut", f"{d['owner_cut']:.1%}")
    t.add_row("registration burn", f"{fmt(d['burn'], 4)} τ")
    t.add_row("validators (permits)", f"{d.get('validator_count', 0)} / {d['hyper'].get('max_validators', '?')}")
    t.add_row("UIDs", f"{mg.num_uids} / {d['max_uids']}")
    t.add_row("concentration (HHI)", f"{d.get('hhi', 0):.3f}")
    con.print(Panel(t, title="market & slot", border_style="dim", box=box.ROUNDED))

    # --- takeover gate -----------------------------------------------------
    tk = d.get("takeover", {})
    open_in = tk.get("blocks_until_open")
    when = ("[bold red]OPEN NOW[/]" if (open_in is not None and open_in <= 0)
            else f"opens in {blocks_to_human(open_in)} (block {tk.get('changeable_at_block'):,})"
            if tk.get("changeable_at_block") else "unknown")
    seize = tk.get("tao_to_seize")
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column(style="dim", no_wrap=True)
    t.add_column(justify="right")
    t.add_row("ownership-change window", when)
    t.add_row("conviction threshold (18%)", f"{human(tk.get('threshold_alpha', 0))} {sym}")
    t.add_row("owner conviction today", f"{human(d.get('owner_conviction', 0))} {sym}")
    t.add_row("cost to seize the slot", "pool too shallow" if seize is None else f"{human(seize)} τ")
    dfn = d.get("defense", {})
    t.add_row("cost to reach immunity", f"{human(dfn.get('tao_for_takeover_immunity') or 0)} τ")
    parity = dfn.get("tao_for_parity") or 0
    t.add_row("cost to match top rival", f"{human(parity)} τ" if parity else "already ahead")
    t.add_row("top 5 rivals, combined", f"{human(d.get('top5_rival_alpha', 0))} {sym}")
    t.add_row("owner alpha", f"{human(d.get('owner_alpha', 0))} {sym}")
    con.print(Panel(t, title="ownership defensibility", border_style="magenta", box=box.ROUNDED))

    # --- cap table ---------------------------------------------------------
    t = Table(box=box.SIMPLE_HEAD, title=None)
    t.add_column("#", justify="right", style="dim")
    t.add_column("entity")
    t.add_column("wal", justify="right")
    t.add_column("alpha", justify="right")
    t.add_column("%circ", justify="right")
    t.add_column("τ val", justify="right")
    t.add_column("uid", justify="right")
    t.add_column("emis", justify="right")
    t.add_column("convic", justify="right")
    total_emis = sum(amt(n.emission) for n in mg.neurons) or 1.0
    for k, cl in enumerate(insp.clusters[:15], 1):
        tag = "[bold green]OWNER[/] " if cl["is_owner"] else ""
        t.add_row(
            str(k), tag + cl["label"][:26], str(cl["size"]),
            human(cl["alpha"]), f"{pct(cl['alpha'], max(d['alpha_out'],1)):.1f}%",
            human(cl["alpha"] * d["spot"]),
            str(len(cl["uids"])), f"{pct(cl['emission_per_epoch'], total_emis):.1f}%",
            human(cl["conviction_alpha"]),
        )
    con.print(Panel(t, title="cap table (clustered by likely entity)",
                    border_style="cyan", box=box.ROUNDED))

    for cl in insp.clusters[:6]:
        if cl["size"] > 1 and cl["evidence"]:
            con.print(f"  [dim]{cl['label']} = {cl['size']} wallets:[/] " +
                      ", ".join(short(m) for m in cl["members"][:8]))
            for e in cl["evidence"][:4]:
                con.print(f"      [dim]· {e}[/]")

    # --- findings ----------------------------------------------------------
    con.print()
    fs = sorted(insp.findings, key=lambda f: (SEV_RANK[f.severity], f.code))
    if not fs:
        con.print(Panel("no findings", border_style="green"))
    for f in fs:
        con.print(Panel(f.detail, title=f"[{SEV_COLOR[f.severity]}] {f.severity} [/] {f.title}",
                        subtitle=f"[dim]{f.code}[/]", border_style=SEV_COLOR[f.severity].split()[-1],
                        box=box.ROUNDED))

    # --- coverage ----------------------------------------------------------
    cov = insp.coverage
    con.print(f"[dim]attribution: {cov['attributed_pct']:.1f}% of staked alpha across "
              f"{len(insp.holders):,} coldkeys · {len(cov['truncated_hotkeys'])} pools truncated · "
              f"{len(cov['skipped_hotkeys'])} skipped · {cov['scan_seconds']}s"
              f"{' · deep mode' if cov['deep'] else ''}[/]")
    throttled = sum(1 for n in insp.notes if "throttled" in n)
    if throttled:
        con.print(f"[yellow]{throttled} stake pools were refused by the public endpoint's scan "
                  f"limits. Point --network at your own node for a complete cap table.[/]")
    for n in insp.notes[:10]:
        con.print(f"[dim]note: {n}[/]")

    if insp.args.price:
        ask = insp.args.price
        con.print()
        seize_txt = "n/a" if seize is None else f"{fmt(seize)} τ ({seize/ask:.0%} of ask)"
        con.print(Panel(
            f"asking price: {fmt(ask)} τ\n"
            f"cost for someone else to seize the slot from you: {seize_txt}\n"
            f"cost to make your ownership defensible: {fmt(dfn.get('tao_for_takeover_immunity') or 0)} τ\n"
            f"total to own it safely: "
            f"{fmt(ask + (dfn.get('tao_for_takeover_immunity') or 0))} τ",
            title="deal math", border_style="yellow", box=box.ROUNDED))


def to_json(insp: Inspector) -> dict:
    d = insp.d
    g, score = grade(insp.findings)
    mg = d["mg"]
    return {
        "netuid": insp.netuid,
        "block": insp.block,
        "name": getattr(mg, "name", None),
        "symbol": getattr(mg, "symbol", None),
        "grade": g,
        "risk_score": score,
        "owner_coldkey": d["owner_ck"],
        "owner_hotkey": d["owner_hk"],
        "registered_at": d["registered_at"],
        "market": {
            "price": d.get("spot"), "subnet_tao": d["subnet_tao"],
            "alpha_in": d["alpha_in"], "alpha_out": d["alpha_out"],
            "staked_alpha": d["total_alpha"], "volume": d["volume"],
            "owner_cut": d["owner_cut"], "burn": d["burn"],
            "hhi": d.get("hhi"), "top10_share": d.get("top10_share"),
        },
        "takeover": d.get("takeover"),
        "defense": d.get("defense"),
        "owner_conviction": d.get("owner_conviction"),
        "hyperparameters": d["hyper"],
        "clusters": insp.clusters,
        "findings": [
            {"code": f.code, "severity": f.severity, "title": f.title,
             "detail": f.detail, "evidence": _jsonable(f.evidence)}
            for f in sorted(insp.findings, key=lambda f: SEV_RANK[f.severity])
        ],
        "coverage": insp.coverage,
        "provenance": d.get("provenance") or {},
        "notes": insp.notes,
        "context": {
            "network": insp.args.network,
            "price": insp.args.price,
            "buyer": insp.args.buyer,
            "age_blocks": insp.block - d["registered_at"],
            "owner_alpha": d.get("owner_alpha"),
            "top5_rival_alpha": d.get("top5_rival_alpha"),
            "top_rival_exit": d.get("top_rival_exit"),
            "root_consensus_share": d.get("root_consensus_share"),
            "validator_count": d.get("validator_count"),
            "num_uids": getattr(mg, "num_uids", None),
            "max_uids": d.get("max_uids"),
            "offregister_alpha": d.get("offregister_alpha"),
            "emission_to_neurons_per_epoch": sum(amt(n.emission) for n in mg.neurons),
        },
    }


def _jsonable(x):
    if isinstance(x, dict):
        return {k: _jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_jsonable(v) for v in x]
    if isinstance(x, Decimal):
        return float(x)
    if hasattr(x, "rao"):
        return amt(x)
    return x


# --------------------------------------------------------------------------
# plain-English report
#
# The console view is for someone reading the chain. This is the same reading
# written out in sentences: who owns the slot, where the alpha sits and how it
# moves between keys, and what each of those facts costs the buyer. Every key
# is spelled in full so it can be checked. It renders from the JSON report, so
# --from-json rewrites it without touching the network.
# --------------------------------------------------------------------------

REPORT_WIDTH = 86

# Short forms (5Grwva..utQY) cannot be verified or pasted anywhere. Anything
# the findings abbreviated gets expanded back to the full key.
_SHORT_RE = re.compile(r"\b5[A-Za-z0-9]{5}\.\.[A-Za-z0-9]{4}\b")


def _key_index(rep: dict) -> dict:
    """short form -> full ss58, from every address the report mentions."""
    idx: dict[str, str] = {}

    def put(a):
        if isinstance(a, str) and a.startswith("5") and len(a) > 40:
            idx[short(a)] = a

    put(rep.get("owner_coldkey"))
    put(rep.get("owner_hotkey"))
    for cl in rep.get("clusters", []):
        for a in cl.get("members", []) + cl.get("hotkeys", []) + cl.get("owned_hotkeys", []):
            put(a)

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                walk(v)
        else:
            put(x)
    walk([f.get("evidence") for f in rep.get("findings", [])])
    return idx


def _expand(text: str, idx: dict) -> str:
    return _SHORT_RE.sub(lambda m: idx.get(m.group(0), m.group(0)), text)


def _hotkey_users(rep: dict) -> dict:
    """hotkey -> how many attributed coldkeys stake through it.

    A hotkey shared by hundreds of coldkeys is a public delegate and links its
    stakers to each other not at all. A hotkey shared by three is worth a
    question. The report has to say which one it is looking at.
    """
    pop: dict[str, int] = defaultdict(int)
    for cl in rep.get("clusters", []):
        for h in cl.get("hotkeys", []):
            pop[h] += 1
    return pop


def _para(text: str, indent: str = "") -> str:
    out = []
    for block in text.split("\n"):
        if not block.strip():
            out.append("")
        else:
            out.extend(textwrap.wrap(block, REPORT_WIDTH, initial_indent=indent,
                                     subsequent_indent=indent,
                                     break_long_words=False, break_on_hyphens=False))
    return "\n".join(out)


def _head(title: str) -> str:
    return f"\n\n{title.upper()}\n{'-' * len(title)}\n"


def _owner_hotkey_holder(rep: dict) -> Optional[dict]:
    """The cluster that owns the subnet owner's hotkey, when it is not the owner.

    The owner coldkey holds the slot; the hotkey it validates through can be
    registered to a different coldkey, and a transfer of one is not a transfer
    of the other.
    """
    ohk = rep.get("owner_hotkey")
    if not ohk:
        return None
    for cl in rep.get("clusters", []):
        if not cl.get("is_owner") and ohk in (cl.get("owned_hotkeys") or []):
            return cl
    return None


# What each finding costs the buyer, in one line. Severity says how loud it is;
# this says what it does to you.
BUYER_RISK: dict[str, str] = {
    "TAKEOVER_WINDOW_OPEN":
        "You can lose the slot on any day you own it, to anyone willing to pay the number "
        "below.",
    "TAKEOVER_WINDOW_PENDING":
        "You have until that date to get conviction locked; after it, the slot is contestable "
        "for as long as you hold it.",
    "OWNER_CONVICTION_WEAK":
        "The slot's defence is not in place, so it becomes your cost, on top of the price.",
    "RIVAL_CONVICTION":
        "Someone is already accumulating towards the ownership threshold.",
    "RIVAL_CAN_SEIZE_NOW":
        "This holder can take the slot without buying anything further.",
    "ALPHA_OVERHANG":
        "The largest position is not yours, so the largest holder sets the terms: they can sell "
        "into anything you launch, or name a price for not doing it.",
    "SYBIL_CLUSTER":
        "Several holdings are one counterparty, so the position is larger than any single line "
        "of the cap table shows.",
    "SPLIT_PATTERN":
        "If these wallets are one holder, the combined position is what you are actually up "
        "against; the chain cannot settle which it is.",
    "COALITION_RISK":
        "These holders do not have to be one entity, only to agree once.",
    "CONCENTRATION":
        "Price, emissions and governance move on a handful of decisions you do not control.",
    "OFF_REGISTER_ALPHA":
        "Not visible in the metagraph, so a cap table quoted from one is incomplete.",
    "EXIT_PRESSURE":
        "The price you are valuing alpha at is not the price that survives the largest holder "
        "leaving.",
    "SHALLOW_POOL":
        "Both the attack and the defence are cheap, and every TAO figure here moves fast.",
    "EMISSION_CAPTURE":
        "This is paid out of the subnet every epoch you own it.",
    "VALIDATOR_CONTROL":
        "Whoever sets weights decides which miners earn, including anyone you bring in.",
    "PENDING_CHILDKEYS":
        "Stake will be redirected on a schedule already set, without further action by anyone.",
    "CHILDKEY_EXPORT":
        "Stake registered here is being credited elsewhere.",
    "LEASE_ACTIVE":
        "The seller may not be the party that controls the slot.",
    "OWNER_PROXY_RIGHTS":
        "Proxies survive a sale unless they are explicitly revoked.",
    "OWNER_COLDKEY_SWAP_PENDING":
        "A swap already scheduled can move ownership after you have agreed terms.",
    "EMISSION_DISABLED": "The subnet is not paying emission.",
    "SUBNET_INACTIVE": "The subnet is not active.",
    "REGISTRATION_CLOSED": "New miners cannot register until you reopen it.",
    "OWNER_CUT_NOT_AUTOLOCKED":
        "The cut arrives unlocked, so conviction has to be bought rather than accrued.",
    "ROOT_DRIVEN_CONSENSUS":
        "Weights are decided by root validators, who can be re-pointed at any time.",
    "STALE_VALIDATORS": "These validators draw dividends without contributing consensus.",
    "UID_SQUAT": "These UIDs are paid whether or not they do anything.",
    "VALIDATOR_SLOTS_FULL": "There is no free validator slot for anyone you bring in.",
    "HIDDEN_HOLDER_BOUND":
        "Part of the cap table was never read, so the holder list is a floor, not a ceiling.",
    "LONG_IMMUNITY": "New registrations cannot be deregistered for that long.",
}


def _row(label: str, value: str, indent: str = "  ") -> str:
    """One aligned label/value line, the console tables' shape in plain text."""
    return f"{indent}{label:<26}{value}"


def _title_block(rep: dict) -> str:
    ctx = rep.get("context") or {}
    title = (f"SUBNET {rep['netuid']} -- {rep.get('name') or '?'}"
             + (f" ({rep['symbol']})" if rep.get("symbol") else ""))
    return (f"{title}\n{'=' * len(title)}\n"
            f"read at block {rep['block']:,}"
            + (f" on {ctx['network']}" if ctx.get("network") else "")
            + f" · grade {rep['grade']} · alpha at {(rep['market'].get('price') or 0):.6f} TAO")


def short_report(rep: dict) -> str:
    """The console view on its own -- every number, none of the prose."""
    return _title_block(rep) + "\n" + _digest(rep).rstrip() + "\n"


def _digest(rep: dict) -> str:
    """The console view, in text: the numbers a reader wants before the prose.

    Same figures the terminal prints while the scan runs, so a saved report
    carries them instead of leaving them on a screen nobody kept.
    """
    m = rep["market"]
    tk = rep.get("takeover") or {}
    dfn = rep.get("defense") or {}
    ctx = rep.get("context") or {}
    hyp = rep.get("hyperparameters") or {}
    cov = rep.get("coverage") or {}
    fs = rep["findings"]
    price = m.get("price") or 0.0
    circ = m.get("alpha_out") or 1.0
    clusters = sorted(rep.get("clusters", []), key=lambda c: -c["alpha"])
    out: list[str] = []

    crit = sum(1 for f in fs if f["severity"] == "CRITICAL")
    high = sum(1 for f in fs if f["severity"] == "HIGH")
    out.append(_head("At a glance").rstrip("\n"))
    out.append("")
    out.append(_row("grade", f"{rep['grade']}  (risk score {rep['risk_score']})"))
    out.append(_row("findings", f"{crit} critical · {high} high · {len(fs)} total"))
    out.append(_row("owner coldkey", rep["owner_coldkey"]))
    out.append(_row("owner hotkey", rep["owner_hotkey"]))
    out.append(_row("registered", f"block {rep['registered_at']:,}"
                    + (f" ({blocks_to_human(ctx['age_blocks'])} old)"
                       if ctx.get("age_blocks") else "")))

    out.append("")
    out.append("  MARKET & SLOT")
    out.append(_row("alpha price", f"{price:.6f} TAO"))
    out.append(_row("pool TAO reserve", f"{human(m.get('subnet_tao') or 0)} TAO"))
    out.append(_row("pool alpha reserve", f"{human(m.get('alpha_in') or 0)} alpha"))
    out.append(_row("circulating alpha", f"{human(circ)} alpha"))
    out.append(_row("staked alpha", f"{human(m.get('staked_alpha') or 0)} alpha"))
    out.append(_row("market cap (spot)", f"{human(circ * price)} TAO"))
    if ctx.get("root_consensus_share") is not None:
        out.append(_row("root share of consensus", f"{ctx['root_consensus_share']:.0f}%"))
    out.append(_row("owner cut", f"{(m.get('owner_cut') or 0):.1%}"))
    out.append(_row("registration burn", f"{fmt(m.get('burn') or 0, 4)} TAO"
                    + ("" if hyp.get("registration_allowed", True) else "  (closed)")))
    if ctx.get("validator_count") is not None:
        out.append(_row("validators (permits)",
                        f"{ctx['validator_count']} / {hyp.get('max_validators', '?')}"))
    if ctx.get("num_uids") is not None:
        out.append(_row("UIDs", f"{ctx['num_uids']} / {ctx.get('max_uids', '?')}"))
    if m.get("hhi") is not None:
        out.append(_row("concentration (HHI)", f"{m['hhi']:.3f}"
                        + (f"  ·  top 10 hold {m['top10_share']:.1f}%"
                           if m.get("top10_share") is not None else "")))

    out.append("")
    out.append("  OWNERSHIP DEFENSIBILITY")
    ob = tk.get("blocks_until_open")
    when = ("OPEN NOW" if ob is not None and ob <= 0
            else f"opens in {blocks_to_human(ob)}" if ob else "unknown")
    if tk.get("changeable_at_block"):
        when += f" (block {tk['changeable_at_block']:,})"
    out.append(_row("ownership-change window", when))
    out.append(_row("conviction threshold", f"{human(tk.get('threshold_alpha') or 0)} alpha"))
    out.append(_row("owner conviction today", f"{human(rep.get('owner_conviction') or 0)} alpha"
                    + f"  ({(rep.get('owner_conviction') or 0) / max(tk.get('threshold_alpha') or 1, 1):.0%})"))
    seize = tk.get("tao_to_seize")
    out.append(_row("cost to seize the slot",
                    "pool too shallow" if seize is None else f"{human(seize)} TAO"))
    out.append(_row("cost to reach immunity",
                    f"{human(dfn.get('tao_for_takeover_immunity') or 0)} TAO"))
    parity = dfn.get("tao_for_parity") or 0
    out.append(_row("cost to match top rival",
                    f"{human(parity)} TAO" if parity else "already ahead"))
    if ctx.get("top5_rival_alpha") is not None:
        out.append(_row("top 5 rivals, combined", f"{human(ctx['top5_rival_alpha'])} alpha"))
    out.append(_row("owner alpha", f"{human(ctx.get('owner_alpha') or 0)} alpha"))

    out.append("")
    out.append(f"  CAP TABLE (top {min(12, len(clusters))} of {len(clusters)} entities)")
    total_emis = sum(c.get("emission_per_epoch") or 0 for c in clusters) or 1.0
    out.append(f"  {'#':>2}  {'entity':<29} {'wal':>3} {'alpha':>10} {'%circ':>7} "
               f"{'TAO':>8} {'uid':>4} {'emis':>6} {'convic':>8}")
    for k, cl in enumerate(clusters[:12], 1):
        who = ("OWNER " if cl.get("is_owner") else "") + cl["label"]
        conv = cl.get("conviction_alpha") or 0
        out.append(
            f"  {k:>2}  {who[:29]:<29} {cl['size']:>3} {human(cl['alpha']):>10} "
            f"{pct(cl['alpha'], circ):>6.1f}% {human(cl['alpha'] * price):>8} "
            f"{len(cl.get('uids') or []):>4} "
            f"{pct(cl.get('emission_per_epoch') or 0, total_emis):>5.1f}% "
            f"{(human(conv) if conv else '-'):>8}")

    out.append("")
    out.append("  FINDINGS")
    for f in fs:
        out.append("\n".join(textwrap.wrap(
            f"{f['severity']:<9} {f['title']}", REPORT_WIDTH,
            initial_indent="  ", subsequent_indent=" " * 12,
            break_long_words=False, break_on_hyphens=False)))

    out.append("")
    out.append(_row("coverage", f"{(cov.get('attributed_pct') or 0):.1f}% of staked alpha · "
                                f"{cov.get('rows_read', 0):,} rows · "
                                f"{cov.get('scan_seconds', 0):.0f}s"))
    out.append(_row("hidden-holder ceiling",
                    f"{human(cov.get('largest_possible_hidden_holder') or 0)} alpha "
                    f"({pct(cov.get('largest_possible_hidden_holder') or 0, circ):.1f}% of circulating)"))
    return "\n".join(out)


def report(rep: dict) -> str:
    idx = _key_index(rep)
    m = rep["market"]
    tk = rep.get("takeover") or {}
    dfn = rep.get("defense") or {}
    ctx = rep.get("context") or {}
    hyp = rep.get("hyperparameters") or {}
    cov = rep.get("coverage") or {}
    fs = rep["findings"]
    by_code: dict[str, list] = defaultdict(list)
    for f in fs:
        by_code[f["code"]].append(f)
    price = m.get("price") or 0.0
    circ = m.get("alpha_out") or 1.0
    users = _hotkey_users(rep)
    clusters = sorted(rep.get("clusters", []), key=lambda c: -c["alpha"])
    owner_alpha = ctx.get("owner_alpha") or next(
        (c["alpha"] for c in clusters if c.get("is_owner")), 0.0)
    thr = tk.get("threshold_alpha") or 0.0
    open_in = tk.get("blocks_until_open")
    seize = tk.get("tao_to_seize")
    hk_holder = _owner_hotkey_holder(rep)
    out: list[str] = []

    def tao(alpha):
        return f"{human(alpha * price)} TAO"

    out.append(_title_block(rep))
    out.append(_digest(rep))

    # ---- summary --------------------------------------------------------
    out.append(_head("In short"))
    crit = [f for f in fs if f["severity"] == "CRITICAL"]
    high = [f for f in fs if f["severity"] == "HIGH"]
    when = ("has been open for " + blocks_to_human(-open_in)
            if open_in is not None and open_in <= 0
            else "opens in " + blocks_to_human(open_in) if open_in else "is of unknown timing")
    top_rival = next((c for c in clusters if not c.get("is_owner")), None)
    out.append(_para(
        f"Subnet {rep['netuid']} is owned by coldkey {rep['owner_coldkey']}. The conviction "
        f"threshold is {fmt(thr)} alpha and the ownership window {when}. The owner holds "
        f"{fmt(rep.get('owner_conviction') or 0)} alpha of conviction, "
        f"{(rep.get('owner_conviction') or 0) / max(thr, 1):.0%} of it."))
    out.append("")
    out.append(_para(
        f"Buying that much alpha on the open market costs about "
        f"{'more than the pool can supply' if seize is None else human(seize) + ' TAO'} at "
        f"current pool depth; putting the owner's own conviction on the line costs about "
        f"{human(dfn.get('tao_for_takeover_immunity') or 0)} TAO. The owner's unlocked position "
        f"is {human(owner_alpha)} alpha ({tao(owner_alpha)})"
        + (f", against {human(top_rival['alpha'])} alpha held by the largest outside holder, "
           f"{top_rival['members'][0]}" if top_rival else "")
        + f". {len(crit)} critical and {len(high)} high risks are listed below, out of "
          f"{len(fs)}."))
    if (cov.get("attributed_pct") or 100) < 85:
        out.append("")
        out.append(_para(
            f"The scan attributed only {cov['attributed_pct']:.0f}% of staked alpha before the "
            f"endpoint refused further reads, and a single holder of up to "
            f"{human(cov.get('largest_possible_hidden_holder') or 0)} alpha could sit in the "
            f"pools it did not open. Treat the holder list as a floor."))

    # ---- ownership ------------------------------------------------------
    out.append(_head("Ownership"))
    out.append(_para(
        f"owner coldkey   {rep['owner_coldkey']}\n"
        f"owner hotkey    {rep['owner_hotkey']}\n"
        f"registered at   block {rep['registered_at']:,}"
        + (f" ({blocks_to_human(ctx['age_blocks'])} old)" if ctx.get("age_blocks") else "")))
    out.append("")
    cut = m.get("owner_cut") or 0.0
    epochs_day = 7200.0 / max(hyp.get("tempo") or 360, 1)
    neuron_emis = ctx.get("emission_to_neurons_per_epoch") or sum(
        c.get("emission_per_epoch") or 0 for c in clusters)
    line = f"The owner cut is {cut:.1%} of subnet emission."
    if neuron_emis and cut < 0.9:
        owner_epoch = neuron_emis / max(1 - cut, 1e-9) * cut
        line += (f" Neurons are paid {fmt(neuron_emis)} alpha per epoch, putting the cut at about "
                 f"{fmt(owner_epoch)} alpha per epoch, {human(owner_epoch * epochs_day)} alpha a "
                 f"day, {tao(owner_epoch * epochs_day)} a day at today's price.")
    out.append(_para(line))

    if hk_holder:
        out.append("")
        out.append(_para(
            f"The hotkey the subnet operates through, {rep['owner_hotkey']}, is registered to a "
            f"different coldkey: {hk_holder['members'][0]}. That coldkey holds the "
            f"{human(hk_holder.get('conviction_alpha') or 0)} alpha of conviction this report "
            f"credits to the owner, plus {human(hk_holder['alpha'])} alpha unlocked"
            + (f", UID {', '.join(str(u) for u in hk_holder['uids'])}" if hk_holder.get("uids") else "")
            + (" and a validator permit" if (hk_holder.get("validator_permits") or 0) == 1
               else f" and {hk_holder['validator_permits']} validator permits"
               if hk_holder.get("validator_permits") else "")
            + ". Transferring the owner coldkey alone leaves that key holding the validator, its "
              "emission, and the conviction defending the slot."))

    lever_codes = ("LEASE_ACTIVE", "OWNER_PROXY_RIGHTS", "OWNER_COLDKEY_SWAP_PENDING")
    levers = [f for code in lever_codes for f in by_code.get(code, [])]
    out.append("")
    if levers:
        for f in levers:
            out.append(_para(_expand(f["detail"], idx)))
            out.append("")
    else:
        out.append(_para(
            "No lease is registered, no coldkey swap is pending on the owner coldkey, and no "
            "proxy rights are delegated from it."))

    # ---- holdings -------------------------------------------------------
    out.append(_head("Who holds the alpha"))
    out.append(_para(
        f"{human(cov.get('attributed_alpha') or 0)} alpha "
        f"({(cov.get('attributed_pct') or 0):.1f}% of staked alpha) traced to coldkeys. Grouped "
        f"only where the chain evidences common control, printed with the group. Figures are "
        f"unlocked alpha unless conviction is shown."))
    out.append("")
    for k, cl in enumerate(clusters[:12], 1):
        tag = "OWNER -- " if cl.get("is_owner") else ""
        out.append(_para(
            f"{k:>2}. {tag}{human(cl['alpha'])} alpha ({pct(cl['alpha'], circ):.1f}% of "
            f"circulating, {tao(cl['alpha'])})"
            + (f", across {cl['size']} coldkeys" if cl["size"] > 1 else "")))
        for mem in cl["members"][:8]:
            out.append(_para(mem, indent="      "))
        for e in cl.get("evidence", [])[:4]:
            out.append(_para("linked by: " + _expand(e, idx), indent="      "))
        facts = []
        facts.append(f"UID {', '.join(str(u) for u in cl['uids'])}" if cl.get("uids")
                     else "no UID on this subnet")
        if cl.get("validator_permits"):
            facts.append("validator permit" if cl["validator_permits"] == 1
                         else f"{cl['validator_permits']} validator permits")
        if cl.get("emission_per_epoch"):
            facts.append(f"{fmt(cl['emission_per_epoch'])} alpha per epoch")
        if cl.get("conviction_alpha"):
            facts.append(f"{human(cl['conviction_alpha'])} alpha locked as conviction")
        out.append(_para("· " + "; ".join(facts), indent="      "))
        for h in cl.get("hotkeys", [])[:3]:
            n = users.get(h, 1)
            out.append(_para(
                f"via {h}"
                + (f" (public delegate, {n} holders)" if n >= 25
                   else f" (shared with {n - 1} other holders here)" if n > 1
                   else " (no other holder here uses it)"), indent="      "))
        out.append("")
    out.append(_para(
        f"Read against the {fmt(thr)} alpha conviction threshold, not against the owner's "
        f"{human(owner_alpha)}."))

    for code in ("ALPHA_OVERHANG", "SYBIL_CLUSTER", "SPLIT_PATTERN", "COALITION_RISK",
                 "CONCENTRATION", "EXIT_PRESSURE"):
        for f in by_code.get(code, []):
            out.append("")
            out.append(_para(_expand(f["title"], idx) + "."))
            out.append(_para(_expand(f["detail"], idx)))
            ev = f.get("evidence") or {}
            wallets = ev.get("wallets") or ev.get("members") or ev.get("holders") or []
            each = ev.get("each") or []
            if wallets:
                out.append("")
                for j, w in enumerate(wallets[:10]):
                    amount = f"  {fmt(each[j])} alpha" if j < len(each) else ""
                    out.append(_para(_expand(str(w), idx) + amount, indent="      "))

    # ---- provenance ------------------------------------------------------
    prov = rep.get("provenance") or {}
    traced = {k: v for k, v in prov.items() if v.get("created")}
    if traced:
        out.append(_head("Where the wallets came from"))
        out.append(_para(
            "Account creation block, the transfer that paid for it, and the first block "
            "the wallet held alpha here. Read for wallets appearing together."))
        out.append("")
        for ck, r in sorted(traced.items(), key=lambda kv: kv[1]["created"]):
            stake = next((v for k, v in r.items() if k.startswith("stake:") and v), None)
            out.append(_para(ck))
            out.append(_para(f"created block {r['created']:,}"
                             + (f"  {r['created_at']}" if r.get("created_at") else ""),
                             indent="      "))
            if r.get("funder"):
                nonce = int((prov.get(r["funder"]) or {}).get("nonce") or 0)
                kind = (" (exchange-scale wallet, {:,} txs)".format(nonce)
                        if nonce >= PROV_EXCHANGE_NONCE else
                        " (personal wallet, {:,} txs)".format(nonce)
                        if nonce and nonce < PROV_PERSONAL_NONCE else
                        f" ({nonce:,} txs)" if nonce else "")
                out.append(_para(f"funded by {r['funder']}{kind}"
                                 + (f", {fmt(r.get('funded_tao') or 0, 4)} TAO"
                                    if r.get("funded_tao") else ""), indent="      "))
            if stake:
                out.append(_para(f"first staked here at block {stake:,}", indent="      "))
            out.append("")

    # ---- how alpha moves between keys -----------------------------------
    out.append(_head("How the alpha moves between keys"))

    routes: dict[str, list] = defaultdict(list)
    for cl in clusters[:25]:
        for h in cl.get("hotkeys", []):
            routes[h].append(cl)
    for h, cls in sorted(routes.items(), key=lambda kv: -sum(c["alpha"] for c in kv[1]))[:8]:
        n = users.get(h, len(cls))
        crowd = (f"public delegate, {n} holders in this scan stake through it" if n >= 25
                 else f"{n} holders in this scan stake through it" if n > 1
                 else "one holder in this scan stakes through it")
        out.append(_para(f"{h}"))
        out.append(_para(f"{crowd}; {len(cls)} of the top holders above "
                         f"{'routes' if len(cls) == 1 else 'route'} through it, "
                         f"{human(sum(c['alpha'] for c in cls))} alpha between them.",
                         indent="      "))
        out.append("")

    if any("hotkey index scan unavailable" in n for n in rep.get("notes", [])):
        out.append(_para(
            "The endpoint refused the hotkey index scan on this run, so stake on hotkeys with "
            "no UID here was never measured. Re-run against your own node before relying on the "
            "holder list."))
        out.append("")
    off = by_code.get("OFF_REGISTER_ALPHA")
    if off:
        f = off[0]
        out.append(_para(_expand(f["title"], idx) + "."))
        out.append(_para(_expand(f["detail"], idx)))
        out.append("")
        out.append(_para(
            "Each figure is that hotkey's pool total across its stakers, not one holder's "
            "position."))
        out.append("")
    for code in ("PENDING_CHILDKEYS", "CHILDKEY_EXPORT"):
        for f in by_code.get(code, []):
            out.append(_para(_expand(f["title"], idx) + "."))
            out.append(_para(_expand(f["detail"], idx)))
            out.append("")

    # ---- emission -------------------------------------------------------
    out.append(_head("Where the emission lands"))
    total_emis = sum(c.get("emission_per_epoch") or 0 for c in clusters) or 1.0
    with_uid = sum(1 for c in clusters[:12] if c.get("uids"))
    out.append(_para(
        f"Neurons share {fmt(total_emis)} alpha per epoch, about "
        f"{human(total_emis * epochs_day)} alpha a day. Of the twelve largest holders above, "
        f"{with_uid} {'holds' if with_uid == 1 else 'hold'} a UID here."))
    for code in ("VALIDATOR_CONTROL", "EMISSION_CAPTURE", "UID_SQUAT", "ROOT_DRIVEN_CONSENSUS",
                 "STALE_VALIDATORS", "VALIDATOR_SLOTS_FULL"):
        for f in by_code.get(code, []):
            out.append("")
            out.append(_para(_expand(f["title"], idx) + "."))
            out.append(_para(_expand(f["detail"], idx)))
            ev = f.get("evidence") or {}
            if ev.get("uids") and "UID" not in f["detail"]:
                out.append(_para("UIDs: " + ", ".join(str(u) for u in ev["uids"]), indent="      "))
            lab = ev.get("cluster") or ev.get("label")
            cl = next((c for c in clusters if c["label"] == lab), None) if lab else None
            if cl:
                out.append(_para(f"coldkey {cl['members'][0]}", indent="      "))
                for h in cl.get("hotkeys", [])[:3]:
                    out.append(_para(f"hotkey  {h}", indent="      "))
                if hk_holder and cl["members"] == hk_holder["members"]:
                    out.append(_para(
                        "this is the coldkey that owns the subnet owner's hotkey, so it is most "
                        "likely the owner's own validator; it stays with whoever keeps that "
                        "coldkey after a sale.", indent="      "))

    # ---- risk list ------------------------------------------------------
    out.append(_head("What each finding costs the buyer"))
    for f in fs:
        out.append("\n".join(textwrap.wrap(
            f"[{f['severity']}] " + _expand(f["title"], idx), REPORT_WIDTH,
            subsequent_indent=" " * (len(f["severity"]) + 3),
            break_long_words=False, break_on_hyphens=False)))
        risk = BUYER_RISK.get(f["code"])
        if risk:
            out.append(_para(risk, indent="      "))
        out.append("")

    # ---- coverage -------------------------------------------------------
    out.append(_head("What this scan could not see"))
    out.append(_para(
        f"Attribution reached {(cov.get('attributed_pct') or 0):.1f}% of staked alpha "
        f"({human(cov.get('attributed_alpha') or 0)} of "
        f"{human(cov.get('staked_alpha_total') or 0)}), from {cov.get('rows_read', 0):,} rows in "
        f"{cov.get('scan_seconds', 0):.0f} seconds. The shortfall is the endpoint refusing "
        f"scans under load, not sampling. Unread pools carry a hard ceiling"
        + (f" of {human(cov.get('largest_possible_hidden_holder') or 0)} alpha "
           f"({pct(cov.get('largest_possible_hidden_holder') or 0, circ):.1f}% of circulating)"
           if cov.get("largest_possible_hidden_holder") else "")
        + ". Your own node removes the limit."))
    out.append("")
    out.append(_para(
        "Two things no scan settles at any coverage: whether several wallets are one holder or "
        "several, and what any holder intends to do."))
    out.append("")
    out.append(_para(f"Read at block {rep['block']:,}. Chain state only; nothing here was "
                     f"signed, staked or transacted."))
    text = "\n".join(out).rstrip() + "\n"
    return re.sub(r"\n{4,}", "\n\n\n", text)


# --------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Pre-purchase risk inspection for a Bittensor subnet slot.")
    p.add_argument("netuid", type=int, nargs="?", help="subnet to inspect")
    p.add_argument("--network", default="finney",
                   help="finney, test, or a ws:// endpoint. Public endpoints meter\n                         storage scans; your own node gives a complete cap table")
    p.add_argument("--buyer", help="your coldkey, to model your position after the buy")
    p.add_argument("--watch", nargs="*", default=[],
                   help="extra coldkeys to force into the analysis")
    p.add_argument("--price", type=float, help="asking price in TAO, for deal math")
    p.add_argument("--fast", action="store_true",
                   help="skip the full hotkey index scan; only look at registered hotkeys")
    p.add_argument("--deep", action="store_true",
                   help="fully enumerate every delegate pool (slow, exact)")
    p.add_argument("--row-budget", type=int, default=300000,
                   help="stake rows to spend on attribution, allocated by holder size")
    p.add_argument("--max-scan-seconds", type=float, default=420.0,
                   help="hard wall-clock cap on the holder scan")
    p.add_argument("--candidates", type=int, default=150,
                   help="how many top holders to profile for entity clustering")
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--materiality", type=float, default=0.005,
                   help="expand every stake pool holding at least this fraction of\n                         subnet alpha; smaller pools are bounded instead of read")
    p.add_argument("--retries", type=int, default=4,
                   help="retries per pool when the RPC endpoint throttles the scan")
    p.add_argument("--provenance", action="store_true",
                   help="trace where the suspicious wallets came from: account\n                         creation block, who funded them, when they first staked")
    p.add_argument("--history-network", default=None,
                   help="archive endpoint for the provenance pass -- required for it\n                         to run. Point it at your own archive node; a pruned node\n                         cannot answer historical state, and pointing a public tool\n                         at somebody else's archive by default is not neighbourly")
    p.add_argument("--provenance-max", type=int, default=25,
                   help="how many wallets to trace (about 50 reads each)")
    p.add_argument("--provenance-pace", type=float, default=0.2,
                   help="seconds between historical reads")
    p.add_argument("--no-progress", action="store_true",
                   help="suppress the progress bars (they are off already when stderr\n                         is not a terminal)")
    p.add_argument("--json", metavar="PATH", help="write the full report as JSON")
    p.add_argument("--report", metavar="PATH", nargs="?", const="-",
                   help="write the plain-English report; PATH, or - for stdout")
    p.add_argument("--report-short", metavar="PATH", nargs="?", const="-",
                   help="write only the at-a-glance section -- the same figures the\n                         terminal prints; PATH, or - for stdout")
    p.add_argument("--from-json", metavar="PATH",
                   help="render from a saved JSON report instead of reading the chain")
    a = p.parse_args(argv)
    if a.netuid is None and not a.from_json:
        p.error("give a netuid, or --from-json PATH")
    return a


async def run(args) -> int:
    global PROG
    async with bt.Client(network=args.network) as c:
        insp = Inspector(c, args.netuid, args)
        with RunProgress(args.netuid, enabled=not args.no_progress) as prog:
            PROG = prog
            try:
                await insp.collect()
                phase("clustering")
                insp.clusters = Clusterer(insp).run()
                say(f"resolved {len(insp.clusters)} distinct entities")
                if args.provenance and not args.history_network:
                    insp.note("provenance was requested but skipped: no --history-network "
                              "given, and historical state needs an archive node")
                    say("provenance skipped: pass --history-network <archive ws:// url>. "
                        "Your own archive node is the right answer; a pruned node cannot "
                        "serve historical state at all")
                elif args.provenance:
                    # clustering picks the targets, provenance re-clusters them:
                    # the historical evidence only matters for wallets state
                    # could not already tell apart
                    await trace_provenance(insp)
                    phase("clustering")
                    insp.clusters = Clusterer(insp).run()
                    say(f"re-clustered with provenance: "
                        f"{len(insp.clusters)} distinct entities")
                phase("analysis")
                await analyze(insp)
            finally:
                PROG = None
        render(insp)
        rep = to_json(insp) if (args.json or args.report or args.report_short) else None
        if args.json:
            with open(args.json, "w") as fh:
                json.dump(rep, fh, indent=2, default=str)
            say(f"wrote {args.json}")
        if args.report:
            emit_report(rep, args.report)
        if args.report_short:
            emit_report(rep, args.report_short, short=True)
        return 2 if any(f.severity == "CRITICAL" for f in insp.findings) else 0


def emit_report(rep: dict, path: str, short: bool = False) -> None:
    text = short_report(rep) if short else report(rep)
    if path == "-":
        print(text)
    else:
        with open(path, "w") as fh:
            fh.write(text)
        say(f"wrote {path}")


def main() -> None:
    args = parse_args()
    if args.from_json:
        with open(args.from_json) as fh:
            rep = json.load(fh)
        if args.report or not args.report_short:
            emit_report(rep, args.report or "-")
        if args.report_short:
            emit_report(rep, args.report_short, short=True)
        sys.exit(2 if any(f["severity"] == "CRITICAL" for f in rep["findings"]) else 0)
    t0 = time.time()
    try:
        rc = asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit(130)
    say(f"done in {time.time()-t0:.1f}s")
    sys.exit(rc)


if __name__ == "__main__":
    main()
