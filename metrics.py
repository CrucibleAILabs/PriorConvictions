#!/usr/bin/env python3
"""
metrics.py -- continuous risk measurements, driven by risk_model.json.

Extractors emit NUMBERS, not findings. A finding is a rule over a number, and
rules live in the config so recalibration is a data change. That split is the
point: the current grader scores booleans, which is why 19 of 20 subnets come
out F -- a boolean cannot distinguish "holds 1.01x the takeover bar" from
"holds 3.2x".

Source of truth is the subtensor pallet source at the spec mainnet is running
(v450 at time of writing), NOT the indexer's own scripts and NOT vault notes,
both of which have been observed to lag the chain. Every formula below cites
the function it was ported from.

Register a new metric with @metric("name"); it receives the collected
Inspector and returns a dict of emitted values.

DATA SOURCE. Most extractors here read history -- trades, swaps, lock state,
metagraph snapshots -- which only the ClickHouse indexer serves. This repo's
Inspector reads chain state over RPC and has no `.ch`, so those extractors
raise NeedsIndexer and `collect()` records them in `_errors`; scoring then
reports the rule as `metric_missing` rather than scoring it zero. Where a
metric is mostly derivable from RPC state, it is computed and the part that
came from a bound rather than a reading is flagged with an explicit
`*_known: false` -- never silently defaulted, since every default here is a
default in the direction of understating risk.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Callable, Optional

RAO = 1_000_000_000
BLOCK_SECONDS = 12.0
CONFIG_PATH = Path(__file__).resolve().parent / "risk_model.json"


def load_config(path: Optional[str] = None) -> dict:
    return json.loads(Path(path or CONFIG_PATH).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

REGISTRY: dict[str, Callable] = {}


def metric(name: str):
    def deco(fn: Callable) -> Callable:
        REGISTRY[name] = fn
        return fn
    return deco


class NeedsIndexer(RuntimeError):
    """Raised by an extractor whose inputs only the indexer serves.

    Distinct from a bug: `collect()` catches both, but this one says the
    reading is unavailable on this data source, not that the code is wrong.
    """


def _ch(insp):
    """The ClickHouse handle, or None on the RPC Inspector."""
    return getattr(insp, "ch", None)


def _head(insp) -> int:
    """Latest block. The indexer Inspector calls it `head`, the RPC one
    `block`; the metrics only ever want "now"."""
    return int(getattr(insp, "head", None) or getattr(insp, "block", 0) or 0)


def collect(insp, config: Optional[dict] = None) -> dict[str, Any]:
    """Run every enabled extractor. One failing metric must not lose the rest."""
    cfg = config or load_config()
    out: dict[str, Any] = {}
    for name, spec in (cfg.get("metrics") or {}).items():
        if not spec.get("enabled", True):
            continue
        fn = REGISTRY.get(spec.get("extractor", name))
        if fn is None:
            out.setdefault("_errors", []).append(f"{name}: no extractor registered")
            continue
        try:
            out.update(fn(insp) or {})
        except Exception as e:
            out.setdefault("_errors", []).append(f"{name}: {type(e).__name__}: {e}")
    return out


# --------------------------------------------------------------------------
# conviction mechanics, ported from pallets/subtensor/src/staking/lock.rs @ v450
# --------------------------------------------------------------------------

def exp_decay(dt: float, tau: float) -> float:
    """lock.rs::exp_decay. tau == 0 means "fully decayed", NOT "no decay"."""
    if dt == 0:
        return 1.0
    if tau == 0:
        return 0.0
    return math.exp(max(-dt / tau, -40.0))


def conviction_after(mass: float, dt_blocks: float, maturity_rate: int,
                     perpetual: bool, unlock_rate: int) -> float:
    """Conviction a lock of `mass` carries `dt_blocks` after being opened.

    From do_lock_stake @ v450: a fresh lock is written with
    `conviction: U64F64::saturating_from_num(0)` -- it starts at ZERO and
    matures. (A vault note claims conviction starts at locked_mass; that was a
    conviction-v2-era observation and is wrong for v450.)

    Perpetual lock, from calculate_decayed_mass_and_conviction:
        conviction(t) = mass * (1 - exp(-t / maturity_rate))

    Decaying lock with unlock_rate == 0 -- the live configuration -- takes the
    `unlock_rate == 0` branch, so conviction_from_mass is 0 forever AND the
    mass itself decays via exp_decay(dt, 0) == 0. A decaying lock is therefore
    worthless for a takeover; an attacker must call set_perpetual_lock(true).
    """
    if not perpetual:
        if unlock_rate == 0:
            return 0.0
        return 0.0        # non-perpetual accrual is not modelled beyond this
    if maturity_rate <= 0:
        return 0.0
    return mass * (1.0 - exp_decay(dt_blocks, maturity_rate))


def blocks_to_reach_from(mass: float, conviction_now: float, target: float,
                         maturity_rate: int) -> Optional[float]:
    """Blocks until a lock ALREADY carrying `conviction_now` passes `target`.

    conviction(t) = mass - (mass - c0) * exp(-t / maturity_rate), so
    t = -maturity_rate * ln((mass - target) / (mass - c0)).
    """
    import math
    if maturity_rate <= 0 or mass <= target or mass <= conviction_now:
        return None
    if conviction_now >= target:
        return 0.0
    return -maturity_rate * math.log((mass - target) / (mass - conviction_now))


def blocks_to_reach(mass: float, target: float, maturity_rate: int) -> Optional[float]:
    """Invert the perpetual curve: blocks for `mass` to mature past `target`.

    conviction asymptotes at `mass`, so a mass at or below the target never
    gets there however long it is left -- that is a None, not a large number.
    """
    if mass <= 0 or target <= 0 or maturity_rate <= 0:
        return None
    if mass <= target:
        return None
    return -maturity_rate * math.log(1.0 - target / mass)


# --------------------------------------------------------------------------
# A -- seizure headroom
# --------------------------------------------------------------------------

@metric("seizure_headroom")
def seizure_headroom(insp) -> dict:
    """Largest non-owner ENTITY's liquid alpha against the takeover bar.

    The buyer's blind spot this exists for: an entity holding well over the
    threshold in LIQUID alpha, having locked none of it, reads as safe in a
    report that shows conviction and holdings separately. It is the opposite
    of safe -- they can lock at will.

    Entity, not coldkey: a cap table read per-wallet is defeated by splitting,
    which is the whole reason the clusterer exists.
    """
    conv = insp.d.get("conv") or {}
    threshold = conv.get("threshold_alpha") or 0.0
    locked = _locked_by_coldkey(insp)

    owner_ck = insp.d.get("owner_ck")
    best = None
    for cl in (insp.clusters or []):
        if cl.get("is_owner"):
            continue
        members = cl.get("members") or []
        liquid = sum(max(0.0, (insp.holders[m].alpha if m in insp.holders else 0.0)
                         - locked.get(m, 0.0)) for m in members)
        if best is None or liquid > best[0]:
            best = (liquid, cl)
    if best is None:
        return {"seizure_headroom_ratio": 0.0, "seizure_headroom_alpha": 0.0,
                "seizure_headroom_entity": None, "seizure_headroom_entity_size": 0,
                "seizure_headroom_locks_known": _ch(insp) is not None}

    liquid, cl = best
    # Highest NON-OWNER locked conviction against the bar. This is intent, not
    # capacity: locking is public, matures over weeks, and cannot be freely
    # undone, so a rival who has locked has committed and is visible doing it.
    # Across 129 subnets only 25 have any non-owner lock and only 2 exceed the
    # bar -- which is why this discriminates where liquid headroom does not.
    owner_hk = insp.d.get("owner_hk")
    rivals = [r for r in conv.get("hotkeys", []) if not r.get("is_owner")]
    rival_conv = max([r["conviction_alpha"] for r in rivals] or [0.0])
    # Locked MASS is where a committed locker ends up: conviction asymptotes at
    # the mass, so mass >= bar means they cross it given time. SN24 shows why
    # both are needed -- 700,000 locked against a 514,850 bar, but only 215,835
    # conviction so far, because they locked ~16 days into an ~84-day
    # maturation. Conviction alone reads 0.42 and understates a takeover that
    # is already determined.
    rival_mass = max([r.get("locked_mass_alpha", 0.0) for r in rivals] or [0.0])
    eta = None
    if rival_mass > 0 and threshold > 0 and rival_mass > threshold:
        mr = max(rivals, key=lambda r: r.get("locked_mass_alpha", 0.0))
        eta_blocks = blocks_to_reach_from(
            rival_mass, mr.get("conviction_alpha", 0.0), threshold,
            int(conv.get("maturity_rate") or 0))
        eta = (eta_blocks * BLOCK_SECONDS / 86400.0) if eta_blocks is not None else None
    return {
        "rival_conviction_alpha": rival_conv,
        "rival_conviction_ratio": (rival_conv / threshold) if threshold else 0.0,
        "rival_locked_mass_alpha": rival_mass,
        "rival_locked_mass_ratio": (rival_mass / threshold) if threshold else 0.0,
        "rival_crosses_bar_in_days": eta,
        "seizure_headroom_ratio": (liquid / threshold) if threshold else 0.0,
        "seizure_headroom_alpha": liquid,
        "seizure_headroom_entity": (cl.get("members") or [None])[0],
        "seizure_headroom_entity_size": cl.get("size", 1),
        "conviction_threshold_alpha": threshold,
        # false == locked mass could not be read, so `liquid` is the whole
        # holding and the headroom ratio is an UPPER BOUND. It can only
        # overstate, never hide, a rival -- but a bound is not a measurement
        # and the two must not be quoted the same way.
        "seizure_headroom_locks_known": _ch(insp) is not None,
    }


def _locked_by_coldkey(insp) -> dict[str, float]:
    """Per-coldkey locked mass, so 'liquid' really means unlocked.

    lock_state is the individual `Lock` map -- correct here precisely because
    it is per-coldkey. It must NOT be summed for a subnet total (that
    double-counts against the aggregates); see the conviction note.
    """
    ch = _ch(insp)
    if ch is None:
        # No lock_state on the RPC path. Returning {} makes every holding read
        # as liquid, which OVERSTATES seizure headroom -- the caller flags it
        # rather than presenting the number as a reading. Only 25 of 128
        # subnets have any non-owner lock at all, so on most subnets the two
        # agree exactly; on the rest this is an upper bound.
        return {}
    rows = ch.q(
        """SELECT coldkey, locked_mass FROM lock_state
           WHERE netuid = %(n)s AND block_number = (
               SELECT max(block_number) FROM lock_state WHERE netuid = %(n)s)""",
        {"n": insp.netuid})
    import indexer_source as ix
    return {ix.to_ss58(ck): lm / RAO for ck, lm in rows}


# --------------------------------------------------------------------------
# B -- time to seize
# --------------------------------------------------------------------------

@metric("time_to_seize")
def time_to_seize(insp) -> dict:
    """Days before the strongest challenger's alpha could mature into a win.

    Converts "could seize" into "could seize in N days", which is the number
    that decides whether an owner can mount any defence at all -- conviction
    cannot be bought on the day of an attack.
    """
    conv = insp.d.get("conv") or {}
    maturity = int(conv.get("maturity_rate") or 0)
    threshold = conv.get("threshold_alpha") or 0.0

    head = seizure_headroom(insp)
    mass = head.get("seizure_headroom_alpha") or 0.0

    blocks = blocks_to_reach(mass, threshold, maturity)
    return {
        "maturity_rate_blocks": maturity,
        "maturity_half_life_days": (maturity * math.log(2) * BLOCK_SECONDS / 86400.0)
                                   if maturity else None,
        "time_to_seize_days": (blocks * BLOCK_SECONDS / 86400.0) if blocks else None,
        "time_to_seize_reachable": blocks is not None,
        "time_to_seize_resolved": True,
        "time_to_seize_basis": (
            "do_lock_stake @ v450 writes a fresh lock with conviction 0; perpetual "
            "locks mature as mass*(1-exp(-t/maturity_rate)). Decaying locks accrue "
            "nothing while unlock_rate == 0, so an attacker must set_perpetual_lock."),
    }


# --------------------------------------------------------------------------
# C -- owner net alpha flow
# --------------------------------------------------------------------------

def coldkey_lineage(insp, coldkey: str) -> list:
    """Every coldkey this account has been, walking executed swaps backwards.

    A coldkey swap re-keys the position inside one storage transaction and
    emits NO alpha_trades rows, so the new key's history starts empty with no
    acquisition behind it. Any owner-behaviour metric that reads only the
    current key therefore under-reports across a swap -- silently, and to
    zero.

    This is not hypothetical. On SN102 the owner key was drained of 145,105
    alpha in a single sale on 2026-07-12 and swapped nine days later; reading
    only the post-swap key scored the owner at 0.001 net selling. The drain
    was a compromise, not an exit, but on chain the two are the same shape --
    see the note in risk_model.json.
    """
    ch = _ch(insp)
    if ch is None:
        # coldkey_swap_history is indexer-only. The current key alone is what
        # the tool read before the lineage fix; across a swap it under-reports
        # owner behaviour, silently and to zero. Callers flag it.
        return [coldkey]
    seen, frontier = {coldkey}, [coldkey]
    import indexer_source as ix
    while frontier:
        cur = frontier.pop()
        rows = ch.q(
            """SELECT old_coldkey FROM coldkey_swap_history
               WHERE new_coldkey = %(ck)s AND phase = 'executed' AND success = 1""",
            {"ck": ix.to_hex(cur)})
        for (old_hex,) in rows:
            prev = ix.to_ss58(old_hex)
            if prev and prev not in seen:
                seen.add(prev)
                frontier.append(prev)
    return sorted(seen)


@metric("owner_flow")
def owner_flow(insp) -> dict:
    """Is the owner net selling their own alpha?

    Nothing in the tool looks at owner behaviour over time, which is the
    retail investor's biggest blind spot: the cap table can look stable while
    the owner distributes into every bid.

    Sourced from alpha_trades, a base table. See source_policy in
    risk_model.json: the P&L sidecars are absent here and unverified besides,
    and wallet_pnl_event_log is a materialized view that needs verifying on the
    target host before anything depends on it.
    """
    if _ch(insp) is None:
        raise NeedsIndexer("owner_flow reads alpha_trades, which only the "
                           "indexer serves")
    owner = insp.d.get("owner_ck")
    if not owner:
        return {}
    head = _head(insp)
    lineage = coldkey_lineage(insp, owner)
    windows = {"7d": 7, "30d": 30, "90d": 90, "180d": 180}
    out: dict[str, Any] = {"owner_coldkey_lineage": lineage,
                           "owner_coldkey_swapped": len(lineage) > 1}
    owner_alpha = sum(insp.holders[c].alpha for c in lineage if c in insp.holders)

    for label, days in windows.items():
        lo = head - int(days * 86400 / BLOCK_SECONDS)
        # Three different events wear the direction 'sell' in alpha_trades and
        # must NOT be summed together:
        #   is_transfer=0            a real market sale -- moves the price
        #   transfer_stake           custody moves to another coldkey; emits
        #                            BOTH a sell and a buy leg, and tao_amount
        #                            is a notional valuation, not TAO received
        #   move_stake               same coldkey rebalancing -- not a disposal
        # Measured on SN102: 148,819 of 148,920 alpha counted as "sold" was
        # transfer_stake, and the actual market sale was 99.9 alpha. Summing
        # them invented a dump that never touched the pool.
        rows = _ch(insp).q(
            """SELECT direction, is_transfer, call, sum(alpha_amount)
               FROM alpha_trades
               WHERE netuid = %(n)s AND coldkey IN %(cks)s
                 AND block_number >= %(lo)s AND is_fee = 0
               GROUP BY direction, is_transfer, call""",
            {"n": insp.netuid, "cks": tuple(lineage), "lo": lo})
        bought = sold = moved_out = 0.0
        for direction, is_transfer, call, raw in rows:
            alpha = raw / RAO
            if call == "move_stake":
                continue                      # internal rebalance, not a disposal
            if is_transfer:
                if direction == "sell":
                    moved_out += alpha        # custody left the lineage
                continue
            if direction == "buy":
                bought += alpha
            else:
                sold += alpha
        out[f"owner_net_alpha_{label}"] = bought - sold
        out[f"owner_sold_alpha_{label}"] = sold
        out[f"owner_transferred_out_{label}"] = moved_out

    # NET, not gross. An owner who buys 39k and sells 82k is a net seller of
    # 43k, not a 99%-dumper -- and owners churn heavily because owner-cut
    # emission arrives as alpha they routinely sell. Measured on SN21: 171
    # sells against 56 buys in 30 days. Gross would score routine income
    # disposal the same as liquidation.
    net30 = out.get("owner_net_alpha_30d", 0.0)
    shed30 = max(0.0, -net30)
    denom = owner_alpha + shed30                 # approx position 30d ago
    out["owner_net_sell_ratio_30d"] = (shed30 / denom) if denom > 0 else 0.0
    out["owner_alpha_now"] = owner_alpha

    # Churn is a separate signal from distribution: heavy two-way flow with a
    # flat net is market-making or income cycling, not an exit.
    gross30 = out.get("owner_sold_alpha_30d", 0.0) + max(0.0, net30) + shed30
    out["owner_churn_ratio_30d"] = (gross30 / denom) if denom > 0 else 0.0
    return out


# --------------------------------------------------------------------------
# E -- post-sale headroom
# --------------------------------------------------------------------------

@metric("post_sale_headroom")
def post_sale_headroom(insp) -> dict:
    """Would the slot be defensible once YOU own it?

    The report today answers "is the current owner safe". A purchaser is
    buying the owner's position, so their question is different: after the
    sale, can the largest rival still out-convict me, and what would it cost
    to close the gap?

    The threshold itself does not move -- it is 18% of eligible alpha, which
    is unaffected by who holds what. What moves is who is on each side of it.
    """
    head = seizure_headroom(insp)
    rival = head.get("seizure_headroom_alpha") or 0.0
    threshold = head.get("conviction_threshold_alpha") or 0.0

    owner_ck = insp.d.get("owner_ck")
    acquired = sum(insp.holders[c].alpha for c in coldkey_lineage(insp, owner_ck)
                   if c in insp.holders) if owner_ck else 0.0

    # To hold the slot you must out-convict the strongest rival AND clear the
    # bar yourself; conviction asymptotes at locked mass, so the target is the
    # larger of the two.
    need = max(threshold, rival)
    return {
        "post_sale_acquired_alpha": acquired,
        "post_sale_defence_ratio": (acquired / need) if need else 0.0,
        "post_sale_gap_alpha": max(0.0, need - acquired),
        "post_sale_rival_still_clears": rival >= threshold if threshold else False,
        # false == the owner's coldkey lineage could not be walked, so
        # `acquired` counts the current key only and a pre-swap position is
        # invisible. That understates what you are buying, and so the defence.
        "owner_lineage_known": _ch(insp) is not None,
        "seizure_headroom_locks_known": head.get("seizure_headroom_locks_known"),
    }


# --------------------------------------------------------------------------
# I -- rival accumulation
# --------------------------------------------------------------------------

@metric("rival_accumulation")
def rival_accumulation(insp) -> dict:
    """Is the strongest rival building, holding, or leaving?

    "Holds 14%" and "went 2% to 14% in three weeks" are different disclosures.
    Entity-wide and lineage-aware, for the same reason owner flow is: a
    per-coldkey read is defeated by splitting and by swaps.
    """
    if _ch(insp) is None:
        raise NeedsIndexer("rival_accumulation reads alpha_trades over a window, "
                           "which only the indexer serves")
    head = seizure_headroom(insp)
    entity = head.get("seizure_headroom_entity")
    if not entity:
        return {}
    cluster = next((c for c in (insp.clusters or [])
                    if entity in (c.get("members") or [])), None)
    members: list[str] = []
    for m in (cluster.get("members") if cluster else [entity]):
        members.extend(coldkey_lineage(insp, m))
    members = sorted(set(members))

    out: dict[str, Any] = {"rival_entity_coldkeys": len(members)}
    now = head.get("seizure_headroom_alpha") or 0.0
    for label, days in (("30d", 30), ("90d", 90)):
        lo = _head(insp) - int(days * 86400 / BLOCK_SECONDS)
        # Market flow only: transfer_stake legs are custody changes, not
        # accumulation, and move_stake is internal. Counting them would show a
        # rival "accumulating" alpha they merely moved between their own keys.
        rows = _ch(insp).q(
            """SELECT direction, sum(alpha_amount) FROM alpha_trades
               WHERE netuid = %(n)s AND coldkey IN %(cks)s
                 AND block_number >= %(lo)s AND is_fee = 0
                 AND is_transfer = 0 AND call != 'move_stake'
               GROUP BY direction""",
            {"n": insp.netuid, "cks": tuple(members), "lo": lo})
        moved = {d: a / RAO for d, a in rows}
        net = moved.get("buy", 0.0) - moved.get("sell", 0.0)
        out[f"rival_net_alpha_{label}"] = net
        # share of today's position acquired inside the window
        out[f"rival_accumulation_ratio_{label}"] = (net / now) if now > 0 else 0.0
    return out


# --------------------------------------------------------------------------
# Q -- drain then swap
# --------------------------------------------------------------------------

@metric("drain_then_swap")
def drain_then_swap(insp) -> dict:
    """Compromise, or a voluntary exit? They are the same shape on chain.

    The SN102 case taught the actual signature, and it is NOT a market dump:
    the attacker used `transfer_stake` to move 145,105 alpha to a wallet they
    controlled, then the owner recovered with a coldkey swap nine days later.
    A transfer moves custody without touching the pool, so there is no price
    impact and no slippage to measure -- an execution-quality test reads 1.000
    and discriminates nothing.

    What does discriminate: how much of the position left, whether it left by
    transfer or by sale, and how soon a swap followed.

    Present the evidence, never a motive. A theft and a planned exit through a
    new wallet are indistinguishable here.
    """
    if _ch(insp) is None:
        raise NeedsIndexer("drain_then_swap reads alpha_trades and "
                           "coldkey_swap_history, which only the indexer serves")
    import indexer_source as ix
    owner = insp.d.get("owner_ck")
    if not owner:
        return {}
    lineage = coldkey_lineage(insp, owner)

    swaps = _ch(insp).q(
        """SELECT block_number, old_coldkey FROM coldkey_swap_history
           WHERE new_coldkey IN %(cks)s AND phase = 'executed' AND success = 1
           ORDER BY block_number""",
        {"cks": tuple(ix.to_hex(c) for c in lineage)})
    if not swaps:
        return {"drain_then_swap_detected": False, "owner_swap_count": 0}

    WINDOW = 30 * 7200
    best = None
    for swap_block, old_hex in swaps:
        old_ck = ix.to_ss58(old_hex)
        rows = _ch(insp).q(
            """SELECT block_number, alpha_amount, tao_amount, is_transfer, call
               FROM alpha_trades
               WHERE netuid = %(n)s AND coldkey = %(ck)s AND direction = 'sell'
                 AND is_fee = 0 AND call != 'move_stake'
                 AND block_number BETWEEN %(lo)s AND %(hi)s
               ORDER BY alpha_amount DESC LIMIT 1""",
            {"n": insp.netuid, "ck": old_ck,
             "lo": swap_block - WINDOW, "hi": swap_block})
        if not rows:
            continue
        blk, alpha_raw, tao_raw, is_transfer, call = rows[0]
        alpha = alpha_raw / RAO
        if alpha <= 0:
            continue

        # Size it against what the key held just before, so a big number on a
        # big wallet is not confused with a wallet being emptied.
        held = _ch(insp).one(
            """SELECT sum(alpha_amount)/1e9 FROM stake_positions
               WHERE netuid = %(n)s AND coldkey = %(ck)s
                 AND block_number = (SELECT max(block_number) FROM stake_positions
                                     WHERE netuid = %(n)s AND block_number <= %(b)s)""",
            {"n": insp.netuid, "ck": old_ck, "b": blk})
        held_before = float(held[0]) if held and held[0] else 0.0

        cand = {
            "drain_then_swap_detected": True,
            "drain_alpha": alpha,
            "drain_block": int(blk),
            "drain_kind": "transfer" if is_transfer else "market_sell",
            "drain_call": call,
            "drain_to_swap_days": (swap_block - blk) * BLOCK_SECONDS / 86400.0,
            "drain_share_of_position": (alpha / (held_before + alpha)
                                        if (held_before + alpha) > 0 else 0.0),
        }
        if best is None or cand["drain_alpha"] > best["drain_alpha"]:
            best = cand

    out = best or {"drain_then_swap_detected": False}
    out["owner_swap_count"] = len(swaps)
    return out


# --------------------------------------------------------------------------
# R -- transfer follow-through
# --------------------------------------------------------------------------

@metric("transfer_follow_through")
def transfer_follow_through(insp) -> dict:
    """Of the alpha that left the owner by transfer, how much then hit the market?

    Treating a transfer as "not a sale" is too clean. On SN102 the attacker
    moved 145,105 alpha to a wallet they controlled and sold ALL of it from
    there -- 97,067 via remove_stake_limit and 51,974 via batch_all, ending
    at a zero balance. Economically that was a sale; it merely took two steps
    and a second key.

    So follow the destination. A transfer whose recipient still holds is a
    custody change; a transfer whose recipient liquidated is a disposal with
    an extra hop, and the alpha reached the pool either way.

    Also worth reading: the destinations realised ~1,293 TAO against a 2,142
    TAO notional at transfer time -- dumping into a thin pool costs about 40%,
    which is why a thief transfers first rather than selling from the victim's
    key.
    """
    if _ch(insp) is None:
        raise NeedsIndexer("transfer_follow_through traces transfer destinations "
                           "through alpha_trades, which only the indexer serves")
    owner = insp.d.get("owner_ck")
    if not owner:
        return {}
    lineage = coldkey_lineage(insp, owner)
    lo = _head(insp) - int(180 * 86400 / BLOCK_SECONDS)

    # Computed FIRST: a subnet with no transfers at all still has an outflow if
    # the owner sold directly. Leaving this below the early returns reported
    # SN115 -- the largest genuine seller in the sample, 153,035 alpha into the
    # market -- as zero effective outflow.
    own_row = _ch(insp).one(
        """SELECT sum(alpha_amount)/1e9 FROM alpha_trades
           WHERE netuid = %(n)s AND coldkey IN %(cks)s AND direction = 'sell'
             AND is_transfer = 0 AND call != 'move_stake' AND is_fee = 0
             AND block_number >= %(lo)s""",
        {"n": insp.netuid, "cks": tuple(lineage), "lo": lo})
    own_sold_alpha = float(own_row[0]) if own_row and own_row[0] else 0.0

    legs = _ch(insp).q(
        """SELECT block_number, sum(alpha_amount)/1e9 FROM alpha_trades
           WHERE netuid = %(n)s AND coldkey IN %(cks)s AND direction = 'sell'
             AND call = 'transfer_stake' AND is_fee = 0 AND block_number >= %(lo)s
           GROUP BY block_number""",
        {"n": insp.netuid, "cks": tuple(lineage), "lo": lo})
    if not legs:
        return {"owner_transfer_out_180d": 0.0,
                "transfer_destinations": 0,
                "transfer_follow_through_ratio": 0.0,
                "effective_owner_outflow_180d": own_sold_alpha,
                "owner_outflow_share_180d": _share(own_sold_alpha, insp, lineage)}

    blocks = tuple(int(b) for b, _ in legs)
    moved = sum(a for _, a in legs)

    dests = [r[0] for r in _ch(insp).q(
        """SELECT DISTINCT coldkey FROM alpha_trades
           WHERE netuid = %(n)s AND block_number IN %(bs)s AND direction = 'buy'
             AND call = 'transfer_stake' AND coldkey NOT IN %(cks)s""",
        {"n": insp.netuid, "bs": blocks, "cks": tuple(lineage)})]
    if not dests:
        return {"owner_transfer_out_180d": moved,
                "transfer_follow_through_ratio": 0.0,
                "effective_owner_outflow_180d": own_sold_alpha,
                "owner_outflow_share_180d": _share(own_sold_alpha, insp, lineage),
                "transfer_destinations": 0}

    row = _ch(insp).one(
        """SELECT sum(alpha_amount)/1e9, sum(tao_amount)/1e9 FROM alpha_trades
           WHERE netuid = %(n)s AND coldkey IN %(ds)s AND direction = 'sell'
             AND is_transfer = 0 AND call != 'move_stake' AND is_fee = 0
             AND block_number >= %(lo)s""",
        {"n": insp.netuid, "ds": tuple(dests), "lo": min(blocks)})
    dest_sold = float(row[0]) if row and row[0] else 0.0
    dest_tao = float(row[1]) if row and row[1] else 0.0

    still_held = _ch(insp).one(
        """SELECT sum(alpha_amount)/1e9 FROM stake_positions
           WHERE netuid = %(n)s AND coldkey IN %(ds)s
             AND block_number = (SELECT max(block_number) FROM stake_positions
                                 WHERE netuid = %(n)s)""",
        {"n": insp.netuid, "ds": tuple(dests)})

    return {
        "owner_transfer_out_180d": moved,
        "transfer_destinations": len(dests),
        "transfer_dest_sold_alpha": dest_sold,
        "transfer_dest_sold_tao": dest_tao,
        "transfer_dest_still_holds": float(still_held[0]) if still_held and still_held[0] else 0.0,
        # capped: destinations may sell alpha they held before the transfer
        "transfer_follow_through_ratio": min(1.0, dest_sold / moved) if moved > 0 else 0.0,
        # the honest number -- everything the owner's side put into the pool,
        # whether it went directly or via a second key
        "effective_owner_outflow_180d": own_sold_alpha + min(dest_sold, moved),
        # Bounded 0-1: what fraction of everything the owner has held over the
        # window actually left for the market. Dividing by the CURRENT holding
        # is unbounded -- an owner who sold almost everything scores 2.3, which
        # pins any sane scale at its maximum and turns the rule back into the
        # boolean it was meant to replace.
        "owner_outflow_share_180d": _share(own_sold_alpha + min(dest_sold, moved),
                                           insp, lineage),
    }


def _share(outflow: float, insp, lineage: list) -> float:
    held = sum(insp.holders[c].alpha for c in lineage if c in insp.holders)
    denom = held + outflow
    return (outflow / denom) if denom > 0 else 0.0


@metric("subnet_context")
def subnet_context(insp) -> dict:
    """Flat facts the anchors test against. Not scored on their own."""
    conv = insp.d.get("conv") or {}
    threshold = conv.get("threshold_alpha") or 0.0
    # Eligible alpha back out of the threshold, which is 18% of it. Derived
    # rather than read so it is present on every row even where the raw
    # subnet_alpha_out was not collected -- a missing denominator silently
    # falling back to 1 already produced one wrong analysis.
    eligible = (threshold / 0.18) if threshold > 0 else None
    owner_ck = insp.d.get("owner_ck")
    owner_alpha = (sum(insp.holders[c].alpha for c in coldkey_lineage(insp, owner_ck)
                       if c in insp.holders) if owner_ck else 0.0)
    # SubnetEmissionEnabled=false covers two opposite states, and
    # FirstEmissionBlockNumber is what separates them:
    #   never emitted   -> awaiting activation, not damaged
    #   emitted before  -> deliberately switched off
    # Per the v450 storage doc, "off" disables POOL-side emission only:
    # alpha_in / tao_in / excess_tao go to zero while alpha_out, owner cut,
    # root proportion and pending server/validator emission are unchanged.
    # Miners keep earning; what stops is TAO backing the pool.
    enabled = bool(insp.d.get("emission_enabled"))
    first = insp.d.get("first_emission_block")
    never_started = (not enabled) and (first is None) and bool(
        insp.d.get("first_emission_known"))
    return {
        "subnet_eligible_alpha": eligible,
        "owner_share_of_eligible": (owner_alpha / eligible) if eligible else None,
        "subnet_emission_enabled": enabled,
        "subnet_never_started": never_started,
        "subnet_emission_switched_off": (not enabled) and first is not None,
        "subnet_registered_at": insp.d.get("registered_at"),
        "subnet_alpha_out": insp.d.get("alpha_out"),
        "takeover_window_open": (
            (conv.get("ownership_changeable_at_block") or 0) <= _head(insp)
            if conv.get("ownership_changeable_at_block") else False),
        "owner_lineage_known": _ch(insp) is not None,
    }


# --------------------------------------------------------------------------
# S -- miner productivity
# --------------------------------------------------------------------------

@metric("miner_productivity")
def miner_productivity(insp) -> dict:
    """Is the subnet actually rewarding work, and to how many?

    Nothing else in the model asks whether the thing does anything. An
    investor holding alpha is betting on a network that produces something;
    a subnet where no miner has earned in a week is a shell regardless of how
    clean its cap table looks.

    Measured over a WINDOW, never at a single block. metagraph_state is a
    point-in-time snapshot and emission is reset each tempo, so an instant
    reading depends on where the snapshot fell: SN102 shows 0 miners earning
    at its latest block and 32% across seven days.

    Two independent axes, because they fail differently:
      breadth      -- what share of miners earned anything at all
      concentration-- how much of miner emission the top 10 took
    A subnet can have broad participation with captured rewards (SN8: 25%
    earning, top 10 take 99%) or the reverse.
    """
    if _ch(insp) is None:
        raise NeedsIndexer("miner_productivity needs ~7 days of metagraph_state "
                           "snapshots; a single RPC metagraph read cannot answer "
                           "it, because emission resets each tempo")
    ch, nid = _ch(insp), insp.netuid
    head = insp.d.get("metagraph_block") or _head(insp)
    lo = head - 50_000                      # ~7 days

    row = ch.one(
        """SELECT uniqExact(uid), uniqExactIf(uid, emission > 0),
                  uniqExactIf(uid, incentive > 0), sum(emission)
           FROM metagraph_state
           WHERE netuid = %(n)s AND block_number BETWEEN %(lo)s AND %(hi)s
             AND validator_permit = 0""",
        {"n": nid, "lo": lo, "hi": head})
    if not row or not row[0]:
        return {}
    miners, earning, incentivised, total = row[0], row[1], row[2], (row[3] or 0.0)

    top = ch.q(
        """SELECT sum(emission) s FROM metagraph_state
           WHERE netuid = %(n)s AND block_number BETWEEN %(lo)s AND %(hi)s
             AND validator_permit = 0
           GROUP BY uid ORDER BY s DESC LIMIT 10""",
        {"n": nid, "lo": lo, "hi": head})

    return {
        "miner_count": miners,
        "miner_earning_count": earning,
        "miner_earning_share": earning / miners if miners else 0.0,
        "miner_incentivised_share": incentivised / miners if miners else 0.0,
        "miner_emission_top10_share": (sum(x[0] for x in top) / total) if total else 0.0,
        "miner_window_blocks": head - lo,
    }


# --------------------------------------------------------------------------
# T -- validator set and self-dealing
# --------------------------------------------------------------------------

@metric("participation")
def participation(insp) -> dict:
    """Who validates, how diverse are they, and is the subnet talking to itself?

    Two questions an alpha holder should ask that nothing else here answers:

    Validators decide consensus and take the dividends. A handful of them,
    or a set that agrees with itself perfectly, is a captured subnet however
    healthy the miner side looks.

    Self-dealing: a subnet where the same hands run the miners AND the
    validators is a closed loop -- emission cycles back to the operator and
    the "market" is a costume. Measured at ENTITY level, never by raw
    coldkey: coldkey overlap reads ~0% on every subnet sampled, because
    anyone doing this uses separate wallets. The clusterer exists precisely
    to see through that.
    """
    if _ch(insp) is None:
        raise NeedsIndexer("participation reads validator history from "
                           "metagraph_state, which only the indexer serves")
    ch, nid = _ch(insp), insp.netuid
    mg = insp.d.get("mg")
    if not mg or not mg.neurons:
        return {}

    vals = [n for n in mg.neurons if n.validator_permit]
    miners = [n for n in mg.neurons if not n.validator_permit]
    if not miners:
        return {}

    # entity lookup: coldkey -> cluster id
    ent: dict[str, int] = {}
    for i, cl in enumerate(insp.clusters or []):
        for m in (cl.get("members") or []):
            ent[m] = i

    def entity_of(ck):
        return ent.get(ck, f"ck:{ck}")

    val_entities = {entity_of(n.coldkey) for n in vals}
    owner_entity = entity_of(insp.d.get("owner_ck"))

    miner_in_val = sum(1 for n in miners if entity_of(n.coldkey) in val_entities)
    miner_is_owner = sum(1 for n in miners if entity_of(n.coldkey) == owner_entity)
    miner_cks = {n.coldkey for n in miners}
    val_cks = {n.coldkey for n in vals}

    vt = [n.vtrust for n in vals if n.vtrust is not None]
    head = insp.d.get("metagraph_block") or _head(insp)

    row = ch.one(
        """SELECT count(), countIf(alpha_dividends > 0) FROM epoch_dividends
           WHERE netuid = %(n)s AND block_number = (
               SELECT max(block_number) FROM epoch_dividends WHERE netuid = %(n)s)""",
        {"n": nid})
    div_total, div_earning = (row[0], row[1]) if row else (0, 0)

    return {
        "validator_count": len(vals),
        "validator_coldkey_count": len(val_cks),
        "validator_entity_count": len(val_entities),
        "validator_mean_vtrust": (sum(vt) / len(vt)) if vt else None,
        "validator_earning_share": (div_earning / div_total) if div_total else None,
        "miner_coldkey_count": len(miner_cks),
        # UIDs per operator: SN115 runs 237 miner slots from 26 coldkeys while
        # SN64 spreads 238 across 186. A low number is a closed shop.
        "miner_uids_per_coldkey": len(miners) / len(miner_cks) if miner_cks else 0.0,
        "miner_validator_entity_overlap": miner_in_val / len(miners),
        "owner_affiliated_miner_share": miner_is_owner / len(miners),
    }
