# PriorConvictions

Read-only due diligence on a Bittensor subnet slot, before you buy, lease or inherit it.

A dashboard shows you what a subnet earns. It does not show you that five wallets holding
"independent" positions were created sixty seconds apart from the same funder, that their
combined stake clears the threshold at which the chain hands them your subnet, or that the
hotkey the owner validates through belongs to a coldkey that isn't part of the sale.

That is the class of problem this tool exists to find. It reads live chain state and reports
the ways the slot can be taken from you, held hostage, or drained.

Nothing here signs, stakes, or transacts.

> [!IMPORTANT]
> PriorConvictions is an automated informational and diagnostic tool, not a security audit,
> certification, or guarantee that a subnet is safe or unsafe. Its results may include false
> positives, false negatives, incomplete findings, or outdated conclusions. A clean report does
> not mean that no risk exists. Independently verify the results and do not rely on this tool as
> the sole basis for any staking, investment, acquisition, custody, governance, or security
> decision. See the [full disclaimer](#disclaimer).

---

## What it checks

**Ownership.** The conviction takeover gate — the chain mechanism that reassigns subnet
ownership, without the owner's consent, to whichever single hotkey's conviction passes 18% of
eligible stake once the subnet is about a year old. The report gives you the threshold in
alpha, when the window opens, what it costs in TAO to seize the slot at current pool depth,
and what it costs to make your own ownership defensible. Plus the levers a seller keeps after
a sale: active leases, pending coldkey swaps, and proxy rights on the owner coldkey.

**Overhang.** Every alpha holder it can attribute down to individual coldkeys, grouped into
entities on weighted evidence. The metagraph only sees hotkeys that hold a UID on the subnet
— on SN 38 that is 18 hotkeys out of 94 holding alpha — so attribution walks the chain's own
`TotalHotkeyAlpha` index instead, and reports what it could not read as a hard ceiling rather
than pretending the gap isn't there.

**Capture.** Where emission actually lands each epoch, who holds validator permits and
weight-setting power, which UIDs are squatted, and which childkeys are quietly redirecting
stake.

**Provenance.** Where the wallets came from: account creation block, the transfer that paid
for it, and the block it first staked into the subnet. This is the only part that reads
history rather than current state, and it is what turns "six wallets that happen to be the
same size" into an answer.

---

## Install

Requires Python 3.10+ and the Bittensor SDK (11.x dev — the async `bittensor.Client` API),
plus `rich` for the console view and `qrcode`, which the SDK imports unconditionally.

```bash
pip install -e ~/.bittensor/subtensor/sdk/python
pip install rich qrcode
```

## Usage

```bash
# the basics
python3 subnet_inspector.py 38

# a real diligence run: full report, saved JSON, deal math against an asking price
python3 subnet_inspector.py 4 --price 25000 --json sn4.json --report sn4.txt

# with the history pass, which is what catches split positions
python3 subnet_inspector.py 38 --provenance --report sn38.txt

# re-render a saved report without touching the network
python3 subnet_inspector.py --from-json sn4.json --report-short -
```

Exits `2` when a CRITICAL finding is present, `0` otherwise — so it drops into a pre-purchase
checklist or CI without parsing anything.

### Output

| flag | what you get |
|---|---|
| *(none)* | rich console view: market, defensibility, cap table, findings |
| `--json PATH` | the complete report as structured JSON |
| `--report PATH` | plain-English narrative — ownership, holders, key routing, emission, per-finding buyer impact |
| `--report-short PATH` | the at-a-glance digest alone: the same figures the console prints |
| `--from-json PATH` | re-render either report from saved JSON, no chain reads |

`PATH` may be `-` for stdout. Progress bars appear on a terminal and disable themselves when
stderr is redirected, so piped output is unchanged.

---

## Quick Example

Here's an example where a subnet has 6 wallets that have very close balances. 
Without the history pass, the six largest outside holders look like six strangers:

```
 2  wallet A   1    45.59k   3.0%
 3  wallet B   1    45.55k   3.0%
 4  wallet C   1    45.08k   2.9%
 5  wallet D   1    42.95k   2.8%
 6  wallet E   1    40.48k   2.6%
 7  wallet F   1    40.12k   2.6%
```

Grade D. A `SPLIT_PATTERN` finding names the shape and that chain state cannot
settle it.

With `--provenance`, the account creation blocks come back:

```
wallet A   block 7,434,793   12:47:24
wallet D   block 7,434,798   12:48:24
wallet B   block 7,434,803   12:49:24
wallet F   block 7,434,813   12:51:24
wallet C   block 7,434,823   12:53:24
```

Five accounts, five blocks apart, one per minute, in sequence. Their first stakes are spread
across weeks — creation is batched because it's tedious, buys are spread because simultaneous
buys are what gets noticed. They merge into one entity:

```
 1  OWNER subnet owner   1   226.99k   14.7%
 2  wallet A  (+4)       5   219.60k   14.3%
```

219,597 alpha against a 167,199 alpha takeover threshold. Grade F, and `RIVAL_CAN_SEIZE_NOW`
fires: they do not need to buy anything, only to concentrate what they already hold behind one
hotkey. Wallet E was created 445,000 blocks later by a different funder and correctly stays
separate.

---

## How entities are clustered

No single on-chain fact proves common control, so evidence is weighted and accumulated with
union-find. Pairs clearing `LINK_THRESHOLD = 5.0` merge.

| evidence | weight |
|---|---|
| shared proxy delegate | 5.0 (1.0 if the delegate serves more than 8 wallets) |
| identical on-chain identity | 5.0 |
| created within 60 blocks of each other | 5.0 |
| same funder, funder is a personal wallet (< 1k txs) | 5.0 |
| funds ≥75% of another's hotkey | 3.0 |
| cross-subnet portfolio ≥70% identical | 3.0 |
| created within 300 blocks | 3.0 |
| first staked within 300 blocks | 3.0 |
| their funders were paid by the same wallet | 3.0 |
| same funder, mid-range | 3.0 |
| rare shared hotkey (≤4 holders) | 2.0 |
| childkey delegation | 2.0 |
| same auto-stake destination | 2.0 |
| created within 1,800 blocks / first staked within 5,000 | 1.5 |
| same funder, funder is exchange-scale (> 50k txs) | 1.0 |

Two deliberate choices sit behind that table.

**Childkey links are only worth 2.0.** At 4.0 they transitively merged a subnet owner into an
unrelated validator and inflated his apparent holdings.

**A shared funder is weighted by the funder's transaction count.** An exchange hot wallet funds
thousands of unrelated people; a key with 592 transactions funds a desk. Without that damping,
every exchange-funded wallet on the network clusters together.

And one thing it deliberately does **not** do: merge wallets that merely hold similar amounts.
Chain state genuinely cannot distinguish one desk splitting a position from N independent
whales, so that emits a `SPLIT_PATTERN` finding instead of a false certainty.

---

## The provenance pass

Three facts per coldkey, all cheap against an archive node:

| fact | method | cost |
|---|---|---|
| creation block | binary search `System.Account` — `providers` flips 0→1 | ~24 reads |
| funder + amount | the `Balances.Transfer` in that block's events | 1 read |
| funder fan-out | the funder's `nonce` — how many extrinsics it ever signed | 1 read |
| first stake here | binary search the stake map from the creation block | ~24 reads |

The stake map was renamed mid-history: older runtimes have `Alpha`, newer ones `AlphaV2`, and a
migrated position reads zero on the old map. Both are probed, with the one that answered last
tried first.

Clustering runs twice — once on state alone to pick targets (members of a tight size band
first, then the largest holders), then again once the history is in. Only wallets that state
couldn't already tell apart cost any reads. Results are cached in
`~/.cache/subnet_inspector/provenance.json`; creation blocks never change, so a second run on
the same wallets costs nothing. In practice: 1,272 reads on the first SN 38 run, 6 on the next.

**`--history-network` has no default and the pass does not run without it.** Historical state
needs an archive node, and a tool that shipped pointing at somebody else's archive would have
every user of it hammering a stranger's infrastructure. Run your own:

```bash
# in the subtensor repo
docker compose up -d mainnet-archive

python3 subnet_inspector.py 38 --provenance --provenance-max 25 \
    --history-network ws://127.0.0.1:9944
```

Public archives exist and will work if you pace yourself, but they meter historical reads
separately from ordinary ones and a full trace can exhaust that budget mid-run. If you use one,
be a good guest: keep `--provenance-pace` at or above the default, and keep `--provenance-max`
tight. Ask before pointing sustained load at infrastructure you don't pay for.

---

## Endpoints and throttling

The public entrypoint meters large storage scans, and a throttled run silently drops findings —
if the endpoint refuses the pool a group of wallets sits in, that group vanishes from the cap
table and the report looks *cleaner* than the truth. Every run therefore states its attribution
percentage and a hard ceiling on the largest holder that could still be hiding, via
`HIDDEN_HOLDER_BOUND`.

Observed on SN 38, same subnet, same day:

| endpoint | attribution | time |
|---|---|---|
| `entrypoint-finney` (public) | 39% | 359s |
| own / private node | 93.9% | 124s |

Point `--network` at your own node. `docker compose up -d mainnet-lite` in the subtensor repo
is enough for everything except provenance — the main scan only reads at the head.

The provenance pass needs an **archive** node, which is a heavier proposition: a pruned or
warp-synced node answers `State discarded` for anything outside its window, so `mainnet-lite`
cannot serve it. `mainnet-archive` in the same compose file can. Public archive endpoints also
meter historical reads under their own budget, separate from the storage-scan one, and a full
trace can exhaust it partway through — which is the other reason `--history-network` is
something you supply deliberately rather than a default you inherit.

---

## Findings

| severity | code |
|---|---|
| CRITICAL | `TAKEOVER_WINDOW_OPEN` `RIVAL_CAN_SEIZE_NOW` `RIVAL_CONVICTION` `ALPHA_OVERHANG` `VALIDATOR_CONTROL` `LEASE_ACTIVE` `EMISSION_DISABLED` |
| HIGH | `SYBIL_CLUSTER` `SPLIT_PATTERN` `COALITION_RISK` `CONCENTRATION` `OFF_REGISTER_ALPHA` `EXIT_PRESSURE` `EMISSION_CAPTURE` `PENDING_CHILDKEYS` `OWNER_PROXY_RIGHTS` `OWNER_COLDKEY_SWAP_PENDING` `OWNER_CONVICTION_WEAK` `UID_SQUAT` `SUBNET_INACTIVE` |
| MEDIUM | `TAKEOVER_WINDOW_PENDING` `SHALLOW_POOL` `CHILDKEY_EXPORT` `OWNER_CUT_NOT_AUTOLOCKED` `ROOT_DRIVEN_CONSENSUS` `REGISTRATION_CLOSED` |
| LOW | `STALE_VALIDATORS` `LONG_IMMUNITY` `VALIDATOR_SLOTS_FULL` |
| INFO | `HIDDEN_HOLDER_BOUND` |

Severity escalates on the numbers: `SPLIT_PATTERN` is HIGH when the combined band exceeds the
owner's position, `VALIDATOR_CONTROL` is CRITICAL above 50% of validator stake weight,
`HIDDEN_HOLDER_BOUND` rises when coverage falls.

---

## What it cannot tell you

Two things, at any coverage:

**Whether several wallets are one holder.** Identical behaviour and identical sizing are
suggestive; funding origin and creation timing are strong; none of it is proof. The tool states
its evidence — including when that evidence is weak, like a shared exchange funder — so you can
weigh it yourself.

**What anyone intends to do.** A large holder who has been friendly for a year is
indistinguishable on chain from one who is waiting.

The gap between those two and a signed deal is what the diligence questions in the report are
for.

---
## Disclaimer

PriorConvictions analyzes selected aspects of Bittensor subnet configuration, on-chain state,
and, when enabled, historical chain data in an attempt to identify security, control, custody,
economic, and operational risks. It is provided for general informational and diagnostic
purposes only. It is not a security audit, guarantee, certification, or representation that any
subnet, transaction, wallet, participant, or proposed acquisition is safe or unsafe, and it is
not legal, financial, investment, tax, or other professional advice.

The tool may produce false positives, false negatives, incomplete findings, outdated results,
or incorrect conclusions. Among other things, it may fail to identify vulnerabilities, attack
paths, ownership or governance risks, configuration issues, economic risks, or other conditions
that could result in the loss, theft, locking, dilution, impairment, or unauthorized control of
digital assets. Conversely, a reported condition may not be exploitable and may never result in
loss. A result stating that no issue was detected means only that the checks performed by that
version of the tool did not detect one; it does not establish that no issue exists.

Results are point-in-time and depend on the data available to the tool, including the accuracy,
availability, and completeness of RPC responses, endpoint coverage, archive history, runtime
metadata, and other third-party infrastructure. Bittensor runtime upgrades, governance actions,
network conditions, configuration changes, key changes, software updates, or later changes in
on-chain state may make a result inaccurate or obsolete at any time.

Users are solely responsible for independently verifying all results and conducting appropriate
technical, security, legal, and financial due diligence before acting. Do not rely on this tool
as the sole basis for decisions involving subnet ownership, staking, investment, acquisition,
leasing, custody, governance, operations, security, or digital assets.

To the maximum extent permitted by applicable law, Crucible Labs, its affiliates, and their
respective contributors, officers, employees, and agents make no warranties regarding the
accuracy, completeness, reliability, availability, or fitness of the tool or its output and
accept no responsibility or liability for losses or damages arising from use of, or reliance on,
the tool or its results. This disclaimer supplements, and does not replace, the warranty
disclaimer and limitation of liability in the MIT License.

---

## License

MIT
---
