---
name: pharos-safety-gate
description: 
  Read-only on-chain risk scanner for Pharos. Given any token or contract
  address, it checks for the red flags an autonomous agent cannot see before
  it swaps, approves, or transfers — ownership not renounced, mint functions,
  blacklist/freeze hooks, upgradeable proxies, pause switches, and (with a
  holder) honeypot/transfer-tax behavior — and returns a risk scorecard plus a
  verdict (SAFE / CAUTION / DANGER / INSUFFICIENT_DATA). Trigger this whenever
  the user or another agent is about to interact with a token or contract and
  asks things like "is 0x… safe", "is this a honeypot", "is this token a rug",
  "should I approve/buy this", "check this contract before I trade". Never signs,
  never needs a private key.
---

# Pharos Safety Gate

A pre-interaction safety check. It answers one question — **"is it safe for my
agent to touch this address?"** — using only public JSON-RPC reads.

## Prerequisites

- Node.js 18+ (uses built-in `fetch`; zero npm dependencies)
- No wallet, no private key, no signing — this skill only reads chain state

## Capability index

| User need | What it does | How |
|-----------|--------------|-----|
| "Is 0x… safe to interact with / is this a rug / honeypot?" | Full risk scan + verdict | `node scripts/safety-gate.mjs <address>` |
| "Vet this token before I approve/swap it" | Same scan, JSON for an agent | `... --format json` |
| "Can a real holder actually sell this token?" | Transfer simulation (no funds move) | `... --holder <holder_address>` |
| "Check this contract on testnet" | Run against Atlantic testnet | `... --network atlantic-testnet` |

## Usage

```bash
node scripts/safety-gate.mjs <address> [--network mainnet|atlantic-testnet] \
                                       [--format json|md|console] \
                                       [--holder 0x...] [--rpc <url>]
```

Networks: `mainnet` (chain 1672, native PROS) and `atlantic-testnet`
(chain 688689, native PHRS).

## What it checks

| Check | Reliable? |
|-------|-----------|
| Address has contract code (not an EOA) | yes |
| Behaves like a standard ERC-20 (name/symbol/decimals/totalSupply) | yes |
| Upgradeable proxy (EIP-1967 impl/admin/beacon slots) | yes |
| Ownership renounced (`owner()`/`getOwner()` == zero/dead) | yes |
| Mint functions present (bytecode selector scan) | heuristic |
| Blacklist / freeze hooks present (bytecode selector scan) | heuristic |
| Pause switch present, and whether paused right now | yes for `paused()` |
| Honeypot / transfer tax (real transfer simulation) | only with `--holder` |
| Liquidity locked | not asserted without LP + locker config |

> **Honest by design.** Checks it cannot prove return `unknown`, never a false
> "pass". A proxy makes the bytecode scan inconclusive (logic lives in the
> implementation), so the tool says so and tells the agent to re-scan the
> implementation address. Full buy/sell honeypot detection needs a known DEX
> router on the target network; transfer-tax and sellability need a funded
> holder. The verdict downgrades to `INSUFFICIENT_DATA` rather than `SAFE` when
> coverage is low.

## Output schema (`--format json`)

```jsonc
{
  "skill": "pharos-safety-gate",
  "network": "Pharos Pacific Mainnet",
  "chainId": 1672,
  "address": "0x...",
  "token": { "name": "...", "symbol": "...", "decimals": 18 },
  "verdict": "DANGER",            // SAFE | CAUTION | DANGER | INSUFFICIENT_DATA
  "riskScore": 100,               // 0–100
  "confidence": "medium",         // high | medium | low
  "reasons": ["FAIL: ...", "WARN: ..."],
  "checks": [ { "id": "...", "label": "...", "status": "fail", "detail": "..." } ],
  "disclaimer": "..."
}
```

## Agent guidelines

1. Run the scan **before** any swap/approve/transfer the user requests against
   an unfamiliar address. Treat it as a gate, not an afterthought.
2. Branch on the JSON `verdict` field, not the process exit code (exit is 0 on a
   completed scan).
3. On `DANGER`, do not proceed — surface the `reasons` to the user and stop.
   On `CAUTION`, surface the warnings and ask the user to confirm.
4. If the report flags a proxy, re-run against the `implementation` address it
   reports before trusting the bytecode-based checks.
5. To prove sellability, re-run with `--holder` set to an address that actually
   holds the token (the user's own wallet, or a known holder from the explorer).
6. Never present an `INSUFFICIENT_DATA` verdict as safe.

## Composability (Phase 2)

This is the guardrail other agents call first. A trading, approval, or payment
agent wraps every write in a Safety Gate check: scan → branch on verdict →
proceed or abort. It is the read-only "is this safe?" half of an
agent's act-on-chain loop.
