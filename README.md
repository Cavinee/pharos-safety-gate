# Pharos Safety Gate

> **Should your agent touch `0x…`?** A read-only scan that catches the contract
> red flags an autonomous agent can't see — *before* it swaps, approves, or
> transfers. One address in, one verdict out.

```
$ node scripts/safety-gate.mjs 0xTokenAddress --network mainnet
VERDICT: DANGER   risk 100/100   confidence medium
```

## Why it matters

Thousands of tokens launch on every chain, and most traps are invisible on a
price chart. A token can be a honeypot (buyable, not sellable), carry a hidden
transfer tax, expose a `mint()` that dilutes you, freeze your address with a
blacklist hook, or hide behind an upgradeable proxy that changes the rules after
you're in. Reading the contract to catch these takes Solidity fluency most
traders — and every autonomous agent — don't have.

The Safety Gate turns that review into a single call any human or agent can run
before interacting. It's the **vet-someone-else's-contract** counterpart to a
symbol-collision check (which protects your *own* launch).

## What it checks

- **Is it even a contract?** (EOA vs contract code)
- **Standard ERC-20 shape** — name / symbol / decimals / totalSupply
- **Upgradeable proxy** — EIP-1967 implementation / admin / beacon slots
- **Ownership renounced** — `owner()` / `getOwner()` is zero or dead
- **Mint functions** — bytecode selector scan (supply can be inflated)
- **Blacklist / freeze hooks** — bytecode selector scan (your address can be blocked)
- **Pause switch** — present, and whether transfers are halted *right now*
- **Honeypot / transfer tax** — real transfer simulation via `eth_call` (with `--holder`)
- **Liquidity locked** — reported as unknown unless an LP + locker is configured

Each check returns `pass` / `warn` / `fail` / `unknown` / `info`, and the tool
rolls them into a weighted **risk score** and a **verdict**:
`SAFE` · `CAUTION` · `DANGER` · `INSUFFICIENT_DATA`.

## Honest by design

This is the part that makes it trustworthy: **the scanner never claims a clean
bill of health it can't back up.**

- Checks it can't prove return `unknown`, never a false `pass`.
- A proxy makes the bytecode scan inconclusive (the logic lives in the
  implementation) — so it says so and tells you to re-scan the implementation.
- Sellability and transfer-tax need a funded holder (`--holder`); full buy/sell
  honeypot detection additionally needs a known DEX router on the network.
- When too much is unknown, the verdict downgrades to `INSUFFICIENT_DATA`
  instead of `SAFE`.

Pharos DeFi is still young, so this matters: the tool reports what it can verify
on-chain and refuses to invent the rest.

## Install

```bash
git clone https://github.com/Cavinee/pharos-safety-gate.git
cd pharos-safety-gate
node scripts/safety-gate.mjs --help   # zero dependencies, Node 18+
```

## Use

```bash
# Full scan (human readable)
node scripts/safety-gate.mjs 0xToken --network mainnet

# JSON for an AI agent to consume
node scripts/safety-gate.mjs 0xToken --format json

# Prove sellability with a real holder (no funds move — eth_call only)
node scripts/safety-gate.mjs 0xToken --holder 0xHolderThatOwnsIt

# Markdown report
node scripts/safety-gate.mjs 0xToken --format md

# Atlantic testnet
node scripts/safety-gate.mjs 0xToken --network atlantic-testnet
```

See [`examples/example-output.md`](examples/example-output.md) for a full run.

## In an AI agent

Drop `SKILL.md` into your agent's skills directory and ask:

```
> is 0xToken safe to swap on Pharos?
```

The agent runs `safety-gate.mjs --format json`, branches on the `verdict`
field, and refuses to proceed on `DANGER`.

## How it works

Pure JSON-RPC against Pharos (`eth_getCode`, `eth_call`, `eth_getStorageAt`).
Function selectors are hardcoded so there's no keccak/ABI dependency. The
transfer simulation uses `eth_call` with a real holder as `from`, so it observes
whether a transfer would revert or skim a fee **without moving any tokens**.

## Networks

| Network | Chain ID | Native | RPC |
|---------|----------|--------|-----|
| Pharos Pacific Mainnet | 1672 | PROS | `https://rpc.pharos.xyz` |
| Pharos Atlantic Testnet | 688689 | PHRS | `https://atlantic.dplabs-internal.com` |

## Roadmap

- DEX-router buy/sell round-trip simulation for full honeypot proof (per-network router registry)
- LP-lock verification against known locker/timelock contracts
- Auto-resolve a top holder from `Transfer` logs so `--holder` is optional
- Cache implementation re-scan for proxies in one pass

## Safety

Read-only. Public RPC only. No private keys, no wallet connection, no signing,
no transactions. Not financial advice.

## License

MIT
