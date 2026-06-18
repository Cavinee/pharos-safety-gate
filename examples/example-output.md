# Example: scanning a risky token

Command:

```bash
node scripts/safety-gate.mjs 0x1111111111111111111111111111111111111111 --network mainnet
```

Output (console format):

```
Pharos Safety Gate — Pharos Pacific Mainnet (chain 1672)
Address: 0x1111111111111111111111111111111111111111
Token:   Rug Token (RUG), 18 decimals

VERDICT: DANGER   risk 100/100   confidence medium

✅ Address has contract code
    Contract bytecode present.
✅ Behaves like a standard ERC-20
    name=Rug Token symbol=RUG decimals=18 totalSupply=1000000000000000000000000
✅ Not an upgradeable proxy
    No EIP-1967 proxy slots set — logic appears immutable at this address.
⚠️ Ownership renounced or absent
    Owner is 0x...c0ffee01 — ownership is NOT renounced. This address may hold
    privileged powers (minting, pausing, fee changes, blacklisting).
⚠️ No mint function exposed
    Mint-like selector(s) present: mint(address,uint256). Supply can be inflated.
❌ No blacklist/freeze hooks
    Blacklist/freeze selector(s) present: isBlacklisted(address). Your address
    could be blocked from transferring after you buy in.
✅ Transfers are currently active
    paused() returns false — transfers are currently enabled.
❔ Token is sellable (not a honeypot)
    Not simulated. Pass --holder <address that owns this token> to simulate a
    real transfer and detect reverts/hidden fees.
❔ Liquidity is locked
    Not checked. Needs the LP token + locker contract for this market.

Explorer: https://pharosscan.xyz/address/0x1111111111111111111111111111111111111111
```

Note how the dangerous mechanisms (blacklist hook, mint, owner not renounced)
drive a `DANGER` verdict, while the things the tool cannot prove on-chain
(sellability, LP lock) are honestly reported as `unknown` — not silently passed.

To prove sellability, re-run with a real holder:

```bash
node scripts/safety-gate.mjs 0xToken --holder 0xYourWalletThatHoldsIt
```
