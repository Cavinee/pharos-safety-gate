#!/usr/bin/env node
// Pharos Safety Gate — read-only contract risk scanner for AI agents.
// Given a token/contract address, runs a battery of on-chain checks and
// returns a risk scorecard + verdict. Never signs, never needs a private key.
//
// Usage:
//   node scripts/safety-gate.mjs <address> [--network mainnet|atlantic-testnet]
//                                          [--format json|md|console]
//                                          [--holder 0x..]   (enables transfer sim)
//                                          [--rpc <url>]
//
// Exit code is always 0 on a completed scan (the verdict is in the output),
// and non-zero only on a usage/transport error, so agents can branch on the
// JSON `verdict` field rather than the process code.

// ─────────────────────────────────────────────────────────────────────────────
// Network registry
// ─────────────────────────────────────────────────────────────────────────────
const NETWORKS = {
  mainnet: {
    name: "Pharos Pacific Mainnet",
    chainId: 1672,
    rpc: "https://rpc.pharos.xyz",
    explorer: "https://pharosscan.xyz",
    native: "PROS",
  },
  "atlantic-testnet": {
    name: "Pharos Atlantic Testnet",
    chainId: 688689,
    rpc: "https://atlantic.dplabs-internal.com",
    explorer: "https://atlantic.pharosscan.xyz",
    native: "PHRS",
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Function selectors (hardcoded to keep this zero-dependency — no keccak needed)
// ─────────────────────────────────────────────────────────────────────────────
const SEL = {
  name: "0x06fdde03",
  symbol: "0x95d89b41",
  decimals: "0x313ce567",
  totalSupply: "0x18160ddd",
  balanceOf: "0x70a08231", // balanceOf(address)
  owner: "0x8da5cb5b", // owner()
  getOwner: "0x893d20e8", // getOwner()
  transfer: "0xa9059cbb", // transfer(address,uint256)
  paused: "0x5c975abb", // paused()
};

// Selectors we look for *inside* contract bytecode as red-flag heuristics.
// Presence is a signal, not a proof — see caveats in the output.
const CODE_FLAGS = [
  { sel: "40c10f19", label: "mint(address,uint256)", risk: "mint" },
  { sel: "a0712d68", label: "mint(uint256)", risk: "mint" },
  { sel: "449a52f8", label: "mintTo(address,uint256)", risk: "mint" },
  { sel: "fe575a87", label: "isBlacklisted(address)", risk: "blacklist" },
  { sel: "f9f92be4", label: "blacklist(address)", risk: "blacklist" },
  { sel: "1a8d7d99", label: "addToBlacklist", risk: "blacklist" },
  { sel: "e47d6060", label: "isBlackListed(address)", risk: "blacklist" },
  { sel: "8456cb59", label: "pause()", risk: "pausable" },
  { sel: "3f4ba83a", label: "unpause()", risk: "pausable" },
  { sel: "70a08231", label: "balanceOf(address)", risk: "erc20" }, // sanity marker
];

// EIP-1967 storage slots (proxy detection)
const SLOT_IMPL =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const SLOT_ADMIN =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const SLOT_BEACON =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
const DEAD_ADDR = "0x000000000000000000000000000000000000dead";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal ABI helpers
// ─────────────────────────────────────────────────────────────────────────────
// BigInt-safe JSON serializer — report.checks[].data can carry a BigInt
// totalSupply, which plain JSON.stringify cannot serialize (it throws).
const jsonReplacer = (_k, v) => (typeof v === "bigint" ? v.toString() : v);

const strip0x = (h) => (h.startsWith("0x") ? h.slice(2) : h);
const pad32 = (h) => strip0x(h).padStart(64, "0");
const encAddr = (a) => pad32(strip0x(a).toLowerCase());

function isHexAddress(a) {
  return typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
}

function decodeUint(hex) {
  const h = strip0x(hex);
  if (!h || /^0+$/.test(h)) return 0n;
  return BigInt("0x" + h);
}

function decodeAddress(hex) {
  const h = strip0x(hex);
  if (h.length < 64) return ZERO_ADDR;
  return "0x" + h.slice(24, 64);
}

function decodeBool(hex) {
  return decodeUint(hex) !== 0n;
}

// Handles both dynamic `string` returns and legacy `bytes32` (e.g. old MKR-style).
function decodeString(hex) {
  const h = strip0x(hex);
  if (!h) return "";
  // Dynamic string: [offset][length][data...]
  if (h.length >= 128) {
    try {
      const offset = Number(decodeUint("0x" + h.slice(0, 64))) * 2;
      const lenStart = offset;
      const len = Number(decodeUint("0x" + h.slice(lenStart, lenStart + 64)));
      if (len > 0 && len < 1024) {
        const dataHex = h.slice(lenStart + 64, lenStart + 64 + len * 2);
        const s = Buffer.from(dataHex, "hex").toString("utf8").replace(/\0+$/, "");
        if (s.length) return s;
      }
    } catch { /* fall through to bytes32 */ }
  }
  // bytes32 packed string
  const s = Buffer.from(h.slice(0, 64), "hex").toString("utf8").replace(/\0+$/, "");
  return s.replace(/[^\x20-\x7e]/g, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC
// ─────────────────────────────────────────────────────────────────────────────
let RPC_URL = null;
let RPC_ID = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Bound concurrent RPC calls. The Pharos RPC drops/rate-limits large parallel
// bursts (the checks fire Promise.all of many eth_call at once), which made
// scans non-deterministic — metadata would intermittently come back empty,
// flipping the verdict, and occasionally the whole scan failed. A small pool
// plus retry keeps the verdict stable.
const MAX_CONCURRENCY = 3;
let _active = 0;
const _waiters = [];
async function _acquire() {
  if (_active < MAX_CONCURRENCY) { _active++; return; }
  await new Promise((res) => _waiters.push(res)); // slot handed to us by _release
}
function _release() {
  const next = _waiters.shift();
  if (next) next();       // hand the slot to the next waiter (active unchanged)
  else _active--;         // no waiter — free the slot
}

// JSON-RPC with retry-with-backoff on TRANSPORT errors (fetch reject, 429, 5xx).
// Legitimate JSON-RPC errors (e.g. a revert) are surfaced immediately, never
// retried — they are real answers, and tryCall() treats them as "not ok".
async function rpc(method, params) {
  await _acquire();
  try {
    const MAX_ATTEMPTS = 4;
    let lastErr;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      if (attempt) await sleep(120 * attempt);
      let res;
      try {
        res = await fetch(RPC_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: ++RPC_ID, method, params }),
        });
      } catch (err) {
        lastErr = err; // network drop — retry
        continue;
      }
      if (!res.ok) {
        if (res.status === 429 || res.status >= 500) {
          lastErr = new Error(`RPC HTTP ${res.status} for ${method}`);
          continue; // transient — retry
        }
        throw new Error(`RPC HTTP ${res.status} for ${method}`);
      }
      const json = await res.json();
      if (json.error) {
        const e = new Error(json.error.message || "RPC error");
        e.rpcError = json.error;
        throw e; // real RPC error — do not retry
      }
      return json.result;
    }
    throw lastErr || new Error(`RPC failed after ${MAX_ATTEMPTS} attempts for ${method}`);
  } finally {
    _release();
  }
}

async function ethCall(to, data, overrides) {
  const callObj = { to, data };
  const params = overrides
    ? [callObj, "latest", overrides]
    : [callObj, "latest"];
  return rpc("eth_call", params);
}

// Safe call: returns {ok, value|reason}. Never throws on a revert.
async function tryCall(to, data, overrides) {
  try {
    const value = await ethCall(to, data, overrides);
    return { ok: true, value };
  } catch (err) {
    return { ok: false, reason: err.rpcError?.message || err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checks. Each returns { id, label, status, detail }.
//   status ∈ pass | warn | fail | unknown | info
// ─────────────────────────────────────────────────────────────────────────────
async function checkIsContract(addr, ctx) {
  const code = await rpc("eth_getCode", [addr, "latest"]);
  ctx.code = code;
  const empty = !code || code === "0x" || code === "0x0";
  if (empty) {
    return {
      id: "is_contract",
      label: "Address has contract code",
      status: "fail",
      detail:
        "No bytecode at this address — it is an externally owned account (EOA), not a token/contract. Do not treat it as a token.",
    };
  }
  return {
    id: "is_contract",
    label: "Address has contract code",
    status: "pass",
    detail: `Contract bytecode present (${(code.length - 2) / 2} bytes).`,
  };
}

async function checkErc20Metadata(addr, ctx) {
  const [n, s, d, ts] = await Promise.all([
    tryCall(addr, SEL.name),
    tryCall(addr, SEL.symbol),
    tryCall(addr, SEL.decimals),
    tryCall(addr, SEL.totalSupply),
  ]);
  const name = n.ok ? decodeString(n.value) : null;
  const symbol = s.ok ? decodeString(s.value) : null;
  const decimals = d.ok ? Number(decodeUint(d.value)) : null;
  const totalSupply = ts.ok ? decodeUint(ts.value) : null;
  ctx.meta = { name, symbol, decimals, totalSupply };

  const looksErc20 = s.ok && d.ok && ts.ok;
  if (!looksErc20) {
    return {
      id: "erc20_shape",
      label: "Behaves like a standard ERC-20",
      status: "warn",
      detail:
        "One or more core ERC-20 views (symbol/decimals/totalSupply) did not return. This may not be a standard token; interact with caution.",
      data: ctx.meta,
    };
  }
  return {
    id: "erc20_shape",
    label: "Behaves like a standard ERC-20",
    status: "pass",
    detail: `name=${name ?? "?"} symbol=${symbol ?? "?"} decimals=${decimals} totalSupply=${totalSupply}`,
    data: ctx.meta,
  };
}

async function checkProxy(addr, ctx) {
  const [impl, admin, beacon] = await Promise.all([
    rpc("eth_getStorageAt", [addr, SLOT_IMPL, "latest"]),
    rpc("eth_getStorageAt", [addr, SLOT_ADMIN, "latest"]),
    rpc("eth_getStorageAt", [addr, SLOT_BEACON, "latest"]),
  ]);
  const implAddr = decodeAddress(impl);
  const beaconAddr = decodeAddress(beacon);
  const isProxy =
    implAddr !== ZERO_ADDR || beaconAddr !== ZERO_ADDR;
  ctx.proxy = isProxy;
  ctx.implementation = implAddr !== ZERO_ADDR ? implAddr : null;

  if (isProxy) {
    return {
      id: "upgradeable",
      label: "Not an upgradeable proxy",
      status: "warn",
      detail:
        `Upgradeable proxy detected (EIP-1967). Implementation = ${ctx.implementation ?? beaconAddr}. ` +
        `The contract's logic can be changed after you interact — re-run this scan against the implementation address, ` +
        `and trust it only as much as you trust whoever controls the admin.`,
      data: { implementation: ctx.implementation, beacon: beaconAddr === ZERO_ADDR ? null : beaconAddr },
    };
  }
  return {
    id: "upgradeable",
    label: "Not an upgradeable proxy",
    status: "pass",
    detail: "No EIP-1967 proxy slots set — logic appears immutable at this address.",
  };
}

async function checkOwnership(addr, ctx) {
  let res = await tryCall(addr, SEL.owner);
  if (!res.ok) res = await tryCall(addr, SEL.getOwner);
  if (!res.ok) {
    return {
      id: "ownership",
      label: "Ownership renounced or absent",
      status: "info",
      detail:
        "No standard owner()/getOwner() function. Privilege is not exposed via the common interface — check the source for custom admin roles.",
    };
  }
  const owner = decodeAddress(res.value);
  ctx.owner = owner;
  const renounced = owner === ZERO_ADDR || owner === DEAD_ADDR;
  if (renounced) {
    return {
      id: "ownership",
      label: "Ownership renounced or absent",
      status: "pass",
      detail: `Owner is the zero/dead address — ownership is renounced. No single key holds owner privileges.`,
    };
  }
  return {
    id: "ownership",
    label: "Ownership renounced or absent",
    status: "warn",
    detail:
      `Owner is ${owner} — ownership is NOT renounced. This address may hold privileged powers ` +
      `(depending on the contract: minting, pausing, fee changes, blacklisting).`,
    data: { owner },
  };
}

function scanBytecode(ctx) {
  const code = (ctx.code || "").toLowerCase();
  const found = { mint: [], blacklist: [], pausable: [], erc20: false };
  for (const f of CODE_FLAGS) {
    if (code.includes(f.sel)) {
      if (f.risk === "erc20") found.erc20 = true;
      else found[f.risk]?.push(f.label);
    }
  }
  ctx.codeFlags = found;

  const results = [];
  const proxyNote = ctx.proxy
    ? " NOTE: this is a proxy, so the real logic lives in the implementation — this bytecode scan is inconclusive here; re-scan the implementation address."
    : "";

  // mint
  if (found.mint.length) {
    results.push({
      id: "mint",
      label: "No mint function exposed",
      status: ctx.proxy ? "unknown" : "warn",
      detail:
        `Mint-like selector(s) present: ${found.mint.join(", ")}. The supply can potentially be inflated, ` +
        `diluting holders.${proxyNote}`,
      data: { selectors: found.mint },
    });
  } else if (ctx.proxy) {
    results.push({
      id: "mint",
      label: "No mint function exposed",
      status: "unknown",
      detail: "Could not inspect for mint functions on a proxy — re-scan the implementation address.",
    });
  } else {
    results.push({
      id: "mint",
      label: "No mint function exposed",
      status: "pass",
      detail: "No common mint selector found in bytecode.",
    });
  }

  // blacklist
  if (found.blacklist.length) {
    results.push({
      id: "blacklist",
      label: "No blacklist/freeze hooks",
      status: ctx.proxy ? "unknown" : "fail",
      detail:
        `Blacklist/freeze selector(s) present: ${found.blacklist.join(", ")}. Your address could be blocked from ` +
        `transferring after you buy in — a common rug/honeypot mechanism.${proxyNote}`,
      data: { selectors: found.blacklist },
    });
  } else if (!ctx.proxy) {
    results.push({
      id: "blacklist",
      label: "No blacklist/freeze hooks",
      status: "pass",
      detail: "No common blacklist selector found in bytecode.",
    });
  } else {
    results.push({
      id: "blacklist",
      label: "No blacklist/freeze hooks",
      status: "unknown",
      detail: "Could not inspect for blacklist hooks on a proxy — re-scan the implementation address.",
    });
  }

  // pausable
  if (found.pausable.length) {
    results.push({
      id: "pausable",
      label: "Transfers not pausable by owner",
      status: "warn",
      detail:
        `Pause selector(s) present: ${found.pausable.join(", ")}. An admin may be able to halt all transfers.${proxyNote}`,
      data: { selectors: found.pausable },
    });
  }
  return results;
}

async function checkPaused(addr, ctx) {
  const res = await tryCall(addr, SEL.paused);
  if (!res.ok) return null; // no paused() — handled by bytecode scan
  const paused = decodeBool(res.value);
  if (paused) {
    return {
      id: "paused_now",
      label: "Transfers are currently active",
      status: "fail",
      detail: "paused() returns true — transfers are HALTED right now. Any interaction will revert.",
    };
  }
  return {
    id: "paused_now",
    label: "Transfers are currently active",
    status: "pass",
    detail: "paused() returns false — transfers are currently enabled.",
  };
}

// Best-effort transfer simulation. Requires a --holder that actually owns the
// token so we can simulate a real transfer via eth_call (no funds move). If no
// holder is supplied, we return UNKNOWN rather than guessing — honest by design.
async function checkTransferSim(addr, ctx, holder) {
  if (!holder) {
    return {
      id: "honeypot_sim",
      label: "Token is sellable (not a honeypot)",
      status: "unknown",
      detail:
        "Not simulated. Pass --holder <address that owns this token> to let the scanner simulate a real transfer " +
        "via eth_call and detect transfer reverts or hidden fees. Without a funded holder, sellability cannot be proven, " +
        "and full buy/sell honeypot detection additionally needs a known DEX router on this network.",
    };
  }
  if (!isHexAddress(holder)) {
    return {
      id: "honeypot_sim",
      label: "Token is sellable (not a honeypot)",
      status: "unknown",
      detail: `--holder ${holder} is not a valid address; skipping transfer simulation.`,
    };
  }

  // Confirm the holder has a balance to move.
  const balRes = await tryCall(addr, SEL.balanceOf + encAddr(holder));
  if (!balRes.ok) {
    return {
      id: "honeypot_sim",
      label: "Token is sellable (not a honeypot)",
      status: "unknown",
      detail: "Could not read balanceOf for the holder; skipping transfer simulation.",
    };
  }
  const bal = decodeUint(balRes.value);
  if (bal === 0n) {
    return {
      id: "honeypot_sim",
      label: "Token is sellable (not a honeypot)",
      status: "unknown",
      detail: `Holder ${holder} owns 0 of this token — supply a holder with a non-zero balance to simulate a transfer.`,
    };
  }

  // Simulate transfer(DEAD, balance/2) FROM the holder via eth_call `from`.
  const amount = bal / 2n > 0n ? bal / 2n : bal;
  const data =
    SEL.transfer + encAddr(DEAD_ADDR) + pad32(amount.toString(16));
  let sim;
  try {
    const out = await rpc("eth_call", [
      { from: holder, to: addr, data },
      "latest",
    ]);
    sim = { ok: true, out };
  } catch (err) {
    sim = { ok: false, reason: err.rpcError?.message || err.message };
  }

  if (!sim.ok) {
    return {
      id: "honeypot_sim",
      label: "Token is sellable (not a honeypot)",
      status: "fail",
      detail:
        `Simulated transfer from a real holder REVERTED (${sim.reason}). This is a strong honeypot signal — ` +
        `holders may be unable to move/sell the token.`,
    };
  }

  // transfer() returns bool on most tokens; if it returned false, also a red flag.
  if (/^0x0*$/.test(sim.out) && sim.out !== "0x") {
    return {
      id: "honeypot_sim",
      label: "Token is sellable (not a honeypot)",
      status: "warn",
      detail: "Simulated transfer returned false (did not throw) — transfer may silently fail. Investigate before trusting.",
    };
  }
  return {
    id: "honeypot_sim",
    label: "Token is sellable (not a honeypot)",
    status: "pass",
    detail:
      "A real holder's transfer simulates successfully. (This proves transferability, not the absence of a sell tax on a DEX " +
      "or LP-removal risk — configure a router/LP locker to extend coverage.)",
  };
}

function lpLockInfo() {
  return {
    id: "lp_lock",
    label: "Liquidity is locked",
    status: "unknown",
    detail:
      "Not checked. LP-lock verification needs the LP token address and the locker/timelock contract for this market, " +
      "which vary per DEX and are not yet wired in. This scanner will not pretend liquidity is locked when it cannot prove it.",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring → verdict
// ─────────────────────────────────────────────────────────────────────────────
function scoreVerdict(checks) {
  // Severity weights per failing/warning check id.
  const FAIL_W = {
    is_contract: 100,
    honeypot_sim: 100,
    blacklist: 70,
    paused_now: 60,
    erc20_shape: 25,
  };
  const WARN_W = {
    blacklist: 35,
    mint: 30,
    upgradeable: 20,
    ownership: 20,
    pausable: 20,
    erc20_shape: 15,
    honeypot_sim: 25,
  };
  let risk = 0;
  let unknowns = 0;
  const reasons = [];
  for (const c of checks) {
    if (c.status === "fail") {
      risk += FAIL_W[c.id] ?? 40;
      reasons.push(`FAIL: ${c.label}`);
    } else if (c.status === "warn") {
      risk += WARN_W[c.id] ?? 15;
      reasons.push(`WARN: ${c.label}`);
    } else if (c.status === "unknown") {
      unknowns += 1;
    }
  }
  risk = Math.min(100, risk);

  let verdict;
  if (checks.some((c) => c.id === "is_contract" && c.status === "fail")) {
    verdict = "DANGER";
  } else if (risk >= 70) verdict = "DANGER";
  else if (risk >= 25) verdict = "CAUTION";
  else verdict = "SAFE";

  // Honesty overlay: if too much is unknown, never claim SAFE outright.
  const coverage = checks.length ? 1 - unknowns / checks.length : 0;
  let confidence = "high";
  if (unknowns >= 3 || coverage < 0.6) confidence = "low";
  else if (unknowns >= 1) confidence = "medium";
  if (verdict === "SAFE" && confidence === "low") verdict = "INSUFFICIENT_DATA";

  return { verdict, riskScore: risk, confidence, unknowns, reasons };
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration
// ─────────────────────────────────────────────────────────────────────────────
async function runScan(addr, net, holder) {
  const ctx = {};
  const checks = [];

  const contractCheck = await checkIsContract(addr, ctx);
  checks.push(contractCheck);
  if (contractCheck.status === "fail") {
    // No code → stop; the rest is meaningless.
    return { ctx, checks };
  }

  checks.push(await checkErc20Metadata(addr, ctx));
  checks.push(await checkProxy(addr, ctx)); // sets ctx.proxy before bytecode scan
  checks.push(await checkOwnership(addr, ctx));
  for (const r of scanBytecode(ctx)) checks.push(r);
  const pausedNow = await checkPaused(addr, ctx);
  if (pausedNow) checks.push(pausedNow);
  checks.push(await checkTransferSim(addr, ctx, holder));
  checks.push(lpLockInfo());

  return { ctx, checks };
}

// ─────────────────────────────────────────────────────────────────────────────
// Output formatting
// ─────────────────────────────────────────────────────────────────────────────
const ICON = { pass: "✅", warn: "⚠️", fail: "❌", unknown: "❔", info: "ℹ️" };

function buildReport(addr, net, ctx, checks) {
  const v = scoreVerdict(checks);
  return {
    skill: "pharos-safety-gate",
    network: net.name,
    chainId: net.chainId,
    address: addr,
    explorer: `${net.explorer}/address/${addr}`,
    token: ctx.meta
      ? { name: ctx.meta.name, symbol: ctx.meta.symbol, decimals: ctx.meta.decimals }
      : null,
    verdict: v.verdict,
    riskScore: v.riskScore,
    confidence: v.confidence,
    reasons: v.reasons,
    checks: checks.map(({ id, label, status, detail, data }) => ({
      id, label, status, detail, ...(data ? { data } : {}),
    })),
    disclaimer:
      "Read-only heuristic scan. UNKNOWN checks are not failures — they are things this tool will not assert without proof. " +
      "Not financial advice; always do your own review for high-value interactions.",
    scannedAt: new Date().toISOString(),
  };
}

function renderConsole(r) {
  const L = [];
  L.push(`\nPharos Safety Gate — ${r.network} (chain ${r.chainId})`);
  L.push(`Address: ${r.address}`);
  if (r.token?.symbol) L.push(`Token:   ${r.token.name ?? "?"} (${r.token.symbol}), ${r.token.decimals} decimals`);
  L.push("");
  L.push(`VERDICT: ${r.verdict}   risk ${r.riskScore}/100   confidence ${r.confidence}`);
  L.push("");
  for (const c of r.checks) {
    L.push(`${ICON[c.status] || " "} ${c.label}`);
    L.push(`    ${c.detail}`);
  }
  L.push("");
  L.push(`Explorer: ${r.explorer}`);
  L.push(r.disclaimer);
  L.push("");
  return L.join("\n");
}

function renderMarkdown(r) {
  const L = [];
  L.push(`# Pharos Safety Gate report`);
  L.push("");
  L.push(`**Verdict:** ${r.verdict} · **Risk:** ${r.riskScore}/100 · **Confidence:** ${r.confidence}`);
  L.push("");
  L.push(`- **Network:** ${r.network} (chain ${r.chainId})`);
  L.push(`- **Address:** \`${r.address}\``);
  if (r.token?.symbol) L.push(`- **Token:** ${r.token.name ?? "?"} (\`${r.token.symbol}\`), ${r.token.decimals} decimals`);
  L.push(`- **Explorer:** ${r.explorer}`);
  L.push("");
  L.push(`## Checks`);
  L.push("");
  L.push(`| | Check | Status | Detail |`);
  L.push(`|---|---|---|---|`);
  for (const c of r.checks) {
    L.push(`| ${ICON[c.status] || ""} | ${c.label} | ${c.status} | ${c.detail.replace(/\n/g, " ")} |`);
  }
  L.push("");
  L.push(`> ${r.disclaimer}`);
  L.push("");
  return L.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const a = { network: "mainnet", format: "console", holder: null, rpc: null, address: null };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === "--network") a.network = argv[++i];
    else if (t === "--format") a.format = argv[++i];
    else if (t === "--holder") a.holder = argv[++i];
    else if (t === "--rpc") a.rpc = argv[++i];
    else if (t === "-h" || t === "--help") a.help = true;
    else rest.push(t);
  }
  a.address = rest[0] || null;
  return a;
}

const HELP = `
Pharos Safety Gate — read-only contract risk scanner

Usage:
  node scripts/safety-gate.mjs <address> [options]

Options:
  --network <net>   mainnet | atlantic-testnet   (default: mainnet)
  --format <fmt>    json | md | console          (default: console)
  --holder <addr>   an address that owns the token; enables transfer simulation
  --rpc <url>       override the RPC endpoint
  -h, --help        show this help

The verdict is in the output (SAFE / CAUTION / DANGER / INSUFFICIENT_DATA),
not the exit code, so agents can branch on the JSON 'verdict' field.
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.address) {
    console.log(HELP);
    process.exit(args.help ? 0 : 1);
  }
  if (!isHexAddress(args.address)) {
    console.error(`Error: '${args.address}' is not a valid 0x address.`);
    process.exit(1);
  }
  const net = NETWORKS[args.network];
  if (!net) {
    console.error(`Error: unknown network '${args.network}'. Use mainnet or atlantic-testnet.`);
    process.exit(1);
  }
  RPC_URL = args.rpc || net.rpc;

  let scan;
  try {
    scan = await runScan(args.address.toLowerCase(), net, args.holder);
  } catch (err) {
    if (args.format === "json") {
      console.log(JSON.stringify({ skill: "pharos-safety-gate", error: err.message, address: args.address }, jsonReplacer, 2));
    } else {
      console.error(`Transport error talking to ${RPC_URL}: ${err.message}`);
    }
    process.exit(2);
  }

  const report = buildReport(args.address.toLowerCase(), net, scan.ctx, scan.checks);
  if (args.format === "json") console.log(JSON.stringify(report, jsonReplacer, 2));
  else if (args.format === "md") console.log(renderMarkdown(report));
  else console.log(renderConsole(report));
}

main();
