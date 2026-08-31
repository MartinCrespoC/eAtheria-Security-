#!/usr/bin/env node
/**
 * free-port — make `npm run start` idempotent.
 *
 * Kills whatever is already listening on the app port (PORT, default 3000) so
 * a stale `next start` never blocks a fresh one. Dependency-free and
 * cross-platform:
 *   - Linux/macOS: `lsof` → `ss` → `fuser` (first that yields a PID wins;
 *     `ss` is netlink-based and works even where /proc scanning is restricted).
 *   - Windows:     `netstat -ano` to resolve the PID.
 *
 * All commands run via `spawnSync` with an argv array (never a shell string),
 * and the port is validated as numeric, so nothing is shell-interpretable.
 * Sends SIGTERM first (graceful), escalating to SIGKILL if the process
 * lingers. A final pure-Node bind test confirms the port is really free.
 * Always exits 0 so it chains cleanly with
 * `node scripts/free-port.mjs && next start`.
 */
import { spawnSync } from "child_process";
import net from "net";

const rawPort = String(process.env.PORT || "3000");
const log = (msg) => process.stdout.write(`[free-port] ${msg}\n`);

if (!/^\d+$/.test(rawPort)) {
  log(`invalid PORT "${rawPort}" — skipping port check`);
  process.exit(0);
}
const port = rawPort;
const isWin = process.platform === "win32";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Run a command with an argv array (no shell). Never throws. */
function run(cmd, args) {
  const res = spawnSync(cmd, args, { encoding: "utf8" });
  return {
    stdout: res.stdout || "",
    stderr: res.stderr || "",
    // res.error is set only when the command could not be spawned (e.g. ENOENT).
    missing: Boolean(res.error),
  };
}

/** Extract positive integers from arbitrary tool output. */
function parseNumbers(text) {
  return text
    .split(/\s+/)
    .map((tok) => Number(tok.replace(/[^0-9]/g, "")))
    .filter((n) => Number.isInteger(n) && n > 0);
}

/** Parse PIDs from `ss -ltnp` output (matches the local-address column). */
function pidsFromSs(stdout) {
  const pids = new Set();
  for (const line of stdout.split(/\r?\n/)) {
    const cols = line.trim().split(/\s+/);
    // `ss -ltn`: [State, Recv-Q, Send-Q, Local:Port, Peer:Port, Process]
    const local = cols[3] || "";
    if (!local.endsWith(`:${port}`)) continue;
    const m = line.match(/pid=(\d+)/);
    if (m) pids.add(Number(m[1]));
  }
  return [...pids];
}

/** Return the numeric PIDs currently LISTENING on the port. */
function pidsOnPort() {
  if (isWin) {
    const { stdout } = run("netstat", ["-ano", "-p", "TCP"]);
    const pids = new Set();
    for (const line of stdout.split(/\r?\n/)) {
      if (!line.includes("LISTENING")) continue;
      const cols = line.trim().split(/\s+/);
      if ((cols[1] || "").endsWith(`:${port}`)) {
        const pid = cols[cols.length - 1];
        if (pid && pid !== "0") pids.add(Number(pid));
      }
    }
    return [...pids];
  }

  // Unix: try several resolvers and use the first that yields a PID. An empty
  // result from one tool is NOT trusted as "free" (e.g. lsof can be blind in
  // restricted environments), so we fall through to the next.
  const lsof = run("lsof", ["-t", "-i", `tcp:${port}`, "-s", "tcp:LISTEN"]);
  if (!lsof.missing) {
    const pids = parseNumbers(lsof.stdout);
    if (pids.length > 0) return pids;
  }

  const ss = run("ss", ["-ltnp"]);
  if (!ss.missing) {
    const pids = pidsFromSs(ss.stdout);
    if (pids.length > 0) return pids;
  }

  const fuser = run("fuser", [`${port}/tcp`]);
  if (!fuser.missing) {
    const pids = parseNumbers(`${fuser.stdout} ${fuser.stderr}`);
    if (pids.length > 0) return pids;
  }

  return [];
}

function kill(pids, signal) {
  for (const pid of pids) {
    try {
      process.kill(pid, signal);
    } catch {
      /* already gone, or not ours to kill */
    }
  }
}

/** Definitive, tool-independent check: can we bind the port? */
function portInUse() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once("error", (err) => resolve(err?.code === "EADDRINUSE"));
    srv.once("listening", () => srv.close(() => resolve(false)));
    srv.listen(Number(port));
  });
}

let pids = pidsOnPort();
if (pids.length === 0) {
  // No PID found — but double-check the port is truly free before declaring it.
  if (await portInUse()) {
    log(`port ${port} is busy but no owning PID could be resolved — start may fail`);
  } else {
    log(`port ${port} is free`);
  }
} else {
  log(`port ${port} is busy (PID ${pids.join(", ")}) — stopping it`);
  kill(pids, "SIGTERM");

  // Wait up to ~3s for a graceful exit; escalate to SIGKILL after ~0.9s.
  for (let i = 0; i < 10; i++) {
    await sleep(300);
    pids = pidsOnPort();
    if (pids.length === 0 && !(await portInUse())) break;
    if (i === 2) kill(pids, "SIGKILL");
  }

  log(
    (await portInUse())
      ? `warning: port ${port} still busy — start may fail`
      : `port ${port} freed`
  );
}
