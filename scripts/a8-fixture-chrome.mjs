#!/usr/bin/env node
// Native measurement launcher. Browser initialization precedes the measured
// typed navigation; it never changes profile data or fixture expectations.
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const chrome = process.env.A8_FIXTURE_CHROME;
if (!chrome) throw new Error("A8_FIXTURE_CHROME is required");
const args = process.argv.slice(2);
const environment = Object.fromEntries(
  Object.entries(process.env).filter(
    ([key]) => key.toUpperCase() !== "SSLKEYLOGFILE",
  ),
);
if (args.includes("--version") || args.includes("--dump-dom")) {
  const result = spawnSync(chrome, args, {
    stdio: "inherit",
    env: environment,
  });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}
const scenario = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "a8-fixture-scenario.json"),
    "utf8",
  ),
);
const url = args.at(-1);
const flags = args.slice(0, -1);
const userData = flags
  .find((value) => value.startsWith("--user-data-dir="))
  ?.slice("--user-data-dir=".length);
if (!userData || !url)
  throw new Error("owned user-data-dir and target URL required");
if (!process.env.A8_FIXTURE_EVIDENCE)
  throw new Error("private A8_FIXTURE_EVIDENCE directory required");
const directory = join(
  process.env.A8_FIXTURE_EVIDENCE,
  basename(userData) + "-" + randomUUID(),
);
mkdirSync(directory, { recursive: true, mode: 0o700 });
const portFile = join(userData, "DevToolsActivePort");
rmSync(portFile, { force: true });
const actualFlags = [
  ...flags,
  "--remote-debugging-port=0",
  "--no-startup-window",
  `--log-net-log=${join(directory, "netlog.json")}`,
];
const child = spawn(chrome, actualFlags, {
  stdio: ["ignore", "pipe", "pipe"],
  env: environment,
});
for (const stream of [child.stdout, child.stderr])
  stream.on("data", (data) =>
    appendFileSync(join(directory, "browser.log"), data),
  );
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const started = Date.now();
let socket;
let sequence = 0;
const pending = new Map();
try {
  while (!existsSync(portFile)) {
    if (
      child.exitCode !== null ||
      Date.now() - started > scenario.startup_limit_ms
    )
      throw new Error("browser startup failed");
    await sleep(25);
  }
  const [port, path] = readFileSync(portFile, "utf8").split("\n");
  socket = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = reject;
  });
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject, timer } = pending.get(message.id);
      pending.delete(message.id);
      clearTimeout(timer);
      if (message.error) reject(new Error(JSON.stringify(message.error)));
      else resolve(message.result);
    } else if (message.method?.startsWith("Network.")) {
      appendFileSync(
        join(directory, "events.jsonl"),
        JSON.stringify({ time: Date.now(), ...message }) + "\n",
      );
    }
  };
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("CDP timeout: " + method));
      }, scenario.command_timeout_ms);
      pending.set(id, { resolve, reject, timer });
      socket.send(
        JSON.stringify({
          id,
          method,
          params,
          ...(sessionId ? { sessionId } : {}),
        }),
      );
    });
  const version = await send("Browser.getVersion");
  const { targetId } = await send("Target.createTarget", {
    url: "about:blank",
    background: true,
  });
  const { sessionId } = await send("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  await send("Page.enable", {}, sessionId);
  await send("Network.enable", {}, sessionId);
  appendFileSync(
    join(directory, "launch.jsonl"),
    JSON.stringify({ started, version, flags: actualFlags, url, scenario }) +
      "\n",
  );
  await sleep(scenario.startup_quiet_ms);
  const navigation = await send(
    "Page.navigate",
    { url, transitionType: "typed" },
    sessionId,
  );
  appendFileSync(
    join(directory, "launch.jsonl"),
    JSON.stringify({ navigated: Date.now(), navigation }) + "\n",
  );
  await new Promise((resolve) => child.on("exit", resolve));
} finally {
  if (socket) socket.close();
  for (const { reject, timer } of pending.values()) {
    clearTimeout(timer);
    reject(new Error("observer closed"));
  }
  if (child.exitCode === null) child.kill("SIGKILL");
}
