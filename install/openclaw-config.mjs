// What install/openclaw-linux.sh reads and changes in an OpenClaw
// configuration, through OpenClaw's own CLI (openclaw config get/set/unset):
// OpenClaw stays the only writer of its openclaw.json and validates each
// change.
//
// Run as the agent, with OpenClaw's Node, OPENCLAW set to its command. One
// mode, and its arguments:
//
//   fresh <model>   onboards OpenClaw without prompts: its model is <model>
//                   at nia-edge (provider nia), its gateway on the loopback
//   model [<model>] points an existing OpenClaw at nia-edge: provider nia,
//                   primary model nia/<model>; without <model>, the model of
//                   the current primary. Prints the model
//   paths <home>    rewrites the strings of the copied configuration that
//                   start with <home> (an OpenClaw copied from another
//                   account) to this account's home; prints the lines that
//                   still name it
//   scrub           removes the apiKey of every provider but nia: the model
//                   is nia-edge's. Prints the providers it removed it from
//   harden <image>  every tool in a rootless Podman container without
//                   network or host directory, no elevated exec, the
//                   runtime's network through nia-edge's proxy; then checks
//                   each of those settings as OpenClaw reports it
//   mcp             sends the network of every MCP server OpenClaw starts
//                   itself through nia-edge's proxy (OpenClaw gives a stdio
//                   server a few variables and its own env only). Prints the
//                   servers whose command lies outside the agent's home and
//                   the system's directories
//   host            adds nia-edge's MCP server of host actions
//   local <name>    points the MCP server <name> at the one nia-edge runs in
//                   a container (install/mcp-linux.sh)
//
// OpenClaw names an MCP tool <server>__<tool>: nia-edge's servers are named
// mcp__host and mcp__<name>, so that their tools reach the model as
// mcp__host__<action> and mcp__<name>__<tool>, the names nia-edge releases
// them under, as with Hermes. The server <name> of the agent's own
// configuration goes, its container takes its place.
//
// Exit status: 0 done, 2 bad arguments, 3 OpenClaw refused a change, 4 a
// check failed, 5 a server named mcp__host is not nia-edge's.

import { execFileSync } from "node:child_process";
import { realpathSync, accessSync, constants, readFileSync, writeFileSync, statSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, sep } from "node:path";

const OPENCLAW = process.env.OPENCLAW;
const NIA = "http://127.0.0.1:8787";
const PROXY = "http://127.0.0.1:3128";
const PROXY_ENV = {
  HTTPS_PROXY: PROXY, HTTP_PROXY: PROXY, https_proxy: PROXY, http_proxy: PROXY,
  NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost", NODE_USE_ENV_PROXY: "1",
};
const NAME = /^[a-z][a-z0-9_]{0,31}$/;
// A key OpenClaw's path syntax reads as itself.
const KEY = /^[A-Za-z0-9_-]+$/;

class Refused extends Error {}
class Failed extends Error {}

function run(args) {
  return execFileSync(OPENCLAW, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 << 20 });
}

// The value at a path, or undefined when it is unset.
function get(path) {
  let text;
  try {
    text = run(["config", "get", path, "--json"]);
  } catch (error) {
    const out = String(error.stdout || "");
    if (out.includes("is valid but unset")) return undefined;
    throw new Refused(`config get ${path}: ${out.trim() || error.message}`);
  }
  return JSON.parse(text);
}

function set(path, value) {
  try {
    run(["config", "set", path, JSON.stringify(value), "--strict-json"]);
  } catch (error) {
    throw new Refused(`config set ${path}: ${String(error.stdout || error.stderr || error.message).trim()}`);
  }
}

function unset(path) {
  try {
    run(["config", "unset", path]);
  } catch (error) {
    throw new Refused(`config unset ${path}: ${String(error.stdout || error.stderr || error.message).trim()}`);
  }
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function line(text) {
  if (/[\n\r]/.test(text)) throw new Failed("a name holds a line break");
  process.stdout.write(text + "\n");
}

function provider(model) {
  return {
    baseUrl: `${NIA}/v1`,
    api: "openai-completions",
    apiKey: "provided-by-nia-edge",
    models: [{ id: model, name: model }],
  };
}

function validModel(model) {
  return typeof model === "string" && /^[A-Za-z0-9._:@\/-]{1,200}$/.test(model);
}

function fresh(model) {
  if (!validModel(model)) return 2;
  try {
    run([
      "onboard", "--non-interactive", "--accept-risk", "--mode", "local",
      "--auth-choice", "custom-api-key", "--custom-provider-id", "nia",
      "--custom-base-url", `${NIA}/v1`, "--custom-compatibility", "openai",
      "--custom-model-id", model, "--custom-api-key", "provided-by-nia-edge",
      "--gateway-bind", "loopback", "--skip-daemon", "--skip-health",
      "--skip-channels", "--skip-search", "--skip-skills", "--skip-ui", "--skip-hooks",
    ]);
  } catch (error) {
    throw new Refused(`onboard: ${String(error.stdout || error.stderr || error.message).trim().split("\n").slice(-3).join(" ")}`);
  }
  return 0;
}

function model(chosen) {
  let name = chosen;
  if (!name) {
    const primary = get("agents.defaults.model.primary") ?? object(get("agents.defaults.model")).primary;
    const text = typeof primary === "string" ? primary : "";
    name = text.includes("/") ? text.slice(text.indexOf("/") + 1) : text;
  }
  if (!validModel(name)) throw new Failed("no model to ask nia-edge for: set OPENCLAW_MODEL");
  set("models.providers.nia", provider(name));
  set("agents.defaults.model.primary", `nia/${name}`);
  line(name);
  return 0;
}

// Before OpenClaw runs on the copy: OpenClaw refuses to move an agent's
// directory through its CLI (its credentials stay where they are named), so
// the copied file is rewritten as text, every quoted string that starts with
// the other home now starting with this one; OpenClaw then validates it.
function paths(from) {
  if (!isAbsolute(from) || from === "/" || from.endsWith("/")) return 2;
  const home = homedir();
  const file = `${home}/.openclaw/openclaw.json`;
  const text = readFileSync(file, "utf8");
  const escaped = from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const moved = text.replace(new RegExp(`(["'])${escaped}(?=[/"'])`, "g"), (_, quote) => quote + home);
  if (moved !== text) {
    const temporary = `${file}.nia`;
    writeFileSync(temporary, moved, { mode: statSync(file).mode & 0o777 });
    renameSync(temporary, file);
  }
  try {
    run(["config", "validate"]);
  } catch (error) {
    throw new Refused(`config validate: ${String(error.stdout || error.stderr || error.message).trim()}`);
  }
  // What still names the other home, inside a string: for a person to see.
  for (const [index, row] of moved.split("\n").entries()) {
    if (row.includes(from)) line(`openclaw.json line ${index + 1}`);
  }
  return 0;
}

function scrub() {
  const providers = object(get("models.providers"));
  for (const [id, entry] of Object.entries(providers)) {
    if (id === "nia" || !KEY.test(id)) continue;
    if (object(entry).apiKey === undefined) continue;
    unset(`models.providers.${id}.apiKey`);
    line(id);
  }
  return 0;
}

const SANDBOX = { mode: "all", backend: "podman", workspaceAccess: "none" };
const SYSTEM_TOOLS = ["openclaw", "gateway"];
const DOCKER = { network: "none", readOnlyRoot: true, capDrop: ["ALL"] };

// A setting that hands the sandbox something of the host.
function opening(docker) {
  const d = object(docker);
  if (Array.isArray(d.binds) && d.binds.length) return "binds";
  for (const key of Object.keys(d)) if (key.startsWith("dangerously") && d[key]) return key;
  return null;
}

function harden(image) {
  if (!image || /\s/.test(image)) return 2;
  const defaults = object(get("agents.defaults.sandbox"));
  const open = opening(defaults.docker);
  if (open) throw new Failed(`agents.defaults.sandbox.docker.${open} opens the host to the sandbox: remove it`);
  set("agents.defaults.sandbox", {
    ...defaults, ...SANDBOX, scope: defaults.scope ?? "agent",
    docker: { ...object(defaults.docker), ...DOCKER, image },
  });
  set("tools.elevated.enabled", false);
  set("tools.exec.host", "sandbox");
  // Every call under its own name: no dispatcher hides it (dispatch_action),
  // and no tool of the model changes OpenClaw's configuration (openclaw,
  // gateway): the sandbox is not the model's to turn off.
  set("tools.toolSearch", false);
  const deny = Array.isArray(get("tools.deny")) ? get("tools.deny") : [];
  set("tools.deny", [...new Set([...deny, ...SYSTEM_TOOLS])]);
  set("proxy.proxyUrl", PROXY);
  set("proxy.loopbackMode", "gateway-only");
  // An agent of its own may loosen each of these: never past the defaults.
  const entries = object(get("agents.entries"));
  for (const [id, entry] of Object.entries(entries)) {
    if (!KEY.test(id)) throw new Failed(`agent ${JSON.stringify(id)}: its name cannot be addressed`);
    const own = object(entry);
    if (own.sandbox !== undefined) {
      const sandbox = object(own.sandbox);
      const opened = opening(sandbox.docker);
      if (opened) throw new Failed(`agents.entries.${id}.sandbox.docker.${opened} opens the host to the sandbox: remove it`);
      set(`agents.entries.${id}.sandbox`, { ...sandbox, ...SANDBOX, docker: { ...object(sandbox.docker), ...DOCKER } });
    }
    const tools = object(own.tools);
    if (tools.elevated !== undefined) set(`agents.entries.${id}.tools.elevated.enabled`, false);
    if (object(tools.exec).host !== undefined) set(`agents.entries.${id}.tools.exec.host`, "sandbox");
  }
  // What OpenClaw reports, not what was asked.
  const now = object(get("agents.defaults.sandbox"));
  const docker = object(now.docker);
  const checks = [
    [now.mode === "all", "agents.defaults.sandbox.mode all"],
    [now.backend === "podman", "agents.defaults.sandbox.backend podman"],
    [now.workspaceAccess === "none", "agents.defaults.sandbox.workspaceAccess none"],
    [docker.network === "none", "agents.defaults.sandbox.docker.network none"],
    [docker.image === image, `agents.defaults.sandbox.docker.image ${image}`],
    [!opening(docker), "no bind into the sandbox"],
    [get("tools.elevated.enabled") === false, "tools.elevated.enabled false"],
    [get("tools.exec.host") === "sandbox", "tools.exec.host sandbox"],
    [get("tools.toolSearch") === false, "tools.toolSearch false"],
    [SYSTEM_TOOLS.every((tool) => (get("tools.deny") ?? []).includes(tool)), `tools.deny ${SYSTEM_TOOLS.join(", ")}`],
  ];
  for (const [id, entry] of Object.entries(object(get("agents.entries")))) {
    const sandbox = object(object(entry).sandbox);
    if (object(entry).sandbox !== undefined) {
      checks.push([sandbox.mode === "all" && sandbox.backend === "podman" && object(sandbox.docker).network === "none" && !opening(sandbox.docker), `agent ${id} sandboxed`]);
    }
    const tools = object(object(entry).tools);
    if (tools.elevated !== undefined) checks.push([object(tools.elevated).enabled === false, `agent ${id} without elevated exec`]);
  }
  for (const [ok, what] of checks) if (!ok) throw new Failed(`OpenClaw does not report ${what}`);
  return 0;
}

function mcp() {
  const servers = object(get("mcp.servers"));
  const home = realpathSync(homedir());
  for (const [name, entry] of Object.entries(servers)) {
    const server = object(entry);
    if (!server.command) continue;
    if (!KEY.test(name)) throw new Failed(`MCP server ${JSON.stringify(name)}: its name cannot be addressed`);
    for (const [key, value] of Object.entries(PROXY_ENV)) set(`mcp.servers.${name}.env.${key}`, value);
    const command = String(server.command);
    if (!isAbsolute(command)) continue;
    let real = command;
    let runnable = true;
    try {
      real = realpathSync(command);
      accessSync(real, constants.X_OK);
    } catch {
      runnable = false;
    }
    const mine = real.startsWith(home + sep);
    const system = ["/usr/", "/bin/", "/sbin/", "/opt/"].some((dir) => real.startsWith(dir));
    if (!runnable || !(mine || system)) line(`${name}=${command}`);
  }
  return 0;
}

function point(name, url) {
  const current = object(get(`mcp.servers.${name}`));
  if (Object.keys(current).length && current.url !== url) return 5;
  set(`mcp.servers.${name}`, { url, transport: "streamable-http", enabled: true });
  return 0;
}

function local(name) {
  if (!NAME.test(name) || name === "host" || name.includes("__")) return 2;
  // Its command, its variables and its token are nia-edge's now: nothing of
  // the former entry stays with the agent.
  if (get(`mcp.servers.${name}`) !== undefined) unset(`mcp.servers.${name}`);
  const own = `mcp__${name}`;
  if (get(`mcp.servers.${own}`) !== undefined) unset(`mcp.servers.${own}`);
  return point(own, `${NIA}/local/${name}/mcp`);
}

function main(argv) {
  if (!OPENCLAW || !isAbsolute(OPENCLAW)) return 2;
  const [mode, ...rest] = argv;
  switch (mode) {
    case "fresh": return rest.length === 1 ? fresh(rest[0]) : 2;
    case "model": return rest.length <= 1 ? model(rest[0]) : 2;
    case "paths": return rest.length === 1 ? paths(rest[0]) : 2;
    case "scrub": return rest.length === 0 ? scrub() : 2;
    case "harden": return rest.length === 1 ? harden(rest[0]) : 2;
    case "mcp": return rest.length === 0 ? mcp() : 2;
    case "host": return rest.length === 0 ? point("mcp__host", `${NIA}/host/mcp`) : 2;
    case "local": return rest.length === 1 ? local(rest[0]) : 2;
    default: return 2;
  }
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`openclaw-config: ${error.message}\n`);
  process.exitCode = error instanceof Refused ? 3 : error instanceof Failed ? 4 : 1;
}
