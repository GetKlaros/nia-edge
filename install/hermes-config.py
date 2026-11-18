"""What install/hermes-linux.sh reads and changes in a Hermes configuration,
with Hermes' own code.

Run as the agent, with Hermes' Python, -I, and HERMES_HOME set. One argument:

  describe  prints provider=, api_mode=, base_url=, static= and has_key=
            lines; never the key
  key       prints the key alone, when it is one written in the agent's .env
            or config.yaml (not an OAuth token Hermes renews itself)
  scrub     removes that key from the agent's .env and config.yaml, and fails
            if it is still there
  mcp       sends the network of every MCP server Hermes starts itself
            through nia-edge's proxy: Hermes gives such a server only a few
            variables and its own env, so the agent's proxy does not reach it.
            Prints, one per line, the servers whose command lies outside the
            agent's home and the system's directories
  host      adds nia-edge's MCP server of host actions, as "host": its
            tools reach the model as mcp__host__<action>, also on the
            platforms whose saved toolsets list MCP servers

Hermes' imports may write to stdout: everything but the answer goes to stderr.
"""

import os
import sys

out = sys.stdout
sys.stdout = sys.stderr


PROXY = "http://127.0.0.1:3128"
# Node reads the proxy variables only when told to (NODE_USE_ENV_PROXY).
PROXY_ENV = {
    "HTTPS_PROXY": PROXY, "HTTP_PROXY": PROXY, "https_proxy": PROXY, "http_proxy": PROXY,
    "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost", "NODE_USE_ENV_PROXY": "1",
}


def mcp() -> int:
    from hermes_cli.config import read_raw_config, save_config

    config = read_raw_config()
    servers = config.get("mcp_servers")
    if not isinstance(servers, dict) or not servers:
        return 0
    agent_home = os.path.realpath(os.path.expanduser("~"))
    elsewhere = []
    for name, server in servers.items():
        if not isinstance(server, dict) or not server.get("command"):
            continue
        env = server.get("env") if isinstance(server.get("env"), dict) else {}
        env.update(PROXY_ENV)
        server["env"] = env
        command = str(server["command"])
        if os.path.isabs(command):
            real = os.path.realpath(command)
            mine = real.startswith(agent_home + os.sep)
            system = real.startswith(("/usr/", "/bin/", "/sbin/", "/opt/"))
            if not (mine or system) or not os.access(real, os.X_OK):
                elsewhere.append(f"{name}={command}")
    save_config(config)
    for line in elsewhere:
        if "\n" in line:
            return 2
        out.write(line + "\n")
    return 0


HOST = {"url": "http://127.0.0.1:8787/host/mcp", "enabled": True}


def host() -> int:
    from hermes_cli.config import read_raw_config, save_config

    config = read_raw_config()
    servers = config.get("mcp_servers")
    if not isinstance(servers, dict):
        servers = {}
    current = servers.get("host")
    # Another server of that name would take the host actions' tool names.
    if isinstance(current, dict) and current.get("url") != HOST["url"]:
        return 5
    servers["host"] = dict(HOST)
    config["mcp_servers"] = servers
    # A platform whose saved toolsets name MCP servers loads those servers
    # only (Hermes' _merge_mcp_servers): host joins every such list. An
    # empty list, or one with no_mcp, stays the user's choice of none.
    known = {str(name) for name in servers if name != "host"}
    platforms = config.get("platform_toolsets")
    if isinstance(platforms, dict):
        for names in platforms.values():
            if not isinstance(names, list) or "no_mcp" in names:
                continue
            listed = {str(n)[4:] if str(n).startswith("mcp-") else str(n) for n in names}
            if listed & known and not {"host", "mcp-host"} & {str(n) for n in names}:
                names.append("host")
    save_config(config)
    return 0


def main(mode: str) -> int:
    if mode == "mcp":
        return mcp()
    if mode == "host":
        return host()
    home = os.environ["HERMES_HOME"]
    from hermes_cli.env_loader import load_hermes_dotenv
    from hermes_cli.runtime_provider import resolve_runtime_provider

    load_hermes_dotenv(hermes_home=home, load_external_secrets=False)
    runtime = resolve_runtime_provider()
    key = str(runtime.get("api_key") or "")
    files = [os.path.join(home, ".env"), os.path.join(home, "config.yaml")]

    def read(path: str) -> str:
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read()
        except FileNotFoundError:
            return ""

    # A key Hermes renews (OAuth) lives elsewhere: it cannot be handed over.
    static = len(key) >= 8 and any(key in read(path) for path in files)

    if mode == "describe":
        for name, value in (
            ("provider", runtime.get("provider")),
            ("api_mode", runtime.get("api_mode")),
            ("base_url", str(runtime.get("base_url") or "").rstrip("/")),
            ("static", "1" if static else "0"),
            ("has_key", "1" if key else "0"),
        ):
            text = str(value or "")
            if "\n" in text or "'" in text:
                return 2
            out.write(f"{name}={text}\n")
        return 0
    if not static:
        return 3
    if mode == "key":
        out.write(key + "\n")
        return 0
    if mode == "scrub":
        for path in files:
            text = read(path)
            if key not in text:
                continue
            if path.endswith(".env"):
                kept = []
                for line in text.splitlines(keepends=True):
                    value = line.split("=", 1)[1].strip().strip("'\"") if "=" in line else ""
                    if key in line and value == key:
                        continue
                    kept.append(line)
                text = "".join(kept)
            text = text.replace(key, "")
            temporary = path + ".nia"
            with open(temporary, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.chmod(temporary, os.stat(path).st_mode & 0o777)
            os.replace(temporary, path)
        return 0 if all(key not in read(path) for path in files) else 4
    return 2


sys.exit(main(sys.argv[1] if len(sys.argv) == 2 else ""))
