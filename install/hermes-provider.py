"""The model provider a Hermes agent uses, read by Hermes' own code.

Run by install/hermes-linux.sh as the agent, with Hermes' Python, -I, and
HERMES_HOME set. One argument:

  describe  prints provider=, api_mode=, base_url=, static= and has_key=
            lines; never the key
  key       prints the key alone, when it is one written in the agent's .env
            or config.yaml (not an OAuth token Hermes renews itself)
  scrub     removes that key from the agent's .env and config.yaml, and fails
            if it is still there

Hermes' imports may write to stdout: everything but the answer goes to stderr.
"""

import os
import sys

out = sys.stdout
sys.stdout = sys.stderr


def main(mode: str) -> int:
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
