#!/usr/bin/env python3
"""Run a Codex task against the existing proxy with one inherited account key."""
import argparse
import os
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("scope", choices=["personal", "work"])
parser.add_argument("--model", required=True, help="Full scope/source/model route")
parser.add_argument("--key-dir", type=Path, required=True)
parser.add_argument("--endpoint", default="http://127.0.0.1:8317/v1")
parser.add_argument("codex_args", nargs=argparse.REMAINDER)
args = parser.parse_args()
model = args.model
if not model.startswith(args.scope + "/"):
    parser.error("model must belong to the selected account scope")
key = (args.key_dir / (args.scope + ".key")).read_text().strip()
if not key:
    parser.error("scope key is empty")
env = dict(os.environ)
env["CPA_ACCOUNT_SCOPE_KEY"] = key
# Keys are inherited through the environment, never placed in argv or output.
# A different scoped model in a descendant is still denied by the proxy.
import json
config = {
    "model_provider": "account-scope",
    "model": model,
    "model_providers.account-scope.name": "CPA " + args.scope,
    "model_providers.account-scope.base_url": args.endpoint,
    "model_providers.account-scope.wire_api": "responses",
    "model_providers.account-scope.env_key": "CPA_ACCOUNT_SCOPE_KEY",
    "agents.default_subagent_model": model,
}
command = ["codex"]
for name, value in config.items():
    command.extend(["-c", name + "=" + json.dumps(value)])
trailing = args.codex_args
if trailing[:1] == ["--"]:
    trailing = trailing[1:]
os.execvpe("codex", command + trailing, env)
