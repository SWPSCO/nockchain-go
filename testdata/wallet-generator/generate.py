#!/usr/bin/env python3
"""Extract exact based-noun payloads from the pinned official Hoon fixtures."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("tx_types", type=Path)
parser.add_argument("--output", type=Path, default=Path(__file__).parents[1] / "wallet/reference.json")
parser.add_argument("--check", action="store_true")
parser.add_argument("--protocol-corpus", type=Path,
                    help="canonicalize the JAM fields of this public protocol corpus")
args = parser.parse_args()
root = args.tx_types.resolve()
pin = "02d194605c475013745cc65b26f1413cd098932e"
if subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip() != pin:
    raise SystemExit(f"tx-types must be checked out at {pin}")
source = root / "tx-types/tests/reference"
subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=source, check=True)
with tempfile.TemporaryDirectory(prefix="nockchain-wallet-fixtures-") as temporary:
    project = Path(temporary)
    (project / "src").mkdir()
    (project / "Cargo.toml").write_text(f"""[package]
name = "nockchain-wallet-fixtures"
version = "0.1.0"
edition = "2021"
[dependencies]
tx-types = {{ path = {json.dumps(str(root / "tx-types"))}, default-features = false }}
pokenoun = {{ path = {json.dumps(str(root / "pokenoun"))} }}
serde_json = "1"
hex = "0.4"
""")
    shutil.copyfile(Path(__file__).with_name("main.rs"), project / "src/main.rs")
    command = ["cargo", "run", "--quiet", "--manifest-path", str(project / "Cargo.toml"),
               "--", str(source)]
    if args.protocol_corpus:
        command.append(str(args.protocol_corpus.resolve()))
    value = json.loads(subprocess.check_output(command))
    if args.protocol_corpus:
        corpus = json.dumps(value.pop("canonicalProtocol"), indent=2, ensure_ascii=False) + "\n"
        if args.check:
            if json.loads(corpus) != json.loads(args.protocol_corpus.read_text()):
                raise SystemExit("protocol corpus is not canonical")
        else:
            args.protocol_corpus.write_text(corpus)
    output = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    if args.check:
        if output != args.output.read_bytes():
            raise SystemExit("wallet fixture export differs")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(output)
