#!/usr/bin/env python3
"""Regenerate public test vectors from local Rust reference checkouts."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 3:
    raise SystemExit('usage: generate.py TX_TYPES_ROOT NOCKSTER_ROOT')
tx = pathlib.Path(sys.argv[1]).resolve()
nockster = pathlib.Path(sys.argv[2]).resolve()
core = nockster / 'crates/nockster-core'
q = lambda path: json.dumps(str(path))
manifest = f'''[package]
name = "nockchain-go-reference"
version = "0.1.0"
edition = "2021"
[dependencies]
nockster-core = {{ path = {q(core)}, default-features = false, features = ["alloc-path"] }}
tx-types = {{ path = {q(tx / 'tx-types')}, default-features = false }}
pokenoun = {{ path = {q(tx / 'pokenoun')} }}
serde_json = "1"
hex = "0.4"
bs58 = {{ version = "0.5", features = ["check"] }}
[patch."https://github.com/SWPSCO/tx-types.git"]
tx-types = {{ path = {q(tx / 'tx-types')} }}
pokenoun = {{ path = {q(tx / 'pokenoun')} }}
'''
with tempfile.TemporaryDirectory(prefix='nockchain-go-reference-') as tmp:
    project = pathlib.Path(tmp)
    (project / 'src').mkdir()
    (project / 'Cargo.toml').write_text(manifest)
    shutil.copyfile(pathlib.Path(__file__).with_name('main.rs'), project / 'src/main.rs')
    output = subprocess.check_output(['cargo', 'run', '--quiet', '--release', '--manifest-path', str(project / 'Cargo.toml')])
    json.loads(output)
    pathlib.Path(__file__).parents[1].joinpath('reference.json').write_bytes(output)
