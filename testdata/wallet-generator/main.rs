use pokenoun::codec::{Decode, Fields};
use pokenoun::{Arena, Noun};
use serde_json::{json, Value};
use std::{env, fs, path::Path};
use tx_types::Hash;

fn fields(noun: Noun, arena: &Arena, count: usize) -> Vec<Noun> {
    let mut fields = Fields::new(noun, count);
    (0..count).map(|_| fields.next(arena).unwrap()).collect()
}
fn list(noun: Noun, arena: &Arena) -> Vec<Noun> {
    let mut out = Vec::new();
    let mut noun = noun;
    while let Noun::Cell(id) = noun {
        let cell = arena.cell(id);
        out.push(cell.head);
        noun = cell.tail;
    }
    assert_eq!(u64::decode(noun, arena).unwrap(), 0);
    out
}
fn jam(noun: Noun, arena: &Arena) -> String {
    hex::encode(pokenoun::jam(noun, arena))
}
fn hash(noun: Noun, arena: &Arena) -> Value {
    json!(Hash::decode(noun, arena)
        .unwrap()
        .values
        .map(|v| v.to_string()))
}
fn text(noun: Noun, arena: &Arena) -> String {
    String::decode(noun, arena).unwrap()
}
fn number(noun: Noun, arena: &Arena) -> String {
    u64::decode(noun, arena).unwrap().to_string()
}
fn load(path: &Path) -> (Noun, Arena) {
    let bytes = fs::read(path).unwrap();
    let mut arena = Arena::new();
    let noun = pokenoun::cue(&bytes, &mut arena).unwrap();
    assert_eq!(
        pokenoun::jam(noun, &arena),
        bytes[..bytes.iter().rposition(|v| *v != 0).unwrap() + 1]
    );
    (noun, arena)
}
fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Object(values) => {
            for (key, value) in values {
                if (key == "jam" || key.ends_with("Jam")) && value.is_string() {
                    let mut arena = Arena::new();
                    let noun =
                        pokenoun::cue(&hex::decode(value.as_str().unwrap()).unwrap(), &mut arena)
                            .unwrap();
                    *value = json!(jam(noun, &arena));
                } else {
                    canonicalize(value);
                }
            }
        }
        _ => {}
    }
}
fn encoded(value: &impl pokenoun::codec::Encode) -> String {
    hex::encode(value.to_jam().unwrap())
}
fn digest_json(value: &Hash) -> Value {
    json!(value.values.map(|v| v.to_string()))
}
fn output_json(output: &tx_types::planner::PlannedOutput) -> Value {
    json!({"root":digest_json(&output.lock_root),"data":encoded(&output.note_data),"amount":output.amount.to_string()})
}
fn planner_vectors() -> Vec<Value> {
    use tx_types::lock::{Lock, LockV2};
    use tx_types::lock_resolver::{simple_pkh, SigningKeyLockMatcher};
    use tx_types::planner::*;
    use tx_types::{Coins, NName, NNote, NNoteV1, NoteData, PageNumber, RawTransactionV1};
    let pkh = Hash {
        values: [7, 8, 9, 10, 11],
    };
    let recipient = Hash {
        values: [17, 18, 19, 20, 21],
    };
    let plain = Lock::SpendCondition(simple_pkh(pkh.clone()));
    let tree = Lock::V2(LockV2 {
        p: simple_pkh(recipient.clone()),
        q: simple_pkh(pkh.clone()),
    });
    let matcher = SigningKeyLockMatcher {
        signer_pkh: pkh.clone(),
        public_key: None,
        coinbase_relative_min: Some(100),
    };
    let mut rows = Vec::new();
    for (case, height, order, manual, sweep, exact, lock) in [
        (
            "before-activation",
            53999,
            SelectionOrder::Descending,
            false,
            false,
            None,
            plain.clone(),
        ),
        (
            "at-activation",
            54000,
            SelectionOrder::Descending,
            false,
            false,
            None,
            plain.clone(),
        ),
        (
            "ascending-ties",
            170000,
            SelectionOrder::Ascending,
            false,
            false,
            None,
            plain.clone(),
        ),
        (
            "manual",
            170000,
            SelectionOrder::Descending,
            true,
            false,
            None,
            plain.clone(),
        ),
        (
            "sweep",
            170000,
            SelectionOrder::Ascending,
            false,
            true,
            None,
            plain.clone(),
        ),
        (
            "exact-fee",
            170000,
            SelectionOrder::Descending,
            false,
            false,
            Some(100),
            plain.clone(),
        ),
        (
            "tree-refund",
            170000,
            SelectionOrder::Descending,
            false,
            false,
            None,
            tree,
        ),
    ] {
        let mut data = NoteData::from_lock(lock.clone()).unwrap();
        data.map.put(
            "memo".into(),
            tx_types::UntypedNoun::from_value(&42u64).unwrap(),
        );
        let notes: Vec<_> = [(2000000, 1), (4000000, 2), (4000000, 3)]
            .into_iter()
            .map(|(amount, last)| {
                NNote::V1(NNoteV1 {
                    version: 1,
                    origin_page: PageNumber { value: 100 },
                    name: NName {
                        p: vec![
                            NName::first_v1(lock.hash()),
                            Hash {
                                values: [last, 2, 3, 4, 5],
                            },
                        ],
                    },
                    note_data: data.clone(),
                    assets: Coins { value: amount },
                })
            })
            .collect();
        let outputs = if sweep {
            vec![]
        } else {
            vec![PlannedOutput::payment(recipient.clone(), 1000000, false).unwrap()]
        };
        let refund = PlannedOutput {
            lock_root: lock.hash(),
            note_data: NoteData::from_lock(lock.clone()).unwrap(),
            amount: 0,
        };
        let destination = PlannedOutput::payment(recipient.clone(), 0, false).unwrap();
        let selection = if manual {
            SelectionMode::Manual(vec![
                match &notes[0] {
                    NNote::V1(n) => n.name.clone(),
                    _ => unreachable!(),
                },
                match &notes[2] {
                    NNote::V1(n) => n.name.clone(),
                    _ => unreachable!(),
                },
            ])
        } else {
            SelectionMode::Auto
        };
        let selection_json = match &selection {
            SelectionMode::Auto => Value::Null,
            SelectionMode::Manual(names) => {
                json!(names.iter().map(|n| encoded(n)).collect::<Vec<_>>())
            }
        };
        let result = plan(
            PlanRequest {
                candidates: &notes,
                outputs: &outputs,
                refund: &refund,
                selection,
                order,
                version: CandidateVersionPolicy::V1Only,
                mode: if sweep {
                    PlanningMode::Sweep {
                        destination: destination.clone(),
                    }
                } else {
                    PlanningMode::Standard
                },
                fee: exact.map(FeePolicy::Exact).unwrap_or(FeePolicy::Minimum),
                chain: ChainContext::at_height(height),
            },
            &matcher,
        )
        .unwrap();
        let id = tx_types::compute_tx_id_v1(&result.spends).unwrap();
        let raw = RawTransactionV1 {
            version: 1,
            id: id.clone(),
            spends: result.spends.clone(),
        };
        rows.push(json!({"case":case,"version":1,"signer":digest_json(&pkh),"height":height.to_string(),"order":if order==SelectionOrder::Ascending{"ascending"}else{"descending"},"selection":selection_json,"sweep":if sweep{output_json(&destination)}else{Value::Null},"exactFee":exact.map(|n|n.to_string()),"candidates":notes.iter().map(|n|encoded(n)).collect::<Vec<_>>(),"outputs":outputs.iter().map(output_json).collect::<Vec<_>>(),"refund":output_json(&refund),"selected":result.selected.iter().map(|n|encoded(n)).collect::<Vec<_>>(),"selectedTotal":result.selected_total.to_string(),"refunds":result.refunds.iter().map(|(name,amount)|json!({"name":encoded(name),"amount":amount.to_string()})).collect::<Vec<_>>(),"emitted":result.outputs.iter().map(output_json).collect::<Vec<_>>(),"fee":result.final_fee.to_string(),"minimumFee":result.minimum_fee.to_string(),"seedWords":result.word_counts.seed_words.to_string(),"witnessWords":result.word_counts.witness_words.to_string(),"jam":encoded(&raw),"id":digest_json(&id)}));
    }
    rows
}

fn migration_vectors() -> Vec<Value> {
    use tx_types::crypto::cheetah_nostd::{
        cheetah_pub_from_sk, master_from_seed, schnorr_sign_digest, ser_a_pt,
    };
    use tx_types::lock_resolver::SigningKeyLockMatcher;
    use tx_types::planner::*;
    use tx_types::*;
    let seed: Vec<u8> = (0..64).collect();
    let (secret, _) = master_from_seed(&seed);
    let point = cheetah_pub_from_sk(secret);
    let key = SchnorrPubkey {
        x: F6LT { values: point.0 },
        y: F6LT { values: point.1 },
        inf: false,
    };
    let lock = tx_types::Lock {
        m: 1,
        pubkeys: ZSet::gas(vec![key.clone()]),
    };
    let matcher = SigningKeyLockMatcher {
        signer_pkh: key.to_hash(),
        public_key: Some(key.clone()),
        coinbase_relative_min: None,
    };
    let recipient = Hash {
        values: [17, 18, 19, 20, 21],
    };
    let mut rows = Vec::new();
    for (case, height, timed, sweep) in [
        ("migration-before", 53999, false, false),
        ("migration-at", 54000, false, false),
        ("migration-timelock", 170000, true, false),
        ("migration-sweep", 170000, false, true),
    ] {
        let notes: Vec<_> = [(3000000, 1), (4000000, 2)]
            .into_iter()
            .map(|(amount, last)| {
                NNote::V0(NNoteV0 {
                    meta: NNoteHead {
                        version: 0,
                        origin_page: PageNumber { value: 100 },
                        timelock: Timelock {
                            intent: if timed {
                                Some((
                                    TimelockRange {
                                        min: None,
                                        max: None,
                                    },
                                    TimelockRange {
                                        min: Some(PageNumber { value: 100 }),
                                        max: None,
                                    },
                                ))
                            } else {
                                None
                            },
                        },
                    },
                    name: NName {
                        p: vec![
                            NName::first_v0(lock.clone(), timed),
                            Hash {
                                values: [last, 2, 3, 4, 5],
                            },
                        ],
                    },
                    lock: lock.clone(),
                    source: Source {
                        p: Hash {
                            values: [99, 8, 7, 6, 5],
                        },
                        is_coinbase: timed,
                    },
                    assets: Coins { value: amount },
                })
            })
            .collect();
        let outputs = if sweep {
            vec![]
        } else {
            vec![PlannedOutput::payment(recipient.clone(), 1000000, false).unwrap()]
        };
        let refund = PlannedOutput::payment(key.to_hash(), 0, false).unwrap();
        let destination = PlannedOutput::payment(recipient.clone(), 0, true).unwrap();
        let result = plan(
            PlanRequest {
                candidates: &notes,
                outputs: &outputs,
                refund: &refund,
                selection: SelectionMode::Auto,
                order: SelectionOrder::Descending,
                version: CandidateVersionPolicy::V0Only,
                mode: if sweep {
                    PlanningMode::Sweep {
                        destination: destination.clone(),
                    }
                } else {
                    PlanningMode::Standard
                },
                fee: FeePolicy::Minimum,
                chain: ChainContext::at_height(height),
            },
            &matcher,
        )
        .unwrap();
        let id = compute_tx_id_v1(&result.spends).unwrap();
        let raw = RawTransactionV1 {
            version: 1,
            id,
            spends: result.spends.clone(),
        };
        let mut signed = ZMap::new();
        let mut sig_hashes = Vec::new();
        for (name, mut spend) in result.spends.map.tap() {
            let SpendBody::V0ToV1(body) = &mut spend.body else {
                panic!("migration spend")
            };
            let hash = body.compute_sig_hash().unwrap();
            let (chal, sig) = schnorr_sign_digest(secret, point, hash.values);
            body.signature.put(
                key.clone(),
                SchnorrSignature {
                    chal: Chal {
                        values: T8 {
                            values: chal.values,
                        },
                    },
                    sig: Sig {
                        values: T8 { values: sig.values },
                    },
                },
            );
            sig_hashes.push(json!({"name":encoded(&name),"hash":digest_json(&hash)}));
            signed.put(name, spend);
        }
        let signed = SpendsV1 { map: signed };
        let signed = RawTransactionV1 {
            version: 1,
            id: compute_tx_id_v1(&signed).unwrap(),
            spends: signed,
        };
        rows.push(json!({"case":case,"version":0,"seed":hex::encode(&seed),"public":hex::encode(ser_a_pt(&point)),"signer":digest_json(&key.to_hash()),"height":height.to_string(),"candidates":notes.iter().map(|n|encoded(n)).collect::<Vec<_>>(),"parents":notes.iter().map(|n|digest_json(&n.to_hash().unwrap())).collect::<Vec<_>>(),"outputs":outputs.iter().map(output_json).collect::<Vec<_>>(),"refund":output_json(&refund),"sweep":if sweep{output_json(&destination)}else{Value::Null},"selected":result.selected.iter().map(|n|encoded(n)).collect::<Vec<_>>(),"fee":result.final_fee.to_string(),"minimumFee":result.minimum_fee.to_string(),"seedWords":result.word_counts.seed_words.to_string(),"witnessWords":result.word_counts.witness_words.to_string(),"jam":encoded(&raw),"signedJam":encoded(&signed),"signatureHashes":sig_hashes}));
    }
    rows
}

fn main() {
    let directory = env::args().nth(1).expect("reference directory");
    let directory = Path::new(&directory);
    let (noun, arena) = load(&directory.join("lock-proofs.jam"));
    let locks: Vec<_> = list(noun, &arena)
        .into_iter()
        .map(|row| {
            let f = fields(row, &arena, 3);
            let proofs: Vec<_> = list(f[2], &arena)
                .into_iter()
                .map(|row| {
                    let p = fields(row, &arena, 7);
                    json!({
                        "index": u64::decode(p[0], &arena).unwrap(),
                        "stub": jam(p[1], &arena), "full": jam(p[2], &arena),
                        "stubHash": hash(p[3], &arena), "fullHash": hash(p[4], &arena),
                        "stubValid": bool::decode(p[5], &arena).unwrap(),
                        "fullValid": bool::decode(p[6], &arena).unwrap()
                    })
                })
                .collect();
            json!({"form":jam(f[0], &arena), "root":hash(f[1], &arena), "proofs":proofs})
        })
        .collect();
    let (noun, arena) = load(&directory.join("note-data-oracle.jam"));
    let note_data: Vec<_> = list(noun, &arena)
        .into_iter()
        .map(|row| {
            let f = fields(row, &arena, 4);
            json!({"case":text(f[0], &arena), "data":jam(f[1], &arena),
               "hash":hash(f[2], &arena), "words":number(f[3], &arena)})
        })
        .collect();
    let (noun, arena) = load(&directory.join("fee-oracle.jam"));
    let fees: Vec<_> = list(noun, &arena)
        .into_iter()
        .map(|row| {
            let f = fields(row, &arena, 9);
            json!({"case":text(f[0], &arena), "spends":jam(f[1], &arena),
            "height":number(f[2], &arena), "base":number(f[3], &arena),
            "divisor":number(f[4], &arena), "minimum":number(f[5], &arena),
            "seedWords":number(f[6], &arena), "witnessWords":number(f[7], &arena),
            "fee":number(f[8], &arena)})
        })
        .collect();
    let (noun, arena) = load(&directory.join("withdrawal-transactions.jam"));
    let withdrawals: Vec<_> = list(noun, &arena)
        .into_iter()
        .map(|row| {
            let f = fields(row, &arena, 6);
            let transaction = fields(f[1], &arena, 5);
            json!({"case":text(f[0], &arena), "spends":jam(transaction[2], &arena),
            "height":number(f[2], &arena), "fee":number(f[3], &arena),
            "seedWords":number(f[4], &arena), "witnessWords":number(f[5], &arena)})
        })
        .collect();
    let raw: Vec<_> = ["raw-tx-v0.jam", "raw-tx-v1.jam", "spend1-sig-hash.jam"]
        .into_iter()
        .map(|name| {
            let (noun, arena) = load(&directory.join(name));
            json!({"name":name, "jam":jam(noun, &arena)})
        })
        .collect();
    let mut output = json!({
        "reference":"9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902",
        "core":"02d194605c475013745cc65b26f1413cd098932e",
        "plans":planner_vectors(), "migrations":migration_vectors(),
        "locks":locks, "noteData":note_data, "fees":fees, "withdrawals":withdrawals, "raw":raw
    });
    if let Some(path) = env::args().nth(2) {
        let mut corpus: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        canonicalize(&mut corpus);
        corpus["jamEncoder"] = json!("tx-types 02d194605c475013745cc65b26f1413cd098932e");
        output["canonicalProtocol"] = corpus;
    }
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
