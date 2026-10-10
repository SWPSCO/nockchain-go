use nockster_core::{
    cheetah::{master_from_seed, ser_a_pt, xprv_derive_child, XKey},
    draft_sign,
};
use serde_json::json;
fn main() {
    let seeds: Vec<[u8; 64]> = vec![
        core::array::from_fn(|i| i as u8),
        [7; 64],
        [0; 64],
        [255; 64],
        core::array::from_fn(|i| (i * 3 + 19) as u8),
    ];
    let paths: Vec<Vec<u32>> = vec![
        vec![],
        vec![5],
        vec![0x80000007],
        vec![0x8000002c, 0x80000000, 0x80000000, 9000, 3],
        vec![0, 1, 2, 3, 4],
        vec![2147483647],
        vec![0x80000000, 0, 0x80000001, 2],
    ];
    let mut vectors = vec![];
    for seed in seeds {
        for path in &paths {
            let (sk, cc) = master_from_seed(&seed);
            let mut k = XKey::from_master(sk, cc);
            for i in path {
                k = xprv_derive_child(&k, *i);
            }
            let pk = k.pk.unwrap();
            let mut pub_payload = vec![];
            pub_payload.extend_from_slice(&0x0c0ebb09u32.to_be_bytes());
            pub_payload.push(1);
            pub_payload.push(k.depth);
            pub_payload.extend_from_slice(&k.parent_fingerprint);
            pub_payload.extend_from_slice(&k.index.to_be_bytes());
            pub_payload.extend_from_slice(&k.chain_code);
            pub_payload.extend_from_slice(&ser_a_pt(&pk));
            let mut prv_payload = pub_payload[..46].to_vec();
            prv_payload[..4].copy_from_slice(&0x01106331u32.to_be_bytes());
            prv_payload.push(0);
            prv_payload.extend_from_slice(&k.sk.unwrap());
            vectors.push(json!({"seed":hex::encode(seed),"path":path,"secret":hex::encode(k.sk.unwrap()),"chain":hex::encode(k.chain_code),"public":hex::encode(ser_a_pt(&pk)),"address":draft_sign::cheetah_pubkey_pkh_v1(pk).unwrap(),"lock":draft_sign::cheetah_pubkey_pkh_lock_root_v1(pk).unwrap(),"zpub":bs58::encode(pub_payload).with_check().into_string(),"zprv":bs58::encode(prv_payload).with_check().into_string()}));
        }
    }
    let mut hashes: Vec<_> = [0, 1, 2, 9, 10, 11, 20, 32, 100]
        .into_iter()
        .map(|len| {
            let words: Vec<u64> = (0..len).map(|i| i as u64 * 982451653).collect();
            let hash = tx_types::crypto::cheetah_nostd::tip5_hash_words(&words);
            json!({"words":words,"digest":hash})
        })
        .collect();
    for words in [
        vec![0; 10],
        vec![pokenoun::GOLDILOCKS_P - 1; 10],
        vec![pokenoun::GOLDILOCKS_P - 1],
        vec![0, 1, pokenoun::GOLDILOCKS_P - 1, 42],
    ] {
        let hash = tx_types::crypto::cheetah_nostd::tip5_hash_words(&words);
        hashes.push(json!({"words":words,"digest":hash}));
    }
    fn node(v: &serde_json::Value, a: &mut pokenoun::Arena) -> pokenoun::Noun {
        if let Some(n) = v.as_u64() {
            a.alloc_atom_u64(n)
        } else {
            let x = v.as_array().unwrap();
            let h = node(&x[0], a);
            let t = node(&x[1], a);
            a.alloc_cell(h, t)
        }
    }
    let nouns: Vec<_> = vec![
        json!(0),
        json!(1),
        json!(pokenoun::GOLDILOCKS_P - 1),
        json!([1, 2]),
        json!([1, [2, 3]]),
        json!([[1, 2], 3]),
        json!([[0, [1, 0]], [[2, 3], 4]]),
    ]
    .into_iter()
    .map(|v| {
        let mut a = pokenoun::Arena::new();
        let n = node(&v, &mut a);
        json!({"noun":v,"digest":pokenoun::hash_noun_varlen(n,&a).unwrap()})
    })
    .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"keys":vectors,"hashes":hashes,"nouns":nouns}))
            .unwrap()
    );
}
