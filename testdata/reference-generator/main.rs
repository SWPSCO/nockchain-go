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
    let mut signatures = vec![];
    for seed in seeds {
        for path in &paths {
            let (sk, cc) = master_from_seed(&seed);
            let mut k = XKey::from_master(sk, cc);
            for i in path {
                k = xprv_derive_child(&k, *i);
            }
            let pk = k.pk.unwrap();
            for message in [[0u64; 5], [1, 2, 3, 4, 5], [pokenoun::GOLDILOCKS_P - 1; 5]] {
                let (c, r) = tx_types::crypto::cheetah_nostd::schnorr_sign_digest(
                    k.sk.unwrap(),
                    pk,
                    message,
                );
                signatures.push(json!({"seed":hex::encode(seed),"path":path,"message":message,"challenge":c.values,"response":r.values}));
            }
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
        json!({"noun":v,"digest":pokenoun::hash_noun_varlen(n,&a).unwrap(),"jam":hex::encode(pokenoun::jam(n,&a))})
    })
    .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"keys":vectors,"hashes":hashes,"nouns":nouns,"signatures":signatures,"transactions":transaction_vectors()}))
            .unwrap()
    );
}

fn tuple(a: &mut pokenoun::Arena, ns: &[pokenoun::Noun]) -> pokenoun::Noun {
    let mut t = *ns.last().unwrap();
    for n in ns[..ns.len() - 1].iter().rev() {
        t = a.alloc_cell(*n, t);
    }
    t
}
fn digest(a: &mut pokenoun::Arena, d: [u64; 5]) -> pokenoun::Noun {
    let ns: Vec<_> = d.into_iter().map(|n| a.alloc_atom_u64(n)).collect();
    tuple(a, &ns)
}
fn hc(x: [u64; 5], y: [u64; 5]) -> [u64; 5] {
    pokenoun::hash_ten_cell(x, y).unwrap()
}
fn ha(n: u64) -> [u64; 5] {
    let mut a = pokenoun::Arena::new();
    let n = a.alloc_atom_u64(n);
    pokenoun::hash_noun_varlen(n, &a).unwrap()
}
fn lock(p: [u64; 5]) -> [u64; 5] {
    hc(hc(ha(0x686b70), hc(ha(1), hc(p, hc(ha(0), ha(0))))), ha(0))
}
fn condition(a: &mut pokenoun::Arena, p: [u64; 5]) -> pokenoun::Noun {
    let nil = a.atom0();
    let pn = digest(a, p);
    let set = pokenoun::canonical_zset_put(a, nil, pn).unwrap();
    let tag = a.alloc_atom_u64(0x686b70);
    let one = a.alloc_atom_u64(1);
    let prim = tuple(a, &[tag, one, set]);
    a.alloc_cell(prim, nil)
}
fn transaction_vectors() -> Vec<serde_json::Value> {
    use nockster_core::draft_sign::{
        draft_review_v1, rewrite_txid_v1, sign_draft_v1, SignerConfig,
    };
    let seed: [u8; 64] = core::array::from_fn(|i| i as u8);
    let (sk, cc) = master_from_seed(&seed);
    let key = XKey::from_master(sk, cc);
    let pk = key.pk.unwrap();
    let mut pa = pokenoun::Arena::new();
    let coords: Vec<_> =
        pk.0.into_iter()
            .chain(pk.1)
            .map(|n| pa.alloc_atom_u64(n))
            .collect();
    let x = tuple(&mut pa, &coords[..6]);
    let y = tuple(&mut pa, &coords[6..]);
    let one = pa.alloc_atom_u64(1);
    let pn = tuple(&mut pa, &[x, y, one]);
    let pkh = pokenoun::hash_noun_varlen(pn, &pa).unwrap();
    let ownlock = lock(pkh);
    let recipients = [
        pkh,
        tx_types::crypto::cheetah_nostd::tip5_hash_words(&[77]),
        tx_types::crypto::cheetah_nostd::tip5_hash_words(&[88]),
    ];
    let cases: Vec<Vec<Vec<(usize, u64)>>> = vec![
        vec![vec![(1, 2_000_000)]],
        vec![vec![(1, 2_000_000), (0, 3_000_000)]],
        vec![
            vec![(1, 2_000_000), (0, 3_000_000)],
            vec![(1, 4_000_000), (0, 5_000_000)],
        ],
        vec![
            vec![(2, 2_000_000), (1, 3_000_000)],
            vec![(0, 4_000_000)],
            vec![(1, 5_000_000), (2, 6_000_000)],
        ],
    ];
    cases.into_iter().enumerate().map(|(ci,inputs)| {
        let mut a=pokenoun::Arena::new();let nil=a.atom0();let one=a.alloc_atom_u64(1);let mut spends=nil;let mut plans=vec![];
        for (i,outputs) in inputs.into_iter().enumerate() {
            let first=tx_types::crypto::cheetah_nostd::tip5_hash_words(&[ci as u64,i as u64,1]);let last=tx_types::crypto::cheetah_nostd::tip5_hash_words(&[ci as u64,i as u64,2]);
            let parent=hc(first,hc(last,ha(0)));let f=digest(&mut a,first);let l=digest(&mut a,last);let name=tuple(&mut a,&[f,l,nil]);
            let mut seeds=nil;let mut outjson=vec![];let fee=1_000_000;let mut value=fee;
            for (r,gift) in outputs {
                let p=recipients[r];let cond=condition(&mut a,p);let data=a.alloc_cell(nil,cond);let tag=a.alloc_atom_u64(0x6b636f6c);let metadata=pokenoun::canonical_zmap_put(&mut a,nil,tag,data).unwrap();
                let root=digest(&mut a,lock(p));let g=a.alloc_atom_u64(gift);let par=digest(&mut a,parent);let s=tuple(&mut a,&[nil,root,metadata,g,par]);seeds=pokenoun::canonical_zset_put(&mut a,seeds,s).unwrap();
                value+=gift;outjson.push(json!({"recipient":p,"nicks":gift}));
            }
            let tag=a.alloc_atom_u64(0x6c6c7566);let cond=condition(&mut a,pkh);let root=digest(&mut a,ownlock);let proof=a.alloc_cell(root,nil);let full=tuple(&mut a,&[tag,cond,one,proof]);let witness=tuple(&mut a,&[full,nil,nil,nil]);let fee_n=a.alloc_atom_u64(fee);let spend=tuple(&mut a,&[one,witness,seeds,fee_n]);spends=pokenoun::canonical_zmap_put(&mut a,spends,name,spend).unwrap();
            plans.push(json!({"name":{"first":first,"last":last},"value":value,"lockRoot":ownlock,"outputs":outjson,"fee":fee}));
        }
        let zero=digest(&mut a,[0;5]);let raw=tuple(&mut a,&[one,zero,spends]);let draft=pokenoun::jam(raw,&a);let cfg=SignerConfig{sk_be:sk};let signed=sign_draft_v1(&draft,&cfg).unwrap();
        let txid=rewrite_txid_v1(&signed).unwrap();assert!(txid.rewritten.is_none());let review=draft_review_v1(&signed,&cfg).unwrap();
        json!({"seed":hex::encode(seed),"plans":plans,"jam":hex::encode(signed),"id":txid.name,"minimumFee":review.minimum_fee,"fee":review.fee_total,"externalTotal":review.external_total,"change":review.refund_total})
    }).collect()
}
