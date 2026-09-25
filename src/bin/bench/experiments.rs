use super::{Result, Runner};
use ark_bls12_381::Fr;
use lrdas_artifact::{
    domain::{Domain, Scheme},
    fixture,
    kzg::{Opening, PublicSrs},
    protocol::{self, Header, MessagePolys},
    recovery,
    variants::{LongSrs, ProfileBHeader, VerifiedGroup},
};
use rand::Rng;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn check(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(lrdas_artifact::Error(message.into()))
    }
}
struct Query {
    group: usize,
    index: usize,
    raw: Vec<u8>,
}
fn queries(
    d: &Domain,
    srs: &PublicSrs,
    locals: &[Vec<Fr>],
    scheme: Scheme,
    count: usize,
    seed: u64,
) -> Result<Vec<Query>> {
    let mut rng = fixture::rng(seed, "tradeoff-query-positions");
    (0..count)
        .map(|_| {
            let flat = rng.gen_range(0..d.params().n());
            let group = flat / d.params().m();
            let index = flat % d.params().m();
            Ok(Query {
                group,
                index,
                raw: srs
                    .open(&locals[group], &[d.point(scheme, group, index)?])?
                    .to_bytes(d.params().r())?,
            })
        })
        .collect()
}
fn check_queries(
    d: &Domain,
    srs: &PublicSrs,
    queries: &[Query],
    cache: &mut [Option<VerifiedGroup>],
    mut derive: impl FnMut(usize) -> Result<VerifiedGroup>,
) -> Result<()> {
    for q in queries {
        if cache[q.group].is_none() {
            cache[q.group] = Some(derive(q.group)?);
        }
        let opening = Opening::from_bytes(&q.raw, 1, d.params().r())?;
        cache[q.group]
            .as_ref()
            .unwrap()
            .verify(d, srs, q.index, &opening)?;
    }
    Ok(())
}
fn dedicated(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    scheme: Scheme,
    message: &[Fr],
    locals: &[Vec<Fr>],
    meta: &mut Vec<Value>,
) -> Result<()> {
    let name = if scheme == Scheme::Lrdas {
        "lrdas_a"
    } else {
        "product_a"
    };
    let p = d.params();
    let header = MessagePolys::new(d, message)?.commit(d, srs, scheme)?;
    let raw = header.payload()?;
    let context = header.context();
    let qs = queries(
        d,
        srs,
        locals,
        scheme,
        p.queries(scheme, 128)?,
        r.config.seed,
    )?;
    let touched: BTreeSet<_> = qs.iter().map(|q| q.group).collect();
    r.bench(
        name,
        "variant_header_commit",
        p.a(),
        "public_srs",
        true,
        || MessagePolys::new(d, message)?.commit(d, srs, scheme),
    )?;
    r.bench(
        name,
        "variant_light_client",
        qs.len(),
        "cold",
        false,
        || {
            let h = Header::from_payload(d, srs, scheme, context, &raw)?.verify(d, srs)?;
            check_queries(d, srs, &qs, &mut vec![None; p.ell()], |j| {
                VerifiedGroup::dedicated(d, srs, &h, j)
            })
        },
    )?;
    meta.push(json!({"variant":name,"queries":qs.len(),
        "touched_groups":touched.len(),"commitment_bytes":raw.len(),
        "g1_srs_bytes":p.r()*48}));
    Ok(())
}

fn profile_b(
    r: &mut Runner,
    d: &Domain,
    srs: &LongSrs,
    scheme: Scheme,
    message: &[Fr],
    locals: &[Vec<Fr>],
    meta: &mut Vec<Value>,
) -> Result<()> {
    let name = if scheme == Scheme::Lrdas {
        "lrdas_b"
    } else {
        "product_b"
    };
    let p = d.params();
    let header = ProfileBHeader::commit(d, srs, scheme, message)?;
    let raw = header.payload()?;
    let context = header.context();
    let mut rng = fixture::rng(r.config.seed, &format!("verifier-challenges-{name}"));
    let qs = queries(
        d,
        srs.local(),
        locals,
        scheme,
        p.queries(scheme, 128)?,
        r.config.seed,
    )?;
    let touched: BTreeSet<_> = qs.iter().map(|q| q.group).collect();
    r.bench(
        name,
        "variant_header_commit",
        p.a(),
        "public_srs",
        true,
        || ProfileBHeader::commit(d, srs, scheme, message),
    )?;
    r.bench(
        name,
        "variant_light_client",
        qs.len(),
        "cold",
        false,
        || {
            let h = ProfileBHeader::from_payload(d, srs, scheme, context, &raw)?
                .verify(d, srs, &mut rng)?;
            check_queries(d, srs.local(), &qs, &mut vec![None; p.ell()], |j| {
                h.group(d, j)
            })
        },
    )?;
    meta.push(json!({"variant":name,"queries":qs.len(),
        "touched_groups":touched.len(),"commitment_bytes":raw.len(),
        "g1_srs_bytes":(srs.degree()+1)*48}));
    Ok(())
}

fn diagonal(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    scheme: Scheme,
    message: &[Fr],
    meta: &mut Vec<Value>,
) -> Result<()> {
    let p = d.params();
    let name = if scheme == Scheme::Lrdas {
        "lrdas_a"
    } else {
        "product_a"
    };
    let enc = protocol::encode(d, srs, scheme, message)?;
    let header = enc.header.clone().verify(d, srs)?;
    let received = recovery::surviving_values(d, &enc.values)?;
    let (groups, rows) = recovery::pattern_counts(p)?;
    check(
        groups.iter().all(|n| *n == p.r() - 1)
            && rows.iter().all(|n| *n >= p.a())
            && received.len() > p.degree(),
        "Proposition 7 premises",
    )?;
    let decode = || {
        if scheme == Scheme::Lrdas {
            recovery::recover_global(d, &received)
        } else {
            recovery::recover_product_rows(d, &received)
        }
    };
    let checked = decode()?;
    checked.authenticate(d, srs, &header)?;
    check(
        checked.message() == message && checked.values() == enc.values,
        "full decoder fixture mismatch",
    )?;
    r.bench(
        name,
        "diagonal_full_decode",
        received.len(),
        "accepted_values",
        true,
        &decode,
    )?;
    meta.push(json!({"reconstruction_scheme":name,
        "erased_per_group":p.m()-p.r()+1,"survivors":received.len(),
        "survivors_per_group":groups[0],"minimum_row_survivors":rows.iter().min(),
        "outputs":["message","codeword","local_polynomials"],
        "input_verification_excluded":true}));
    Ok(())
}

pub(super) fn run(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    meta: &mut Vec<Value>,
    table: u8,
) -> Result<()> {
    let p = d.params();
    let message = fixture::message(p, r.config.seed);
    if table == 2 {
        let locals = MessagePolys::new(d, &message)?.locals(d)?;
        eprintln!("Preparing Profile B SRS (outside timing)...");
        let long = fixture::long_setup(p, 9001)?;
        let order = if r.process_run_id.is_multiple_of(2) {
            [0, 1, 2, 3]
        } else {
            [3, 2, 1, 0]
        };
        for variant in order {
            match variant {
                0 => dedicated(r, d, srs, Scheme::Lrdas, &message, &locals, meta)?,
                1 => profile_b(r, d, &long, Scheme::Lrdas, &message, &locals, meta)?,
                2 => dedicated(r, d, srs, Scheme::Product, &message, &locals, meta)?,
                _ => profile_b(r, d, &long, Scheme::Product, &message, &locals, meta)?,
            }
        }
        return Ok(());
    }
    let schemes = if r.process_run_id.is_multiple_of(2) {
        [Scheme::Lrdas, Scheme::Product]
    } else {
        [Scheme::Product, Scheme::Lrdas]
    };
    for scheme in schemes {
        diagonal(r, d, srs, scheme, &message, meta)?;
    }
    Ok(())
}
