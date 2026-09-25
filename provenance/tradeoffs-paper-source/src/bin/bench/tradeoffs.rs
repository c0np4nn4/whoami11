//! Three controlled comparisons: setup profiles, supplied commitments and repair.
use super::{Result, Runner};
use ark_bls12_381::Fr;
use ark_poly::EvaluationDomain;
use lrdas_artifact::{
    domain::{Domain, Scheme},
    fixture,
    kzg::{Opening, PublicSrs},
    protocol::{self, Header, MessagePolys},
    recovery,
    variants::{supplied_aux, LongSrs, ProfileBHeader, SuppliedAux, SuppliedHeader, VerifiedGroup},
};
use rand::Rng;
use serde_json::{json, Value};
use std::{collections::BTreeSet, hint::black_box, time::Instant};

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
fn sample_count(r: &Runner, scheme: Scheme) -> Result<usize> {
    if r.config.params == lrdas_artifact::domain::Params::reference() {
        r.config.params.queries(scheme, 128)
    } else {
        Ok(8)
    }
}
fn make_values(d: &Domain, locals: &[Vec<Fr>], scheme: Scheme) -> Result<Vec<Vec<Fr>>> {
    locals
        .iter()
        .enumerate()
        .map(|(j, p)| d.evaluate(scheme, j, p))
        .collect()
}
type EncodedB = (ProfileBHeader, Vec<Vec<Fr>>, Vec<Vec<Fr>>);
fn encode_b(d: &Domain, srs: &LongSrs, scheme: Scheme, message: &[Fr]) -> Result<EncodedB> {
    let locals = MessagePolys::new(d, message)?.locals(d)?;
    let values = make_values(d, &locals, scheme)?;
    Ok((
        ProfileBHeader::commit(d, srs, scheme, message)?,
        locals,
        values,
    ))
}
fn encode_supplied(
    d: &Domain,
    srs: &LongSrs,
    message: &[Fr],
) -> Result<(SuppliedHeader, Vec<SuppliedAux>, Vec<Vec<Fr>>)> {
    let locals = MessagePolys::new(d, message)?.locals(d)?;
    let values = make_values(d, &locals, Scheme::Lrdas)?;
    let f = recovery::global_from_message(d, message)?;
    let h = SuppliedHeader::commit(d, srs, &f)?;
    let aux = locals
        .iter()
        .enumerate()
        .map(|(j, l)| supplied_aux(d, srs, &f, l, j))
        .collect::<Result<Vec<_>>>()?;
    Ok((h, aux, values))
}
fn receiver_benches(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    name: &str,
    indices: &[usize],
    values: &[Fr],
    mut group: impl FnMut() -> Result<VerifiedGroup>,
) -> Result<()> {
    let p = d.params();
    let g = group()?;
    let receiver = g.certify(d, srs, indices, values)?;
    r.bench(
        name,
        "variant_group_auth",
        p.a(),
        "verified_header",
        false,
        &mut group,
    )?;
    r.bench(
        name,
        "variant_group_certify",
        p.r(),
        "verified_header",
        false,
        || group()?.certify(d, srs, indices, values),
    )?;
    r.bench(
        name,
        "variant_serve_fresh",
        1,
        "certified_group",
        false,
        || receiver.serve(d, srs, p.m() - 1),
    )?;
    r.bench(
        name,
        "variant_certify_serve",
        p.r(),
        "verified_header",
        false,
        || {
            let g = group()?;
            let recv = g.certify(d, srs, indices, values)?;
            let recovered = recv.recover(d)?;
            let opening = recv.serve(d, srs, p.m() - 1)?;
            g.verify(d, srs, p.m() - 1, &opening)?;
            Ok((recovered, opening))
        },
    )?;
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
    let h = header.verify(d, srs)?;
    let qs = queries(
        d,
        srs,
        locals,
        scheme,
        sample_count(r, scheme)?,
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
        "variant_encode_total",
        p.n(),
        "public_parameters",
        true,
        || protocol::encode(d, srs, scheme, message),
    )?;
    r.bench(name, "variant_header_verify", p.a(), "cold", false, || {
        Header::from_payload(d, srs, scheme, context, &raw)?.verify(d, srs)
    })?;
    let indices: Vec<_> = (0..p.r()).collect();
    let vals = d.evaluate(scheme, p.a(), &locals[p.a()])?;
    receiver_benches(r, d, srs, name, &indices, &vals[..p.r()], || {
        VerifiedGroup::dedicated(d, srs, &h, p.a())
    })?;
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
    let mut cache = vec![None; p.ell()];
    for &j in &touched {
        cache[j] = Some(VerifiedGroup::dedicated(d, srs, &h, j)?);
    }
    r.bench(
        name,
        "variant_light_client",
        qs.len(),
        "warm",
        false,
        || {
            check_queries(d, srs, &qs, &mut cache, |j| {
                VerifiedGroup::dedicated(d, srs, &h, j)
            })
        },
    )?;
    let receiver =
        VerifiedGroup::dedicated(d, srs, &h, p.a())?.certify(d, srs, &indices, &vals[..p.r()])?;
    r.bench(
        name,
        "variant_fresh_peer_serve",
        1,
        "certified_group",
        false,
        || {
            let reply = receiver.serve(d, srs, p.m() - 1)?.to_bytes(p.r())?;
            let peer = Header::from_payload(d, srs, scheme, context, &raw)?.verify(d, srs)?;
            let opening = Opening::from_bytes(&reply, 1, p.r())?;
            VerifiedGroup::dedicated(d, srs, &peer, p.a())?.verify(d, srs, p.m() - 1, &opening)?;
            Ok(reply)
        },
    )?;
    meta.push(json!({"variant":name,"queries":qs.len(),"touched_groups":touched.len(),"parity_groups":touched.iter().filter(|j|**j>=p.a()).count(),
        "header_bytes":raw.len(),"auxiliary_bytes_per_group":0,"cold_payload_bytes":raw.len()+80*qs.len(),"warm_payload_bytes":80*qs.len(),
        "public_g1_bytes":p.r()*48,"public_g2_bytes":(p.r()+1)*96}));
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
    let h = header.verify(d, srs, &mut rng)?;
    let qs = queries(
        d,
        srs.local(),
        locals,
        scheme,
        sample_count(r, scheme)?,
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
        "variant_encode_total",
        p.n(),
        "public_parameters",
        true,
        || encode_b(d, srs, scheme, message),
    )?;
    r.bench(name, "variant_header_verify", p.a(), "cold", false, || {
        ProfileBHeader::from_payload(d, srs, scheme, context, &raw)?.verify(d, srs, &mut rng)
    })?;
    let indices: Vec<_> = (0..p.r()).collect();
    let vals = d.evaluate(scheme, p.a(), &locals[p.a()])?;
    receiver_benches(r, d, srs.local(), name, &indices, &vals[..p.r()], || {
        h.group(d, p.a())
    })?;
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
    let mut cache = vec![None; p.ell()];
    for &j in &touched {
        cache[j] = Some(h.group(d, j)?);
    }
    r.bench(
        name,
        "variant_light_client",
        qs.len(),
        "warm",
        false,
        || check_queries(d, srs.local(), &qs, &mut cache, |j| h.group(d, j)),
    )?;
    let receiver = h
        .group(d, p.a())?
        .certify(d, srs.local(), &indices, &vals[..p.r()])?;
    r.bench(
        name,
        "variant_fresh_peer_serve",
        1,
        "certified_group",
        false,
        || {
            let reply = receiver.serve(d, srs.local(), p.m() - 1)?.to_bytes(p.r())?;
            let peer = ProfileBHeader::from_payload(d, srs, scheme, context, &raw)?
                .verify(d, srs, &mut rng)?;
            let opening = Opening::from_bytes(&reply, 1, p.r())?;
            peer.group(d, p.a())?
                .verify(d, srs.local(), p.m() - 1, &opening)?;
            Ok(reply)
        },
    )?;
    meta.push(json!({"variant":name,"queries":qs.len(),"touched_groups":touched.len(),"header_bytes":raw.len(),"auxiliary_bytes_per_group":0,
        "cold_payload_bytes":raw.len()+80*qs.len(),"warm_payload_bytes":80*qs.len(),"long_degree":srs.degree(),
        "public_g1_bytes":(srs.degree()+1)*48,"minimum_public_g2_bytes":(p.r()+2)*96,
        "resident_shared_long_g2_bytes":(p.m()+2)*96,"fresh_verifier_challenge_per_cold_iteration":true}));
    Ok(())
}

fn supplied(
    r: &mut Runner,
    d: &Domain,
    srs: &LongSrs,
    message: &[Fr],
    locals: &[Vec<Fr>],
    meta: &mut Vec<Value>,
) -> Result<()> {
    let p = d.params();
    let name = "lrdas_supplied";
    eprintln!(
        "Preparing supplied degree-{} commitments and all {} triples (outside measurement)...",
        p.degree(),
        p.ell()
    );
    let start = Instant::now();
    let f = recovery::global_from_message(d, message)?;
    let header = SuppliedHeader::commit(d, srs, &f)?;
    let aux = locals
        .iter()
        .enumerate()
        .map(|(j, l)| supplied_aux(d, srs, &f, l, j))
        .collect::<Result<Vec<_>>>()?;
    let raw_aux = aux
        .iter()
        .map(SuppliedAux::payload)
        .collect::<Result<Vec<_>>>()?;
    let preparation_seconds = start.elapsed().as_secs_f64();
    let raw = header.payload()?;
    let context = header.context();
    let qs = queries(
        d,
        srs.local(),
        locals,
        Scheme::Lrdas,
        sample_count(r, Scheme::Lrdas)?,
        r.config.seed,
    )?;
    let touched: BTreeSet<_> = qs.iter().map(|q| q.group).collect();
    r.bench(
        name,
        "global_polynomial_expand",
        p.k(),
        "message",
        false,
        || recovery::global_from_message(d, message),
    )?;
    r.bench(
        name,
        "variant_header_commit",
        p.degree() + 1,
        "expanded_global_polynomial",
        true,
        || SuppliedHeader::commit(d, srs, &f),
    )?;
    r.bench(
        name,
        "supplied_one_aux",
        p.degree() + 1,
        "global_and_local_polynomials",
        true,
        || supplied_aux(d, srs, &f, &locals[p.a()], p.a()),
    )?;
    r.bench(
        name,
        "supplied_all_aux",
        p.ell(),
        "global_and_local_polynomials",
        true,
        || {
            locals
                .iter()
                .enumerate()
                .map(|(j, l)| supplied_aux(d, srs, &f, l, j))
                .collect::<Result<Vec<_>>>()
        },
    )?;
    r.bench(
        name,
        "variant_encode_total",
        p.n(),
        "public_parameters",
        true,
        || encode_supplied(d, srs, message),
    )?;
    r.bench(name, "variant_header_verify", 1, "cold", false, || {
        SuppliedHeader::from_payload(d, srs, context, &raw)
    })?;
    let indices: Vec<_> = (0..p.r()).collect();
    let vals = d.evaluate(Scheme::Lrdas, p.a(), &locals[p.a()])?;
    receiver_benches(r, d, srs.local(), name, &indices, &vals[..p.r()], || {
        header.verify_group(d, srs, p.a(), &SuppliedAux::from_payload(&raw_aux[p.a()])?)
    })?;
    r.bench(
        name,
        "variant_light_client",
        qs.len(),
        "cold",
        false,
        || {
            let h = SuppliedHeader::from_payload(d, srs, context, &raw)?;
            check_queries(d, srs.local(), &qs, &mut vec![None; p.ell()], |j| {
                h.verify_group(d, srs, j, &SuppliedAux::from_payload(&raw_aux[j])?)
            })
        },
    )?;
    let mut cache = vec![None; p.ell()];
    for &j in &touched {
        cache[j] = Some(header.verify_group(d, srs, j, &aux[j])?);
    }
    r.bench(
        name,
        "variant_light_client",
        qs.len(),
        "warm",
        false,
        || {
            check_queries(d, srs.local(), &qs, &mut cache, |j| {
                header.verify_group(d, srs, j, &aux[j])
            })
        },
    )?;
    let receiver = header.certify_group(d, srs, p.a(), &aux[p.a()], &indices, &vals[..p.r()])?;
    let reply = receiver.serve_reply(d, srs.local(), p.m() - 1)?;
    check(
        header
            .verify_reply(d, srs, p.a(), p.m() - 1, &reply[144..])
            .is_err(),
        "missing auxiliary triple accepted",
    )?;
    r.bench(
        name,
        "variant_fresh_peer_serve",
        1,
        "certified_group",
        false,
        || {
            let reply = receiver.serve_reply(d, srs.local(), p.m() - 1)?;
            let peer = SuppliedHeader::from_payload(d, srs, context, &raw)?;
            peer.verify_reply(d, srs, p.a(), p.m() - 1, &reply)?;
            Ok(reply)
        },
    )?;
    meta.push(json!({"variant":name,"queries":qs.len(),"touched_groups":touched.len(),"header_bytes":raw.len(),"auxiliary_bytes_per_group":144,
        "cold_payload_bytes":raw.len()+144*touched.len()+80*qs.len(),"warm_payload_bytes":80*qs.len(),
        "public_g1_bytes":(p.degree()+1)*48,"public_g2_bytes":(p.m()+2)*96,"all_auxiliary_bytes":144*p.ell(),
        "fixture_preparation_seconds":preparation_seconds,"both_pairing_checks":true,"retained_auxiliary_bytes_per_group":144,"fresh_peer_rejects_missing_auxiliary":true}));
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
    r.bench(
        name,
        "diagonal_decode_authenticate",
        received.len(),
        "accepted_values",
        true,
        || {
            let out = decode()?;
            out.authenticate(d, srs, &header)?;
            Ok(out)
        },
    )?;
    let target = p.a();
    let index = p.m() * target / p.ell();
    check(recovery::erased(p, target, index)?, "target is not erased")?;
    if scheme == Scheme::Lrdas {
        let selected = &received[..p.degree() + 1];
        r.bench(
            name,
            "diagonal_recover_serve",
            selected.len(),
            "accepted_helpers",
            true,
            || {
                let rec = recovery::recover_global(d, selected)?;
                rec.authenticate(d, srs, &header)?;
                let opening = rec.serve(d, srs, scheme, target, index)?;
                srs.verify(
                    header.derive(d, target)?,
                    &[d.point(scheme, target, index)?],
                    &opening,
                )?;
                Ok(opening)
            },
        )?;
    } else {
        let helpers = (0..p.ell())
            .filter(|j| !recovery::erased(p, *j, index).unwrap())
            .take(p.a())
            .map(|j| Ok((j, srs.open(&enc.locals[j], &[d.point(scheme, j, index)?])?)))
            .collect::<Result<Vec<_>>>()?;
        let raw_helpers = helpers
            .iter()
            .map(|(j, o)| Ok((*j, o.to_bytes(p.r())?)))
            .collect::<Result<Vec<_>>>()?;
        // Authenticate the helper fixture outside the accepted-helper measurement.
        for (j, o) in &helpers {
            srs.verify(header.derive(d, *j)?, &[d.point(scheme, *j, index)?], o)?;
        }
        let proof = recovery::repair_product_point(d, srs, &header, target, index, &helpers)?;
        check(
            proof.values[0] == enc.values[target][index],
            "row repair fixture mismatch",
        )?;
        r.bench(
            name,
            "diagonal_recover_serve",
            helpers.len(),
            "accepted_helpers",
            true,
            || recovery::repair_product_point(d, srs, &header, target, index, &helpers),
        )?;
        r.bench(
            name,
            "diagonal_row_receive_repair",
            helpers.len(),
            "response_bytes",
            false,
            || {
                let mut helpers = Vec::with_capacity(raw_helpers.len());
                for (j, raw) in &raw_helpers {
                    let opening = Opening::from_bytes(raw, 1, p.r())?;
                    srs.verify(
                        header.derive(d, *j)?,
                        &[d.point(scheme, *j, index)?],
                        &opening,
                    )?;
                    helpers.push((*j, opening));
                }
                recovery::repair_product_point(d, srs, &header, target, index, &helpers)
            },
        )?;
    }
    meta.push(json!({"diagonal_scheme":name,"erased_symbols":p.n()-received.len(),"survivors":received.len(),
        "survivors_per_group":groups[0],"minimum_row_survivors":rows.iter().min(),"locally_completable_groups":0,
        "single_target_group":target,"single_target_index":index,
        "single_target_input_values":if scheme==Scheme::Lrdas {p.degree()+1} else {p.a()},
        "single_target_retained_input_bytes":if scheme==Scheme::Lrdas {(p.degree()+1)*32} else {p.a()*80},
        "single_point_authenticated_download_payload_bytes":80*if scheme==Scheme::Lrdas {p.degree()+1} else {p.a()},
        "full_decode_outputs":["original_message","all_codeword_values","local_serving_polynomials"],
        "input_authentication_excluded_from_decoder":true,"global_coordinate_preprocessing_included":true}));
    Ok(())
}

pub(super) fn run(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    meta: &mut Vec<Value>,
) -> Result<()> {
    let p = d.params();
    let message = fixture::message(p, r.config.seed);
    let locals = MessagePolys::new(d, &message)?.locals(d)?;
    let variants_enabled = !r.filter.starts_with("diagonal");
    let diagonal_enabled = r.filter.is_empty() || r.filter.starts_with("diagonal");
    if variants_enabled {
        let start = Instant::now();
        let long = fixture::long_setup(p, 9001)?;
        meta.push(json!({"long_srs_fixture_ms":start.elapsed().as_secs_f64()*1000.,"degree":long.degree(),
        "trapdoor_separated_from_dedicated_fixture":true,"local_prefix_not_a_dedicated_setup":true}));
        let order = if r.process_run_id.is_multiple_of(2) {
            vec![0, 1, 2, 3, 4]
        } else {
            vec![4, 3, 2, 1, 0]
        };
        for v in order {
            match v {
                0 => dedicated(r, d, srs, Scheme::Lrdas, &message, &locals, meta)?,
                1 => profile_b(r, d, &long, Scheme::Lrdas, &message, &locals, meta)?,
                2 => supplied(r, d, &long, &message, &locals, meta)?,
                3 => dedicated(r, d, srs, Scheme::Product, &message, &locals, meta)?,
                _ => profile_b(r, d, &long, Scheme::Product, &message, &locals, meta)?,
            }
        }
    }
    if diagonal_enabled {
        let schemes = if r.process_run_id.is_multiple_of(2) {
            [Scheme::Lrdas, Scheme::Product]
        } else {
            [Scheme::Product, Scheme::Lrdas]
        };
        for scheme in schemes {
            diagonal(r, d, srs, scheme, &message, meta)?;
        }
    }
    black_box(d.fft().size());
    Ok(())
}
