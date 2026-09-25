//! Coding separation and matched erasure controls, with receiver-side reconstruction.
use super::*;
use lrdas_artifact::{
    recovery,
    separation::{self, ErasureMask},
};

fn checked(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(err(message))
    }
}
pub(super) fn run(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    meta: &mut Vec<serde_json::Value>,
) -> Result<()> {
    let p = d.params();
    let mut rng = fixture::rng(r.config.seed, "separation-rectangle");
    let mut groups: Vec<_> = (0..p.ell()).collect();
    let mut indices: Vec<_> = (0..p.m()).collect();
    groups.shuffle(&mut rng);
    indices.shuffle(&mut rng);
    groups.truncate(p.ell() - p.a() + 1);
    indices.truncate(p.m() - p.r() + 1);
    groups.sort_unstable();
    indices.sort_unstable();
    let rect = separation::rectangle(d, &groups, &indices)?;
    let mut boundary = rect.clone();
    let restored = (groups[0], indices[0]);
    boundary.restore(restored.0, restored.1)?;
    let mut coords: Vec<_> = (0..p.n()).collect();
    coords.shuffle(&mut fixture::rng(r.config.seed, "separation-random"));
    let positions: Vec<_> = coords[..rect.count()]
        .iter()
        .map(|v| (v / p.m(), v % p.m()))
        .collect();
    let random = ErasureMask::new(p, &positions)?;
    let witness = separation::product_witness(d, &groups, &indices)?;
    let message = fixture::message(p, r.config.seed);
    let alternative: Vec<_> = message
        .iter()
        .zip(&witness.message)
        .map(|(x, y)| *x + y)
        .collect();
    let witness_hash = format!("{:x}", Sha256::digest(bytes(&witness.message)?));
    let mut order = vec![
        ("rectangle", rect),
        ("rectangle_minus_one", boundary),
        ("random_matched", random),
    ];
    if !r.process_run_id.is_multiple_of(2) {
        order.reverse();
    }
    let schemes = if r.process_run_id.is_multiple_of(2) {
        [Scheme::Lrdas, Scheme::Product]
    } else {
        [Scheme::Product, Scheme::Lrdas]
    };
    for scheme in schemes {
        let enc = protocol::encode(d, srs, scheme, &message)?;
        let header = enc.header.clone().verify(d, srs)?;
        let alt = if scheme == Scheme::Product {
            Some(protocol::encode(d, srs, scheme, &alternative)?)
        } else {
            None
        };
        for (name, mask) in &order {
            let received = mask.retain(&enc.values)?;
            let (gc, rc) = mask.survivor_counts();
            let complete = gc.iter().filter(|n| **n >= p.r()).count();
            let mut record = json!({
                "pattern":name, "scheme":scheme.name(), "erased":mask.count(), "survivors":received.len(),
                "mask_sha256":format!("{:x}",Sha256::digest(mask.bytes())),
                "groups_locally_completeable":complete,
                "min_group_survivors":gc.iter().min(), "min_row_survivors":rc.iter().min(),
                "restored_coordinate":restored, "rectangle_groups":groups, "rectangle_indices":indices,
                "input_boundary":"already_authenticated_field_values_and_verified_header",
                "output_boundary":"message_full_codeword_local_polynomials_then_header_authentication",
            });
            if *name == "rectangle" && scheme == Scheme::Product {
                let alternative_enc = alt.as_ref().unwrap();
                checked(message != alternative, "witness messages identical")?;
                checked(
                    received
                        .iter()
                        .all(|v| alternative_enc.values[v.group][v.index] == v.value),
                    "alternative differs on surviving symbols",
                )?;
                checked(
                    enc.values != alternative_enc.values,
                    "witness encodings identical",
                )?;
                checked(
                    enc.header.payload()? != alternative_enc.header.payload()?,
                    "unexpected header collision",
                )?;
                checked(
                    recovery::recover_groups(d, scheme, &received).is_err()
                        && recovery::recover_product_rows(d, &received).is_err(),
                    "rectangle decoder should stall",
                )?;
                record["outcome"] = json!("not_uniquely_decodable_from_symbols");
                record["witness_verified"] = json!(true);
                record["witness_message_sha256"] = json!(witness_hash);
                record["witness_nonzero_symbols"] = json!(mask.count());
                record["same_header_claimed"] = json!(false);
                // Deliberately no latency row: identifying ambiguity is not a successful decoder.
                eprintln!("{name} / product: constructive coding ambiguity verified");
            } else {
                let route = if complete >= p.a() {
                    "groups"
                } else if scheme == Scheme::Lrdas {
                    "global"
                } else {
                    "rows"
                };
                let decode = || match route {
                    "groups" => recovery::recover_groups(d, scheme, &received),
                    "global" => recovery::recover_global(d, &received),
                    _ => recovery::recover_product_rows(d, &received),
                };
                let rec = decode()?;
                rec.authenticate(d, srs, &header)?;
                checked(
                    rec.message() == message && rec.values() == enc.values,
                    "separation reconstruction mismatch",
                )?;
                if *name == "rectangle_minus_one" && scheme == Scheme::Product {
                    checked(
                        alt.as_ref().unwrap().values[restored.0][restored.1]
                            != enc.values[restored.0][restored.1],
                        "restored symbol must distinguish witness",
                    )?;
                }
                record["outcome"] = json!("recovered_and_authenticated");
                record["route"] = json!(route);
                for authenticate in [false, true] {
                    let operation = format!(
                        "{name}_{}",
                        if authenticate {
                            "decode_authenticate"
                        } else {
                            "decode"
                        }
                    );
                    r.bench(
                        scheme.name(),
                        &operation,
                        received.len(),
                        "accepted_values",
                        true,
                        || {
                            let out = decode()?;
                            if authenticate {
                                out.authenticate(d, srs, &header)?;
                            }
                            Ok(out)
                        },
                    )?;
                }
            }
            meta.push(record);
        }
    }
    Ok(())
}
