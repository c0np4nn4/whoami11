use ark_bls12_381::{Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, One, Zero};
use lrdas_artifact::{
    bytes, decode,
    domain::{Domain, Params, Scheme},
    fixture,
    kzg::{decode_srs, msm_g1, Opening, PublicSrs},
    polynomial as poly,
    protocol::*,
};
use rand::seq::SliceRandom;

fn small() -> (Domain, PublicSrs) {
    let p = Params::smoke();
    (Domain::new(p).unwrap(), fixture::setup(p.r(), 900).unwrap())
}

#[test]
fn manuscript_profile_and_input_rejection() {
    let p = Params::reference();
    assert_eq!((p.n(), p.k(), p.degree()), (125952, 62976, 83711));
    assert_eq!(p.distance(Scheme::Lrdas).unwrap(), 42241);
    assert_eq!(p.distance(Scheme::Product).unwrap(), 10794);
    assert_eq!(p.queries(Scheme::Lrdas, 128).unwrap(), 218);
    assert_eq!(p.queries(Scheme::Product, 128).unwrap(), 991);
    for args in [
        (0, 16, 12, 4, 0),
        (6, 15, 12, 4, 0),
        (6, 16, 16, 4, 0),
        (6, 16, 12, 7, 0),
        (6, 16, 12, 6, 1),
        (usize::MAX, 16, 12, 4, 0),
    ] {
        assert!(Params::new(args.0, args.1, args.2, args.3, args.4).is_err());
    }
}
#[test]
fn checked_polynomial_reference() {
    let xs = vec![Fr::from(1), Fr::from(2), Fr::from(7)];
    let ys = xs
        .iter()
        .map(|x| Fr::from(3) + Fr::from(4) * x + Fr::from(5) * x * x)
        .collect::<Vec<_>>();
    assert_eq!(
        poly::interpolate(&xs, &ys).unwrap(),
        vec![Fr::from(3), Fr::from(4), Fr::from(5)]
    );
    assert!(poly::interpolate(&[xs[0], xs[0]], &[ys[0], ys[0]]).is_err());
    assert!(poly::divide_exact(&[Fr::one()], &[Fr::one(), Fr::one()]).is_err());
}
#[test]
fn hand_checked_kzg_vector() {
    // p=3+4X, tau=2 -> C=11G1; at x=5, y=23 and quotient=4.
    let mut power = Fr::one();
    let mut g1 = vec![];
    let mut g2 = vec![];
    for i in 0..=4 {
        if i < 4 {
            g1.push((G1Projective::generator() * power).into_affine());
        }
        g2.push((G2Projective::generator() * power).into_affine());
        power *= Fr::from(2);
    }
    let srs = PublicSrs::from_points(4, g1, g2).unwrap();
    let p = vec![Fr::from(3), Fr::from(4)];
    let c = srs.commit(&p).unwrap();
    assert_eq!(c, (G1Projective::generator() * Fr::from(11)).into_affine());
    let opening = srs.open(&p, &[Fr::from(5)]).unwrap();
    assert_eq!(opening.values, vec![Fr::from(23)]);
    assert_eq!(
        opening.proof,
        (G1Projective::generator() * Fr::from(4)).into_affine()
    );
    srs.verify(c, &[Fr::from(5)], &opening).unwrap();
    let mut bad = opening;
    bad.values[0] += Fr::one();
    assert!(srs.verify(c, &[Fr::from(5)], &bad).is_err());
}
#[test]
fn independent_encoding_oracle_and_mutation() {
    let (domain, srs) = small();
    let p = domain.params();
    for seed in 0..4 {
        let message = fixture::message(p, seed);
        for scheme in [Scheme::Lrdas, Scheme::Product] {
            let enc = encode(&domain, &srs, scheme, &message).unwrap();
            let h = enc.header.clone().verify(&domain, &srs).unwrap();
            for j in 0..p.ell() {
                assert_eq!(
                    h.derive(&domain, j).unwrap(),
                    srs.commit(&enc.locals[j]).unwrap()
                );
                for i in 0..p.m() {
                    let x = domain.point(scheme, j, i).unwrap();
                    let gamma = domain.gammas()[j];
                    // Direct Lagrange products, deliberately independent of Domain::weights/FFT.
                    let mut expected = Fr::zero();
                    for a in 0..p.a() {
                        let gs = domain.gammas()[a];
                        let mut w = Fr::one();
                        for t in 0..p.a() {
                            if t != a {
                                w *= (gamma - domain.gammas()[t]) / (gs - domain.gammas()[t]);
                            }
                        }
                        let u = &message[a * p.r()..(a + 1) * p.r()];
                        let mut ux = Fr::zero();
                        for (k, c) in u.iter().enumerate() {
                            ux += *c * x.pow([k as u64]);
                        }
                        expected += w * ux;
                    }
                    assert_eq!(enc.values[j][i], expected, "seed={seed},j={j},i={i}");
                }
            }
            if scheme == Scheme::Lrdas {
                let bad = domain
                    .evaluate(Scheme::Product, p.a(), &enc.locals[p.a()])
                    .unwrap();
                assert_ne!(
                    bad,
                    enc.values[p.a()],
                    "test must detect omitted coset scaling"
                );
            }
        }
    }
}
#[test]
fn opening_permutations_mutations_and_boundaries() {
    let (domain, srs) = small();
    let p = domain.params();
    let m = fixture::message(p, 34);
    for scheme in [Scheme::Lrdas, Scheme::Product] {
        let enc = encode(&domain, &srs, scheme, &m).unwrap();
        for j in [0, p.a()] {
            let c = srs.commit(&enc.locals[j]).unwrap();
            for t in [1, 2, 8, p.r()] {
                let xs = (0..t)
                    .map(|i| domain.point(scheme, j, i).unwrap())
                    .collect::<Vec<_>>();
                let o = srs.open(&enc.locals[j], &xs).unwrap();
                srs.verify(c, &xs, &o).unwrap();
                let raw = o.to_bytes(p.r()).unwrap();
                assert_eq!(raw.len(), 32 * t + if t < p.r() { 48 } else { 0 });
                srs.verify(c, &xs, &Opening::from_bytes(&raw, t, p.r()).unwrap())
                    .unwrap();
                let mut rev = xs.clone();
                rev.reverse();
                let mut ro = o.clone();
                ro.values.reverse();
                srs.verify(c, &rev, &ro).unwrap();
                let mut bad = o.clone();
                bad.values[0] += Fr::one();
                assert!(srs.verify(c, &xs, &bad).is_err());
                let mut bad = o.clone();
                bad.proof = (bad.proof.into_group() + G1Projective::generator()).into_affine();
                assert!(srs.verify(c, &xs, &bad).is_err());
                let mut badx = xs.clone();
                badx[0] = domain.point(scheme, j, p.m() - 1).unwrap();
                assert!(srs.verify(c, &badx, &o).is_err());
            }
        }
    }
    assert!(srs.commit(&vec![Fr::zero(); p.r() + 1]).is_err());
    assert!(srs.open(&m[..p.r()], &[]).is_err());
    assert!(srs.open(&m[..p.r()], &[Fr::one(), Fr::one()]).is_err());
    assert!(msm_g1(srs.g1(), &[Fr::one()]).is_err());
}
#[test]
fn receiver_only_serving_random_subsets_and_streaming() {
    let (d, srs) = small();
    let p = d.params();
    for scheme in [Scheme::Lrdas, Scheme::Product] {
        let enc = encode(&d, &srs, scheme, &fixture::message(p, 4)).unwrap();
        let h = enc.header.clone().verify(&d, &srs).unwrap();
        for j in [0, p.a()] {
            for seed in 0..3 {
                let mut indices = (0..p.m()).collect::<Vec<_>>();
                indices.shuffle(&mut fixture::rng(seed, "subset"));
                indices.truncate(p.r());
                let vals = indices
                    .iter()
                    .map(|&i| enc.values[j][i])
                    .collect::<Vec<_>>();
                let c = CertifiedGroup::from_values(&d, &srs, &h, j, &indices, &vals).unwrap();
                assert_eq!(c.recover(&d).unwrap(), enc.values[j]);
                let missing = (0..p.m()).find(|i| !indices.contains(i)).unwrap();
                let proof = c.serve(&d, &srs, &[missing]).unwrap();
                srs.verify(
                    h.derive(&d, j).unwrap(),
                    &[d.point(scheme, j, missing).unwrap()],
                    &proof,
                )
                .unwrap();
            }
        }
        let mut collector = StreamingCollector::new(p.a());
        let mut cache = GroupCache::new(&h, &d);
        for i in 0..p.r() {
            let x = d.point(scheme, p.a(), i).unwrap();
            let raw = srs
                .open(&enc.locals[p.a()], &[x])
                .unwrap()
                .to_bytes(p.r())
                .unwrap();
            collector.accept(&d, &srs, &h, &mut cache, i, &raw).unwrap();
        }
        let recovered = collector.finish(&d, &srs, &h).unwrap();
        assert_eq!(recovered.recover(&d).unwrap(), enc.values[p.a()]);
    }
}
#[test]
fn residual_coordinates_and_degree_bound_mutation() {
    for b in [1, 11] {
        let p = Params::new(6, 16, 12, 4, b).unwrap();
        let d = Domain::new(p).unwrap();
        let srs = fixture::setup(p.r(), 99).unwrap();
        let msg = fixture::message(p, 98);
        let enc = encode(&d, &srs, Scheme::Lrdas, &msg).unwrap();
        let h = enc.header.clone().verify(&d, &srs).unwrap();
        assert_eq!(&enc.locals[p.a()][..b], &msg[p.a() * p.r()..]);
        assert_ne!(d.residual_weight(p.a()).unwrap(), Fr::zero());
        let mut wrong = enc.header.payload().unwrap();
        let altered = (decode::<G1Affine>(&wrong[(p.a() + 1) * 48..])
            .unwrap()
            .into_group()
            + G1Projective::generator())
        .into_affine();
        wrong[(p.a() + 1) * 48..].copy_from_slice(&bytes(&altered).unwrap());
        let bad =
            Header::from_payload(&d, &srs, Scheme::Lrdas, enc.header.context(), &wrong).unwrap();
        assert!(bad.verify(&d, &srs).is_err());
        let xs = (0..b)
            .map(|i| d.point(Scheme::Lrdas, p.a(), i).unwrap())
            .collect::<Vec<_>>();
        let mut base = vec![];
        for &x in &xs {
            base.push(
                msg[..p.a() * p.r()]
                    .chunks_exact(p.r())
                    .zip(d.weights(p.a()).unwrap())
                    .map(|(u, w)| poly::evaluate(u, x) * w)
                    .sum(),
            );
        }
        let residual = poly::residual_from_values(
            &xs,
            &enc.values[p.a()][..b],
            &base,
            &vec![d.residual_weight(p.a()).unwrap(); b],
        )
        .unwrap();
        let mut restored = base.clone();
        for i in 0..b {
            restored[i] += d.residual_weight(p.a()).unwrap() * poly::evaluate(&residual, xs[i]);
        }
        assert_eq!(restored, enc.values[p.a()][..b]);
        // Deliberately skip v->e conversion, which must not reproduce the residual block.
        let mut badlocal = vec![Fr::zero(); p.r()];
        for (u, w) in msg[..p.a() * p.r()]
            .chunks_exact(p.r())
            .zip(d.weights(p.a()).unwrap())
        {
            for (c, v) in badlocal.iter_mut().zip(u) {
                *c += *w * v;
            }
        }
        for i in 0..b {
            badlocal[i] += d.residual_weight(p.a()).unwrap() * msg[p.a() * p.r() + i];
        }
        assert_ne!(&badlocal[..b], &msg[p.a() * p.r()..]);
        assert_eq!(
            h.derive(&d, p.a()).unwrap(),
            srs.commit(&enc.locals[p.a()]).unwrap()
        );
        assert!(encode(&d, &srs, Scheme::Product, &msg).is_err());
    }
}
#[test]
fn zero_linear_and_source_basis() {
    let (d, srs) = small();
    let p = d.params();
    let z = vec![Fr::zero(); p.k()];
    let enc = encode(&d, &srs, Scheme::Lrdas, &z).unwrap();
    let c = srs.commit(&enc.locals[0]).unwrap();
    assert!(c.is_zero());
    let xs = [d.point(Scheme::Lrdas, 0, 0).unwrap()];
    srs.verify(c, &xs, &srs.open(&enc.locals[0], &xs).unwrap())
        .unwrap();
    let mut a = vec![Fr::zero(); p.r()];
    a[p.r() - 1] = Fr::one();
    let b = vec![Fr::one(); p.r()];
    let sum = a.iter().zip(&b).map(|(a, b)| *a + b).collect::<Vec<_>>();
    assert_eq!(
        srs.commit(&sum).unwrap(),
        (srs.commit(&a).unwrap().into_group() + srs.commit(&b).unwrap()).into_affine()
    );
    let mut unit = z;
    unit[p.r() + 2] = Fr::one();
    let locals = MessagePolys::new(&d, &unit).unwrap().locals(&d).unwrap();
    for (j, v) in locals.iter().enumerate() {
        assert_eq!(v[2], d.weights(j).unwrap()[1]);
    }
}
#[test]
fn serialization_subgroup_and_context() {
    let (d, srs) = small();
    let p = d.params();
    let enc = encode(&d, &srs, Scheme::Lrdas, &fixture::message(p, 3)).unwrap();
    let raw = enc.header.payload().unwrap();
    assert!(Header::from_payload(&d, &srs, Scheme::Lrdas, [0; 32], &raw).is_err());
    assert!(Header::from_payload(&d, &srs, Scheme::Product, enc.header.context(), &raw).is_err());
    assert!(Header::from_payload(
        &d,
        &srs,
        Scheme::Lrdas,
        enc.header.context(),
        &raw[..raw.len() - 1]
    )
    .is_err());
    let other = fixture::setup(p.r(), 44).unwrap();
    assert!(enc.header.clone().verify(&d, &other).is_err());
    let h_context = enc.header.context();
    let h = enc.header.verify(&d, &srs).unwrap();
    let mut cache = GroupCache::new(&h, &d);
    let _ = cache.get(&h, &d, p.a()).unwrap();
    let h2 = encode(&d, &srs, Scheme::Lrdas, &fixture::message(p, 4))
        .unwrap()
        .header
        .verify(&d, &srs)
        .unwrap();
    assert!(cache.get(&h2, &d, p.a()).is_err());
    let d2 = Domain::new(Params::new(6, 32, 12, 4, 0).unwrap()).unwrap();
    assert!(h.derive(&d2, 4).is_err());
    assert!(cache.get(&h, &d2, p.a()).is_err());
    assert!(decode::<Fr>(&[255; 32]).is_err());
    let mut extra = bytes(&Fr::one()).unwrap();
    extra.push(0);
    assert!(decode::<Fr>(&extra).is_err());
    let mut nonsub = None;
    for i in 0..100 {
        if let Some(pt) = G1Affine::get_point_from_x_unchecked(Fq::from(i), false) {
            if !pt.is_in_correct_subgroup_assuming_on_curve() {
                nonsub = Some(pt);
                break;
            }
        }
    }
    let nonsub = nonsub.expect("non-subgroup fixture");
    assert!(nonsub.is_on_curve());
    assert!(decode::<G1Affine>(&bytes(&nonsub).unwrap()).is_err());
    let mut invalid = raw.clone();
    invalid[..48].copy_from_slice(&bytes(&nonsub).unwrap());
    assert!(Header::from_payload(&d, &srs, Scheme::Lrdas, h_context, &invalid).is_err());
    let g1 = srs
        .g1()
        .iter()
        .flat_map(|p| bytes(p).unwrap())
        .collect::<Vec<_>>();
    let g2 = srs
        .g2()
        .iter()
        .flat_map(|p| bytes(p).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(decode_srs(p.r(), &g1, &g2).unwrap().id(), srs.id());
    assert!(decode_srs(p.r(), &g1[..g1.len() - 1], &g2).is_err());
}

#[test]
fn several_code_shapes_and_incomplete_collector() {
    for (ell, m, r, a, b) in [(3, 8, 5, 2, 0), (5, 16, 7, 3, 1), (8, 32, 17, 5, 16)] {
        let p = Params::new(ell, m, r, a, b).unwrap();
        let d = Domain::new(p).unwrap();
        let srs = fixture::setup(r, 912).unwrap();
        for seed in [51, 52] {
            let msg = fixture::message(p, seed);
            let enc = encode(&d, &srs, Scheme::Lrdas, &msg).unwrap();
            let h = enc.header.clone().verify(&d, &srs).unwrap();
            for j in [0, a] {
                for t in [1, 2, r - 1, r] {
                    let xs: Vec<_> = (0..t)
                        .map(|i| d.point(Scheme::Lrdas, j, i).unwrap())
                        .collect();
                    let o = srs.open(&enc.locals[j], &xs).unwrap();
                    srs.verify(h.derive(&d, j).unwrap(), &xs, &o).unwrap();
                }
            }
            assert!(StreamingCollector::new(a).finish(&d, &srs, &h).is_err());
            assert!(d.point(Scheme::Lrdas, ell, 0).is_err());
            assert!(d.point(Scheme::Lrdas, 0, m).is_err());
            let mut collector = StreamingCollector::new(a);
            let mut cache = GroupCache::new(&h, &d);
            let x = d.point(Scheme::Lrdas, a, 0).unwrap();
            let raw = srs.open(&enc.locals[a], &[x]).unwrap().to_bytes(r).unwrap();
            collector.accept(&d, &srs, &h, &mut cache, 0, &raw).unwrap();
            assert!(collector.accept(&d, &srs, &h, &mut cache, 0, &raw).is_err());
            if b > 0 {
                assert_eq!(&enc.locals[a][..b], &msg[a * r..]);
            }
        }
    }
    assert!(serde_json::from_str::<Params>(r#"{"ell":6,"m":16,"r":0,"a":4,"b":0}"#).is_err());
}

#[test]
fn independent_verification_rejects_cancelling_errors() {
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    let (d, srs) = small();
    let p = d.params();
    let enc = encode(&d, &srs, Scheme::Lrdas, &fixture::message(p, 83)).unwrap();
    let x = d.point(Scheme::Lrdas, p.a(), 0).unwrap();
    let c = srs.commit(&enc.locals[p.a()]).unwrap();
    let good = srs.open(&enc.locals[p.a()], &[x]).unwrap();
    let mut plus = good.clone();
    let mut minus = good;
    plus.values[0] += Fr::one();
    minus.values[0] -= Fr::one();
    assert!(srs.verify(c, &[x], &plus).is_err());
    assert!(srs.verify(c, &[x], &minus).is_err());
    let l1 = c.into_group() - G1Projective::generator() * plus.values[0];
    let l2 = c.into_group() - G1Projective::generator() * minus.values[0];
    let z = srs.commit_g2(&[-x, Fr::one()]).unwrap();
    // Demonstrate that unweighted aggregation WOULD accept the two invalid claims.
    let bad_aggregate = Bls12_381::multi_pairing(
        [
            l1.into_affine(),
            (-plus.proof.into_group()).into_affine(),
            l2.into_affine(),
            (-minus.proof.into_group()).into_affine(),
        ],
        [srs.g2()[0], z, srs.g2()[0], z],
    );
    assert!(bad_aggregate.0.is_one());
}
