use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, UniformRand, Zero};
use lrdas_artifact::{
    bytes,
    domain::{Domain, Params, Scheme},
    fast_polynomial::{self, ProductTree},
    fixture,
    kzg::Opening,
    polynomial,
    protocol::{encode, Header},
    recovery::*,
    variants::{supplied_aux, ProfileBHeader, SuppliedAux, SuppliedHeader},
};

#[test]
fn fast_interpolation_matches_independent_values_and_naive_oracle() {
    let mut rng = fixture::rng(21, "fast-test");
    for n in [1, 2, 31, 32, 33, 64, 129, 257, 513, 1025] {
        let xs: Vec<_> = (1..=n).map(|i| Fr::from(i as u64)).collect();
        let mut coeffs: Vec<_> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        if n % 2 == 1 {
            coeffs[n - 1] = Fr::zero();
        }
        let ys: Vec<_> = xs
            .iter()
            .map(|x| polynomial::evaluate(&coeffs, *x))
            .collect();
        let tree = ProductTree::new(&xs).unwrap();
        assert_eq!(tree.evaluate(&coeffs).unwrap(), ys);
        assert_eq!(tree.interpolate(&ys).unwrap(), coeffs);
        if n <= 129 {
            assert_eq!(polynomial::interpolate(&xs, &ys).unwrap(), coeffs);
        }
    }
    assert!(ProductTree::new(&[Fr::one(), Fr::one()]).is_err());
    let xs: Vec<_> = (1..=137).map(Fr::from).collect();
    let z = polynomial::vanishing(&xs).unwrap();
    let a: Vec<_> = (0..291).map(|_| Fr::rand(&mut rng)).collect();
    let r = fast_polynomial::remainder(&a, &z).unwrap();
    for x in xs {
        assert_eq!(polynomial::evaluate(&a, x), polynomial::evaluate(&r, x));
    }
}

#[test]
fn profile_b_checks_honest_headers_and_rejects_degree_mutations() {
    for b in [0, 1, 3, 11] {
        let p = Params::new(6, 16, 12, 4, b).unwrap();
        let d = Domain::new(p).unwrap();
        let srs = fixture::long_setup(p, 41).unwrap();
        let message = fixture::message(p, 42);
        let header = ProfileBHeader::commit(&d, &srs, Scheme::Lrdas, &message).unwrap();
        let raw = header.payload().unwrap();
        let parsed =
            ProfileBHeader::from_payload(&d, &srs, Scheme::Lrdas, header.context(), &raw).unwrap();
        let mut rng = fixture::rng(43, "verifier");
        let verified = parsed.verify(&d, &srs, &mut rng).unwrap();
        let f = global_from_message(&d, &message).unwrap();
        let locals = local_coefficients(&d, &f).unwrap();
        for (j, local) in locals.iter().enumerate() {
            assert_eq!(
                verified.group(&d, j).unwrap().commitment(),
                srs.local().commit(local).unwrap()
            );
        }
        let mut bad = raw.clone();
        bad[0..48].copy_from_slice(&bytes(&srs.g1()[p.r()]).unwrap());
        assert!(
            ProfileBHeader::from_payload(&d, &srs, Scheme::Lrdas, header.context(), &bad)
                .unwrap()
                .verify(&d, &srs, &mut rng)
                .is_err()
        );
        if b > 0 {
            // The manuscript's residual attack uses X^b with the source shift.
            let mut bad = raw.clone();
            bad[p.a() * 48..(p.a() + 1) * 48].copy_from_slice(&bytes(&srs.g1()[b]).unwrap());
            let exponent = srs.degree() - p.r() + 1 + b;
            let last = bad.len() - 48;
            bad[last..].copy_from_slice(&bytes(&srs.g1()[exponent]).unwrap());
            assert!(
                ProfileBHeader::from_payload(&d, &srs, Scheme::Lrdas, header.context(), &bad)
                    .unwrap()
                    .verify(&d, &srs, &mut rng)
                    .is_err()
            );
        }
        assert!(ProfileBHeader::from_payload(&d, &srs, Scheme::Lrdas, [0; 32], &raw).is_err());
        assert!(ProfileBHeader::from_payload(
            &d,
            &srs,
            Scheme::Lrdas,
            header.context(),
            &raw[..raw.len() - 1]
        )
        .is_err());
    }
}

#[test]
fn proposition_3_attack_passes_openings_but_fails_code_binding() {
    let p = Params::smoke();
    let d = Domain::new(p).unwrap();
    let long = fixture::long_setup(p, 61).unwrap();
    let local = long.local();
    // This intentionally misuses a long prefix as Profile A to reproduce the attack.
    let honest = encode(&d, local, Scheme::Lrdas, &fixture::message(p, 62)).unwrap();
    let raw = bytes(&long.g1()[p.r()]).unwrap().repeat(p.a());
    let evil = Header::from_payload(&d, local, Scheme::Lrdas, honest.header.context(), &raw)
        .unwrap()
        .verify(&d, local)
        .unwrap();
    let mut polynomial = vec![Fr::zero(); p.r() + 1];
    polynomial[p.r()] = Fr::one();
    let c = evil.derive(&d, 0).unwrap();
    for i in 0..=p.r() {
        let x = d.point(Scheme::Lrdas, 0, i).unwrap();
        let (q, _) = polynomial::divide_linear(&polynomial, x);
        let opening = Opening {
            values: vec![x.pow([p.r() as u64])],
            proof: local.commit(&q).unwrap(),
        };
        local.verify(c, &[x], &opening).unwrap();
    }
    let xs: Vec<_> = (0..p.r())
        .map(|i| d.point(Scheme::Lrdas, 0, i).unwrap())
        .collect();
    let ys: Vec<_> = xs.iter().map(|x| x.pow([p.r() as u64])).collect();
    let interp = polynomial::interpolate(&xs, &ys).unwrap();
    assert_ne!(local.commit(&interp).unwrap(), c);
    assert_ne!(
        polynomial::evaluate(&interp, d.point(Scheme::Lrdas, 0, p.r()).unwrap()),
        d.point(Scheme::Lrdas, 0, p.r())
            .unwrap()
            .pow([p.r() as u64])
    );
}

#[test]
fn supplied_counterexample_and_full_degree_check() {
    let p = Params::smoke();
    let d = Domain::new(p).unwrap();
    let long = fixture::long_setup(p, 71).unwrap();
    let j = p.a();
    let header = SuppliedHeader::commit(&d, &long, &[Fr::zero()]).unwrap();
    let mut h = vec![Fr::zero(); p.m() + 1];
    h[0] = -d.gammas()[j];
    h[p.m()] = Fr::one();
    let attack = SuppliedAux {
        local: long.commit(&h).unwrap(),
        quotient: long.commit(&[-Fr::one()]).unwrap(),
        shifted: G1Affine::zero(),
    };
    assert!(header.link_equation_holds(&d, &long, j, &attack).unwrap());
    let x = d.point(Scheme::Lrdas, j, 0).unwrap();
    let opening = Opening {
        values: vec![Fr::zero()],
        proof: long.commit(&polynomial::divide_linear(&h, x).0).unwrap(),
    };
    long.local().verify(attack.local, &[x], &opening).unwrap();
    let regenerated = Opening {
        values: vec![Fr::zero()],
        proof: G1Affine::zero(),
    };
    assert!(long
        .local()
        .verify(attack.local, &[x], &regenerated)
        .is_err());
    assert!(header.verify_group(&d, &long, j, &attack).is_err());
    assert!(SuppliedAux::from_payload(&[]).is_err());
}

#[test]
fn supplied_receiver_recovers_and_serves_without_producer_state() {
    for b in [0, 1, 11] {
        let p = Params::new(6, 16, 12, 4, b).unwrap();
        let d = Domain::new(p).unwrap();
        let long = fixture::long_setup(p, 81).unwrap();
        let message = fixture::message(p, 82);
        let f = global_from_message(&d, &message).unwrap();
        let locals = local_coefficients(&d, &f).unwrap();
        let header = SuppliedHeader::commit(&d, &long, &f).unwrap();
        for j in [0, p.a(), p.ell() - 1] {
            let aux = supplied_aux(&d, &long, &f, &locals[j], j).unwrap();
            let raw = aux.payload().unwrap();
            let group = header
                .verify_group(&d, &long, j, &SuppliedAux::from_payload(&raw).unwrap())
                .unwrap();
            let indices: Vec<_> = (0..p.r()).rev().collect();
            let values = indices
                .iter()
                .map(|i| polynomial::evaluate(&f, d.point(Scheme::Lrdas, j, *i).unwrap()))
                .collect::<Vec<_>>();
            let receiver = group.certify(&d, long.local(), &indices, &values).unwrap();
            let opening = receiver.serve(&d, long.local(), p.m() - 1).unwrap();
            group.verify(&d, long.local(), p.m() - 1, &opening).unwrap();
            assert_eq!(
                receiver.recover(&d).unwrap(),
                d.evaluate(Scheme::Lrdas, j, &locals[j]).unwrap()
            );
            let state = header
                .certify_group(&d, &long, j, &aux, &indices, &values)
                .unwrap();
            let reply = state.serve_reply(&d, long.local(), p.m() - 1).unwrap();
            header
                .verify_reply(&d, &long, j, p.m() - 1, &reply)
                .unwrap();
            assert!(header
                .verify_reply(&d, &long, j, p.m() - 1, &reply[144..])
                .is_err());
            let mut bad = aux.clone();
            bad.quotient = (bad.quotient.into_group() + G1Affine::generator()).into_affine();
            assert!(header.verify_group(&d, &long, j, &bad).is_err());
            let wrong = (j + 1) % p.ell();
            assert!(header.verify_group(&d, &long, wrong, &aux).is_err());
        }
    }
}

#[test]
fn proposition_7_reconstruction_and_proof_repair() {
    let p = Params::smoke();
    let d = Domain::new(p).unwrap();
    let srs = fixture::setup(p.r(), 91).unwrap();
    let message = fixture::message(p, 92);
    let (groups, rows) = pattern_counts(p).unwrap();
    assert!(groups.iter().all(|n| *n == p.r() - 1));
    assert!(rows.iter().all(|n| *n >= p.a()));
    for scheme in [Scheme::Lrdas, Scheme::Product] {
        let enc = encode(&d, &srs, scheme, &message).unwrap();
        let h = enc.header.clone().verify(&d, &srs).unwrap();
        let received = surviving_values(&d, &enc.values).unwrap();
        let rec = if scheme == Scheme::Lrdas {
            recover_global(&d, &received)
        } else {
            recover_product_rows(&d, &received)
        }
        .unwrap();
        assert_eq!(rec.message(), message);
        assert_eq!(rec.values(), enc.values);
        rec.authenticate(&d, &srs, &h).unwrap();
        let mut bad = received.clone();
        bad.last_mut().unwrap().value += Fr::one();
        assert!(if scheme == Scheme::Lrdas {
            recover_global(&d, &bad)
        } else {
            recover_product_rows(&d, &bad)
        }
        .is_err());
        if scheme == Scheme::Lrdas {
            assert!(recover_global(&d, &received[..p.degree()]).is_err());
            let mut bad = received.clone();
            bad[1] = bad[0];
            assert!(recover_global(&d, &bad).is_err());
        } else {
            let target = p.a();
            let index = p.m() * target / p.ell();
            assert!(erased(p, target, index).unwrap());
            let helpers: Vec<_> = (0..p.ell())
                .filter(|j| !erased(p, *j, index).unwrap())
                .take(p.a())
                .map(|j| {
                    (
                        j,
                        srs.open(&enc.locals[j], &[d.point(scheme, j, index).unwrap()])
                            .unwrap(),
                    )
                })
                .collect();
            let repaired = repair_product_point(&d, &srs, &h, target, index, &helpers).unwrap();
            assert_eq!(repaired.values, vec![enc.values[target][index]]);
            let mut bad = helpers.clone();
            bad[0].1.values[0] += Fr::one();
            assert!(repair_product_point(&d, &srs, &h, target, index, &bad).is_err());
        }
    }
    let (groups, rows) = pattern_counts(Params::reference()).unwrap();
    assert!(groups.iter().all(|n| *n == 767));
    assert_eq!(*rows.iter().min().unwrap(), 92);
}
