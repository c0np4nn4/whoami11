//! Independent checks for coding ambiguity and receiver-side recovery.
use ark_bls12_381::Fr;
use ark_ff::{Field, One, Zero};
use lrdas_artifact::{
    domain::{Domain, Params, Scheme},
    fixture,
    protocol::{self, MessagePolys},
    recovery::{self, AcceptedValue},
    separation::{self, ErasureMask},
};
fn rank(mut matrix: Vec<Vec<Fr>>, columns: usize) -> usize {
    let mut pivot = 0;
    for c in 0..columns {
        let Some(i) = (pivot..matrix.len()).find(|i| !matrix[*i][c].is_zero()) else {
            continue;
        };
        matrix.swap(pivot, i);
        let inv = matrix[pivot][c].inverse().unwrap();
        for v in &mut matrix[pivot] {
            *v *= inv;
        }
        let row = matrix[pivot].clone();
        for (i, values) in matrix.iter_mut().enumerate() {
            if i == pivot {
                continue;
            }
            let scale = values[c];
            for (v, x) in values.iter_mut().zip(&row) {
                *v -= scale * x;
            }
        }
        pivot += 1;
        if pivot == matrix.len() {
            break;
        }
    }
    pivot
}
fn survivor_rank(d: &Domain, scheme: Scheme, mask: &ErasureMask) -> usize {
    let p = d.params();
    let positions: Vec<_> = (0..p.ell())
        .flat_map(|j| (0..p.m()).map(move |i| (j, i)))
        .filter(|(j, i)| !mask.contains(*j, *i).unwrap())
        .collect();
    let mut matrix = vec![vec![Fr::zero(); p.k()]; positions.len()];
    for c in 0..p.k() {
        let mut message = vec![Fr::zero(); p.k()];
        message[c] = Fr::one();
        let locals = MessagePolys::new(d, &message).unwrap().locals(d).unwrap();
        for (row, (j, i)) in positions.iter().enumerate() {
            // Horner, independent of FFT evaluation used by the benchmark.
            let x = d.point(scheme, *j, *i).unwrap();
            matrix[row][c] = locals[*j]
                .iter()
                .rev()
                .fold(Fr::zero(), |acc, v| acc * x + v);
        }
    }
    rank(matrix, p.k())
}
#[test]
fn rectangle_has_exactly_one_missing_dimension_and_restoring_one_symbol_fixes_it() {
    let p = Params::new(5, 8, 6, 3, 0).unwrap();
    let d = Domain::new(p).unwrap();
    // Mix source and parity groups; group shortcut must not assume source indices.
    let gs = [0, 3, 4];
    let is = [0, 3, 7];
    let rect = separation::rectangle(&d, &gs, &is).unwrap();
    assert_eq!(rect.count(), p.distance(Scheme::Product).unwrap());
    assert!(rect.count() < p.distance(Scheme::Lrdas).unwrap());
    let w = separation::product_witness(&d, &gs, &is).unwrap();
    assert!(w.message.iter().any(|v| !v.is_zero()));
    assert_eq!(survivor_rank(&d, Scheme::Product, &rect), p.k() - 1);
    assert_eq!(survivor_rank(&d, Scheme::Lrdas, &rect), p.k());
    let mut restored = rect.clone();
    restored.restore(gs[1], is[1]).unwrap();
    assert!(!w.values[gs[1]][is[1]].is_zero());
    assert_eq!(survivor_rank(&d, Scheme::Product, &restored), p.k());
    assert_eq!(survivor_rank(&d, Scheme::Lrdas, &restored), p.k());
}
#[test]
fn receiver_recovers_both_controls_and_authenticates_full_outputs() {
    for p in [Params::new(5, 8, 6, 3, 0).unwrap(), Params::smoke()] {
        let d = Domain::new(p).unwrap();
        let srs = fixture::setup(p.r(), 91).unwrap();
        let gs: Vec<_> = (p.a() - 1..p.ell()).collect();
        let is: Vec<_> = (p.r() - 1..p.m()).collect();
        let mask = separation::rectangle(&d, &gs, &is).unwrap();
        let mut boundary = mask.clone();
        boundary.restore(gs[0], is[0]).unwrap();
        let message = fixture::message(p, 19);
        for scheme in [Scheme::Lrdas, Scheme::Product] {
            let enc = protocol::encode(&d, &srs, scheme, &message).unwrap();
            let header = enc.header.clone().verify(&d, &srs).unwrap();
            let received = boundary.retain(&enc.values).unwrap();
            let rec = recovery::recover_groups(&d, scheme, &received).unwrap();
            assert_eq!(rec.message(), message);
            assert_eq!(rec.values(), enc.values);
            rec.authenticate(&d, &srs, &header).unwrap();
            let missing = mask.retain(&enc.values).unwrap();
            assert!(recovery::recover_groups(&d, scheme, &missing).is_err());
            if scheme == Scheme::Lrdas {
                let rec = recovery::recover_global(&d, &missing).unwrap();
                assert_eq!(rec.message(), message);
                assert_eq!(rec.values(), enc.values);
                rec.authenticate(&d, &srs, &header).unwrap();
            } else {
                assert!(recovery::recover_product_rows(&d, &missing).is_err());
            }
            let mut bad = received.clone();
            bad.push(received[0]);
            assert!(recovery::recover_groups(&d, scheme, &bad).is_err());
            let mut bad = received.clone();
            bad[0].value += Fr::one();
            let rejected = match recovery::recover_groups(&d, scheme, &bad) {
                Err(_) => true,
                Ok(rec) => rec.authenticate(&d, &srs, &header).is_err(),
            };
            assert!(
                rejected,
                "altered survivor must not yield authenticated output"
            );
            let invalid = [AcceptedValue {
                group: p.ell(),
                index: 0,
                value: Fr::zero(),
            }];
            assert!(recovery::recover_groups(&d, scheme, &invalid).is_err());
        }
    }
}
#[test]
fn malformed_masks_and_unsupported_dimensions_are_rejected() {
    let p = Params::smoke();
    let d = Domain::new(p).unwrap();
    assert!(ErasureMask::new(p, &[(0, 0), (0, 0)]).is_err());
    assert!(ErasureMask::new(p, &[(p.ell(), 0)]).is_err());
    assert!(ErasureMask::new(p, &[(0, p.m())]).is_err());
    let mut empty = ErasureMask::new(p, &[]).unwrap();
    assert!(empty.restore(0, 0).is_err());
    assert!(empty.retain(&[]).is_err());
    assert!(separation::rectangle(&d, &[0, 0, 1], &[0, 1, 2, 3, 4]).is_err());
    assert!(separation::product_witness(&d, &[0], &[0]).is_err());
    let residual = Domain::new(Params::new(6, 16, 12, 4, 1).unwrap()).unwrap();
    assert!(separation::rectangle(&residual, &[0, 1, 2], &[0, 1, 2, 3, 4]).is_err());
    assert!(recovery::recover_groups(&residual, Scheme::Lrdas, &[]).is_err());
}
