//! Erasure masks and a constructive ambiguity witness for the product code.
//! The witness concerns surviving field symbols, not two openings of one header.
use crate::{
    domain::{Domain, Params, Scheme},
    polynomial,
    protocol::MessagePolys,
    recovery::AcceptedValue,
    require, Result,
};
use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use std::collections::HashSet;

/// A checked set of erased coordinates, independent of the code's values.
#[derive(Clone)]
pub struct ErasureMask {
    params: Params,
    erased: Vec<bool>,
}
impl ErasureMask {
    /// Reject duplicate and out-of-domain positions before allocating a fixture.
    pub fn new(params: Params, positions: &[(usize, usize)]) -> Result<Self> {
        let mut erased = vec![false; params.n()];
        for &(j, i) in positions {
            require(j < params.ell() && i < params.m(), "erasure coordinate")?;
            let slot = &mut erased[j * params.m() + i];
            require(!*slot, "duplicate erasure coordinate")?;
            *slot = true;
        }
        Ok(Self { params, erased })
    }
    /// Query membership with domain bounds checking.
    pub fn contains(&self, group: usize, index: usize) -> Result<bool> {
        require(
            group < self.params.ell() && index < self.params.m(),
            "erasure coordinate",
        )?;
        Ok(self.erased[group * self.params.m() + index])
    }
    /// Restore one erased symbol to form a distance-boundary control.
    pub fn restore(&mut self, group: usize, index: usize) -> Result<()> {
        require(self.contains(group, index)?, "symbol is not erased")?;
        self.erased[group * self.params.m() + index] = false;
        Ok(())
    }
    /// Number of erased symbols.
    pub fn count(&self) -> usize {
        self.erased.iter().filter(|x| **x).count()
    }
    /// Canonical row-major mask bytes for fixture hashes.
    pub fn bytes(&self) -> Vec<u8> {
        self.erased.iter().map(|x| u8::from(*x)).collect()
    }
    /// The survivor counts per local group and per product row.
    pub fn survivor_counts(&self) -> (Vec<usize>, Vec<usize>) {
        let mut groups = vec![0; self.params.ell()];
        let mut rows = vec![0; self.params.m()];
        for (j, group) in groups.iter_mut().enumerate() {
            for (i, row) in rows.iter_mut().enumerate() {
                if !self.erased[j * self.params.m() + i] {
                    *group += 1;
                    *row += 1;
                }
            }
        }
        (groups, rows)
    }
    /// Select only received values. No producer state is passed to the decoder.
    pub fn retain(&self, values: &[Vec<Fr>]) -> Result<Vec<AcceptedValue>> {
        require(
            values.len() == self.params.ell() && values.iter().all(|v| v.len() == self.params.m()),
            "codeword shape",
        )?;
        Ok(values
            .iter()
            .enumerate()
            .flat_map(|(j, group)| {
                group.iter().enumerate().filter_map(move |(i, &value)| {
                    (!self.erased[j * self.params.m() + i]).then_some(AcceptedValue {
                        group: j,
                        index: i,
                        value,
                    })
                })
            })
            .collect())
    }
}
/// Construct a minimum-distance rectangle with exactly ell-a+1 groups and m-r+1 indices.
pub fn rectangle(domain: &Domain, groups: &[usize], indices: &[usize]) -> Result<ErasureMask> {
    let p = domain.params();
    require(p.b() == 0, "rectangle requires b=0")?;
    require(
        groups.len() == p.ell() - p.a() + 1 && indices.len() == p.m() - p.r() + 1,
        "rectangle dimensions",
    )?;
    let positions: Vec<_> = groups
        .iter()
        .flat_map(|j| indices.iter().map(move |i| (*j, *i)))
        .collect();
    ErasureMask::new(p, &positions)
}
/// Two-message difference that vanishes at every surviving product-code coordinate.
pub struct ProductWitness {
    /// Nonzero source-message difference, ordered exactly as the protocol API.
    pub message: Vec<Fr>,
    /// Its product-code encoding. Support is exactly the erased rectangle.
    pub values: Vec<Vec<Fr>>,
}
/// Construct q(Y)p(X), vanishing outside the rectangle on each axis.
/// q has degree a-1, p has degree r-1; this is a nonzero valid product codeword.
pub fn product_witness(
    domain: &Domain,
    groups: &[usize],
    indices: &[usize],
) -> Result<ProductWitness> {
    let mask = rectangle(domain, groups, indices)?;
    let p = domain.params();
    let gs: HashSet<_> = groups.iter().copied().collect();
    let is: HashSet<_> = indices.iter().copied().collect();
    let outer_roots: Vec<_> = (0..p.ell())
        .filter(|j| !gs.contains(j))
        .map(|j| domain.gammas()[j])
        .collect();
    let inner_roots: Vec<_> = (0..p.m())
        .filter(|i| !is.contains(i))
        .map(|i| domain.point(Scheme::Product, 0, i))
        .collect::<Result<_>>()?;
    let q = polynomial::vanishing(&outer_roots)?;
    let poly = polynomial::vanishing(&inner_roots)?;
    let message: Vec<_> = (0..p.a())
        .flat_map(|j| {
            let w = polynomial::evaluate(&q, domain.gammas()[j]);
            poly.iter().map(move |c| w * c)
        })
        .collect();
    require(
        message.len() == p.k() && message.iter().any(|x| !x.is_zero()),
        "zero witness",
    )?;
    let locals = MessagePolys::new(domain, &message)?.locals(domain)?;
    let values = locals
        .iter()
        .enumerate()
        .map(|(j, v)| domain.evaluate(Scheme::Product, j, v))
        .collect::<Result<Vec<_>>>()?;
    for (j, row) in values.iter().enumerate() {
        for (i, value) in row.iter().enumerate() {
            // Direct factor evaluation is an independent check on the encoding path.
            let x = domain.point(Scheme::Product, j, i)?;
            let direct = outer_roots
                .iter()
                .fold(Fr::one(), |z, y| z * (domain.gammas()[j] - y))
                * inner_roots.iter().fold(Fr::one(), |z, y| z * (x - y));
            require(*value == direct, "witness factor/encoding mismatch")?;
            require(
                value.is_zero() != mask.contains(j, i)?,
                "witness support mismatch",
            )?;
        }
    }
    Ok(ProductWitness { message, values })
}
