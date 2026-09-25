use crate::{require, Error, Result};
use ark_bls12_381::Fr;
use ark_ff::{batch_inversion, Field, One, Zero};
pub fn evaluate(p: &[Fr], x: Fr) -> Fr {
    p.iter().rev().fold(Fr::zero(), |v, c| v * x + c)
}
pub fn vanishing(xs: &[Fr]) -> Result<Vec<Fr>> {
    let mut p = vec![Fr::one()];
    for (i, &x) in xs.iter().enumerate() {
        require(!xs[..i].contains(&x), "duplicate coordinates")?;
        p.push(Fr::zero());
        for k in (1..p.len()).rev() {
            p[k] = p[k - 1] - x * p[k];
        }
        p[0] *= -x;
    }
    Ok(p)
}
pub fn divide_linear(p: &[Fr], x: Fr) -> (Vec<Fr>, Fr) {
    if p.len() < 2 {
        return (vec![], p.first().copied().unwrap_or_default());
    }
    let mut q = vec![Fr::zero(); p.len() - 1];
    let mut c = p[p.len() - 1];
    for i in (1..p.len()).rev() {
        q[i - 1] = c;
        c = p[i - 1] + x * c;
    }
    (q, c)
}
pub fn interpolate(xs: &[Fr], ys: &[Fr]) -> Result<Vec<Fr>> {
    require(
        !xs.is_empty() && xs.len() == ys.len(),
        "interpolation lengths",
    )?;
    let z = vanishing(xs)?;
    let deriv: Vec<_> = z
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, c)| *c * Fr::from(i as u64))
        .collect();
    let mut inv: Vec<_> = xs.iter().map(|x| evaluate(&deriv, *x)).collect();
    require(
        inv.iter().all(|v| !v.is_zero()),
        "interpolation denominator",
    )?;
    batch_inversion(&mut inv);
    let mut out = vec![Fr::zero(); xs.len()];
    for ((&x, &y), &d) in xs.iter().zip(ys).zip(&inv) {
        let (q, _) = divide_linear(&z, x);
        let w = y * d;
        for (o, c) in out.iter_mut().zip(q) {
            *o += c * w;
        }
    }
    Ok(out)
}
pub fn divide_exact(p: &[Fr], z: &[Fr]) -> Result<Vec<Fr>> {
    require(
        !z.is_empty() && z.last() == Some(&Fr::one()),
        "divisor must be monic",
    )?;
    if p.len() < z.len() {
        require(p.iter().all(Zero::is_zero), "nonzero remainder")?;
        return Ok(vec![]);
    }
    let d = z.len() - 1;
    let mut rem = p.to_vec();
    let mut q = vec![Fr::zero(); p.len() - d];
    for i in (d..p.len()).rev() {
        let c = rem[i];
        q[i - d] = c;
        for j in 0..=d {
            rem[i - d + j] -= c * z[j];
        }
    }
    require(rem.iter().all(Zero::is_zero), "nonzero remainder")?;
    Ok(q)
}
pub fn residual_from_values(xs: &[Fr], ys: &[Fr], base: &[Fr], weights: &[Fr]) -> Result<Vec<Fr>> {
    require(
        xs.len() == ys.len() && ys.len() == base.len() && base.len() == weights.len(),
        "residual lengths",
    )?;
    let values = ys
        .iter()
        .zip(base)
        .zip(weights)
        .map(|((&y, &f), &b)| {
            b.inverse()
                .map(|inv| (y - f) * inv)
                .ok_or_else(|| Error("residual at source group".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    interpolate(xs, &values)
}
