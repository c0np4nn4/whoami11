use crate::{polynomial, require, Error, Result};
use ark_bls12_381::Fr;
use ark_ff::{batch_inversion, Field, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use std::collections::HashSet;

fn trim(mut p: Vec<Fr>) -> Vec<Fr> {
    while p.last().is_some_and(Zero::is_zero) {
        p.pop();
    }
    p
}
pub fn multiply(a: &[Fr], b: &[Fr]) -> Result<Vec<Fr>> {
    if a.is_empty() || b.is_empty() {
        return Ok(vec![]);
    }
    let len = a
        .len()
        .checked_add(b.len())
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| Error("convolution size overflow".into()))?;
    require(len <= 4_194_305, "convolution size limit")?;
    if a.len().min(b.len()) <= 8 || len <= 128 {
        let mut c = vec![Fr::zero(); len];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                c[i + j] += *x * y;
            }
        }
        return Ok(trim(c));
    }
    let fft = Radix2EvaluationDomain::<Fr>::new(len)
        .ok_or_else(|| Error("convolution FFT size".into()))?;
    let mut x = fft.fft(a);
    for (x, y) in x.iter_mut().zip(fft.fft(b)) {
        *x *= y;
    }
    fft.ifft_in_place(&mut x);
    x.truncate(len);
    Ok(trim(x))
}
fn inverse_series(p: &[Fr], n: usize) -> Result<Vec<Fr>> {
    let mut g = vec![p
        .first()
        .and_then(Field::inverse)
        .ok_or_else(|| Error("noninvertible series".into()))?];
    while g.len() < n {
        let size = (2 * g.len()).min(n);
        let mut fg = multiply(&p[..p.len().min(size)], &g)?;
        fg.resize(size, Fr::zero());
        fg.truncate(size);
        for x in &mut fg {
            *x = -*x;
        }
        fg[0] += Fr::from(2u64);
        g = multiply(&g, &fg)?;
        g.resize(size, Fr::zero());
        g.truncate(size);
    }
    Ok(g)
}
pub fn remainder(a: &[Fr], b: &[Fr]) -> Result<Vec<Fr>> {
    let a = trim(a.to_vec());
    let b = trim(b.to_vec());
    require(!b.is_empty(), "zero divisor")?;
    if a.len() < b.len() {
        return Ok(a);
    }
    if b.len() == 1 {
        return Ok(vec![]);
    }
    let qlen = a.len() - b.len() + 1;
    if b.len() <= 65 || qlen <= 32 {
        let mut rem = a;
        let inv = b.last().unwrap().inverse().unwrap();
        for i in (b.len() - 1..rem.len()).rev() {
            let c = rem[i] * inv;
            for (j, x) in b.iter().enumerate() {
                rem[i + 1 - b.len() + j] -= c * x;
            }
        }
        rem.truncate(b.len() - 1);
        return Ok(trim(rem));
    }
    let ar: Vec<_> = a.iter().rev().take(qlen).copied().collect();
    let br: Vec<_> = b.iter().rev().take(qlen).copied().collect();
    let mut q = multiply(&ar, &inverse_series(&br, qlen)?)?;
    q.resize(qlen, Fr::zero());
    q.truncate(qlen);
    q.reverse();
    let qb = multiply(&q, &b)?;
    let mut rem = a;
    for (v, x) in rem.iter_mut().zip(qb) {
        *v -= x;
    }
    require(
        rem[b.len() - 1..].iter().all(Zero::is_zero),
        "fast division identity",
    )?;
    rem.truncate(b.len() - 1);
    Ok(trim(rem))
}
const LEAF: usize = 32;
pub struct ProductTree {
    xs: Vec<Fr>,
    levels: Vec<Vec<Vec<Fr>>>,
}
impl ProductTree {
    pub fn new(xs: &[Fr]) -> Result<Self> {
        require(!xs.is_empty() && xs.len() <= 1_048_576, "product tree size")?;
        let set: HashSet<_> = xs.iter().copied().collect();
        require(set.len() == xs.len(), "duplicate coordinates")?;
        let mut levels = vec![xs
            .chunks(LEAF)
            .map(polynomial::vanishing)
            .collect::<Result<Vec<_>>>()?];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|pair| {
                    if pair.len() == 1 {
                        Ok(pair[0].clone())
                    } else {
                        multiply(&pair[0], &pair[1])
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            levels.push(next);
        }
        Ok(Self {
            xs: xs.to_vec(),
            levels,
        })
    }
    pub fn evaluate(&self, p: &[Fr]) -> Result<Vec<Fr>> {
        let mut remainders = vec![remainder(p, &self.levels.last().unwrap()[0])?];
        for level in self.levels[..self.levels.len() - 1].iter().rev() {
            remainders = level
                .iter()
                .enumerate()
                .map(|(i, z)| remainder(&remainders[i / 2], z))
                .collect::<Result<Vec<_>>>()?;
        }
        Ok(self
            .xs
            .iter()
            .enumerate()
            .map(|(i, x)| polynomial::evaluate(&remainders[i / LEAF], *x))
            .collect())
    }
    pub fn interpolate(&self, ys: &[Fr]) -> Result<Vec<Fr>> {
        require(ys.len() == self.xs.len(), "tree interpolation lengths")?;
        let root = &self.levels.last().unwrap()[0];
        let derivative: Vec<_> = root
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, x)| *x * Fr::from(i as u64))
            .collect();
        let mut inverse = self.evaluate(&derivative)?;
        require(inverse.iter().all(|x| !x.is_zero()), "tree derivative zero")?;
        batch_inversion(&mut inverse);
        let mut polys = Vec::with_capacity(self.levels[0].len());
        for (leaf, xs) in self.xs.chunks(LEAF).enumerate() {
            let mut out = vec![Fr::zero(); xs.len()];
            for (i, x) in xs.iter().enumerate() {
                let idx = leaf * LEAF + i;
                let (q, _) = polynomial::divide_linear(&self.levels[0][leaf], *x);
                for (out, c) in out.iter_mut().zip(q) {
                    *out += c * ys[idx] * inverse[idx];
                }
            }
            polys.push(out);
        }
        for level in &self.levels[..self.levels.len() - 1] {
            let mut next = Vec::with_capacity(polys.len().div_ceil(2));
            for i in (0..polys.len()).step_by(2) {
                if i + 1 == polys.len() {
                    next.push(polys[i].clone());
                    continue;
                }
                let mut left = multiply(&polys[i], &level[i + 1])?;
                let right = multiply(&polys[i + 1], &level[i])?;
                left.resize(left.len().max(right.len()), Fr::zero());
                for (l, r) in left.iter_mut().zip(right) {
                    *l += r;
                }
                next.push(trim(left));
            }
            polys = next;
        }
        let mut out = polys.pop().unwrap();
        out.resize(ys.len(), Fr::zero());
        Ok(out)
    }
}
