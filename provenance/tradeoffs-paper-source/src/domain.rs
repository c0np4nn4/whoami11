use crate::{require, Error, Result};
use ark_bls12_381::Fr;
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct Params {
    ell: usize,
    m: usize,
    r: usize,
    a: usize,
    b: usize,
}
impl<'de> Deserialize<'de> for Params {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            ell: usize,
            m: usize,
            r: usize,
            a: usize,
            b: usize,
        }
        let v = Input::deserialize(deserializer)?;
        Self::new(v.ell, v.m, v.r, v.a, v.b).map_err(serde::de::Error::custom)
    }
}
impl Params {
    pub fn new(ell: usize, m: usize, r: usize, a: usize, b: usize) -> Result<Self> {
        require(
            ell > 0 && ell <= 4096 && m.is_power_of_two() && m <= 16384,
            "unsupported domain size",
        )?;
        require(
            r >= 2 && r < m && a >= 1 && a <= ell && b < r && (b == 0 || a < ell),
            "invalid code dimensions",
        )?;
        let n = ell
            .checked_mul(m)
            .ok_or_else(|| Error("size overflow".into()))?;
        require(n <= 4_194_304, "experiment size limit exceeded")?;
        require(
            Fr::get_root_of_unity(m as u64).is_some(),
            "no inner root of unity",
        )?;
        Ok(Self { ell, m, r, a, b })
    }
    pub fn validate(self) -> Result<Self> {
        Self::new(self.ell, self.m, self.r, self.a, self.b)
    }
    pub fn reference() -> Self {
        Self {
            ell: 123,
            m: 1024,
            r: 768,
            a: 82,
            b: 0,
        }
    }
    pub fn smoke() -> Self {
        Self {
            ell: 6,
            m: 16,
            r: 12,
            a: 4,
            b: 0,
        }
    }
    pub fn ell(self) -> usize {
        self.ell
    }
    pub fn m(self) -> usize {
        self.m
    }
    pub fn r(self) -> usize {
        self.r
    }
    pub fn a(self) -> usize {
        self.a
    }
    pub fn b(self) -> usize {
        self.b
    }
    pub fn n(self) -> usize {
        self.ell * self.m
    }
    pub fn k(self) -> usize {
        self.a * self.r + self.b
    }
    pub fn degree(self) -> usize {
        self.k() - 1 + (self.k().div_ceil(self.r) - 1) * (self.m - self.r)
    }
    pub fn distance(self, scheme: Scheme) -> Result<usize> {
        match scheme {
            Scheme::Lrdas => Ok(self.n() - self.degree()),
            Scheme::Product => {
                require(self.b == 0, "product baseline supports b=0")?;
                Ok((self.ell - self.a + 1) * (self.m - self.r + 1))
            }
        }
    }
    pub fn queries(self, scheme: Scheme, bits: u32) -> Result<usize> {
        let ratio = self.distance(scheme)? as f64 / self.n() as f64;
        Ok((f64::from(bits) * std::f64::consts::LN_2 / -(-ratio).ln_1p()).ceil() as usize)
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Lrdas,
    Product,
}
impl Scheme {
    pub fn name(self) -> &'static str {
        match self {
            Self::Lrdas => "lrdas",
            Self::Product => "product",
        }
    }
}
pub struct Domain {
    p: Params,
    fft: Radix2EvaluationDomain<Fr>,
    betas: Vec<Fr>,
    gammas: Vec<Fr>,
    weights: Vec<Vec<Fr>>,
    residual: Vec<Fr>,
    powers: Vec<Vec<Fr>>,
}
impl Domain {
    pub fn new(p: Params) -> Result<Self> {
        let p = p.validate()?;
        let fft = Radix2EvaluationDomain::new(p.m).ok_or_else(|| Error("FFT domain".into()))?;
        require(fft.size() == p.m, "unexpected FFT padding")?;
        let mut betas = Vec::with_capacity(p.ell);
        let mut gammas = Vec::with_capacity(p.ell);
        let mut beta = Fr::one();
        for _ in 0..p.ell {
            betas.push(beta);
            let gamma = beta.pow([p.m as u64]);
            require(!gammas.contains(&gamma), "cosets are not distinct")?;
            gammas.push(gamma);
            beta *= Fr::GENERATOR;
        }
        let mut weights = Vec::with_capacity(p.ell);
        let mut residual = Vec::with_capacity(p.ell);
        for (j, &g) in gammas.iter().enumerate() {
            let mut row = vec![Fr::zero(); p.a];
            let bv = gammas[..p.a].iter().fold(Fr::one(), |v, s| v * (g - s));
            if j < p.a {
                row[j] = Fr::one();
            } else {
                for s in 0..p.a {
                    let den = gammas[..p.a]
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != s)
                        .fold(Fr::one(), |v, (_, x)| v * (gammas[s] - x));
                    row[s] = bv
                        * ((g - gammas[s]) * den)
                            .inverse()
                            .ok_or_else(|| Error("Lagrange denominator".into()))?;
                }
            }
            weights.push(row);
            residual.push(bv);
        }
        let powers = betas
            .iter()
            .map(|b| {
                let mut x = Fr::one();
                (0..p.r)
                    .map(|_| {
                        let old = x;
                        x *= b;
                        old
                    })
                    .collect()
            })
            .collect();
        Ok(Self {
            p,
            fft,
            betas,
            gammas,
            weights,
            residual,
            powers,
        })
    }
    pub fn fft(&self) -> &Radix2EvaluationDomain<Fr> {
        &self.fft
    }
    pub fn params(&self) -> Params {
        self.p
    }
    pub fn gammas(&self) -> &[Fr] {
        &self.gammas
    }
    pub fn weights(&self, j: usize) -> Result<&[Fr]> {
        self.weights
            .get(j)
            .map(Vec::as_slice)
            .ok_or_else(|| Error("group index".into()))
    }
    pub fn residual_weight(&self, j: usize) -> Result<Fr> {
        self.residual
            .get(j)
            .copied()
            .ok_or_else(|| Error("group index".into()))
    }
    pub fn point(&self, scheme: Scheme, j: usize, index: usize) -> Result<Fr> {
        require(
            j < self.p.ell && index < self.p.m,
            "coordinate out of bounds",
        )?;
        require(
            scheme != Scheme::Product || self.p.b == 0,
            "product baseline requires b=0",
        )?;
        Ok(self.fft.element(index)
            * if scheme == Scheme::Lrdas {
                self.betas[j]
            } else {
                Fr::one()
            })
    }
    pub fn scale_in_place(&self, j: usize, coeffs: &mut [Fr]) -> Result<()> {
        require(
            j < self.p.ell && coeffs.len() <= self.p.r,
            "scaling dimensions",
        )?;
        for (c, b) in coeffs.iter_mut().zip(&self.powers[j]) {
            *c *= b;
        }
        Ok(())
    }
    pub fn evaluate(&self, scheme: Scheme, j: usize, coeffs: &[Fr]) -> Result<Vec<Fr>> {
        require(
            j < self.p.ell && coeffs.len() <= self.p.r,
            "evaluation dimensions",
        )?;
        require(
            scheme != Scheme::Product || self.p.b == 0,
            "product baseline requires b=0",
        )?;
        let mut padded = coeffs.to_vec();
        if scheme == Scheme::Lrdas {
            self.scale_in_place(j, &mut padded)?;
        }
        padded.resize(self.p.m, Fr::zero());
        self.fft.fft_in_place(&mut padded);
        Ok(padded)
    }
}
