use crate::{
    bytes, decode,
    domain::{Domain, Params, Scheme},
    kzg::{msm_g1, pairing_product, Opening, PublicSrs},
    polynomial as poly, require, Error, Result,
};
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use sha2::{Digest, Sha256};

pub struct MessagePolys {
    source: Vec<Vec<Fr>>,
    residual: Vec<Fr>,
}
impl MessagePolys {
    pub fn new(domain: &Domain, message: &[Fr]) -> Result<Self> {
        let p = domain.params();
        require(message.len() == p.k(), "message dimension")?;
        let source: Vec<Vec<Fr>> = message[..p.a() * p.r()]
            .chunks_exact(p.r())
            .map(<[Fr]>::to_vec)
            .collect();
        let mut residual = message[p.a() * p.r()..].to_vec();
        if p.b() > 0 {
            let inv = domain
                .residual_weight(p.a())?
                .inverse()
                .ok_or_else(|| Error("residual weight".into()))?;
            for (i, e) in residual.iter_mut().enumerate() {
                let f: Fr = source
                    .iter()
                    .zip(domain.weights(p.a())?)
                    .map(|(u, w)| u[i] * w)
                    .sum();
                *e = (*e - f) * inv;
            }
        }
        Ok(Self { source, residual })
    }
    pub fn source_coefficients(&self) -> &[Vec<Fr>] {
        &self.source
    }
    pub fn residual_coefficients(&self) -> &[Fr] {
        &self.residual
    }
    pub fn locals(&self, domain: &Domain) -> Result<Vec<Vec<Fr>>> {
        let p = domain.params();
        let mut locals = self.source.clone();
        for j in p.a()..p.ell() {
            let mut d = vec![Fr::zero(); p.r()];
            for (u, &w) in self.source.iter().zip(domain.weights(j)?) {
                for (x, &c) in d.iter_mut().zip(u) {
                    *x += w * c;
                }
            }
            for (x, &e) in d.iter_mut().zip(&self.residual) {
                *x += domain.residual_weight(j)? * e;
            }
            locals.push(d);
        }
        Ok(locals)
    }
    pub fn commit(&self, domain: &Domain, srs: &PublicSrs, scheme: Scheme) -> Result<Header> {
        let p = domain.params();
        require(srs.r() == p.r(), "SRS profile mismatch")?;
        require(
            scheme != Scheme::Product || p.b() == 0,
            "product requires b=0",
        )?;
        let mut points = self
            .source
            .iter()
            .map(|u| srs.commit(u))
            .collect::<Result<Vec<_>>>()?;
        if p.b() > 0 {
            points.push(srs.commit(&self.residual)?);
            let mut shift = vec![Fr::zero(); p.r() - p.b()];
            shift.extend(&self.residual);
            points.push(srs.commit(&shift)?);
        }
        Ok(Header {
            points,
            context: context(p, srs, scheme)?,
            scheme,
        })
    }
}
fn context(p: Params, srs: &PublicSrs, scheme: Scheme) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"lrdas-v1-fixed-generator-domains");
    h.update(srs.id());
    h.update(serde_json::to_vec(&p).map_err(|e| Error(e.to_string()))?);
    h.update(scheme.name());
    Ok(h.finalize().into())
}
#[derive(Clone)]
pub struct Header {
    points: Vec<G1Affine>,
    context: [u8; 32],
    scheme: Scheme,
}
impl Header {
    pub fn payload(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        for p in &self.points {
            b.extend(bytes(p)?);
        }
        Ok(b)
    }
    pub fn context(&self) -> [u8; 32] {
        self.context
    }
    pub fn from_payload(
        domain: &Domain,
        srs: &PublicSrs,
        scheme: Scheme,
        id: [u8; 32],
        raw: &[u8],
    ) -> Result<Self> {
        let p = domain.params();
        require(srs.r() == p.r(), "SRS profile mismatch")?;
        require(id == context(p, srs, scheme)?, "header context mismatch")?;
        let count = p.a() + if p.b() > 0 { 2 } else { 0 };
        require(raw.len() == count * 48, "header byte length")?;
        Ok(Self {
            points: raw.chunks_exact(48).map(decode).collect::<Result<_>>()?,
            context: id,
            scheme,
        })
    }
    pub fn verify(self, domain: &Domain, srs: &PublicSrs) -> Result<VerifiedHeader> {
        let p = domain.params();
        require(
            self.context == context(p, srs, self.scheme)?,
            "header context mismatch",
        )?;
        require(
            self.points.len() == p.a() + if p.b() > 0 { 2 } else { 0 },
            "header shape",
        )?;
        require(
            self.scheme != Scheme::Product || p.b() == 0,
            "product requires b=0",
        )?;
        if p.b() > 0 {
            require(
                pairing_product(
                    self.points[p.a()],
                    srs.g2()[p.r() - p.b()],
                    self.points[p.a() + 1],
                    srs.g2()[0],
                ),
                "residual degree check",
            )?;
        }
        let mut h = Sha256::new();
        h.update(self.context);
        h.update(self.payload()?);
        let id = h.finalize().into();
        Ok(VerifiedHeader {
            header: self,
            id,
            params: p,
        })
    }
}
#[derive(Clone)]
pub struct VerifiedHeader {
    header: Header,
    id: [u8; 32],
    params: Params,
}
impl VerifiedHeader {
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn scheme(&self) -> Scheme {
        self.header.scheme
    }
    pub fn derive(&self, domain: &Domain, j: usize) -> Result<G1Affine> {
        let p = domain.params();
        require(j < p.ell(), "group index")?;
        require(self.params == p, "domain dimensions")?;
        if j < p.a() {
            return Ok(self.header.points[j]);
        }
        let mut c = msm_g1(&self.header.points[..p.a()], domain.weights(j)?)?.into_group();
        if p.b() > 0 {
            c += self.header.points[p.a()] * domain.residual_weight(j)?;
        }
        Ok(c.into_affine())
    }
}
#[derive(Clone)]
pub struct GroupCache {
    header_id: [u8; 32],
    entries: Vec<Option<G1Affine>>,
}
impl GroupCache {
    pub fn new(h: &VerifiedHeader, domain: &Domain) -> Self {
        Self {
            header_id: h.id(),
            entries: vec![None; domain.params().ell()],
        }
    }
    pub fn get(&mut self, h: &VerifiedHeader, domain: &Domain, j: usize) -> Result<G1Affine> {
        require(
            self.header_id == h.id()
                && self.entries.len() == domain.params().ell()
                && h.params == domain.params(),
            "stale cache",
        )?;
        let entry = self
            .entries
            .get_mut(j)
            .ok_or_else(|| Error("group index".into()))?;
        if let Some(c) = entry {
            return Ok(*c);
        }
        let c = h.derive(domain, j)?;
        *entry = Some(c);
        Ok(c)
    }
}
pub struct Encoded {
    pub header: Header,
    pub locals: Vec<Vec<Fr>>,
    pub values: Vec<Vec<Fr>>,
}
pub fn encode(domain: &Domain, srs: &PublicSrs, scheme: Scheme, message: &[Fr]) -> Result<Encoded> {
    let polys = MessagePolys::new(domain, message)?;
    let header = polys.commit(domain, srs, scheme)?;
    let locals = polys.locals(domain)?;
    let values = locals
        .iter()
        .enumerate()
        .map(|(j, d)| domain.evaluate(scheme, j, d))
        .collect::<Result<_>>()?;
    Ok(Encoded {
        header,
        locals,
        values,
    })
}
pub struct CertifiedGroup {
    j: usize,
    scheme: Scheme,
    coeffs: Vec<Fr>,
    commitment: G1Affine,
    context: [u8; 32],
    params: Params,
}
impl CertifiedGroup {
    pub fn from_values(
        domain: &Domain,
        srs: &PublicSrs,
        h: &VerifiedHeader,
        j: usize,
        indices: &[usize],
        values: &[Fr],
    ) -> Result<Self> {
        let p = domain.params();
        require(
            indices.len() == p.r() && values.len() == p.r(),
            "certification requires r values",
        )?;
        let xs = indices
            .iter()
            .map(|&i| domain.point(h.scheme(), j, i))
            .collect::<Result<Vec<_>>>()?;
        let coeffs = poly::interpolate(&xs, values)?;
        let commitment = h.derive(domain, j)?;
        require(
            srs.commit(&coeffs)? == commitment,
            "certification commitment mismatch",
        )?;
        Ok(Self {
            j,
            scheme: h.scheme(),
            coeffs,
            commitment,
            context: context(p, srs, h.scheme())?,
            params: p,
        })
    }
    pub fn recover(&self, domain: &Domain) -> Result<Vec<Fr>> {
        require(self.params == domain.params(), "recovery domain mismatch")?;
        domain.evaluate(self.scheme, self.j, &self.coeffs)
    }
    pub fn serve(&self, domain: &Domain, srs: &PublicSrs, indices: &[usize]) -> Result<Opening> {
        require(
            self.context == context(domain.params(), srs, self.scheme)?,
            "serving context mismatch",
        )?;
        let xs = indices
            .iter()
            .map(|&i| domain.point(self.scheme, self.j, i))
            .collect::<Result<Vec<_>>>()?;
        srs.open(&self.coeffs, &xs)
    }
    pub fn commitment(&self) -> G1Affine {
        self.commitment
    }
    pub fn coefficients(&self) -> &[Fr] {
        &self.coeffs
    }
}
pub struct StreamingCollector {
    j: usize,
    indices: Vec<usize>,
    values: Vec<Fr>,
}
impl StreamingCollector {
    pub fn new(j: usize) -> Self {
        Self {
            j,
            indices: vec![],
            values: vec![],
        }
    }
    pub fn accept(
        &mut self,
        domain: &Domain,
        srs: &PublicSrs,
        h: &VerifiedHeader,
        cache: &mut GroupCache,
        index: usize,
        raw: &[u8],
    ) -> Result<()> {
        require(
            self.indices.len() < domain.params().r() && !self.indices.contains(&index),
            "collector duplicate or full",
        )?;
        let x = domain.point(h.scheme(), self.j, index)?;
        let opening = Opening::from_bytes(raw, 1, srs.r())?;
        srs.verify(cache.get(h, domain, self.j)?, &[x], &opening)?;
        self.indices.push(index);
        self.values.push(opening.values[0]);
        Ok(())
    }
    pub fn finish(
        self,
        domain: &Domain,
        srs: &PublicSrs,
        h: &VerifiedHeader,
    ) -> Result<CertifiedGroup> {
        require(
            self.indices.len() == domain.params().r(),
            "insufficient accepted values",
        )?;
        CertifiedGroup::from_values(domain, srs, h, self.j, &self.indices, &self.values)
    }
}
