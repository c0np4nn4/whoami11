use crate::{
    bytes, decode,
    domain::{Domain, Params, Scheme},
    kzg::{msm_g1, pairing_product, Opening, PublicSrs},
    polynomial,
    protocol::{MessagePolys, VerifiedHeader},
    require, Error, Result,
};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub struct LongSrs {
    params: Params,
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    shift_r: G2Affine,
    shift_b: Option<G2Affine>,
    local: PublicSrs,
    id: [u8; 32],
}
impl LongSrs {
    pub fn from_points(
        p: Params,
        g1: Vec<G1Affine>,
        g2: Vec<G2Affine>,
        shift_r: G2Affine,
        shift_b: Option<G2Affine>,
    ) -> Result<Self> {
        require(
            g1.len() > p.m() && g1.len() <= 1_048_576 && g2.len() == p.m() + 1,
            "long SRS dimensions",
        )?;
        require(
            shift_b.is_some() == (p.b() > 0),
            "residual degree-check element",
        )?;
        require(
            g1.iter().all(valid_g1)
                && g2
                    .iter()
                    .chain(std::iter::once(&shift_r))
                    .chain(shift_b.iter())
                    .all(|v| {
                        v.is_on_curve()
                            && v.is_in_correct_subgroup_assuming_on_curve()
                            && !v.is_zero()
                    }),
            "invalid long SRS point",
        )?;
        require(
            g1.iter().all(|v| !v.is_zero())
                && g1[0] == G1Affine::generator()
                && g2[0] == G2Affine::generator(),
            "long SRS generators",
        )?;
        let local = PublicSrs::from_points(p.r(), g1[..p.r()].to_vec(), g2[..=p.r()].to_vec())?;
        let mut digest = Sha256::new();
        digest.update(b"long-srs-with-degree-enforcement-v1");
        for v in &g1 {
            digest.update(bytes(v)?);
        }
        for v in g2
            .iter()
            .chain(std::iter::once(&shift_r))
            .chain(shift_b.iter())
        {
            digest.update(bytes(v)?);
        }
        Ok(Self {
            params: p,
            g1,
            g2,
            shift_r,
            shift_b,
            local,
            id: digest.finalize().into(),
        })
    }
    pub fn degree(&self) -> usize {
        self.g1.len() - 1
    }
    pub fn local(&self) -> &PublicSrs {
        &self.local
    }
    pub fn g1(&self) -> &[G1Affine] {
        &self.g1
    }
    pub fn g2(&self) -> &[G2Affine] {
        &self.g2
    }
    pub fn commit(&self, coeffs: &[Fr]) -> Result<G1Affine> {
        require(coeffs.len() <= self.g1.len(), "long commitment degree")?;
        msm_g1(&self.g1[..coeffs.len()], coeffs)
    }
    pub fn shifted(&self, coeffs: &[Fr], bound: usize) -> Result<G1Affine> {
        require(
            bound > 0 && bound <= self.g1.len() && coeffs.len() <= bound,
            "shifted commitment degree",
        )?;
        let start = self.g1.len() - bound;
        msm_g1(&self.g1[start..start + coeffs.len()], coeffs)
    }
    pub fn context(&self, domain: &Domain, scheme: Scheme) -> Result<[u8; 32]> {
        require(self.params == domain.params(), "long SRS parameters")?;
        let mut hash = Sha256::new();
        hash.update(self.id);
        hash.update(serde_json::to_vec(&self.params).map_err(|e| Error(e.to_string()))?);
        hash.update(scheme.name());
        Ok(hash.finalize().into())
    }
}
fn valid_g1(v: &G1Affine) -> bool {
    v.is_on_curve() && v.is_in_correct_subgroup_assuming_on_curve()
}
fn decode_points(raw: &[u8], n: usize) -> Result<Vec<G1Affine>> {
    require(raw.len() == 48 * n, "commitment payload length")?;
    raw.chunks_exact(48).map(decode).collect()
}
fn serialize_points(points: impl IntoIterator<Item = G1Affine>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for p in points {
        out.extend(bytes(&p)?);
    }
    Ok(out)
}

#[derive(Clone)]
pub struct ProfileBHeader {
    context: [u8; 32],
    scheme: Scheme,
    source: Vec<G1Affine>,
    shifted: Vec<G1Affine>,
    residual: Option<(G1Affine, G1Affine)>,
}
impl ProfileBHeader {
    pub fn commit(domain: &Domain, srs: &LongSrs, scheme: Scheme, message: &[Fr]) -> Result<Self> {
        let p = domain.params();
        require(
            scheme != Scheme::Product || p.b() == 0,
            "product residual unsupported",
        )?;
        let polys = MessagePolys::new(domain, message)?;
        let source = polys
            .source_coefficients()
            .iter()
            .map(|x| srs.commit(x))
            .collect::<Result<Vec<_>>>()?;
        let shifted = polys
            .source_coefficients()
            .iter()
            .map(|x| srs.shifted(x, p.r()))
            .collect::<Result<Vec<_>>>()?;
        let residual = if p.b() > 0 {
            Some((
                srs.commit(polys.residual_coefficients())?,
                srs.shifted(polys.residual_coefficients(), p.b())?,
            ))
        } else {
            None
        };
        Ok(Self {
            context: srs.context(domain, scheme)?,
            scheme,
            source,
            shifted,
            residual,
        })
    }
    pub fn payload(&self) -> Result<Vec<u8>> {
        serialize_points(
            self.source
                .iter()
                .copied()
                .chain(self.residual.iter().map(|r| r.0))
                .chain(self.shifted.iter().copied())
                .chain(self.residual.iter().map(|r| r.1)),
        )
    }
    pub fn context(&self) -> [u8; 32] {
        self.context
    }
    pub fn from_payload(
        domain: &Domain,
        srs: &LongSrs,
        scheme: Scheme,
        context: [u8; 32],
        raw: &[u8],
    ) -> Result<Self> {
        require(context == srs.context(domain, scheme)?, "Profile B context")?;
        let p = domain.params();
        let b = usize::from(p.b() > 0);
        let points = decode_points(raw, 2 * (p.a() + b))?;
        let residual = if b == 1 {
            Some((points[p.a()], points[2 * p.a() + 1]))
        } else {
            None
        };
        Ok(Self {
            context,
            scheme,
            source: points[..p.a()].to_vec(),
            shifted: points[p.a() + b..2 * p.a() + b].to_vec(),
            residual,
        })
    }
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        domain: &Domain,
        srs: &LongSrs,
        rng: &mut R,
    ) -> Result<VerifiedBHeader> {
        require(
            self.context == srs.context(domain, self.scheme)?,
            "Profile B context",
        )?;
        let p = domain.params();
        require(
            self.source.len() == p.a()
                && self.shifted.len() == p.a()
                && self.residual.is_some() == (p.b() > 0),
            "Profile B shape",
        )?;
        require(
            self.source
                .iter()
                .chain(&self.shifted)
                .chain(self.residual.iter().flat_map(|(a, b)| [a, b]))
                .all(valid_g1),
            "Profile B point",
        )?;
        let rho = Fr::rand(rng);
        let mut power = Fr::one();
        let mut weights = Vec::with_capacity(p.a());
        for _ in 0..p.a() {
            weights.push(power);
            power *= rho;
        }
        let left = msm_g1(&self.source, &weights)?;
        let mut right = msm_g1(&self.shifted, &weights)?.into_group();
        let ok = if let Some((e, shifted)) = self.residual {
            right += shifted * power;
            Bls12_381::multi_pairing(
                [left, (e * power).into_affine(), (-right).into_affine()],
                [
                    srs.shift_r,
                    srs.shift_b
                        .ok_or_else(|| Error("missing residual check".into()))?,
                    srs.g2[0],
                ],
            )
            .0
            .is_one()
        } else {
            pairing_product(left, srs.shift_r, right.into_affine(), srs.g2[0])
        };
        require(ok, "Profile B degree check")?;
        Ok(VerifiedBHeader {
            header: self.clone(),
            params: p,
            local_id: srs.local.id(),
        })
    }
}
pub struct VerifiedBHeader {
    header: ProfileBHeader,
    params: Params,
    local_id: [u8; 32],
}
impl VerifiedBHeader {
    pub fn group(&self, domain: &Domain, j: usize) -> Result<VerifiedGroup> {
        require(
            self.params == domain.params() && j < self.params.ell(),
            "Profile B group",
        )?;
        let mut c = if j < self.params.a() {
            self.header.source[j].into_group()
        } else {
            msm_g1(&self.header.source, domain.weights(j)?)?.into_group()
        };
        if let Some((e, _)) = self.header.residual {
            c += e * domain.residual_weight(j)?;
        }
        Ok(VerifiedGroup {
            commitment: c.into_affine(),
            params: self.params,
            j,
            scheme: self.header.scheme,
            local_id: self.local_id,
        })
    }
}

#[derive(Clone)]
pub struct SuppliedAux {
    pub local: G1Affine,
    pub quotient: G1Affine,
    pub shifted: G1Affine,
}
impl SuppliedAux {
    pub fn payload(&self) -> Result<Vec<u8>> {
        serialize_points([self.local, self.quotient, self.shifted])
    }
    pub fn from_payload(raw: &[u8]) -> Result<Self> {
        let p = decode_points(raw, 3)?;
        Ok(Self {
            local: p[0],
            quotient: p[1],
            shifted: p[2],
        })
    }
}
#[derive(Clone)]
pub struct SuppliedHeader {
    global: G1Affine,
    context: [u8; 32],
}
impl SuppliedHeader {
    pub fn commit(domain: &Domain, srs: &LongSrs, f: &[Fr]) -> Result<Self> {
        require(
            srs.degree() == domain.params().degree() && f.len() <= srs.degree() + 1,
            "supplied degree D",
        )?;
        Ok(Self {
            global: srs.commit(f)?,
            context: srs.context(domain, Scheme::Lrdas)?,
        })
    }
    pub fn payload(&self) -> Result<Vec<u8>> {
        bytes(&self.global)
    }
    pub fn context(&self) -> [u8; 32] {
        self.context
    }
    pub fn from_payload(
        domain: &Domain,
        srs: &LongSrs,
        context: [u8; 32],
        raw: &[u8],
    ) -> Result<Self> {
        require(
            context == srs.context(domain, Scheme::Lrdas)?
                && srs.degree() == domain.params().degree(),
            "supplied context",
        )?;
        Ok(Self {
            global: decode(raw)?,
            context,
        })
    }
    pub fn link_equation_holds(
        &self,
        domain: &Domain,
        srs: &LongSrs,
        j: usize,
        aux: &SuppliedAux,
    ) -> Result<bool> {
        require(
            j < domain.params().ell() && self.context == srs.context(domain, Scheme::Lrdas)?,
            "supplied group context",
        )?;
        require(
            [self.global, aux.local, aux.quotient, aux.shifted]
                .iter()
                .all(valid_g1),
            "supplied point",
        )?;
        let h = (srs.g2[domain.params().m()].into_group() - srs.g2[0] * domain.gammas()[j])
            .into_affine();
        Ok(pairing_product(
            (self.global.into_group() - aux.local).into_affine(),
            srs.g2[0],
            aux.quotient,
            h,
        ))
    }
    pub fn verify_group(
        &self,
        domain: &Domain,
        srs: &LongSrs,
        j: usize,
        aux: &SuppliedAux,
    ) -> Result<VerifiedGroup> {
        require(
            self.link_equation_holds(domain, srs, j, aux)?,
            "supplied quotient link",
        )?;
        require(
            pairing_product(aux.local, srs.shift_r, aux.shifted, srs.g2[0]),
            "supplied degree check",
        )?;
        Ok(VerifiedGroup {
            commitment: aux.local,
            params: domain.params(),
            j,
            scheme: Scheme::Lrdas,
            local_id: srs.local.id(),
        })
    }
}
pub fn supplied_aux(
    domain: &Domain,
    srs: &LongSrs,
    f: &[Fr],
    local: &[Fr],
    j: usize,
) -> Result<SuppliedAux> {
    let p = domain.params();
    require(
        j < p.ell()
            && f.len() <= p.degree() + 1
            && local.len() <= p.r()
            && srs.degree() == p.degree(),
        "supplied generation dimensions",
    )?;
    let mut rem = f.to_vec();
    rem.resize(rem.len().max(local.len()), Fr::zero());
    for (v, x) in rem.iter_mut().zip(local) {
        *v -= x;
    }
    let mut q = vec![Fr::zero(); rem.len().saturating_sub(p.m())];
    for i in (p.m()..rem.len()).rev() {
        let c = rem[i];
        q[i - p.m()] = c;
        rem[i] = Fr::zero();
        rem[i - p.m()] += domain.gammas()[j] * c;
    }
    require(rem.iter().all(Zero::is_zero), "supplied nonexact quotient")?;
    Ok(SuppliedAux {
        local: srs.local.commit(local)?,
        quotient: srs.commit(&q)?,
        shifted: srs.shifted(local, p.r())?,
    })
}

#[derive(Clone)]
pub struct VerifiedGroup {
    commitment: G1Affine,
    params: Params,
    j: usize,
    scheme: Scheme,
    local_id: [u8; 32],
}
impl VerifiedGroup {
    pub fn dedicated(
        domain: &Domain,
        srs: &PublicSrs,
        h: &VerifiedHeader,
        j: usize,
    ) -> Result<Self> {
        require(srs.r() == domain.params().r(), "dedicated local SRS")?;
        Ok(Self {
            commitment: h.derive(domain, j)?,
            params: domain.params(),
            j,
            scheme: h.scheme(),
            local_id: srs.id(),
        })
    }
    pub fn commitment(&self) -> G1Affine {
        self.commitment
    }
    pub fn verify(
        &self,
        domain: &Domain,
        srs: &PublicSrs,
        index: usize,
        opening: &Opening,
    ) -> Result<()> {
        require(
            self.params == domain.params() && self.local_id == srs.id(),
            "group context",
        )?;
        srs.verify(
            self.commitment,
            &[domain.point(self.scheme, self.j, index)?],
            opening,
        )
    }
    pub fn certify(
        &self,
        domain: &Domain,
        srs: &PublicSrs,
        indices: &[usize],
        values: &[Fr],
    ) -> Result<ServingGroup> {
        require(
            self.params == domain.params() && self.local_id == srs.id(),
            "group context",
        )?;
        require(
            indices.len() == self.params.r() && values.len() == indices.len(),
            "group certification size",
        )?;
        let xs = indices
            .iter()
            .map(|&i| domain.point(self.scheme, self.j, i))
            .collect::<Result<Vec<_>>>()?;
        let coeffs = polynomial::interpolate(&xs, values)?;
        require(
            srs.commit(&coeffs)? == self.commitment,
            "reconstructed commitment mismatch",
        )?;
        Ok(ServingGroup {
            group: self.clone(),
            coeffs,
        })
    }
}
pub struct ServingGroup {
    group: VerifiedGroup,
    coeffs: Vec<Fr>,
}
impl ServingGroup {
    pub fn recover(&self, domain: &Domain) -> Result<Vec<Fr>> {
        require(domain.params() == self.group.params, "receiver domain")?;
        domain.evaluate(self.group.scheme, self.group.j, &self.coeffs)
    }
    pub fn serve(&self, domain: &Domain, srs: &PublicSrs, index: usize) -> Result<Opening> {
        require(
            domain.params() == self.group.params && srs.id() == self.group.local_id,
            "receiver context",
        )?;
        srs.open(
            &self.coeffs,
            &[domain.point(self.group.scheme, self.group.j, index)?],
        )
    }
}

pub struct SuppliedReceiver {
    serving: ServingGroup,
    auxiliary: SuppliedAux,
}
impl SuppliedReceiver {
    pub fn serve_reply(&self, domain: &Domain, srs: &PublicSrs, index: usize) -> Result<Vec<u8>> {
        let opening = self.serving.serve(domain, srs, index)?;
        let mut raw = self.auxiliary.payload()?;
        raw.extend(opening.to_bytes(srs.r())?);
        Ok(raw)
    }
}
impl SuppliedHeader {
    pub fn certify_group(
        &self,
        domain: &Domain,
        srs: &LongSrs,
        j: usize,
        auxiliary: &SuppliedAux,
        indices: &[usize],
        values: &[Fr],
    ) -> Result<SuppliedReceiver> {
        let group = self.verify_group(domain, srs, j, auxiliary)?;
        Ok(SuppliedReceiver {
            serving: group.certify(domain, srs.local(), indices, values)?,
            auxiliary: auxiliary.clone(),
        })
    }
    pub fn verify_reply(
        &self,
        domain: &Domain,
        srs: &LongSrs,
        j: usize,
        index: usize,
        raw: &[u8],
    ) -> Result<Opening> {
        require(
            raw.len() == 144 + 80,
            "fresh supplied reply requires auxiliary triple",
        )?;
        let aux = SuppliedAux::from_payload(&raw[..144])?;
        let group = self.verify_group(domain, srs, j, &aux)?;
        let opening = Opening::from_bytes(&raw[144..], 1, domain.params().r())?;
        group.verify(domain, srs.local(), index, &opening)?;
        Ok(opening)
    }
}
