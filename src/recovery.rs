use crate::{
    domain::{Domain, Params, Scheme},
    fast_polynomial::ProductTree,
    kzg::{msm_g1, Opening, PublicSrs},
    polynomial,
    protocol::{MessagePolys, VerifiedHeader},
    require, Error, Result,
};
use ark_bls12_381::Fr;
use ark_ff::{batch_inversion, Field, One, Zero};
use ark_poly::EvaluationDomain;
use std::collections::HashSet;

#[derive(Clone, Copy)]
pub struct AcceptedValue {
    pub group: usize,
    pub index: usize,
    pub value: Fr,
}
pub fn erased(p: Params, j: usize, index: usize) -> Result<bool> {
    require(
        p.b() == 0 && p.m() >= p.ell() && j < p.ell() && index < p.m(),
        "diagonal pattern dimensions",
    )?;
    Ok((index + p.m() - p.m() * j / p.ell()) % p.m() <= p.m() - p.r())
}
pub fn surviving_values(domain: &Domain, values: &[Vec<Fr>]) -> Result<Vec<AcceptedValue>> {
    let p = domain.params();
    require(
        values.len() == p.ell() && values.iter().all(|v| v.len() == p.m()),
        "codeword shape",
    )?;
    let mut out = Vec::new();
    for (j, row) in values.iter().enumerate() {
        for (index, &value) in row.iter().enumerate() {
            if !erased(p, j, index)? {
                out.push(AcceptedValue {
                    group: j,
                    index,
                    value,
                });
            }
        }
    }
    Ok(out)
}
pub fn pattern_counts(p: Params) -> Result<(Vec<usize>, Vec<usize>)> {
    let mut groups = vec![0; p.ell()];
    let mut rows = vec![0; p.m()];
    for (j, group) in groups.iter_mut().enumerate() {
        for (i, row) in rows.iter_mut().enumerate() {
            if !erased(p, j, i)? {
                *group += 1;
                *row += 1;
            }
        }
    }
    Ok((groups, rows))
}
pub fn global_from_message(domain: &Domain, message: &[Fr]) -> Result<Vec<Fr>> {
    let p = domain.params();
    let polys = MessagePolys::new(domain, message)?;
    let nodes = &domain.gammas()[..p.a()];
    let z = polynomial::vanishing(nodes)?;
    let mut out = vec![Fr::zero(); p.degree() + 1];
    for (s, &x) in nodes.iter().enumerate() {
        let (mut basis, _) = polynomial::divide_linear(&z, x);
        let inv = polynomial::evaluate(&basis, x)
            .inverse()
            .ok_or_else(|| Error("basis denominator".into()))?;
        for w in &mut basis {
            *w *= inv;
        }
        for (t, &w) in basis.iter().enumerate() {
            for (i, &u) in polys.source_coefficients()[s].iter().enumerate() {
                out[t * p.m() + i] += w * u;
            }
        }
    }
    for (t, &w) in z.iter().enumerate() {
        for (i, &e) in polys.residual_coefficients().iter().enumerate() {
            out[t * p.m() + i] += w * e;
        }
    }
    Ok(out)
}
pub fn in_code_space(p: Params, f: &[Fr]) -> bool {
    f.iter()
        .enumerate()
        .all(|(i, x)| x.is_zero() || (i <= p.degree() && i % p.m() < p.r()))
}
pub fn local_coefficients(domain: &Domain, f: &[Fr]) -> Result<Vec<Vec<Fr>>> {
    let p = domain.params();
    require(in_code_space(p, f), "global polynomial outside V_D")?;
    let mut locals = Vec::with_capacity(p.ell());
    for &gamma in domain.gammas() {
        let mut local = vec![Fr::zero(); p.r()];
        let mut power = Fr::one();
        for block in f.chunks(p.m()) {
            for (v, c) in local.iter_mut().zip(block) {
                *v += *c * power;
            }
            power *= gamma;
        }
        locals.push(local);
    }
    Ok(locals)
}
pub struct Recovered {
    message: Vec<Fr>,
    values: Vec<Vec<Fr>>,
    locals: Vec<Vec<Fr>>,
}
fn finish(
    domain: &Domain,
    scheme: Scheme,
    locals: Vec<Vec<Fr>>,
    received: &[AcceptedValue],
) -> Result<Recovered> {
    let p = domain.params();
    let values = locals
        .iter()
        .enumerate()
        .map(|(j, v)| domain.evaluate(scheme, j, v))
        .collect::<Result<Vec<_>>>()?;
    for v in received {
        require(
            values[v.group][v.index] == v.value,
            "reconstruction disagrees with evidence",
        )?;
    }
    let mut message: Vec<_> = locals[..p.a()].iter().flatten().copied().collect();
    if p.b() > 0 {
        message.extend(&locals[p.a()][..p.b()]);
    }
    Ok(Recovered {
        message,
        values,
        locals,
    })
}
fn validate_received(p: Params, received: &[AcceptedValue]) -> Result<()> {
    require(received.len() <= p.n(), "too many received values")?;
    let mut seen = HashSet::with_capacity(received.len());
    for v in received {
        require(
            v.group < p.ell() && v.index < p.m() && seen.insert(v.group * p.m() + v.index),
            "invalid/duplicate received position",
        )?;
    }
    Ok(())
}
pub fn recover_global(domain: &Domain, received: &[AcceptedValue]) -> Result<Recovered> {
    let p = domain.params();
    validate_received(p, received)?;
    require(
        received.len() > p.degree(),
        "insufficient global interpolation values",
    )?;
    let selected = &received[..p.degree() + 1];
    let xs = selected
        .iter()
        .map(|v| domain.point(Scheme::Lrdas, v.group, v.index))
        .collect::<Result<Vec<_>>>()?;
    let ys: Vec<_> = selected.iter().map(|v| v.value).collect();
    let f = ProductTree::new(&xs)?.interpolate(&ys)?;
    finish(
        domain,
        Scheme::Lrdas,
        local_coefficients(domain, &f)?,
        received,
    )
}
pub fn recover_groups(
    domain: &Domain,
    scheme: Scheme,
    received: &[AcceptedValue],
) -> Result<Recovered> {
    let p = domain.params();
    require(p.b() == 0, "group shortcut requires b=0")?;
    validate_received(p, received)?;
    let mut groups = vec![Vec::new(); p.ell()];
    for v in received {
        groups[v.group].push((v.index, v.value));
    }
    let helpers: Vec<_> = (0..p.ell())
        .filter(|j| groups[*j].len() >= p.r())
        .take(p.a())
        .collect();
    require(helpers.len() == p.a(), "insufficient completeable groups")?;
    let known = helpers
        .iter()
        .map(|&j| {
            let xs = groups[j][..p.r()]
                .iter()
                .map(|(i, _)| domain.point(scheme, j, *i))
                .collect::<Result<Vec<_>>>()?;
            let ys: Vec<_> = groups[j][..p.r()].iter().map(|(_, value)| *value).collect();
            let mut poly = polynomial::interpolate(&xs, &ys)?;
            poly.resize(p.r(), Fr::zero());
            Ok(poly)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut locals = Vec::with_capacity(p.ell());
    for j in 0..p.ell() {
        if let Some(pos) = helpers.iter().position(|s| *s == j) {
            locals.push(known[pos].clone());
        } else {
            let weights = row_weights(domain, &helpers, j)?;
            let mut coefficients = vec![Fr::zero(); p.r()];
            for (poly, weight) in known.iter().zip(weights) {
                for (out, c) in coefficients.iter_mut().zip(poly) {
                    *out += weight * c;
                }
            }
            locals.push(coefficients);
        }
    }
    finish(domain, scheme, locals, received)
}
pub fn recover_product_rows(domain: &Domain, received: &[AcceptedValue]) -> Result<Recovered> {
    let p = domain.params();
    require(p.b() == 0, "product residual unsupported")?;
    validate_received(p, received)?;
    let mut rows = vec![Vec::new(); p.m()];
    for v in received {
        rows[v.index].push((v.group, v.value));
    }
    let mut values = vec![vec![Fr::zero(); p.m()]; p.ell()];
    for (index, row) in rows.iter().enumerate() {
        require(row.len() >= p.a(), "insufficient row values")?;
        let xs: Vec<_> = row[..p.a()]
            .iter()
            .map(|(j, _)| domain.gammas()[*j])
            .collect();
        let ys: Vec<_> = row[..p.a()].iter().map(|(_, v)| *v).collect();
        let poly = polynomial::interpolate(&xs, &ys)?;
        for (j, group) in values.iter_mut().enumerate() {
            group[index] = polynomial::evaluate(&poly, domain.gammas()[j]);
        }
    }
    let mut locals = Vec::with_capacity(p.ell());
    for group in &values {
        let mut coeffs = domain.fft().ifft(group);
        require(
            coeffs[p.r()..].iter().all(Zero::is_zero),
            "repaired column degree",
        )?;
        coeffs.truncate(p.r());
        locals.push(coeffs);
    }
    finish(domain, Scheme::Product, locals, received)
}
impl Recovered {
    pub fn message(&self) -> &[Fr] {
        &self.message
    }
    pub fn values(&self) -> &[Vec<Fr>] {
        &self.values
    }

    pub fn authenticate(
        &self,
        domain: &Domain,
        srs: &PublicSrs,
        header: &VerifiedHeader,
    ) -> Result<()> {
        let p = domain.params();
        require(
            self.locals.len() == p.ell() && self.message.len() == p.k(),
            "recovered dimensions",
        )?;
        for j in 0..p.a() + usize::from(p.b() > 0) {
            require(
                srs.commit(&self.locals[j])? == header.derive(domain, j)?,
                "reconstructed header mismatch",
            )?;
        }
        Ok(())
    }
    pub fn serve(
        &self,
        domain: &Domain,
        srs: &PublicSrs,
        scheme: Scheme,
        j: usize,
        index: usize,
    ) -> Result<Opening> {
        require(j < self.locals.len(), "recovered group")?;
        srs.open(&self.locals[j], &[domain.point(scheme, j, index)?])
    }
}
pub fn row_weights(domain: &Domain, helpers: &[usize], target: usize) -> Result<Vec<Fr>> {
    let p = domain.params();
    require(
        p.b() == 0 && helpers.len() == p.a() && target < p.ell(),
        "row helper count",
    )?;
    require(
        helpers.iter().all(|j| *j < p.ell() && *j != target)
            && helpers.iter().copied().collect::<HashSet<_>>().len() == helpers.len(),
        "row helper indices",
    )?;
    let xs: Vec<_> = helpers.iter().map(|j| domain.gammas()[*j]).collect();
    let z = polynomial::vanishing(&xs)?;
    let target = domain.gammas()[target];
    let numerator = polynomial::evaluate(&z, target);
    let mut weights = Vec::with_capacity(xs.len());
    for &x in &xs {
        let (q, _) = polynomial::divide_linear(&z, x);
        weights.push((target - x) * polynomial::evaluate(&q, x));
    }
    batch_inversion(&mut weights);
    for v in &mut weights {
        *v *= numerator;
    }
    Ok(weights)
}
pub fn repair_product_point(
    domain: &Domain,
    srs: &PublicSrs,
    header: &VerifiedHeader,
    target: usize,
    index: usize,
    helpers: &[(usize, Opening)],
) -> Result<Opening> {
    require(
        header.scheme() == Scheme::Product && helpers.iter().all(|(_, o)| o.values.len() == 1),
        "row repair scheme/values",
    )?;
    let groups: Vec<_> = helpers.iter().map(|(j, _)| *j).collect();
    let weights = row_weights(domain, &groups, target)?;
    let value: Fr = helpers
        .iter()
        .zip(&weights)
        .map(|((_, o), w)| o.values[0] * w)
        .sum();
    let bases: Vec<_> = helpers.iter().map(|(_, o)| o.proof).collect();
    let proof = msm_g1(&bases, &weights)?;
    let opening = Opening {
        values: vec![value],
        proof,
    };
    srs.verify(
        header.derive(domain, target)?,
        &[domain.point(Scheme::Product, target, index)?],
        &opening,
    )?;
    Ok(opening)
}
