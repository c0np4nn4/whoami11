#![allow(non_local_definitions)]

use ark_bls12_381::Fr;
use ark_ff::{batch_inversion, FftField, Field, Fp64, MontBackend, MontConfig};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use lrdas_artifact::{domain::Params, fixture, recovery};
use rand::seq::SliceRandom;
use serde_json::{json, Value};
use std::{error::Error, fs, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(MontConfig)]
#[modulus = "65537"]
#[generator = "3"]
struct SmallConfig;
type Small = Fp64<MontBackend<SmallConfig, 1>>;

#[derive(Clone, Copy)]
struct Shape {
    m: usize,
    r: usize,
    ell: usize,
    a: usize,
}

struct Layout<F: FftField> {
    shape: Shape,
    domain: Radix2EvaluationDomain<F>,
    betas: Vec<F>,
    gammas: Vec<F>,
    relations: Vec<Vec<F>>,
}

impl<F: FftField> Layout<F> {
    fn new(shape: Shape, generator: F, product: bool) -> Result<Self> {
        let domain = Radix2EvaluationDomain::new(shape.m).ok_or("FFT domain unavailable")?;
        let cosets: Vec<_> = (0..shape.ell).map(|j| generator.pow([j as u64])).collect();
        let gammas: Vec<_> = cosets.iter().map(|b| b.pow([shape.m as u64])).collect();
        if gammas
            .iter()
            .enumerate()
            .any(|(i, x)| gammas[..i].contains(x))
        {
            return Err("outer evaluation points are not distinct".into());
        }
        let sources = &gammas[..shape.a];
        let mut denominators: Vec<F> = sources
            .iter()
            .enumerate()
            .map(|(s, x)| {
                sources
                    .iter()
                    .enumerate()
                    .filter(|(t, _)| *t != s)
                    .fold(F::ONE, |v, (_, y)| v * (*x - y))
            })
            .collect();
        batch_inversion(&mut denominators);
        let relations = (shape.a..shape.ell)
            .map(|j| {
                let mut relation = vec![F::ZERO; shape.ell];
                for s in 0..shape.a {
                    relation[s] = -sources
                        .iter()
                        .enumerate()
                        .filter(|(t, _)| *t != s)
                        .fold(denominators[s], |v, (_, x)| v * (gammas[j] - x));
                }
                relation[j] = F::ONE;
                relation
            })
            .collect();
        let betas = if product {
            vec![F::ONE; shape.ell]
        } else {
            cosets
        };
        Ok(Self {
            shape,
            domain,
            betas,
            gammas,
            relations,
        })
    }

    fn evaluate(&self, group: usize, coefficients: &[F]) -> Vec<F> {
        let mut scaled = coefficients.to_vec();
        let mut power = F::ONE;
        for coefficient in &mut scaled {
            *coefficient *= power;
            power *= self.betas[group];
        }
        self.domain.fft(&scaled)
    }
}

fn evaluate<F: Field>(coefficients: &[F], point: F) -> F {
    coefficients
        .iter()
        .rev()
        .fold(F::ZERO, |value, coefficient| value * point + coefficient)
}

fn multiply_linear<F: Field>(coefficients: &mut Vec<F>, point: F) {
    coefficients.push(F::ZERO);
    for i in (1..coefficients.len()).rev() {
        coefficients[i] = coefficients[i - 1] - point * coefficients[i];
    }
    coefficients[0] *= -point;
}

fn divide_monic<F: Field>(mut numerator: Vec<F>, denominator: &[F]) -> Result<Vec<F>> {
    if denominator.is_empty() || denominator.last() != Some(&F::ONE) {
        return Err("division requires a monic polynomial".into());
    }
    let degree = denominator.len() - 1;
    if numerator.len() <= degree {
        return if numerator.iter().all(|x| x.is_zero()) {
            Ok(vec![F::ZERO])
        } else {
            Err("polynomial division has a nonzero remainder".into())
        };
    }
    let mut quotient = vec![F::ZERO; numerator.len() - degree];
    for i in (degree..numerator.len()).rev() {
        let value = numerator[i];
        quotient[i - degree] = value;
        for (k, coefficient) in denominator[..degree].iter().enumerate() {
            numerator[i - degree + k] -= value * coefficient;
        }
        numerator[i] = F::ZERO;
    }
    if numerator[..degree].iter().any(|x| !x.is_zero()) {
        return Err("polynomial division has a nonzero remainder".into());
    }
    Ok(quotient)
}

fn interpolate<F: FftField>(
    layout: &Layout<F>,
    group: usize,
    received: &[(usize, F)],
) -> Result<(Vec<F>, Vec<F>)> {
    let p = layout.shape;
    let mut seen = vec![false; p.m];
    for &(index, _) in received {
        if index >= p.m || seen[index] {
            return Err("invalid or duplicate received position".into());
        }
        seen[index] = true;
    }
    let selected = &received[..received.len().min(p.r)];
    if selected.is_empty() {
        return Ok((vec![F::ZERO; p.r], vec![F::ONE]));
    }
    seen.fill(false);
    for &(index, _) in selected {
        seen[index] = true;
    }
    let beta = layout.betas[group];
    let mut erasure = vec![F::ONE];
    for (index, known) in seen.iter().enumerate() {
        if !known {
            multiply_linear(&mut erasure, beta * layout.domain.element(index));
        }
    }
    let erasure_values = layout.evaluate(group, &erasure);
    let mut weighted = vec![F::ZERO; p.m];
    for &(index, value) in selected {
        weighted[index] = value * erasure_values[index];
    }
    layout.domain.ifft_in_place(&mut weighted);
    let beta_inverse = beta.inverse().ok_or("zero coset representative")?;
    let mut power = F::ONE;
    for coefficient in &mut weighted {
        *coefficient *= power;
        power *= beta_inverse;
    }
    let mut interpolant = divide_monic(weighted, &erasure)?;
    if interpolant.len() > selected.len()
        && interpolant[selected.len()..].iter().any(|x| !x.is_zero())
    {
        return Err("interpolant degree exceeds its sample count".into());
    }
    interpolant.resize(p.r, F::ZERO);
    for &(index, value) in received {
        if evaluate(&interpolant, beta * layout.domain.element(index)) != value {
            return Err("received values disagree with the local degree bound".into());
        }
    }
    let mut full_vanishing = vec![F::ZERO; p.m + 1];
    full_vanishing[0] = -beta.pow([p.m as u64]);
    full_vanishing[p.m] = F::ONE;
    let vanishing = divide_monic(full_vanishing, &erasure)?;
    Ok((interpolant, vanishing))
}

struct LinearSolution<F: Field> {
    rank: usize,
    consistent: bool,
    values: Option<Vec<F>>,
}

fn solve<F: Field>(mut matrix: Vec<Vec<F>>, unknowns: usize) -> Result<LinearSolution<F>> {
    if matrix.iter().any(|row| row.len() != unknowns + 1) {
        return Err("invalid augmented matrix dimensions".into());
    }
    let mut rank = 0;
    let mut pivots = Vec::new();
    for column in 0..unknowns {
        let Some(pivot) = (rank..matrix.len()).find(|&row| !matrix[row][column].is_zero()) else {
            continue;
        };
        matrix.swap(rank, pivot);
        let inverse = matrix[rank][column]
            .inverse()
            .ok_or("noninvertible pivot")?;
        for value in &mut matrix[rank][column + 1..] {
            *value *= inverse;
        }
        matrix[rank][column] = F::ONE;
        let (head, remaining) = matrix.split_at_mut(rank + 1);
        let pivot_row = &head[rank];
        for row in remaining {
            let factor = row[column];
            if factor.is_zero() {
                continue;
            }
            row[column] = F::ZERO;
            for (value, pivot_value) in row[column + 1..].iter_mut().zip(&pivot_row[column + 1..]) {
                *value -= factor * pivot_value;
            }
        }
        pivots.push(column);
        rank += 1;
        if rank == matrix.len() {
            break;
        }
    }
    let consistent = matrix[rank..].iter().all(|row| row[unknowns].is_zero());
    let values = if consistent && rank == unknowns {
        let mut result = vec![F::ZERO; unknowns];
        for (row, &column) in pivots.iter().enumerate().rev() {
            result[column] = matrix[row][unknowns]
                - matrix[row][column + 1..unknowns]
                    .iter()
                    .zip(&result[column + 1..])
                    .fold(F::ZERO, |v, (x, y)| v + *x * y);
        }
        Some(result)
    } else {
        None
    };
    Ok(LinearSolution {
        rank,
        consistent,
        values,
    })
}

struct Decoded<F: Field> {
    unknowns: usize,
    equations: usize,
    rank: usize,
    consistent: bool,
    locals: Option<Vec<Vec<F>>>,
}

fn decode<F: FftField>(
    layout: &Layout<F>,
    received: &[Vec<(usize, F)>],
    coefficient_count: usize,
) -> Result<Decoded<F>> {
    let p = layout.shape;
    if received.len() != p.ell || coefficient_count == 0 || coefficient_count > p.r {
        return Err("invalid decoder dimensions".into());
    }
    let mut interpolants = Vec::with_capacity(p.ell);
    let mut vanishings = Vec::with_capacity(p.ell);
    let mut offsets = vec![0];
    for (j, values) in received.iter().enumerate() {
        let (interpolant, vanishing) = interpolate(layout, j, values)?;
        interpolants.push(interpolant);
        vanishings.push(vanishing);
        offsets.push(offsets[j] + p.r.saturating_sub(values.len()));
    }
    let unknowns = offsets[p.ell];
    let equations = coefficient_count * (p.ell - p.a);
    let mut matrix = Vec::with_capacity(equations);
    for relation in &layout.relations {
        for coefficient in (p.r - coefficient_count..p.r).rev() {
            let mut row = vec![F::ZERO; unknowns + 1];
            for j in 0..p.ell {
                if relation[j].is_zero() {
                    continue;
                }
                row[unknowns] -= relation[j] * interpolants[j][coefficient];
                for d in 0..offsets[j + 1] - offsets[j] {
                    if coefficient >= d && coefficient - d < vanishings[j].len() {
                        row[offsets[j] + d] = relation[j] * vanishings[j][coefficient - d];
                    }
                }
            }
            matrix.push(row);
        }
    }
    let solution = solve(matrix, unknowns)?;
    let locals = match solution.values {
        Some(values) => {
            let mut locals = interpolants;
            for j in 0..p.ell {
                for d in 0..offsets[j + 1] - offsets[j] {
                    for (i, coefficient) in vanishings[j].iter().enumerate() {
                        locals[j][i + d] += values[offsets[j] + d] * coefficient;
                    }
                }
                for &(index, value) in &received[j] {
                    if evaluate(&locals[j], layout.betas[j] * layout.domain.element(index)) != value
                    {
                        return Err(
                            "reconstructed polynomial disagrees with received evidence".into()
                        );
                    }
                }
            }
            for relation in &layout.relations {
                for coefficient in 0..p.r {
                    if relation
                        .iter()
                        .zip(&locals)
                        .fold(F::ZERO, |v, (weight, local)| {
                            v + *weight * local[coefficient]
                        })
                        != F::ZERO
                    {
                        return Err(
                            "reconstructed polynomials violate an unselected outer equation".into(),
                        );
                    }
                }
            }
            Some(locals)
        }
        None => None,
    };
    Ok(Decoded {
        unknowns,
        equations,
        rank: solution.rank,
        consistent: solution.consistent,
        locals,
    })
}

fn random_locals<F: FftField>(layout: &Layout<F>, seed: u64, label: &str) -> Vec<Vec<F>> {
    let p = layout.shape;
    let mut rng = fixture::rng(seed, label);
    let outer: Vec<Vec<F>> = (0..p.r)
        .map(|_| (0..p.a).map(|_| F::rand(&mut rng)).collect())
        .collect();
    layout
        .gammas
        .iter()
        .map(|&gamma| outer.iter().map(|poly| evaluate(poly, gamma)).collect())
        .collect()
}

fn proposition_pattern(p: Shape) -> Result<Vec<Vec<usize>>> {
    let params = Params::new(p.ell, p.m, p.r, p.a, 0)?;
    (0..p.ell)
        .map(|j| {
            (0..p.m)
                .filter_map(|i| match recovery::erased(params, j, i) {
                    Ok(false) => Some(Ok(i)),
                    Ok(true) => None,
                    Err(error) => Some(Err(error.into())),
                })
                .collect()
        })
        .collect()
}

fn random_pattern(p: Shape, kept: usize, seed: u64) -> Vec<Vec<usize>> {
    let mut rng = fixture::rng(seed, &format!("table8-survivors-{kept}"));
    let mut positions: Vec<_> = (0..p.m * p.ell).collect();
    positions.shuffle(&mut rng);
    let mut groups = vec![Vec::new(); p.ell];
    for position in &positions[..kept] {
        groups[position / p.m].push(position % p.m);
    }
    for group in &mut groups {
        group.sort_unstable();
    }
    groups
}

fn check_case<F: FftField>(
    layout: &Layout<F>,
    locals: &[Vec<F>],
    pattern: &[Vec<usize>],
    coefficients: usize,
) -> Result<Value> {
    let codeword: Vec<_> = locals
        .iter()
        .enumerate()
        .map(|(j, polynomial)| layout.evaluate(j, polynomial))
        .collect();
    let received: Vec<Vec<_>> = pattern
        .iter()
        .enumerate()
        .map(|(j, positions)| positions.iter().map(|&i| (i, codeword[j][i])).collect())
        .collect();
    let decoded = decode(layout, &received, coefficients)?;
    let recovered = decoded.locals.as_ref().is_some_and(|result| {
        result == locals
            && result
                .iter()
                .enumerate()
                .all(|(j, polynomial)| layout.evaluate(j, polynomial) == codeword[j])
    });
    let leading = decoded
        .locals
        .as_ref()
        .is_some_and(|result| result.iter().zip(locals).all(|(x, y)| x.last() == y.last()));
    if !decoded.consistent || !recovered || decoded.rank != decoded.unknowns {
        return Err(format!(
            "structured recovery failed: unknowns={}, rank={}, consistent={}, exact={recovered}",
            decoded.unknowns, decoded.rank, decoded.consistent
        )
        .into());
    }
    Ok(
        json!({"unknowns":decoded.unknowns,"equations":decoded.equations,"rank":decoded.rank,"consistent":decoded.consistent,"local_polynomials_exact":recovered,"full_codeword_exact":recovered,"leading_coefficients_exact":leading}),
    )
}

pub fn run(out: &Path, seed: u64) -> Result<Value> {
    let p = Shape {
        m: 64,
        r: 48,
        ell: 60,
        a: 40,
    };
    let tb = Layout::<Small>::new(p, Small::from(3u64), false)?;
    let product = Layout::<Small>::new(p, Small::from(3u64), true)?;
    let locals = random_locals(&tb, seed, "table8-data");
    let mut rows = Vec::new();
    let mut csv = String::from("pattern,kept,fraction,unknowns,equations,tb_rank,product_rank,tb_recovered,product_recovered,published_unknowns\n");
    for (index, (kept, published_unknowns)) in [
        (2820, 60),
        (2688, 223),
        (2534, 347),
        (2304, 576),
        (2112, 768),
        (1996, 884),
    ]
    .into_iter()
    .enumerate()
    {
        let name = if index == 0 {
            "Proposition 7"
        } else {
            "Random"
        };
        eprintln!("Table 8: {name}, kept {kept}");
        let pattern = if index == 0 {
            proposition_pattern(p)?
        } else {
            random_pattern(p, kept, seed)
        };
        let tb_result = check_case(&tb, &locals, &pattern, p.r)?;
        let product_result = check_case(&product, &locals, &pattern, p.r)?;
        let unknowns = tb_result["unknowns"]
            .as_u64()
            .ok_or("missing unknown count")?;
        csv.push_str(&format!(
            "{name},{kept},{:.6},{unknowns},{},{},{},true,true,{published_unknowns}\n",
            kept as f64 / (p.m * p.ell) as f64,
            (p.ell - p.a) * p.r,
            tb_result["rank"],
            product_result["rank"]
        ));
        rows.push(json!({"pattern":name,"kept":kept,"surviving_indices":pattern,"tb":tb_result,"product":product_result,"published_comparison":{"unknowns":published_unknowns,"tb_rank":published_unknowns,"product_rank":published_unknowns}}));
    }
    fs::write(out.join("table8.csv"), csv)?;
    let small_p = Shape {
        m: 32,
        r: 24,
        ell: 24,
        a: 16,
    };
    let small_tb = Layout::<Small>::new(small_p, Small::from(3u64), false)?;
    let small_product = Layout::<Small>::new(small_p, Small::from(3u64), true)?;
    let small_locals = random_locals(&small_tb, seed, "decoder-additional-data");
    let small_pattern = proposition_pattern(small_p)?;
    let additional = json!({"m":32,"r":24,"ell":24,"a":16,"tb":check_case(&small_tb,&small_locals,&small_pattern,small_p.r)?,"product":check_case(&small_product,&small_locals,&small_pattern,small_p.r)?});
    let reference_p = Shape {
        m: 1024,
        r: 768,
        ell: 123,
        a: 82,
    };
    let reference_pattern = proposition_pattern(reference_p)?;
    eprintln!("Appendix E.2: BLS12-381 reference recovery, beta_j = 7^j");
    let reference = Layout::<Fr>::new(reference_p, Fr::from(7u64), false)?;
    let reference_locals = random_locals(&reference, seed, "decoder-reference-data");
    let reference_result = check_case(&reference, &reference_locals, &reference_pattern, 3)?;
    eprintln!("Appendix E.2: BLS12-381 reference rank, beta_j = omega_17^j");
    let root = Fr::get_root_of_unity(1 << 17).ok_or("missing primitive 2^17 root")?;
    let alternate = Layout::<Fr>::new(reference_p, root, false)?;
    let zero_data = vec![vec![Fr::ZERO; reference_p.r]; reference_p.ell];
    let alternate_result = check_case(&alternate, &zero_data, &reference_pattern, 3)?;
    let report = json!({"field":65537,"m":p.m,"r":p.r,"ell":p.ell,"a":p.a,"seed":seed,"sampling":"Independent uniform subsets from deterministic ChaCha20 streams. The original manuscript seed is unspecified; published counts are comparisons, never solver inputs.","table8":rows,"additional_configuration":additional,"reference":{"field":"BLS12-381 scalar","m":1024,"r":768,"ell":123,"a":82,"beta_7_random_data":reference_result,"beta_primitive_2pow17_rank_check":alternate_result}});
    fs::write(
        out.join("decoder.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    fn layout(product: bool) -> Layout<Small> {
        Layout::new(
            Shape {
                m: 8,
                r: 6,
                ell: 6,
                a: 4,
            },
            Small::from(3u64),
            product,
        )
        .unwrap()
    }

    #[test]
    fn coset_interpolation_uses_only_received_values() {
        for product in [false, true] {
            let domain = layout(product);
            let polynomial: Vec<_> = (1..=6).map(Small::from).collect();
            let values = domain.evaluate(3, &polynomial);
            let received: Vec<_> = [0, 2, 3, 5, 6, 7].iter().map(|&i| (i, values[i])).collect();
            let (actual, z) = interpolate(&domain, 3, &received).unwrap();
            assert_eq!(actual, polynomial);
            assert!(received.iter().all(|&(i, _)| evaluate(
                &z,
                domain.betas[3] * domain.domain.element(i)
            )
            .is_zero()));
            let partial = &received[..4];
            let (actual, z) = interpolate(&domain, 3, partial).unwrap();
            assert!(actual[4..].iter().all(|x| x.is_zero()));
            assert!(partial
                .iter()
                .all(|&(i, y)| evaluate(&actual, domain.betas[3] * domain.domain.element(i)) == y));
            assert_eq!(z.len(), 5);
        }
    }

    #[test]
    fn rank_deficiency_and_inconsistency_are_distinct() {
        let one = Small::ONE;
        let zero = Small::ZERO;
        let result = solve(vec![vec![one, one, one], vec![one, one, one]], 2).unwrap();
        assert_eq!(result.rank, 1);
        assert!(result.consistent && result.values.is_none());
        let result = solve(vec![vec![one, one, one], vec![one, one, zero]], 2).unwrap();
        assert_eq!(result.rank, 1);
        assert!(!result.consistent && result.values.is_none());
    }

    #[test]
    fn rejects_duplicate_and_inconsistent_evidence() {
        let domain = layout(false);
        assert!(interpolate(&domain, 0, &[(0, Small::ONE), (0, Small::ONE)]).is_err());
        let polynomial: Vec<_> = (1..=6).map(Small::from).collect();
        let values = domain.evaluate(0, &polynomial);
        let mut received: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, &value)| (i, value))
            .collect();
        received[7].1 += Small::ONE;
        assert!(interpolate(&domain, 0, &received).is_err());
    }

    #[test]
    fn structured_recovery_handles_full_partial_and_empty_groups() {
        for product in [false, true] {
            let domain = layout(product);
            let locals = random_locals(&domain, 42, "test-decoder");
            let pattern = proposition_pattern(domain.shape).unwrap();
            check_case(&domain, &locals, &pattern, domain.shape.r).unwrap();
            let pattern: Vec<_> = (0..domain.shape.ell)
                .map(|j| {
                    if j < domain.shape.a {
                        (0..domain.shape.m).collect()
                    } else {
                        Vec::new()
                    }
                })
                .collect();
            check_case(&domain, &locals, &pattern, domain.shape.r).unwrap();
            let empty = vec![Vec::new(); domain.shape.ell];
            let result = decode(&domain, &empty, domain.shape.r).unwrap();
            assert!(result.consistent && result.locals.is_none());
            assert!(result.rank < result.unknowns);
        }
    }
}
