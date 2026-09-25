use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

type CheckResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct Field {
    q: u64,
}

impl Field {
    fn new(q: u64) -> CheckResult<Self> {
        ensure(
            (3..=65537).contains(&q)
                && (2..)
                    .take_while(|d| d * d <= q)
                    .all(|d| !q.is_multiple_of(d)),
            "the specification checker requires a prime field of order 3 through 65537",
        )?;
        Ok(Self { q })
    }

    fn add(self, a: u64, b: u64) -> u64 {
        (a + b) % self.q
    }

    fn sub(self, a: u64, b: u64) -> u64 {
        (a + self.q - b) % self.q
    }

    fn mul(self, a: u64, b: u64) -> u64 {
        a * b % self.q
    }

    fn pow(self, mut a: u64, mut exponent: usize) -> u64 {
        let mut result = 1;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = self.mul(result, a);
            }
            a = self.mul(a, a);
            exponent >>= 1;
        }
        result
    }

    fn inverse(self, value: u64) -> CheckResult<u64> {
        ensure(
            value != 0 && value < self.q,
            "inverse of zero or noncanonical field element",
        )?;
        Ok(self.pow(value, (self.q - 2) as usize))
    }

    fn generator(self) -> u64 {
        let factors: Vec<_> = (2..self.q)
            .filter(|d| (self.q - 1).is_multiple_of(*d))
            .filter(|d| {
                (2..)
                    .take_while(|p| p * p <= *d)
                    .all(|p| !d.is_multiple_of(p))
            })
            .collect();
        (2..self.q)
            .find(|&candidate| {
                factors
                    .iter()
                    .all(|&factor| self.pow(candidate, ((self.q - 1) / factor) as usize) != 1)
            })
            .unwrap()
    }
}

fn ensure(condition: bool, message: &str) -> CheckResult<()> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(message).into())
    }
}

fn evaluate(field: Field, polynomial: &[u64], x: u64) -> u64 {
    polynomial
        .iter()
        .rev()
        .fold(0, |accumulator, &coefficient| {
            field.add(field.mul(accumulator, x), coefficient)
        })
}

fn multiply(field: Field, left: &[u64], right: &[u64]) -> Vec<u64> {
    let mut result = vec![0; left.len() + right.len() - 1];
    for (i, &a) in left.iter().enumerate() {
        for (j, &b) in right.iter().enumerate() {
            result[i + j] = field.add(result[i + j], field.mul(a, b));
        }
    }
    result
}

fn interpolate(field: Field, xs: &[u64], ys: &[u64]) -> CheckResult<Vec<u64>> {
    ensure(
        !xs.is_empty() && xs.len() == ys.len(),
        "invalid interpolation dimensions",
    )?;
    ensure(
        xs.iter().enumerate().all(|(i, x)| !xs[..i].contains(x)),
        "duplicate interpolation coordinates",
    )?;
    let mut divided = ys.to_vec();
    for width in 1..xs.len() {
        for index in (width..xs.len()).rev() {
            divided[index] = field.mul(
                field.sub(divided[index], divided[index - 1]),
                field.inverse(field.sub(xs[index], xs[index - width]))?,
            );
        }
    }
    let mut result = vec![0; xs.len()];
    let mut basis = vec![1];
    for (index, &coefficient) in divided.iter().enumerate() {
        for (power, &value) in basis.iter().enumerate() {
            result[power] = field.add(result[power], field.mul(coefficient, value));
        }
        basis = multiply(field, &basis, &[field.sub(0, xs[index]), 1]);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Parameters {
    q: u64,
    m: usize,
    ell: usize,
    r: usize,
    k: usize,
}

impl Parameters {
    fn a(self) -> usize {
        self.k / self.r
    }

    fn b(self) -> usize {
        self.k % self.r
    }

    fn degree(self) -> usize {
        self.k - 1 + (self.k.div_ceil(self.r) - 1) * (self.m - self.r)
    }
}

struct Instance {
    p: Parameters,
    field: Field,
    generator: u64,
    gamma: Vec<u64>,
    points: Vec<Vec<u64>>,
    lagrange: Vec<Vec<u64>>,
    vanishing: Vec<u64>,
    residual_group: Option<usize>,
}

impl Instance {
    fn new(p: Parameters, residual_group: Option<usize>) -> CheckResult<Self> {
        let field = Field::new(p.q)?;
        ensure(
            p.m > 2 && (p.q - 1).is_multiple_of(p.m as u64),
            "invalid multiplicative subgroup order",
        )?;
        ensure(
            p.ell >= 2 && p.ell <= (p.q - 1) as usize / p.m,
            "too many cosets",
        )?;
        ensure(
            2 <= p.r && p.r < p.m && p.r <= p.k && p.k <= p.ell * p.r,
            "invalid code dimensions",
        )?;
        ensure(
            if p.b() == 0 {
                residual_group.is_none()
            } else {
                residual_group.is_some_and(|j| p.a() <= j && j < p.ell)
            },
            "invalid residual group",
        )?;
        let generator = field.generator();
        let root = field.pow(generator, (p.q as usize - 1) / p.m);
        let mut gamma = Vec::with_capacity(p.ell);
        let mut points = Vec::with_capacity(p.ell);
        for j in 0..p.ell {
            let beta = field.pow(generator, j);
            let label = field.pow(beta, p.m);
            ensure(!gamma.contains(&label), "coset labels are not distinct")?;
            gamma.push(label);
            let group: Vec<_> = (0..p.m)
                .map(|i| field.mul(beta, field.pow(root, i)))
                .collect();
            ensure(
                group.iter().all(|&x| field.pow(x, p.m) == label),
                "invalid coset points",
            )?;
            points.push(group);
        }
        let mut lagrange = Vec::with_capacity(p.a());
        for source in 0..p.a() {
            let mut numerator = vec![1];
            let mut denominator = 1;
            for other in 0..p.a() {
                if source != other {
                    numerator = multiply(field, &numerator, &[field.sub(0, gamma[other]), 1]);
                    denominator = field.mul(denominator, field.sub(gamma[source], gamma[other]));
                }
            }
            let inverse = field.inverse(denominator)?;
            lagrange.push(
                numerator
                    .into_iter()
                    .map(|value| field.mul(value, inverse))
                    .collect(),
            );
        }
        let mut vanishing = vec![1];
        for &label in &gamma[..p.a()] {
            vanishing = multiply(field, &vanishing, &[field.sub(0, label), 1]);
        }
        Ok(Self {
            p,
            field,
            generator,
            gamma,
            points,
            lagrange,
            vanishing,
            residual_group,
        })
    }

    fn source_combination(&self, message: &[u64], label: u64) -> Vec<u64> {
        let mut result = vec![0; self.p.r];
        for source in 0..self.p.a() {
            let weight = evaluate(self.field, &self.lagrange[source], label);
            for (i, value) in result.iter_mut().enumerate() {
                *value = self.field.add(
                    *value,
                    self.field.mul(weight, message[source * self.p.r + i]),
                );
            }
        }
        result
    }

    fn residual(&self, message: &[u64], convert: bool) -> CheckResult<Vec<u64>> {
        ensure(
            message.len() == self.p.k && message.iter().all(|&x| x < self.p.q),
            "invalid message",
        )?;
        let Some(group) = self.residual_group else {
            return Ok(vec![]);
        };
        let v = &message[self.p.a() * self.p.r..];
        if !convert {
            return Ok(v.to_vec());
        }
        let base = self.source_combination(message, self.gamma[group]);
        let weight =
            self.field
                .inverse(evaluate(self.field, &self.vanishing, self.gamma[group]))?;
        Ok(v.iter()
            .zip(base)
            .map(|(&v_i, f_i)| self.field.mul(self.field.sub(v_i, f_i), weight))
            .collect())
    }

    fn encode(&self, message: &[u64], convert: bool) -> CheckResult<Vec<u64>> {
        let residual = self.residual(message, convert)?;
        let mut polynomial = vec![0; self.p.degree() + 1];
        for source in 0..self.p.a() {
            for (outer_power, &outer_coefficient) in self.lagrange[source].iter().enumerate() {
                for inner_power in 0..self.p.r {
                    let power = outer_power * self.p.m + inner_power;
                    polynomial[power] = self.field.add(
                        polynomial[power],
                        self.field
                            .mul(outer_coefficient, message[source * self.p.r + inner_power]),
                    );
                }
            }
        }
        for (outer_power, &outer_coefficient) in self.vanishing.iter().enumerate() {
            for (inner_power, &inner_coefficient) in residual.iter().enumerate() {
                let power = outer_power * self.p.m + inner_power;
                polynomial[power] = self.field.add(
                    polynomial[power],
                    self.field.mul(outer_coefficient, inner_coefficient),
                );
            }
        }
        Ok(polynomial)
    }

    fn remainder(&self, polynomial: &[u64], group: usize) -> Vec<u64> {
        let mut remainder = polynomial.to_vec();
        remainder.resize(remainder.len().max(self.p.m), 0);
        for power in (self.p.m..remainder.len()).rev() {
            let coefficient = remainder[power];
            remainder[power] = 0;
            remainder[power - self.p.m] = self.field.add(
                remainder[power - self.p.m],
                self.field.mul(coefficient, self.gamma[group]),
            );
        }
        remainder.truncate(self.p.m);
        remainder
    }

    fn decode(&self, polynomial: &[u64]) -> Vec<u64> {
        let mut message = Vec::with_capacity(self.p.k);
        for source in 0..self.p.a() {
            message.extend_from_slice(&self.remainder(polynomial, source)[..self.p.r]);
        }
        if let Some(group) = self.residual_group {
            message.extend_from_slice(&self.remainder(polynomial, group)[..self.p.b()]);
        }
        message
    }

    fn belongs(&self, polynomial: &[u64]) -> bool {
        polynomial.iter().enumerate().all(|(power, &coefficient)| {
            coefficient == 0 || (power <= self.p.degree() && power % self.p.m < self.p.r)
        })
    }

    fn mutation_condition(&self, message: &[u64]) -> bool {
        let Some(group) = self.residual_group else {
            return true;
        };
        let base = self.source_combination(message, self.gamma[group]);
        let weight = self
            .field
            .sub(evaluate(self.field, &self.vanishing, self.gamma[group]), 1);
        message[self.p.a() * self.p.r..]
            .iter()
            .zip(base)
            .all(|(&v, f)| self.field.add(f, self.field.mul(weight, v)) == 0)
    }

    fn check(&self, message: &[u64]) -> CheckResult<CaseReport> {
        let polynomial = self.encode(message, true)?;
        ensure(
            self.belongs(&polynomial),
            "encoded polynomial violates global support or degree",
        )?;
        let dimension = (0..=self.p.degree())
            .filter(|power| power % self.p.m < self.p.r)
            .count();
        ensure(
            dimension == self.p.k,
            "incorrect dimension of global monomial space",
        )?;
        let residual = self.residual(message, true)?;
        let mut decoded_from_local_interpolation = Vec::with_capacity(self.p.k);
        let mut local_polynomials = Vec::with_capacity(self.p.ell);
        for group in 0..self.p.ell {
            let values: Vec<_> = self.points[group]
                .iter()
                .map(|&point| evaluate(self.field, &polynomial, point))
                .collect();
            let local = interpolate(
                self.field,
                &self.points[group][..self.p.r],
                &values[..self.p.r],
            )?;
            ensure(
                self.points[group]
                    .iter()
                    .zip(&values)
                    .all(|(&point, &value)| evaluate(self.field, &local, point) == value),
                "local interpolation failed to reconstruct all coset evaluations",
            )?;
            let remainder = self.remainder(&polynomial, group);
            ensure(
                remainder[self.p.r..].iter().all(|&value| value == 0),
                "local restriction has degree at least r",
            )?;
            ensure(
                local == remainder[..self.p.r],
                "interpolated local polynomial differs from polynomial remainder",
            )?;
            let mut from_sources = self.source_combination(message, self.gamma[group]);
            let weight = evaluate(self.field, &self.vanishing, self.gamma[group]);
            for (value, &coefficient) in from_sources.iter_mut().zip(&residual) {
                *value = self.field.add(*value, self.field.mul(weight, coefficient));
            }
            ensure(
                local == from_sources,
                "source representation differs from encoded evaluations",
            )?;
            if group < self.p.a() {
                decoded_from_local_interpolation.extend_from_slice(&local);
            }
            local_polynomials.push(local);
        }
        if let Some(group) = self.residual_group {
            decoded_from_local_interpolation
                .extend_from_slice(&local_polynomials[group][..self.p.b()]);
            let recovery_points: Vec<_> = (self.p.a()..self.p.ell)
                .flat_map(|j| self.points[j].iter().copied())
                .take(self.p.b())
                .collect();
            let mut recovered_values = Vec::with_capacity(self.p.b());
            for &point in &recovery_points {
                let label = self.field.pow(point, self.p.m);
                let mut base = 0;
                for source in 0..self.p.a() {
                    let source_value = evaluate(
                        self.field,
                        &message[source * self.p.r..(source + 1) * self.p.r],
                        point,
                    );
                    base = self.field.add(
                        base,
                        self.field.mul(
                            evaluate(self.field, &self.lagrange[source], label),
                            source_value,
                        ),
                    );
                }
                recovered_values.push(
                    self.field.mul(
                        self.field
                            .sub(evaluate(self.field, &polynomial, point), base),
                        self.field
                            .inverse(evaluate(self.field, &self.vanishing, label))?,
                    ),
                );
            }
            let recovered = interpolate(self.field, &recovery_points, &recovered_values)?;
            ensure(recovered == residual, "equation 8 residual recovery failed")?;
        }
        ensure(
            decoded_from_local_interpolation == message,
            "local message coordinates do not round-trip",
        )?;
        ensure(
            self.decode(&polynomial) == message,
            "global polynomial does not round-trip",
        )?;
        let mutation_survived = if self.p.b() != 0 {
            let mutated = self.encode(message, false)?;
            ensure(
                self.belongs(&mutated),
                "mutation unexpectedly left the code space",
            )?;
            let survived = self.decode(&mutated) == message;
            ensure(
                survived == self.mutation_condition(message),
                "mutation round trip differs from equation 16",
            )?;
            Some(survived)
        } else {
            None
        };
        Ok(CaseReport {
            parameters: self.p,
            a: self.p.a(),
            b: self.p.b(),
            degree_bound: self.p.degree(),
            actual_degree: polynomial.iter().rposition(|&coefficient| coefficient != 0),
            primitive_generator: self.generator,
            residual_group: self.residual_group,
            checked_groups: self.p.ell,
            checked_evaluations: self.p.ell * self.p.m,
            passed: true,
            mutation_survived,
        })
    }
}

#[derive(Serialize)]
struct CaseReport {
    parameters: Parameters,
    a: usize,
    b: usize,
    degree_bound: usize,
    actual_degree: Option<usize>,
    primitive_generator: u64,
    residual_group: Option<usize>,
    checked_groups: usize,
    checked_evaluations: usize,
    passed: bool,
    mutation_survived: Option<bool>,
}

fn enumerate() -> Vec<Parameters> {
    let mut cases = Vec::new();
    for (q, m, ell_max) in [(17, 4, 4), (97, 8, 6), (97, 12, 8), (193, 16, 8)] {
        for ell in 2..=ell_max {
            for r in 2..m {
                for k in r..=ell * r {
                    cases.push(Parameters { q, m, ell, r, k });
                }
            }
        }
    }
    cases
}

fn exhaustive_mutation() -> CheckResult<Value> {
    let parameters = Parameters {
        q: 17,
        m: 4,
        ell: 4,
        r: 3,
        k: 4,
    };
    let instance = Instance::new(parameters, Some(2))?;
    ensure(
        instance.gamma[0] == 1 && instance.gamma[2] == 16,
        "unexpected exhaustive-case coset labels",
    )?;
    let total = parameters.q.pow(parameters.k as u32);
    let mut survived = 0u64;
    let mut equation16_satisfied = 0u64;
    for number in 0..total {
        let mut number = number;
        let mut message = vec![0; parameters.k];
        for coefficient in &mut message {
            *coefficient = number % parameters.q;
            number /= parameters.q;
        }
        let correct = instance.encode(&message, true)?;
        ensure(
            instance.decode(&correct) == message,
            "exhaustive correct round trip failed",
        )?;
        let mutated = instance.encode(&message, false)?;
        let round_trip = instance.decode(&mutated) == message;
        let equation16 = instance.mutation_condition(&message);
        ensure(
            round_trip == equation16,
            "exhaustive mutation condition failed",
        )?;
        survived += u64::from(round_trip);
        equation16_satisfied += u64::from(equation16);
    }
    let predicted = parameters.q.pow((parameters.k - parameters.b()) as u32);
    ensure(
        survived == predicted,
        "exhaustive survival count differs from q^(k-b)",
    )?;
    Ok(json!({
        "parameters": parameters,
        "source_gamma": instance.gamma[0],
        "residual_gamma": instance.gamma[2],
        "messages_checked": total,
        "correct_round_trips": total,
        "mutation_survivors": survived,
        "equation16_satisfied": equation16_satisfied,
        "predicted_survivors_q_to_k_minus_b": predicted,
        "passed": true
    }))
}

pub fn run(out: &Path, seed: u64) -> CheckResult<Value> {
    fs::create_dir_all(out)?;
    let cases = enumerate();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut records = BufWriter::new(File::create(out.join("specification_cases.jsonl"))?);
    let mut zero_residual = 0usize;
    let mut nonzero_residual = 0usize;
    let mut mutation_survivors = 0usize;
    let mut checked_groups = 0usize;
    let mut checked_evaluations = 0usize;
    let mut predicted_mutation_survivors = 0.0f64;
    let mut families = std::collections::BTreeMap::new();
    for p in cases.iter().copied() {
        let instance = Instance::new(p, (p.b() > 0).then_some(p.a()))?;
        let message: Vec<u64> = (0..p.k).map(|_| rng.gen_range(0..p.q)).collect();
        let report = instance
            .check(&message)
            .map_err(|error| std::io::Error::other(format!("specification case {p:?}: {error}")))?;
        if p.b() == 0 {
            zero_residual += 1;
        } else {
            nonzero_residual += 1;
            predicted_mutation_survivors += (p.q as f64).powi(-(p.b() as i32));
            mutation_survivors += usize::from(report.mutation_survived == Some(true));
        }
        checked_groups += report.checked_groups;
        checked_evaluations += report.checked_evaluations;
        *families
            .entry(format!("q={},m={}", p.q, p.m))
            .or_insert(0usize) += 1;
        serde_json::to_writer(&mut records, &report)?;
        writeln!(records)?;
    }
    records.flush()?;
    let exhaustive = exhaustive_mutation()?;
    let result = json!({
        "experiment": "Appendix E.4 specification and mutation checks",
        "seed": seed,
        "random_generator": "rand_chacha 0.3.1 ChaCha20Rng::seed_from_u64; one uniform message per enumerated case",
        "enumeration": "(q,m,ell_max)=(17,4,4),(97,8,6),(97,12,8),(193,16,8); ell=2..ell_max, r=2..m-1, k=r..ell*r",
        "parameter_sets": cases.len(),
        "b_zero": zero_residual,
        "b_positive": nonzero_residual,
        "families": families,
        "checked_groups": checked_groups,
        "checked_evaluations": checked_evaluations,
        "checks": [
            "Psi residual conversion and message round trip",
            "global degree bound, exponent support, and monomial dimension",
            "dense global evaluations versus Newton-interpolated local restrictions",
            "local restrictions versus division by X^m-gamma and source representation",
            "source and residual message coordinates",
            "equation 8 recovery of the residual polynomial",
            "mutation retains code-space membership and succeeds exactly when equation 16 holds"
        ],
        "mutation_survivors_observed": mutation_survivors,
        "mutation_survivors_expected_sum_q_to_minus_b": predicted_mutation_survivors,
        "mutation_count_note": "Observed survivors depend on the supplied seed; the paper's 6.62 is an expected count, not a deterministic target.",
        "exhaustive_mutation": exhaustive,
        "case_records": "specification_cases.jsonl",
        "passed": true
    });
    let mut summary = BufWriter::new(File::create(out.join("specification.json"))?);
    serde_json::to_writer_pretty(&mut summary, &result)?;
    writeln!(summary)?;
    summary.flush()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_matches_the_documented_parameter_domain() {
        let cases = enumerate();
        assert_eq!(cases.len(), 5791);
        assert_eq!(cases.iter().filter(|p| p.b() == 0).count(), 978);
        assert_eq!(cases.iter().filter(|p| p.b() > 0).count(), 4813);
    }

    #[test]
    fn non_power_of_two_subgroup_and_dimension_boundaries_round_trip() {
        for k in [7, 8, 55, 56] {
            let p = Parameters {
                q: 97,
                m: 12,
                ell: 8,
                r: 7,
                k,
            };
            let instance = Instance::new(p, (p.b() > 0).then_some(p.a())).unwrap();
            let message: Vec<_> = (0..k).map(|i| (i as u64 * 11 + 3) % p.q).collect();
            assert!(instance.check(&message).unwrap().passed);
        }
    }

    #[test]
    fn residual_conversion_prevents_detectable_mutation() {
        let p = Parameters {
            q: 17,
            m: 4,
            ell: 4,
            r: 3,
            k: 4,
        };
        let instance = Instance::new(p, Some(2)).unwrap();
        let message = [1, 2, 3, 0];
        assert_eq!(
            instance.decode(&instance.encode(&message, true).unwrap()),
            message
        );
        assert_ne!(
            instance.decode(&instance.encode(&message, false).unwrap()),
            message
        );
        assert!(!instance.mutation_condition(&message));
        assert_eq!(
            instance.check(&message).unwrap().mutation_survived,
            Some(false)
        );
        let survivor = [3, 2, 3, 1];
        assert!(instance.mutation_condition(&survivor));
        assert_eq!(
            instance.check(&survivor).unwrap().mutation_survived,
            Some(true)
        );
    }

    #[test]
    fn invalid_fields_domains_and_messages_are_rejected() {
        assert!(Field::new(9).is_err());
        assert!(Field::new(17).unwrap().inverse(0).is_err());
        let p = Parameters {
            q: 17,
            m: 4,
            ell: 4,
            r: 3,
            k: 4,
        };
        assert!(Instance::new(p, Some(0)).is_err());
        assert!(Instance::new(Parameters { ell: 5, ..p }, Some(1)).is_err());
        assert!(Instance::new(Parameters { m: 3, ..p }, Some(1)).is_err());
        let instance = Instance::new(p, Some(1)).unwrap();
        assert!(instance.encode(&[1, 2, 3], true).is_err());
        assert!(instance.encode(&[1, 2, 3, 17], true).is_err());
        assert!(interpolate(instance.field, &[1, 1], &[2, 3]).is_err());
        let mut illegal = vec![0; p.degree() + 1];
        illegal[3] = 1;
        assert!(!instance.belongs(&illegal));
        illegal[3] = 0;
        illegal.push(1);
        assert!(!instance.belongs(&illegal));
    }

    #[test]
    fn exhaustive_mutation_count_is_measured() {
        let result = exhaustive_mutation().unwrap();
        assert_eq!(result["messages_checked"], 83521);
        assert_eq!(result["mutation_survivors"], 4913);
        assert_eq!(result["equation16_satisfied"], 4913);
    }
}
