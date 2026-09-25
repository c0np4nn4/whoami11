use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use lrdas_artifact::{
    bytes, decode,
    domain::{Domain, Params, Scheme},
    fixture,
    kzg::{msm_g1, pairing_product, Opening, PublicSrs},
    polynomial,
    protocol::*,
    Error, Result,
};
use rand::{seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    suite: String,
    name: String,
    params: Params,
    samples: usize,
    warmup_ms: u64,
    min_sample_ms: u64,
    max_iterations: u64,
    slow_samples: usize,
    seed: u64,
    include_streaming: bool,
}
struct Runner {
    writer: BufWriter<File>,
    config: Config,
    run_id: String,
    process_run_id: usize,
    filter: String,
    rows: usize,
}
impl Runner {
    fn bench<T, F: FnMut() -> Result<T>>(
        &mut self,
        scheme: &str,
        op: &str,
        size: usize,
        cache: &str,
        slow: bool,
        mut f: F,
    ) -> Result<()> {
        if !self.filter.is_empty() && !op.contains(&self.filter) {
            return Ok(());
        }
        eprintln!("{} / {} / {} ({})", self.run_id, scheme, op, size);
        let warm = Instant::now();
        if !slow {
            while warm.elapsed().as_millis() < u128::from(self.config.warmup_ms) {
                black_box(f()?);
            }
        }
        let pilot_ns = if slow {
            0
        } else {
            let pilot = Instant::now();
            black_box(f()?);
            pilot.elapsed().as_nanos().max(1)
        };
        let iterations = if slow {
            1
        } else {
            ((u128::from(self.config.min_sample_ms) * 1_000_000 / pilot_ns)
                .max(1)
                .min(u128::from(self.config.max_iterations))) as u64
        };
        let count = if slow {
            self.config.slow_samples
        } else {
            self.config.samples
        };
        for sample_id in 0..count {
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(f()?);
            }
            let elapsed_ns = start.elapsed().as_nanos();
            let row = json!({"schema_version":1,"run_id":self.run_id,"process_run_id":self.process_run_id,"scheme":scheme,"backend":"arkworks-0.4","profile":self.config.name,"operation":op,"workload_id":format!("{scheme}/{op}/{size}/{cache}"),"input_size":size,"sample_id":sample_id,"iterations":iterations,"elapsed_ns":elapsed_ns as u64,"threads":1,"cache_policy":cache,"seed":self.config.seed,"fixture_id":format!("chacha20-v1-{}",self.config.seed),"status":"ok","measurement_kind":"measured","timing_scope":"wall_clock_library_or_role_as_documented","warmup_ms":if slow{0}else{self.config.warmup_ms},"pilot_ns":pilot_ns as u64});
            serde_json::to_writer(&mut self.writer, &row).map_err(err)?;
            writeln!(&mut self.writer).map_err(err)?;
            self.rows += 1;
        }
        self.writer.flush().map_err(err)?;
        Ok(())
    }
}
fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn primitive_benches(r: &mut Runner, srs: &PublicSrs) -> Result<()> {
    let mut rng = fixture::rng(r.config.seed, "primitives");
    let bases = G1Projective::normalize_batch(
        &(0..1024)
            .map(|_| G1Projective::rand(&mut rng))
            .collect::<Vec<_>>(),
    );
    let scalars = (0..1024.max(srs.r() + 1))
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();
    for size in [1, 16, 64, 82, 128, 256, 512, 767, 768, 1024] {
        r.bench("primitive", "g1_msm", size, "none", false, || {
            msm_g1(black_box(&bases[..size]), black_box(&scalars[..size]))
        })?;
    }
    for size in [2, 3, 9, 33, 129, srs.r() + 1] {
        if size > srs.g2().len() {
            continue;
        }
        r.bench("primitive", "g2_msm", size, "none", false, || {
            srs.commit_g2(black_box(&scalars[..size]))
        })?;
    }
    let a = bases[0];
    let b = (G2Projective::generator() * scalars[0]).into_affine();
    r.bench("primitive", "pairing", 1, "unprepared", false, || {
        Ok(Bls12_381::pairing(black_box(a), black_box(b)))
    })?;
    r.bench(
        "primitive",
        "pairing_product",
        2,
        "unprepared",
        false,
        || {
            Ok(pairing_product(
                black_box(a),
                black_box(b),
                black_box(a),
                black_box(b),
            ))
        },
    )?;
    type Prepared = <Bls12_381 as Pairing>::G2Prepared;
    r.bench("primitive", "g2_prepare", 1, "none", false, || {
        Ok(Prepared::from(black_box(b)))
    })?;
    let prepared = Prepared::from(b);
    let neg = (-a.into_group()).into_affine();
    r.bench(
        "primitive",
        "pairing_product",
        2,
        "prepared_g2",
        false,
        || {
            Ok(Bls12_381::multi_pairing(
                [black_box(a), black_box(neg)],
                [prepared.clone(), prepared.clone()],
            ))
        },
    )?;
    let raw = bytes(&a)?;
    r.bench(
        "primitive",
        "g1_deserialize_checked",
        1,
        "none",
        false,
        || decode::<G1Affine>(black_box(&raw)),
    )?;
    let projective = a.into_group() * scalars[1];
    r.bench("primitive", "g1_to_affine", 1, "none", false, || {
        Ok(black_box(projective).into_affine())
    })?;
    Ok(())
}
fn affinity(mask: &str) -> Result<()> {
    let output = std::process::Command::new("taskset")
        .args(["-pc", mask, &std::process::id().to_string()])
        .output()
        .map_err(err)?;
    if !output.status.success() {
        return Err(err("cannot set benchmark affinity"));
    }
    Ok(())
}
fn prepare_streaming(
    d: &Domain,
    srs: &PublicSrs,
    scheme: Scheme,
    locals: &[Vec<Fr>],
    groups: &[usize],
) -> Result<Vec<Vec<Vec<u8>>>> {
    let masks = std::env::var("LRDAS_FIXTURE_CPUS")
        .ok()
        .zip(std::env::var("LRDAS_BENCH_CPU").ok());
    let workers = masks
        .as_ref()
        .map_or(1, |(cpus, _)| cpus.split(',').count().min(8))
        .max(1);
    if let Some((mask, _)) = &masks {
        affinity(mask)?;
    }
    let result = std::thread::scope(|scope| {
        let jobs = groups
            .chunks(groups.len().div_ceil(workers))
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|&j| {
                            (0..d.params().r())
                                .map(|i| {
                                    let x = d.point(scheme, j, i)?;
                                    srs.open(&locals[j], &[x])?.to_bytes(srs.r())
                                })
                                .collect::<Result<Vec<_>>>()
                        })
                        .collect::<Result<Vec<_>>>()
                })
            })
            .collect::<Vec<_>>();
        let mut out = Vec::with_capacity(groups.len());
        for job in jobs {
            out.extend(job.join().map_err(|_| err("fixture worker panicked"))??);
        }
        Ok(out)
    });
    if let Some((_, cpu)) = &masks {
        affinity(cpu)?;
    }
    result
}
struct Request {
    j: usize,
    index: usize,
    raw: Vec<u8>,
}
fn verify_requests(
    d: &Domain,
    srs: &PublicSrs,
    h: &VerifiedHeader,
    cache: &mut GroupCache,
    requests: &[Request],
) -> Result<usize> {
    for q in requests {
        let o = Opening::from_bytes(&q.raw, 1, srs.r())?;
        let x = d.point(h.scheme(), q.j, q.index)?;
        srs.verify(cache.get(h, d, q.j)?, &[x], &o)?;
    }
    Ok(requests.len())
}
fn protocol_benches(
    r: &mut Runner,
    d: &Domain,
    srs: &PublicSrs,
    scheme: Scheme,
    metadata: &mut Vec<serde_json::Value>,
) -> Result<()> {
    let p = d.params();
    let name = scheme.name();
    let message = fixture::message(p, r.config.seed);
    let polys = MessagePolys::new(d, &message)?;
    let enc = encode(d, srs, scheme, &message)?;
    let h = enc.header.clone().verify(d, srs)?;
    let header_raw = enc.header.payload()?;
    let header_context = enc.header.context();
    let j = p.a();
    let indices = (0..p.r()).collect::<Vec<_>>();
    let xs = indices
        .iter()
        .map(|&i| d.point(scheme, j, i))
        .collect::<Result<Vec<_>>>()?;
    let vals = enc.values[j][..p.r()].to_vec();
    let certified = CertifiedGroup::from_values(d, srs, &h, j, &indices, &vals)?;
    r.bench(name, "message_prepare", p.k(), "none", false, || {
        MessagePolys::new(d, black_box(&message))
    })?;
    r.bench(
        name,
        "outer_combine",
        p.ell(),
        "public_weights",
        false,
        || polys.locals(d),
    )?;
    r.bench(
        name,
        "inner_evaluate_all",
        p.ell(),
        "public_powers",
        false,
        || {
            enc.locals
                .iter()
                .enumerate()
                .map(|(j, cs)| d.evaluate(scheme, j, cs))
                .collect::<Result<Vec<_>>>()
        },
    )?;
    if scheme == Scheme::Lrdas {
        r.bench(
            name,
            "coset_scaling_all",
            p.ell(),
            "public_powers",
            false,
            || {
                let mut locals = enc.locals.clone();
                for (j, cs) in locals.iter_mut().enumerate() {
                    d.scale_in_place(j, cs)?;
                }
                Ok(locals)
            },
        )?;
    }
    let padded = {
        let mut v = enc.locals[j].clone();
        v.resize(p.m(), Fr::from(0));
        v
    };
    r.bench(name, "inner_fft", p.m(), "none", false, || {
        Ok(d.fft().fft(black_box(&padded)))
    })?;
    r.bench(name, "header_commit", p.a(), "public_srs", false, || {
        polys.commit(d, srs, scheme)
    })?;
    r.bench(
        name,
        "encode_commit_total",
        p.n(),
        "public_parameters",
        false,
        || encode(d, srs, scheme, black_box(&message)),
    )?;
    r.bench(name, "header_parse_verify", p.a(), "cold", false, || {
        Header::from_payload(d, srs, scheme, header_context, black_box(&header_raw))?.verify(d, srs)
    })?;
    r.bench(name, "derive_source", p.a(), "none", false, || {
        h.derive(d, black_box(0))
    })?;
    r.bench(name, "derive_parity", p.a(), "none", false, || {
        h.derive(d, black_box(j))
    })?;
    r.bench(
        name,
        "derive_all_parity",
        p.ell() - p.a(),
        "none",
        false,
        || {
            (p.a()..p.ell())
                .map(|j| h.derive(d, j))
                .collect::<Result<Vec<_>>>()
        },
    )?;
    let mut ts = vec![1, 2, 8, 32, 128, p.r()];
    ts.sort_unstable();
    ts.dedup();
    for t in ts.into_iter().filter(|&t| t <= p.r()) {
        let points = &xs[..t];
        let opening = srs.open(&enc.locals[j], points)?;
        let c = h.derive(d, j)?;
        srs.verify(c, points, &opening)?;
        r.bench(
            name,
            if t == p.r() {
                "full_group_open"
            } else {
                "open"
            },
            t,
            "local_coefficients",
            false,
            || srs.open(black_box(&enc.locals[j]), black_box(points)),
        )?;
        r.bench(
            name,
            if t == p.r() {
                "full_group_verify"
            } else {
                "verify"
            },
            t,
            "parsed",
            false,
            || srs.verify(black_box(c), black_box(points), black_box(&opening)),
        )?;
    }
    r.bench(name, "local_interpolate", p.r(), "none", false, || {
        polynomial::interpolate(black_box(&xs), black_box(&vals))
    })?;
    r.bench(
        name,
        "group_certify",
        p.r(),
        "verified_header",
        false,
        || CertifiedGroup::from_values(d, srs, &h, j, &indices, &vals),
    )?;
    let mut random_indices = (0..p.m()).collect::<Vec<_>>();
    random_indices.shuffle(&mut fixture::rng(r.config.seed, "recovery-subset"));
    random_indices.truncate(p.r());
    let random_vals = random_indices
        .iter()
        .map(|&i| enc.values[j][i])
        .collect::<Vec<_>>();
    r.bench(
        name,
        "group_certify_random",
        p.r(),
        "verified_header",
        false,
        || CertifiedGroup::from_values(d, srs, &h, j, &random_indices, &random_vals),
    )?;
    r.bench(
        name,
        "group_recover_evaluate",
        p.m(),
        "certified_coefficients",
        false,
        || certified.recover(d),
    )?;
    r.bench(
        name,
        "serve_new_point",
        1,
        "certified_coefficients",
        false,
        || certified.serve(d, srs, &[p.m() - 1]),
    )?;
    r.bench(
        name,
        "certify_recover_first_serve",
        p.r(),
        "verified_header",
        false,
        || {
            let c = CertifiedGroup::from_values(d, srs, &h, j, &indices, &vals)?;
            let v = c.recover(d)?;
            let o = c.serve(d, srs, &[p.m() - 1])?;
            srs.verify(c.commitment(), &[d.point(scheme, j, p.m() - 1)?], &o)?;
            Ok((v, o))
        },
    )?;
    for group_mode in ["source", "mixed"] {
        let groups: Vec<usize> = if group_mode == "source" {
            (0..p.a()).collect()
        } else {
            (p.ell() - p.a()..p.ell()).collect()
        };
        let raw: Vec<Vec<u8>> = groups
            .iter()
            .map(|&j| {
                Opening {
                    values: enc.values[j][..p.r()].to_vec(),
                    proof: G1Affine::zero(),
                }
                .to_bytes(p.r())
            })
            .collect::<Result<_>>()?;
        r.bench(
            name,
            &format!("collector_batch_{group_mode}"),
            p.a(),
            "verified_header",
            true,
            || {
                groups
                    .iter()
                    .zip(&raw)
                    .map(|(&j, raw)| {
                        let o = Opening::from_bytes(raw, p.r(), p.r())?;
                        CertifiedGroup::from_values(d, srs, &h, j, &indices, &o.values)
                    })
                    .collect::<Result<Vec<_>>>()
            },
        )?;
    }
    let queries = if r.config.name == "reference" {
        vec![218, p.queries(scheme, 128)?]
    } else {
        vec![8, 16]
    };
    let maxq = *queries.iter().max().ok_or_else(|| err("empty queries"))?;
    let mut rng = fixture::rng(r.config.seed, "light-client-indices");
    let requests = (0..maxq)
        .map(|_| {
            let flat = rng.gen_range(0..p.n());
            let j = flat / p.m();
            let index = flat % p.m();
            let x = d.point(scheme, j, index)?;
            Ok(Request {
                j,
                index,
                raw: srs.open(&enc.locals[j], &[x])?.to_bytes(p.r())?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut queries = queries;
    queries.sort_unstable();
    queries.dedup();
    for count in queries {
        let qs = &requests[..count];
        let touched = qs
            .iter()
            .map(|q| q.j)
            .collect::<std::collections::BTreeSet<_>>();
        metadata.push(json!({"scheme":name,"queries":count,"touched_groups":touched.len(),"parity_groups":touched.iter().filter(|&&j|j>=p.a()).count(),"response_payload_bytes":80*count,"header_payload_bytes":header_raw.len(),"context_framing_bytes":32,"query_indices":qs.iter().map(|q|(q.j,q.index)).collect::<Vec<_>>()}));
        r.bench(name, "light_client", count, "cold", false, || {
            let hh = Header::from_payload(d, srs, scheme, header_context, &header_raw)?
                .verify(d, srs)?;
            let mut cache = GroupCache::new(&hh, d);
            verify_requests(d, srs, &hh, &mut cache, qs)
        })?;
        let mut cache = GroupCache::new(&h, d);
        for q in qs {
            let _ = cache.get(&h, d, q.j)?;
        }
        r.bench(name, "light_client", count, "warm", false, || {
            verify_requests(d, srs, &h, &mut cache, qs)
        })?;
    }
    if r.config.include_streaming
        && (r.filter.is_empty() || "collector_streaming".contains(&r.filter))
    {
        eprintln!("Preparing {name} streaming responses (outside timed region)...");
        let groups: Vec<_> = (p.ell() - p.a()..p.ell()).collect();
        let preparation_start = Instant::now();
        let responses = prepare_streaming(d, srs, scheme, &enc.locals, &groups)?;
        metadata.push(json!({"scheme":name,"streaming_fixture_seconds":preparation_start.elapsed().as_secs_f64(),"preparation_cpu_list":std::env::var("LRDAS_FIXTURE_CPUS").unwrap_or_else(|_|"single measurement CPU".into()),"timed_threads":1}));
        r.bench(
            name,
            "collector_streaming",
            p.a(),
            "verified_header",
            true,
            || {
                let mut cache = GroupCache::new(&h, d);
                let mut served = Vec::with_capacity(groups.len());
                for (&j, group) in groups.iter().zip(&responses) {
                    let mut collector = StreamingCollector::new(j);
                    for (i, raw) in group.iter().enumerate() {
                        collector.accept(d, srs, &h, &mut cache, i, raw)?;
                    }
                    served.push(collector.finish(d, srs, &h)?);
                }
                Ok(served)
            },
        )?;
    }
    Ok(())
}
#[path = "bench/tradeoffs.rs"]
mod tradeoffs;

fn run(config: Config, out: &Path, process_run_id: usize, filter: String) -> Result<()> {
    let config = Config {
        params: config.params.validate()?,
        ..config
    };
    if !config.suite.is_empty() && config.suite != "tradeoffs" {
        return Err(err("unknown measurement suite"));
    }
    if config.samples == 0
        || config.samples > 10000
        || config.slow_samples == 0
        || config.max_iterations == 0
    {
        return Err(err("invalid measurement settings"));
    }
    if config.params.a() == config.params.ell() || config.params.b() != 0 {
        return Err(err(
            "benchmark comparison requires b=0 and at least one parity group",
        ));
    }
    fs::create_dir_all(out).map_err(err)?;
    let path = out.join(format!("run-{process_run_id}.jsonl"));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(err)?;
    let status_path = out.join(format!("run-{process_run_id}.status.json"));
    fs::write(
        &status_path,
        serde_json::to_vec_pretty(&json!({"status":"running","config":config})).map_err(err)?,
    )
    .map_err(err)?;
    let total_start = Instant::now();
    let init = Instant::now();
    let domain = Domain::new(config.params)?;
    let domain_ms = init.elapsed().as_secs_f64() * 1000.;
    let init = Instant::now();
    let srs = fixture::setup(config.params.r(), 7001)?;
    let setup_ms = init.elapsed().as_secs_f64() * 1000.;
    let run_id = format!("{}-{}", config.name, process_run_id);
    let mut runner = Runner {
        writer: BufWriter::new(file),
        config: config.clone(),
        run_id,
        process_run_id,
        filter,
        rows: 0,
    };
    let mut meta = vec![];
    let result = (|| {
        if config.suite == "tradeoffs" {
            return tradeoffs::run(&mut runner, &domain, &srs, &mut meta);
        }
        primitive_benches(&mut runner, &srs)?;
        let schemes = if process_run_id.is_multiple_of(2) {
            [Scheme::Lrdas, Scheme::Product]
        } else {
            [Scheme::Product, Scheme::Lrdas]
        };
        for scheme in schemes {
            protocol_benches(&mut runner, &domain, &srs, scheme, &mut meta)?;
        }
        Ok(())
    })();
    runner.writer.flush().map_err(err)?;
    let status = if result.is_ok() { "complete" } else { "failed" };
    let memory = fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("VmHWM:") || l.starts_with("Threads:"))
        .collect::<Vec<_>>()
        .join("; ");
    let source_version = fs::read_to_string(out.join("environment.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let manifest = json!({"schema_version":1,"status":status,"error":result.as_ref().err().map(ToString::to_string),"process_run_id":process_run_id,"config":config,"filter":runner.filter,"rows":runner.rows,"domain_setup_ms":domain_ms,"srs_fixture_ms":setup_ms,"srs_id":format!("{:x}",Sha256::digest(srs.id())),"srs_g1_payload_bytes":srs.r()*48,"srs_g2_payload_bytes":(srs.r()+1)*96,"roles":meta,"elapsed_seconds":total_start.elapsed().as_secs_f64(),"whole_runner_high_water":memory,"environment":source_version});
    fs::write(
        status_path,
        serde_json::to_vec_pretty(&manifest).map_err(err)?,
    )
    .map_err(err)?;
    result
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|s| s == "--help") {
        println!("Usage: bench --config FILE --out NEW_RUN_DIRECTORY [--run N] [--filter OP_SUBSTRING] [--seed N]\nEach output run is create-new. No existing samples are overwritten.");
        return Ok(());
    }
    let mut config_path = None;
    let mut out = None;
    let mut number = 0;
    let mut filter = String::new();
    let mut seed = None;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).ok_or("missing argument value")?;
        match args[i].as_str() {
            "--config" => config_path = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            "--run" => number = value.parse()?,
            "--filter" => filter = value.clone(),
            "--seed" => seed = Some(value.parse::<u64>()?),
            _ => return Err(format!("unknown argument {}", args[i]).into()),
        }
        i += 2;
    }
    let mut config: Config =
        serde_json::from_slice(&fs::read(config_path.ok_or("--config required")?)?)?;
    config.seed = seed.unwrap_or(config.seed.wrapping_add(number as u64));
    run(config, &out.ok_or("--out required")?, number, filter)?;
    Ok(())
}
