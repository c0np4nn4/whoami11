#!/usr/bin/env python3
"""Keep new recovery timings, a conditional CPU model, and old A/B comparisons separate."""
import argparse, csv, hashlib, json, math, pathlib
import analyze
ROOT=pathlib.Path(__file__).resolve().parents[1]
PATTERNS=("rectangle","rectangle_minus_one","random_matched")
REFERENCE=dict(ell=123,m=1024,r=768,a=82,b=0)

def finite_nonnegative(x):
    if isinstance(x,bool) or not isinstance(x,(float,int)) or not math.isfinite(x) or x<0:
        raise ValueError("scenario counts must be finite and nonnegative")

def process_keys(*rows):
    keys=set(rows[0]["process_means_ms"])
    if not keys or any(set(row["process_means_ms"])!=keys for row in rows):
        raise ValueError("paired components require identical process IDs from one dataset")
    if any(not math.isfinite(v) or v<=0 for row in rows for v in row["process_means_ms"].values()):
        raise ValueError("invalid component latency")
    return sorted(keys,key=int)

def paired_ratio(top,bottom):
    ids=process_keys(top,bottom)
    mean,half=analyze.confidence([top["process_means_ms"][i]/bottom["process_means_ms"][i] for i in ids])
    return dict(mean=mean,ci95_halfwidth=half)

def cpu_model(components,clients,reconstructions):
    """CPU-work proxy from role subtotals, not concurrent end-to-end latency."""
    finite_nonnegative(clients);finite_nonnegative(reconstructions)
    ids=process_keys(*components.values())
    totals={}
    for s in ("lrdas","product"):
        totals[s]={i:components[s+"_publish"]["process_means_ms"][i]
                     +clients*components[s+"_client"]["process_means_ms"][i]
                     +reconstructions*components[s+"_recovery"]["process_means_ms"][i] for i in ids}
    mean,half=analyze.confidence([totals["product"][i]-totals["lrdas"][i] for i in ids])
    ratio,rhalf=analyze.confidence([totals["product"][i]/totals["lrdas"][i] for i in ids])
    return dict(clients=clients,reconstructions=reconstructions,
                lrdas_ms=analyze.confidence(list(totals["lrdas"].values()))[0],
                product_ms=analyze.confidence(list(totals["product"].values()))[0],
                product_minus_lr_ms=mean,difference_ci95_halfwidth_ms=half,
                product_over_lr=ratio,ratio_ci95_halfwidth=rhalf,
                measurement_kind="model_from_measured_components")

def break_even(components,reconstructions):
    finite_nonnegative(reconstructions);process_keys(*components.values())
    mean=lambda k:analyze.confidence(list(components[k]["process_means_ms"].values()))[0]
    saving=mean("product_client")-mean("lrdas_client")
    if saving<=0:raise ValueError("no positive per-client saving")
    threshold=(mean("lrdas_publish")-mean("product_publish")
               +reconstructions*(mean("lrdas_recovery")-mean("product_recovery")))/saving
    return dict(reconstructions=reconstructions,clients_real_threshold=threshold,
                first_strictly_better_integer_clients=max(0,math.floor(threshold)+1),
                basis="mean components; conditional model, not an observed workload threshold")

def validate_separation(env,manifests):
    p=manifests[0]["config"]["params"]
    if p["b"]!=0 or manifests[0]["config"]["suite"]!="separation" or env["filter"]:
        raise ValueError("require unfiltered b=0 separation suite")
    erased=(p["ell"]-p["a"]+1)*(p["m"]-p["r"]+1)
    expected={(s,t) for s in ("lrdas","product") for t in PATTERNS}
    trials=[]
    for m in manifests:
        roles={(r["scheme"],r["pattern"]):r for r in m["roles"]}
        if len(m["roles"])!=6 or set(roles)!=expected:raise ValueError("outcome matrix mismatch")
        for pattern in PATTERNS:
            lr,pr=roles["lrdas",pattern],roles["product",pattern]
            if lr["mask_sha256"]!=pr["mask_sha256"]:raise ValueError("unmatched loss pattern")
            for row in (lr,pr):
                count=erased-int(pattern=="rectangle_minus_one")
                if row["erased"]!=count or row["survivors"]!=p["ell"]*p["m"]-count:
                    raise ValueError("inconsistent erasure count")
                if row["input_boundary"]!="already_authenticated_field_values_and_verified_header":
                    raise ValueError("unmatched input boundary")
                if pattern=="rectangle" and row["scheme"]=="product":
                    if (row["outcome"]!="not_uniquely_decodable_from_symbols"
                        or row.get("witness_verified") is not True
                        or row.get("same_header_claimed") is not False
                        or row.get("witness_nonzero_symbols")!=erased):
                        raise ValueError("missing constructive ambiguity evidence")
                elif row["outcome"]!="recovered_and_authenticated":
                    raise ValueError("unexpected reconstruction failure")
            trials.append(dict(process_run_id=m["process_run_id"],seed=m["config"]["seed"],
                               pattern=pattern,lrdas=lr,product=pr))
    return trials

def measurements(folder):
    env,manifests,records=analyze.load_runs(folder)
    return env,manifests,records,analyze.summarize(records)
def index(summary):
    return {(r["scheme"],r["operation"],r["cache_policy"]):r for r in summary}

def make_analysis(new_folder,old_folder):
    env,manifests,raw,summary=measurements(new_folder)
    old_env,old_manifests,_,old_summary=measurements(old_folder)
    trials=validate_separation(env,manifests)
    if (old_manifests[0]["config"]["params"]!=REFERENCE
        or old_manifests[0]["config"]["suite"]!="tradeoffs" or old_env["filter"]):
        raise ValueError("cost model requires full reference tradeoffs archive")
    old=index(old_summary);components={}
    for s in ("lrdas","product"):
        for role,op,c in (("publish","variant_encode_total","public_parameters"),
                          ("client","variant_light_client","cold"),
                          ("recovery","diagonal_decode_authenticate","accepted_values")):
            components[s+"_"+role]=old[s+"_a",op,c]
    scenarios=[cpu_model(components,n,r) for r in (0,0.01,0.1,1,10) for n in (1,4,5,10,100,1000)]
    profiles=[]
    for p in ("a","b"):
        lc=old["lrdas_"+p,"variant_light_client","cold"]
        pc=old["product_"+p,"variant_light_client","cold"]
        profiles.append(dict(profile=p.upper(),lrdas_client=lc,product_client=pc,
                             lrdas_producer=old["lrdas_"+p,"variant_encode_total","public_parameters"],
                             product_producer=old["product_"+p,"variant_encode_total","public_parameters"],
                             product_over_lr_client=paired_ratio(pc,lc)))
    def source(folder,e):
        return dict(dataset=folder.name,source_sha256=e["source"]["sha256"],
                    binary_sha256=e["binary_sha256"],processes=e["runs_requested"],
                    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.iterdir())
                           if p.suffix in (".json",".jsonl")})
    return dict(schema_version=1,reference_parameters=REFERENCE,
                separation_parameters=manifests[0]["config"]["params"],
                measured_recovery=summary,separation_trials=trials,recovery_environment=env,
                recovery_samples=len(raw),scenario_components=components,cpu_scenarios=scenarios,
                break_even=[break_even(components,r) for r in (0,0.01,0.1,1,10)],
                profile_comparison=profiles,
                sources=dict(recovery=source(new_folder,env),model=source(old_folder,old_env)),
                analysis_sha256={n:hashlib.sha256((ROOT/"scripts"/n).read_bytes()).hexdigest()
                                 for n in ("analyze_scenarios.py","scenario_report.py","analyze.py",
                                           "separation_matrix.py","tradeoff_matrix.py")},
                distinctions=dict(recovery="new measured timings with separate source/processes",
                                  scenarios="conditional CPU subtotal from old tradeoffs-paper only",
                                  profiles="paired comparison of old A/B observations, not a rerun",
                                  ambiguity="coding symbols only, not a same-header collision",
                                  excluded="setup, recovery input proof verification, response generation, network, distributed scheduling"))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--recovery",type=pathlib.Path,default=ROOT/"results/raw/separation-paper")
    ap.add_argument("--existing",type=pathlib.Path,default=ROOT/"results/raw/tradeoffs-paper")
    ap.add_argument("--out",type=pathlib.Path,default=ROOT/"results/processed/scenarios")
    ap.add_argument("--paper",type=pathlib.Path,default=ROOT/"paper")
    ap.add_argument("--figures",type=pathlib.Path,default=ROOT/"paper/figures/scenarios")
    a=ap.parse_args();data=make_analysis(a.recovery,a.existing);a.out.mkdir(parents=True,exist_ok=True)
    (a.out/"summary.json").write_text(json.dumps(data,indent=2,allow_nan=False)+"\n")
    for name,rows in (("recovery.csv",data["measured_recovery"]),("cpu_scenarios.csv",data["cpu_scenarios"]),
                      ("break_even.csv",data["break_even"])):
        with (a.out/name).open("w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    from scenario_report import write_outputs
    write_outputs(data,a.paper,a.figures)
    print(json.dumps(dict(workloads=len(data["measured_recovery"]),
                         processes=data["sources"]["recovery"]["processes"],break_even=data["break_even"]),indent=2))
if __name__=="__main__":main()
