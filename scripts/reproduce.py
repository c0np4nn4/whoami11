#!/usr/bin/env python3
"""Sequential, CPU-pinned runs with immutable per-run data and source provenance."""
import argparse, datetime, hashlib, json, os, pathlib, platform, subprocess, sys, time, threading
ROOT=pathlib.Path(__file__).resolve().parents[1]

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def capture(args):
    try:
        return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
    except (OSError,subprocess.CalledProcessError) as e:
        return 'unknown: '+str(type(e).__name__)

def read(path):
    try:return pathlib.Path(path).read_text().strip()
    except OSError:return 'unknown'

def source_manifest():
    files=sorted([*ROOT.glob('src/**/*.rs'),ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml'])
    hashes={str(p.relative_to(ROOT)):digest(p) for p in files}
    return {'files':hashes,'sha256':hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--profile',choices=['smoke','reference','tradeoffs-smoke','tradeoffs-reference','separation-smoke','separation-reference'],default='smoke')
    ap.add_argument('--out',type=pathlib.Path)
    ap.add_argument('--runs',type=int,default=3)
    ap.add_argument('--cpu',type=int)
    ap.add_argument('--filter',default='')
    ap.add_argument('--resume',action='store_true')
    ap.add_argument('--timeout-seconds',type=float,help='Optional wall-time limit for each independent process, including fixture preparation')
    ap.add_argument('--offline',action='store_true')
    ap.add_argument('--toolchain',default='1.93.0',help='stable is accepted only if rustc is exactly 1.93.0')
    args=ap.parse_args()
    if args.runs<1:ap.error('--runs must be positive')
    if args.timeout_seconds is not None and args.timeout_seconds<=0:ap.error('--timeout-seconds must be positive')
    version=capture(['rustc','+'+args.toolchain,'--version'])
    if not version.startswith('rustc 1.93.0 '):ap.error('toolchain must provide rustc 1.93.0, got '+version)
    subprocess.run(['cargo','+'+args.toolchain,'build','--locked','--release','--bin','bench',*(['--offline'] if args.offline else [])],cwd=ROOT,check=True)
    allowed=sorted(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else []
    cpu=args.cpu if args.cpu is not None else (allowed[0] if allowed else None)
    if cpu is not None and cpu not in allowed:ap.error('CPU is not in the allowed affinity set')
    fixture_cpus=[];cores=set()
    for c in allowed:
        core=read(f'/sys/devices/system/cpu/cpu{c}/topology/physical_package_id')+':'+read(f'/sys/devices/system/cpu/cpu{c}/topology/core_id')
        if core not in cores:fixture_cpus.append(c);cores.add(core)
        if len(fixture_cpus)==8:break
    out=args.out or ROOT/'results/raw'/f'{args.profile}-{datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")}'
    out=out.resolve()
    if out.exists() and any(out.iterdir()) and not args.resume:ap.error('output exists; select a new path or use --resume')
    out.mkdir(parents=True,exist_ok=True)
    envfile=out/'environment.json'
    config=ROOT/'configs'/f'{args.profile}.json'
    binary=ROOT/'target/release/bench'
    provenance=source_manifest()
    if envfile.exists():
        env=json.loads(envfile.read_text())
        if env['source']['sha256']!=provenance['sha256'] or env['config_sha256']!=digest(config) or env['filter']!=args.filter or env['cpu_affinity']!=cpu or env['runs_requested']!=args.runs:
            ap.error('resume would mix different source/config/filter/CPU/run count')
    else:
        env={'schema_version':1,'utc_started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.system()+' '+platform.release()+' '+platform.machine(),'cpu':capture(['lscpu']),'meminfo':read('/proc/meminfo').splitlines()[:3],'rustc':capture(['rustc','+'+args.toolchain,'-vV']),'cargo':capture(['cargo','+'+args.toolchain,'--version']),'python':sys.version.split()[0],'source':provenance,'config_sha256':digest(config),'binary_sha256':digest(binary),'rustflags':os.environ.get('RUSTFLAGS',''),'cargo_features':'default; arkworks default-features=false; std only; no rayon','cpu_affinity':cpu,'allowed_cpu_count':len(allowed),'governor':read(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor'),'turbo_no_turbo':read('/sys/devices/system/cpu/intel_pstate/no_turbo'),'cpu_quota':read('/sys/fs/cgroup/cpu.max'),'virtualization':capture(['systemd-detect-virt']),'filter':args.filter,'runs_requested':args.runs,'process_timeout_seconds':args.timeout_seconds,'other_load_controlled':False,'fixture_preparation_cpus':fixture_cpus,'environment_label':'local host; single process pinned; system settings unchanged'}
        envfile.write_text(json.dumps(env,indent=2)+'\n')
    for i in range(args.runs):
        status=out/f'run-{i}.status.json'
        if args.resume and status.exists() and json.loads(status.read_text()).get('status')=='complete':continue
        if (out/f'run-{i}.jsonl').exists():ap.error(f'run {i} is incomplete; preserve it and select a new output directory')
        cmd=[str(binary),'--config',str(config),'--out',str(out),'--run',str(i)]
        if args.filter:cmd+=['--filter',args.filter]
        start=time.monotonic()
        with (out/f'run-{i}.log').open('w') as log:
            child_env=dict(os.environ)
            if cpu is not None:child_env.update(LRDAS_FIXTURE_CPUS=','.join(map(str,fixture_cpus)),LRDAS_BENCH_CPU=str(cpu))
            measured_cmd=['taskset','-c',str(cpu),*cmd] if cpu is not None else cmd
            proc=subprocess.Popen(measured_cmd,cwd=ROOT,env=child_env,stdout=log,stderr=subprocess.PIPE,text=True)
            timer=threading.Timer(args.timeout_seconds,proc.terminate) if args.timeout_seconds else None
            if timer:timer.start()
            for line in proc.stderr:
                log.write(line);log.flush();print(line,end='',flush=True)
            returncode=proc.wait()
            if timer:timer.cancel();timer.join()
            if returncode!=0:
                state=json.loads(status.read_text()) if status.exists() else {}
                state.update(status='failed',returncode=returncode,reason='nonzero exit or process time limit; partial raw data preserved')
                status.write_text(json.dumps(state,indent=2)+'\n')
                raise SystemExit(f'run {i} failed; data and logs retained in {out}')
        print(f'run {i} completed in {time.monotonic()-start:.1f}s',flush=True)
    print(str(out))
if __name__=='__main__':main()
