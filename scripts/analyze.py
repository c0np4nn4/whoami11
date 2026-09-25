#!/usr/bin/env python3
"""Validate raw runs and generate deterministic summaries, figures and LaTeX.

95% CIs use independent process means, not individual loop iterations. With three
processes the Student-t critical value is 4.3026527299 (2 degrees of freedom).
This is a small-sample, approximate interval; underlying distribution assumptions
and within-run reuse of fixed workloads are stated in the generated report.
"""
import argparse, collections, csv, hashlib, json, math, pathlib, statistics
ROOT=pathlib.Path(__file__).resolve().parents[1]
CRITICAL={2:12.7062047364,3:4.3026527299,4:3.1824463053,5:2.7764451052,6:2.5705818356,7:2.4469118511,8:2.3646242516,9:2.3060041352,10:2.2621571629}
REQUIRED={'schema_version','run_id','process_run_id','scheme','backend','profile','operation','workload_id','input_size','sample_id','iterations','elapsed_ns','threads','cache_policy','seed','fixture_id','status','measurement_kind','timing_scope','warmup_ms','pilot_ns'}

def load_json(path):
    def bad_constant(s): raise ValueError('non-finite JSON constant '+s)
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('duplicate JSON key '+k)
            result[k]=v
        return result
    return json.loads(path.read_text(),parse_constant=bad_constant,object_pairs_hook=unique)

def per_op_ms(row):
    if REQUIRED-set(row):raise ValueError('missing required columns: '+str(REQUIRED-set(row)))
    for key in ['iterations','elapsed_ns','input_size','sample_id','process_run_id']:
        if type(row[key]) is not int or row[key]<0:raise ValueError('invalid '+key)
    if row['iterations']==0 or row['elapsed_ns']==0:raise ValueError('nonpositive measured time/iterations')
    if row['schema_version']!=1 or row['threads']!=1 or row['status']!='ok' or row['measurement_kind']!='measured':raise ValueError('unsupported or unsuccessful sample')
    return row['elapsed_ns']/row['iterations']/1e6

def key(row):return (row['scheme'],row['operation'],row['input_size'],row['cache_policy'])
def confidence(values):
    n=len(values);mean=statistics.mean(values)
    if n<2:return mean,None
    if n not in CRITICAL:raise ValueError('CI supports 2..10 independent runs; extend critical-value table explicitly')
    return mean,CRITICAL[n]*statistics.stdev(values)/math.sqrt(n)

def expected_workloads(config):
    if config.get('suite')=='separation':
        from separation_matrix import expected_workloads as separation
        return separation(config)
    if config.get('suite')=='tradeoffs':
        from tradeoff_matrix import expected_workloads as extended
        return extended(config)
    p=config['params'];a,r,m,ell=(p[k] for k in ['a','r','m','ell']);n=ell*m
    exp={('primitive','g1_msm',v,'none') for v in [1,16,64,82,128,256,512,767,768,1024]}
    exp|={('primitive','g2_msm',v,'none') for v in [2,3,9,33,129,r+1] if v<=r+1}
    exp|={('primitive','pairing',1,'unprepared'),('primitive','pairing_product',2,'unprepared'),('primitive','pairing_product',2,'prepared_g2'),('primitive','g2_prepare',1,'none'),('primitive','g1_deserialize_checked',1,'none'),('primitive','g1_to_affine',1,'none')}
    for scheme in ['lrdas','product']:
        ops=[('message_prepare',a*r,'none'),('outer_combine',ell,'public_weights'),('inner_evaluate_all',ell,'public_powers'),('inner_fft',m,'none'),('header_commit',a,'public_srs'),('encode_commit_total',n,'public_parameters'),('header_parse_verify',a,'cold'),('derive_source',a,'none'),('derive_parity',a,'none'),('derive_all_parity',ell-a,'none'),('local_interpolate',r,'none'),('group_certify',r,'verified_header'),('group_certify_random',r,'verified_header'),('group_recover_evaluate',m,'certified_coefficients'),('serve_new_point',1,'certified_coefficients'),('certify_recover_first_serve',r,'verified_header'),('collector_batch_source',a,'verified_header'),('collector_batch_mixed',a,'verified_header')]
        if scheme=='lrdas':ops.append(('coset_scaling_all',ell,'public_powers'))
        if config['include_streaming']:ops.append(('collector_streaming',a,'verified_header'))
        for t in sorted(set([1,2,8,32,128,r])):
            if t<=r:ops.extend([('full_group_open' if t==r else 'open',t,'local_coefficients'),('full_group_verify' if t==r else 'verify',t,'parsed')])
        queries=[218,218 if scheme=='lrdas' else 991] if config['name']=='reference' else [8,16]
        for q in set(queries):ops.extend([('light_client',q,'cold'),('light_client',q,'warm')])
        exp|={(scheme,*o) for o in ops}
    return exp

def load_runs(folder):
    env=load_json(folder/'environment.json');count=env['runs_requested']
    manifests=[];records=[];seen=set();ref_config=None
    if count<1 or count>10:raise ValueError('expected 1..10 processes')
    for i in range(count):
        manifest=load_json(folder/f'run-{i}.status.json')
        if manifest['status']!='complete' or manifest['process_run_id']!=i:raise ValueError('incomplete process')
        if manifest['environment']!=env:raise ValueError('incompatible environment/provenance')
        config=manifest['config'];base={k:v for k,v in config.items() if k!='seed'}
        if ref_config is not None and base!=ref_config:raise ValueError('mixed experiment configurations')
        ref_config=base;present=set();lines=(folder/f'run-{i}.jsonl').read_text().splitlines()
        if len(lines)!=manifest['rows']:raise ValueError('row count mismatch')
        workload_counts=collections.Counter()
        for line in lines:
            row=json.loads(line);per_op_ms(row)
            if row['backend']!='arkworks-0.4' or row['profile']!=config['name'] or row['process_run_id']!=i or row['seed']!=config['seed'] or row['timing_scope']!='wall_clock_library_or_role_as_documented':raise ValueError('inconsistent sample identity')
            if row['run_id']!=f"{config['name']}-{i}" or row['workload_id']!='/'.join(map(str,key(row))) or row['fixture_id']!=f"chacha20-v1-{config['seed']}":raise ValueError('inconsistent workload/fixture identifiers')
            identity=(i,key(row),row['sample_id'])
            if identity in seen:raise ValueError('duplicate sample')
            seen.add(identity);present.add(key(row));workload_counts[key(row)]+=1;records.append(row)
        expected=expected_workloads(config)
        if manifest['filter']:
            expected={k for k in expected if manifest['filter'] in k[1]}
        if present!=expected:raise ValueError(f'workload matrix mismatch: missing {expected-present}, unexpected {present-expected}')
        for k,n in workload_counts.items():
            if config.get('suite')=='separation':
                target=config['slow_samples']
            elif config.get('suite')=='tradeoffs':
                from tradeoff_matrix import SLOW
                target=config['slow_samples'] if k[1] in SLOW else config['samples']
            else:
                target=config['slow_samples'] if k[1].startswith('collector_') else config['samples']
            if n!=target:raise ValueError('sample count mismatch: '+str(k))
            if {sample_id for process,work,sample_id in seen if process==i and work==k}!=set(range(target)):raise ValueError('sample index gap')
        manifests.append(manifest)
    return env,manifests,records

def summarize(records):
    groups=collections.defaultdict(lambda:collections.defaultdict(list))
    for row in records:groups[key(row)][row['process_run_id']].append(per_op_ms(row))
    output=[]
    for k,runs in sorted(groups.items()):
        means={str(i):statistics.mean(values) for i,values in sorted(runs.items())};mean,half=confidence(list(means.values()))
        flat=[x for v in runs.values() for x in v]
        output.append(dict(zip(['scheme','operation','input_size','cache_policy'],k),mean_ms=mean,ci95_halfwidth_ms=half,median_batch_ms=statistics.median(flat),within_and_between_batch_sd_ms=statistics.stdev(flat) if len(flat)>1 else 0,process_means_ms=means,process_sd_ms=statistics.stdev(means.values()) if len(means)>1 else 0,samples=len(flat),processes=len(runs)))
    return output

DISPLAY_NAMES={
 'g1_msm':'G1 MSM','g2_msm':'G2 MSM','pairing':'Single pairing',
 'pairing_product':'Two-term pairing product','g2_prepare':'G2 preparation',
 'g1_deserialize_checked':'G1 decode and validate','g1_to_affine':'G1 affine conversion',
 'message_prepare':'Message preparation','outer_combine':'Outer linear combinations',
 'inner_evaluate_all':'All inner evaluations','inner_fft':'One inner FFT',
 'header_commit':'Public commitment generation','encode_commit_total':'Encoding and commitments',
 'header_parse_verify':'Public commitment decoding and verification','derive_source':'Source commitment lookup',
 'derive_parity':'One parity commitment','derive_all_parity':'All parity commitments',
 'local_interpolate':'Local interpolation','group_certify':'Group certification',
 'group_certify_random':'Certification, random positions',
 'group_recover_evaluate':'Evaluate recovered group','serve_new_point':'Serve a new point',
 'certify_recover_first_serve':'Certify, recover and verify first proof',
 'collector_batch_source':'Batch, source groups','collector_batch_mixed':'Batch, mixed groups',
 'collector_streaming':'Streaming, mixed groups'}
def display(op):return DISPLAY_NAMES.get(op,op)
def escape(s):
    table={'\\':r'\textbackslash{}','&':r'\&','%':r'\%','$':r'\$','#':r'\#','_':r'\_','{':r'\{','}':r'\}','~':r'\textasciitilde{}','^':r'\textasciicircum{}'}
    return ''.join(table.get(c,c) for c in str(s))
def number(x):
    if x is None:return '--'
    
    if abs(x)>=0.001:return f'{x:.3f}'
    mantissa,exponent=f'{x:.2e}'.split('e')
    return mantissa+r'\times 10^{'+str(int(exponent))+'}'
def cell(row):
    return f"${number(row['mean_ms'])} \\pm {number(row['ci95_halfwidth_ms'])}$" if row['ci95_halfwidth_ms'] is not None else '$'+number(row['mean_ms'])+'$'

def write_tex(path,env,manifests,summary,raw_name):
    rows={ (r['scheme'],r['operation'],r['input_size'],r['cache_policy']):r for r in summary};p=manifests[0]['config']['params'];cfg=manifests[0]['config'];a,m,r,ell=(p[x] for x in ['a','m','r','ell']);is_ref=cfg['name']=='reference'
    lines=[r'% Generated from immutable measured raw data by code/scripts/analyze.py.',r'% Fragment: requires booktabs, graphicx, and amsmath. local_v1.tex is not modified.',r'\section{Concrete implementation and benchmarks}',r'\label{sec:concrete-bench}',r'\paragraph{Implementation and scope.}',
      'We implement Profile~A of LR-DAS and the source-compressed product-code baseline in safe Rust using arkworks 0.4 (BLS12-381). Both schemes share the same KZG and polynomial routines, source coefficients, outer Lagrange matrix, dedicated-size public SRS, and optimizations. Only the inner evaluation domains differ. The scalar field is Fr; the '+('reference' if is_ref else 'smoke')+f' configuration is $(\\ell,m,r,a,b)=({ell},{m},{r},{a},0)$, hence $(n,k)=({ell*m},{a*r})$. Setup uses a deterministic, publicly reproducible test trapdoor, isolated from all protocol APIs; it is not a deployment ceremony.',r'\paragraph{Measurement environment.}']
    cpu=next((line.split(':',1)[1].strip() for line in env['cpu'].splitlines() if line.startswith('Model name:')),'unknown')
    memory=next((x for x in env['meminfo'] if x.startswith('MemTotal:')),'unknown')
    lines.append(escape(cpu)+', '+escape(env['platform'])+'. '+escape(memory)+'. We use '+escape(env['rustc'].splitlines()[0])+', release optimization with thin LTO and one codegen unit; arkworks parallel features are disabled. Timed regions run on one thread pinned to logical CPU '+str(env['cpu_affinity'])+'. The recorded governor is '+escape(env['governor'])+'; Intel no-turbo is '+escape(env['turbo_no_turbo'])+' (0 means turbo enabled). Only the excluded streaming-response preparation may use up to eight physical cores; all workers join and single-CPU affinity is restored before measurement. Other host load is not controlled. No CPU-frequency governor or hardware cache flush is forced. The wall clock, rather than CPU-cycle time, is measured.')
    lines.extend([r'\paragraph{Method and uncertainty.}',f"The results use {len(manifests)} independent sequential processes, with distinct reproducible message/query seeds and alternating scheme order. Ordinary workloads use {cfg['samples']} timed samples per process, after {cfg['warmup_ms']}~ms of warm-up and a pilot. Each sample repeats the operation an explicitly recorded number of times (at least one), targeting {cfg['min_sample_ms']}~ms, with a cap of {cfg['max_iterations']} iterations. Collector workloads use {cfg['slow_samples']} full execution per process, without warm-up or pilot because of their cost. Samples retain total nanoseconds and iteration counts; tables report milliseconds per operation. Means give equal weight to process means. The accompanying $\\pm$ value is the approximate 95\\% Student-$t$ confidence-interval half-width across process means ({len(manifests)-1} degrees of freedom). This small number of independent runs limits precision. Neither loop iterations nor repeated fixed queries are counted as independent processes. No outliers are discarded and no request-level p95 is inferred from batch averages."])
    if len(manifests)==1:lines.append('This is a single-process smoke execution: no confidence interval or paper-level performance conclusion is reported.')
    lines.extend([r'\paragraph{Timing boundaries.}',r'Primitive pairings include final exponentiation; the two-term pairing product evaluates one KZG equation. Unrelated proofs are verified separately. Public commitment parsing and canonical point validation are included in cold light-client runs. Every cold iteration creates an empty application cache; warm runs reuse the verified public commitment and derived group commitments for the same object, but parse and verify fresh responses. Both include per-response point validation, including the defensive checks inside the public verifier. Sampling, proof generation, public-domain/SRS construction, and file I/O are outside these timed client regions. Fixed fixture queries are reused within each process; there is no proof-result cache. Domain tables and public SRS are resident. Encoding includes source preparation, outer combinations, local FFT evaluation, and public commitment generation. Collector rows start with a verified public commitment and received response bytes. The interpolation implementation is quadratic in the subset size. Coset scaling includes cloning the local coefficient arrays; inner evaluation includes padding/allocation. Phase timings therefore need not sum to the separately measured total.'])
    def table(caption,cols,body,label):
        lines.extend([r'\begin{table}[htbp]',r'\centering\small',r'\caption{'+caption+'}',r'\label{'+label+'}',r'\begin{tabular}{'+cols+'}',r'\toprule',*body,r'\bottomrule',r'\end{tabular}',r'\end{table}'])
    body=[r'Primitive & Input size & Time (ms) \\',r'\midrule']
    for row in summary:
        if row['scheme']=='primitive':body.append(escape(display(row['operation'])+(' (prepared G2)' if row['cache_policy']=='prepared_g2' else ''))+f" & {row['input_size']} & {cell(row)} \\\\")
    table('Primitive latencies. Random-point MSM is separate from the dedicated SRS.', 'lrr',body,'tab:measured-primitives')
    body=[r'Operation & Product code (ms) & LR-DAS (ms) \\',r'\midrule']
    for op,size,cache in [('message_prepare',a*r,'none'),('outer_combine',ell,'public_weights'),('inner_evaluate_all',ell,'public_powers'),('inner_fft',m,'none'),('header_commit',a,'public_srs'),('encode_commit_total',ell*m,'public_parameters'),('header_parse_verify',a,'cold'),('derive_source',a,'none'),('derive_parity',a,'none'),('derive_all_parity',ell-a,'none'),('local_interpolate',r,'none'),('group_certify',r,'verified_header'),('group_certify_random',r,'verified_header'),('group_recover_evaluate',m,'certified_coefficients'),('serve_new_point',1,'certified_coefficients'),('certify_recover_first_serve',r,'verified_header')]:
        if all((s,op,size,cache) in rows for s in ['lrdas','product']):body.append(escape(display(op))+f" & {cell(rows['product',op,size,cache])} & {cell(rows['lrdas',op,size,cache])} \\\\")
    table('Measured protocol components; all times are milliseconds. Source lookup is a memory operation, not an MSM.','lrr',body,'tab:measured-protocol')
    body=[r'$t$ & Product open & LR-DAS open & Product verify & LR-DAS verify \\',r'\midrule']
    for t in sorted(set([1,2,8,32,128,r])):
        if t>r:continue
        op='full_group_open' if t==r else 'open';verify='full_group_verify' if t==r else 'verify'
        keys=[('product',op,t,'local_coefficients'),('lrdas',op,t,'local_coefficients'),('product',verify,t,'parsed'),('lrdas',verify,t,'parsed')]
        if all(k in rows for k in keys):body.append(str(t)+' & '+' & '.join(cell(rows[k]) for k in keys)+r' \\')
    table('Subset opening and verification times (ms). At $t=r$, the proof is omitted and verification uses interpolation and commitment equality.','rllll',body,'tab:measured-openings')
    body=[r'Scheme & Queries & Cache & Time (ms) & Payload bytes \\',r'\midrule']
    for row in summary:
        if row['operation']=='light_client':body.append(escape(row['scheme'])+f" & {row['input_size']} & {escape(row['cache_policy'])} & {cell(row)} & {row['input_size']*80+(a*48 if row['cache_policy']=='cold' else 0)} \\\\")
    table('Light-client computation. Payload counts exclude query indices and a 32-byte context identifier. Both schemes have the same source-compressed public commitment structure.','lrlrr',body,'tab:measured-client')
    if is_ref and all((s,'light_client',q,c) in rows for s,q in [('lrdas',218),('product',991),('product',218)] for c in ['cold','warm']):
        ratios=[]
        for c in ['cold','warm']:
            lr=rows['lrdas','light_client',218,c];pr=rows['product','light_client',991,c]
            mean,half=confidence([pr['process_means_ms'][i]/lr['process_means_ms'][i] for i in lr['process_means_ms']])
            ratios.append(f'{c}: ${mean:.2f} \\pm {half:.2f}$')
        lines.append('At the same 128-bit statistical detection target, LR-DAS uses 218 queries and the product code 991; this is separate from the same-query comparison at 218. The measured product/LR-DAS latency ratios, paired by process seed, are '+', '.join(ratios)+'. These ratios are measured costs, not the ratio of sample counts or an estimate of curve security.')
    body=[r'Workload & Product (ms) & LR-DAS (ms) \\',r'\midrule']
    for op in ['collector_batch_source','collector_batch_mixed','collector_streaming']:
        if all((s,op,a,'verified_header') in rows for s in ['product','lrdas']):body.append(escape(display(op))+f" & {cell(rows['product',op,a,'verified_header'])} & {cell(rows['lrdas',op,a,'verified_header'])} \\\\")
    table(f'Collector workload: {a} groups, {r} received values per group. Batch transfers values; streaming verifies every individual proof on arrival.','lrr',body,'tab:measured-collector')
    lines.append('The mixed set consists of the last $a$ group indices and includes parity groups. Batch certification and streaming are distinct authentication modes. Streaming proof generation is performed before timing, but every received proof is parsed and verified during timing; the reconstructed polynomial is checked and retained. Receiver-only tests create serving state without passing the original message, local coefficients, or producer proof cache. These measurements do not implement a global decoder or the erasure-policy simulations in the manuscript.')
    lines.append(r'\paragraph{Stored sizes and setup.}'+f' The public commitment contains {a} compressed G1 points ({a*48} bytes). The dedicated public SRS contains {r} G1 points ({r*48} bytes) and {r+1} G2 points ({(r+1)*96} bytes). A group stores {r} coefficients ({r*32} serialized bytes); in-memory structures and allocator overhead differ. One response is 80 payload bytes; a full-group response contains {r*32} bytes without a proof. Setup and public-domain construction times are retained per run in the manifest, outside steady-state measurements. The whole-run high-water memory values are '+escape('; '.join(x['whole_runner_high_water'] for x in manifests))+r'. These process-wide figures include fixture data and are not per-role memory measurements.')
    lines.extend([r'\paragraph{Reproducibility and limits.}',r'The accompanying \texttt{code/} package includes pinned dependencies, source, tests, configurations, raw nanosecond samples, environment manifests, and the script generating these tables. The selected dataset is \texttt{'+escape(raw_name)+r'}, source SHA-256 \texttt{'+env['source']['sha256'][:16]+r'\ldots}. This initial dataset uses one local CPU and one backend and excludes network latency, distributed availability, Profile~B, blst comparisons, global reconstruction, and end-to-end producer generation of every codeword proof. The separate extended dataset evaluates Profile~B, supplied commitments, and global reconstruction. Deterministic fixture setup is unsuitable for deployment. The results measure this implementation, whose straightforward quadratic interpolation and independent verification need not be optimal. Confidence intervals do not establish cross-machine performance.',r'\begin{figure}[htbp]\centering',r'\includegraphics[width=0.95\linewidth]{msm_latency.pdf}',r'\caption{G1 MSM latency versus number of scalar-base terms; error bars are 95\% intervals across independent process means.}\end{figure}',r'\begin{figure}[htbp]\centering',r'\includegraphics[width=0.95\linewidth]{client_latency.pdf}',r'\caption{Light-client calculation with cold and warm application state. The product baseline includes both equal-query and equal-detection-target workloads.}\end{figure}'])
    lines.extend([r'\begin{figure}[htbp]\centering',r'\includegraphics[width=0.95\linewidth]{encoding_latency.pdf}',r'\caption{Encoding components and the independently measured total. Phase values are not summed to estimate total time.}\end{figure}'])
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text('\n'.join(lines)+'\n')

def figures(summary,folder):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':10,'pdf.fonttype':42,'svg.fonttype':'none'})
    folder.mkdir(parents=True,exist_ok=True)
    msm=sorted([r for r in summary if r['operation']=='g1_msm'],key=lambda r:r['input_size'])
    fig,ax=plt.subplots(figsize=(6,3.3));ax.errorbar([r['input_size'] for r in msm],[r['mean_ms'] for r in msm],yerr=[r['ci95_halfwidth_ms'] or 0 for r in msm],marker='o',capsize=3);ax.set(xlabel='G1 scalar-base terms',ylabel='Time (ms)');ax.grid(alpha=.2);fig.tight_layout()
    for ext in ['pdf','svg']:fig.savefig(folder/f'msm_latency.{ext}',metadata={'Creator':'LR-DAS artifact'})
    plt.close(fig)
    client=[r for r in summary if r['operation']=='light_client'];fig,ax=plt.subplots(figsize=(7,3.5));labels=[f"{r['scheme']}\n{r['input_size']} queries\n{r['cache_policy']}" for r in client];ax.bar(range(len(client)),[r['mean_ms'] for r in client],yerr=[r['ci95_halfwidth_ms'] or 0 for r in client],capsize=3,color=['#2864a0' if r['scheme']=='lrdas' else '#bb7b25' for r in client]);ax.set_xticks(range(len(client)),labels);ax.set_ylabel('Time (ms)');fig.tight_layout()
    for ext in ['pdf','svg']:fig.savefig(folder/f'client_latency.{ext}',metadata={'Creator':'LR-DAS artifact'})
    plt.close(fig)
    fig,ax=plt.subplots(figsize=(7,3.5));ops=['outer_combine','inner_evaluate_all','header_commit','encode_commit_total']
    for offset,scheme,color in [(-.18,'product','#bb7b25'),(.18,'lrdas','#2864a0')]:
        selected=[next((r for r in summary if r['scheme']==scheme and r['operation']==op),None) for op in ops]
        if all(selected):ax.bar([i+offset for i in range(len(ops))],[r['mean_ms'] for r in selected],width=.36,yerr=[r['ci95_halfwidth_ms'] or 0 for r in selected],capsize=3,label=scheme,color=color)
    ax.set_xticks(range(len(ops)),['Outer mix','Inner evaluation','Public commitment','Measured total']);ax.set_ylabel('Time (ms)');ax.legend();fig.tight_layout()
    for ext in ['pdf','svg']:fig.savefig(folder/f'encoding_latency.{ext}',metadata={'Creator':'LR-DAS artifact'})
    plt.close(fig)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--input',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,default=ROOT/'results/processed');ap.add_argument('--tex',type=pathlib.Path,default=ROOT/'paper/bench.tex');ap.add_argument('--figures',type=pathlib.Path,default=ROOT/'paper/figures');ap.add_argument('--no-figures',action='store_true');ap.add_argument('--summary-only',action='store_true',help='Validate/export CSV and JSON without producing a full paper report');args=ap.parse_args()
    env,manifests,records=load_runs(args.input);summary=summarize(records);args.output.mkdir(parents=True,exist_ok=True)
    payload={'schema_version':1,'raw_dataset':args.input.name,'analysis_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'source_sha256':env['source']['sha256'],'environment':env,'confidence_method':'95% Student t interval of independent process means','summary':summary}
    (args.output/'summary.json').write_text(json.dumps(payload,indent=2)+'\n')
    fields=['scheme','operation','input_size','cache_policy','mean_ms','ci95_halfwidth_ms','median_batch_ms','process_sd_ms','samples','processes']
    with (args.output/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(summary)
    if args.summary_only:
        print(f'Validated {len(records)} samples and exported summaries only');return
    if env.get('filter'):raise ValueError('filtered runs are partial: use --summary-only, not a full paper report')
    if manifests[0]['config'].get('suite')=='tradeoffs':raise ValueError('use analyze_tradeoffs.py for the extended report')
    write_tex(args.tex,env,manifests,summary,args.input.name)
    if not args.no_figures:figures(summary,args.figures)
    print(f'Validated {len(records)} measured samples, {len(summary)} workloads, {len(manifests)} independent processes; generated {args.tex}')
if __name__=='__main__':main()
