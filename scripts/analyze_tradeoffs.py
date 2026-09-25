#!/usr/bin/env python3
"""Validate the extended experiment and regenerate its paper tables and figures."""
import argparse, csv, hashlib, json, pathlib
import analyze
ROOT=pathlib.Path(__file__).resolve().parents[1]

def analysis_sources():
    return {f'scripts/{name}':hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest()
            for name in ['analyze_tradeoffs.py','analyze.py','tradeoff_matrix.py']}

def write_tex(path,env,manifests,summary,dataset):
    rows={(x['scheme'],x['operation'],x['cache_policy']):x for x in summary}
    cfg=manifests[0]['config'];p=cfg['params'];a,r,m,ell=(p[k] for k in ['a','r','m','ell'])
    k=a*r;n=ell*m;D=(a-1)*m+r-1
    roles=[{v['variant']:v for v in x['roles'] if 'variant' in v} for x in manifests]
    def cell(s,op,c):return analyze.cell(rows[s,op,c])
    def ratio(top,bottom,op,cache):
        x=rows[top,op,cache]['process_means_ms'];y=rows[bottom,op,cache]['process_means_ms']
        mean,ci=analyze.confidence([x[i]/y[i] for i in x])
        return '$'+analyze.number(mean)+(r'\pm '+analyze.number(ci) if ci is not None else '')+'$'
    lines=[
        r'% Generated from immutable extended-suite measurements.',
        r'\section{Measured setup, commitment, and recovery trade-offs}',
        r'\label{sec:extended-tradeoffs}',
        r'\paragraph{Questions and scope.}',
        r'This extension separates three questions: the cost of enforcing local degree bounds with a long SRS '
        r'(Proposition~3 and Profile~B); derived versus supplied commitments for the same Tamo--Barg code; '
        r'and recovery under the diagonal erasure pattern of Proposition~7. The supplied construction includes '
        r'both the quotient-link and shifted-degree equations. Its unsafe link-only variant appears only in negative tests.',
        r'All new comparisons have contemporaneously measured controls. Earlier measurements in '
        r'Section~\ref{sec:concrete-bench} are preserved separately and are not pooled with the new samples.',
        r'\paragraph{Configuration and method.}',
        f'The implementation uses arkworks 0.4 over BLS12-381 with $(\\ell,m,r,a,b)=({ell},{m},{r},{a},0)$, '
        f'$(n,k)=({n},{k})$, and $L=D={D}$ for the long-SRS variants. There are {len(summary)} workloads and '
        f'{len(manifests)} independent sequential processes. Ordinary workloads use {cfg["samples"]} samples per process '
        f'after {cfg["warmup_ms"]}~ms warm-up and a calibration call. Iterations target {cfg["min_sample_ms"]}~ms '
        f'and are capped at {cfg["max_iterations"]}. Public commitment generation, complete encoding, supplied auxiliary '
        f'production, and principal decoding/repair workloads use {cfg["slow_samples"]} complete timed invocation '
        r'per process without warm-up or calibration. Fixture correctness checks remain outside timing. '
        r'Tables give milliseconds per operation, mean $\pm$ approximate 95\% Student-$t$ interval half-width '
        r'across process means. A single-process smoke run has no confidence interval. Input seeds vary by process '
        r'and inputs are reused within a process. Variant order reverses in alternating processes.',
    ]
    cpu=next((x.split(':',1)[1].strip() for x in env['cpu'].splitlines() if x.startswith('Model name:')),'unknown')
    lines.append('The host is '+analyze.escape(cpu)+', '+analyze.escape(env['platform'])+', using '+
        analyze.escape(env['rustc'].splitlines()[0])+f'. Release builds use thin LTO and one codegen unit, '
        f'with arkworks parallel features disabled. Timed work is single-threaded and pinned to logical CPU '
        f'{env["cpu_affinity"]}. CPU frequency, hardware caches, and other host load are not controlled.')
    lines.extend([
        r'\paragraph{Trust and timing boundaries.}',
        r'Profile~A uses a dedicated fixture trapdoor. Profile~B and supplied commitments use a separately seeded '
        r'long SRS, which does not extend the Profile~A fixture. Deterministic test trapdoors provide no deployment '
        r'security; protocol routines receive only public points. Profile~B samples a fresh verifier challenge '
        r'after each fixed public commitment is received. This is not a Fiat--Shamir challenge. Nonzero residual blocks are '
        r'tested with their distinct degree-check shift, although the measured profile has $b=0$. '
        r'Profile~C lacks the elements required by the degree check and is not a valid deployment of this '
        r'construction; it therefore has no valid throughput comparison. The Proposition~3 negative test '
        r'demonstrates why merely truncating a long SRS does not restore the Profile~A guarantee.',
        r'SRS/domain construction, input generation, query selection, and network I/O are excluded. Client proof '
        r'generation is outside client timing. Cold clients parse and validate their public commitment, start with an empty '
        r'group cache, derive or authenticate each touched group once, and parse and verify every response. '
        r'Warm clients reuse verified public commitment and group state for the same object but still parse and verify every '
        r'response. There is no proof-result cache. Defensive point-validity rechecks in public APIs are included. '
        r'The supplied public commitment alone does not establish global membership: group authentication enforces both pairing equations.',
        r'\subsection{Dedicated versus long reference strings}',
    ])
    def table(caption,columns,header,body,label):
        lines.extend([r'\begin{table}[htbp]\centering\small',r'\setlength{\tabcolsep}{4pt}',
                      r'\caption{'+caption+'}',r'\label{'+label+'}',r'\begin{tabular}{'+columns+'}',
                      r'\toprule',header+r' \\',r'\midrule',*[row+r' \\' for row in body],
                      r'\bottomrule\end{tabular}\end{table}'])
    ops=[('Public commitment generation','variant_header_commit','public_srs'),
         ('Encode and publish commitments','variant_encode_total','public_parameters'),
         ('Public commitment parsing and verification','variant_header_verify','cold'),
         ('Client, cold','variant_light_client','cold'),('Client, warm','variant_light_client','warm')]
    cols=['lrdas_a','lrdas_b','product_a','product_b']
    table('Profile A/B comparison (ms). At the reference size, LR uses 218 queries and product uses 991. '
          'Within each A/B pair the message, query sequence and query count are identical.',
          r'@{}p{0.29\linewidth}rrrr@{}','Operation & LR, A & LR, B & Product, A & Product, B',
          [' & '.join([title]+[cell(s,op,c) for s in cols]) for title,op,c in ops],'tab:extended-profiles')
    mean=lambda scheme,op,cache:rows[scheme,op,cache]['mean_ms']
    lines.append(r'\paragraph{Measured observations.} '+
        f"For LR-DAS, cold-client means are {mean('lrdas_a','variant_light_client','cold'):.3f}~ms "
        f"under A and {mean('lrdas_b','variant_light_client','cold'):.3f}~ms under B. "
        f"Complete producer means are {mean('lrdas_a','variant_encode_total','public_parameters'):.3f}~ms "
        f"and {mean('lrdas_b','variant_encode_total','public_parameters'):.3f}~ms, respectively. "
        r'The additional source-degree enforcement is therefore reported separately at the producer and client roles.')
    lines.append('The paired LR Profile~B/Profile~A public commitment generation ratio is '+
        ratio('lrdas_b','lrdas_a','variant_header_commit','public_srs')+
        ', while its cold-client ratio is '+ratio('lrdas_b','lrdas_a','variant_light_client','cold')+
        r'. These are cost ratios, not security-strength comparisons. Shifted commitments use local-size MSMs '
        r'against shifted SRS slices, rather than zero-padding every MSM to length $L+1$.')
    lines.extend([r'\subsection{Derived versus supplied group commitments}',
        r'This comparison holds the LR code, message, inner cosets, query sequence, and detection target fixed. '
        r'Profile~A and Profile~B derive group commitments. Supplied commitments require a global-to-local quotient '
        r'link and a local degree bound for each touched group. Every global and auxiliary commitment uses an '
        r'actual public-SRS MSM; evaluation at the known fixture trapdoor is never substituted for a commitment.'])
    cols=['lrdas_a','lrdas_b','lrdas_supplied']
    ops=[('Encode and publish all required commitments','variant_encode_total','public_parameters'),
         ('Authenticate one parity group','variant_group_auth','verified_header'),
         ('Authenticate and certify one group','variant_group_certify','verified_header'),
         ('Generate a fresh local proof','variant_serve_fresh','certified_group'),
         ('Certify, recover, and verify first proof','variant_certify_serve','verified_header'),
         ('Serve and verify at a fresh peer','variant_fresh_peer_serve','certified_group'),
         ('Client, cold','variant_light_client','cold'),('Client, warm','variant_light_client','warm')]
    table('Commitment constructions for the same LR-DAS code (ms). Group rows use the same parity group '
          'and received positions. A new peer has resident public parameters but no cached public commitment or group state.',
          r'@{}p{0.38\linewidth}rrr@{}','Operation & Derived A & Derived B & Supplied',
          [' & '.join([title]+[cell(s,op,c) for s in cols]) for title,op,c in ops],'tab:extended-commitments')
    lines.append('The supplied/derived-A cold-client ratio is '+
        ratio('lrdas_supplied','lrdas_a','variant_light_client','cold')+
        ', and its complete-producer ratio is '+
        ratio('lrdas_supplied','lrdas_a','variant_encode_total','public_parameters')+
        r'. These ratios answer different questions. Complete producer work includes all mandatory auxiliary '
        r'triples for supplied commitments. Neither construction generates every single-point opening in this timer.')
    ops=[('Expand the global polynomial','global_polynomial_expand','message'),
         ('Commit to the expanded global polynomial','variant_header_commit','expanded_global_polynomial'),
         ('Generate one parity-group triple','supplied_one_aux','global_and_local_polynomials'),
         ('Generate all group triples','supplied_all_aux','global_and_local_polynomials')]
    table('Supplied producer components (ms). Work excluded from a component is included in the separately '
          'measured complete-producer row of Table~\\ref{tab:extended-commitments}.',
          r'@{}p{0.65\linewidth}r@{}','Operation & Time',
          [title+' & '+cell('lrdas_supplied',op,c) for title,op,c in ops],'tab:extended-supplied-producer')
    def span(values):
        lo,hi=min(values),max(values)
        return str(lo) if lo==hi else f'{lo}--{hi}'
    body=[]
    for title,field in [('Public commitment','header_bytes'),('Per-group auxiliary data','auxiliary_bytes_per_group'),
                        ('G1 SRS','public_g1_bytes'),('Cold client payload','cold_payload_bytes'),
                        ('Warm client payload','warm_payload_bytes')]:
        body.append(title+' & '+' & '.join(span([rm[s][field] for rm in roles]) for s in cols))
    body.extend([f'Local polynomial coefficients & {r*32} & {r*32} & {r*32}',
                 'Fresh-peer response, public commitment excluded & 80 & 80 & 224'])
    table('Serialized bytes. Ranges report process-specific touched-group counts, rather than an expected '
          'occupancy. Payloads exclude indices and 32-byte context framing.',
          'lrrr','Quantity & Derived A & Derived B & Supplied',body,'tab:extended-bytes')
    lines.append(
        f"For a single response to a fresh peer, the combined serving and verification time is "
        f"{mean('lrdas_supplied','variant_fresh_peer_serve','certified_group'):.3f}~ms for supplied, versus "
        f"{mean('lrdas_a','variant_fresh_peer_serve','certified_group'):.3f}~ms for derived A. "
        r'The smaller supplied public commitment benefits this access pattern, while its auxiliary-state requirement '
        r'and the multi-query cold-client workload have different costs. Warm client times are similar '
        r'because every construction reuses its already authenticated group commitments.')
    lines.extend([
        f'The minimal G2 payload is {(r+1)*96} bytes for A, {(r+2)*96} bytes for B, and {(m+2)*96} bytes for supplied. '
        f'The experiment shares a {(m+2)*96}-byte long G2 fixture between B and supplied; SRS loading is excluded.',
        r'The supplied receiver retains its verified 144-byte auxiliary triple in addition to local coefficients. '
        r'Its fresh-peer response contains that triple and a newly generated 80-byte value/proof pair. Removing '
        r'the triple is tested to fail fresh-peer verification. Derived receivers obtain their group commitment '
        r'from the public commitment for the same object, without per-group auxiliary data. A peer with a previously authenticated group '
        r'commitment can use the warm path, which has a distinct precondition.',
        r'\subsection{Recovery under Proposition 7}',
    ])
    pattern=next(x for x in manifests[0]['roles'] if x.get('diagonal_scheme')=='lrdas_a')
    lines.append(f'Each of {ell} groups loses {m-r+1} symbols, leaving {r-1} per group and '
        f'{pattern["survivors"]} overall. No designated group admits local completion. Each product-code row '
        f'retains at least {pattern["minimum_row_survivors"]} values, sufficient for outer dimension {a}. '
        r'Both full decoders receive the same surviving index set and return the original message, all codeword '
        r'values, and local serving polynomials. Agreement with all received evidence is checked.')
    lines.extend([
        r'The LR decoder interpolates $D+1$ surviving positions, checks the degree/exponent constraints defining '
        r'$V_D$, and compares its evaluations with all evidence. It uses FFT polynomial multiplication, Newton '
        r'division, and a product/remainder tree; coordinate-dependent tree construction is included per invocation. '
        r'The product decoder interpolates every row from surviving outer positions and checks that the restored '
        r'columns have degree below $r$. The authenticated-total row additionally recomputes source commitments '
        r'for both schemes. These rows are actual decoder executions, not operation-count estimates.',
        r'Decoder inputs are already authenticated values. Their individual proof verification, network latency, '
        r'and helper discovery are excluded. Decoder workspaces are rebuilt per invocation; producer coefficients '
        r'are never passed to either decoder.',
    ])
    ops=[('Restore complete message and codeword','diagonal_full_decode','accepted_values'),
         ('Restore and authenticate against public commitment','diagonal_decode_authenticate','accepted_values'),
         ('Recover and serve one erased coordinate','diagonal_recover_serve','accepted_helpers')]
    table('Diagonal-pattern recovery (ms). The first two rows have matching complete-reconstruction outputs. '
          'The last row has a matching single-coordinate output, but different required helper material.',
          r'@{}p{0.52\linewidth}rr@{}','Operation & LR, global fallback & Product, row repair',
          [title+' & '+cell('lrdas_a',op,c)+' & '+cell('product_a',op,c) for title,op,c in ops],'tab:extended-recovery')
    lines.append('The paired LR/product authenticated full-reconstruction ratio is '+
        ratio('lrdas_a','product_a','diagonal_decode_authenticate','accepted_values')+
        ', and the single-erased-coordinate ratio is '+
        ratio('lrdas_a','product_a','diagonal_recover_serve','accepted_helpers')+
        r'. The latter compares the implemented global fallback with the implemented row repair. It is not a '
        r'lower bound on repair complexity for the Tamo--Barg code.')
    lines.append(f'For one erased coordinate, LR retains {D+1} accepted values and product retains {a} accepted '
        f'value/proof pairs, occupying {(D+1)*32} and {a*80} bytes respectively. If all inputs had arrived as '
        f'individually authenticated single-point responses, their payloads would be {(D+1)*80} and {a*80} bytes. '
        r'These byte counts exclude framing and do not measure network time. Product repair interpolates both '
        r'the value and its KZG proof and checks the resulting proof.')
    lines.append('A separate product measurement starts from response bytes and includes parsing and independently '
        f'verifying all {a} helper proofs, commitment derivation, repair, and final verification: '+
        cell('product_a','diagonal_row_receive_repair','response_bytes')+
        r'~ms. Its timing boundary differs from the accepted-input rows; it is excluded from their speed ratios.')
    lines.extend([
        r'\subsection{Correctness, interpretation, and reproducibility}',
        r'Added integration tests compare fast interpolation with independent Horner evaluations and the quadratic '
        r'interpolator; check global/row recovery against the original message and commitment; and reproduce '
        r'Proposition~3 with public long-SRS powers. In that negative test, openings pass while local code binding '
        r'fails. Profile~B rejects degree violations, including a residual block checked with the wrong shift. '
        r'The supplied link-only counterexample gives correct zero values but rejects a proof regenerated from '
        r'the zero polynomial; the complete verifier rejects its malicious triple. Honest supplied receivers '
        r'recover and serve fresh responses from received values and retained auxiliary data. These tests '
        r'exercise implementation behavior and do not replace the manuscript security proofs.',
        r'The experiments distinguish sampling efficiency, commitment costs, and recovery costs. A smaller LR '
        r'query requirement does not imply universal superiority in setup compatibility, producer cost, or repair '
        r'under every erasure pattern. Supplied commitments have different public commitment and auxiliary-state costs. '
        r'The independently generated quotient commitments and chosen global decoder are concrete implementations, '
        r'not claimed optimal algorithms.',
        r'The evidence is limited to one machine, one backend, and three process repeats. No distributed deployment, '
        r'network latency, blst comparison, or full-codeword opening-production benchmark is claimed. Complete '
        r'decoding begins with authenticated evidence; downloading and verifying every surviving position is '
        r'outside these decoder timings.',
        'Dataset \\path{'+dataset+'} has source hash prefix \\texttt{'+
        env['source']['sha256'][:16]+r'}. The original \path{reference-paper} data remain unchanged. '
        r'Their measured source is preserved in \path{provenance/reference-paper-source/}. Raw timings, '
        r'process manifests, separate summaries, configurations, and report scripts accompany both datasets.',
    ])
    if len(manifests)>1:
        lines.extend([r'\begin{figure}[htbp]\centering\includegraphics[width=.9\linewidth]{commitment_tradeoffs.pdf}',
                      r'\caption{Client time for identical LR queries under three commitment constructions. Error bars are process-mean confidence intervals.}\end{figure}',
                      r'\begin{figure}[htbp]\centering\includegraphics[width=.95\linewidth]{recovery_tradeoffs.pdf}',
                      r'\caption{Matched recovery outputs under the diagonal pattern. Each panel has its own scale and already authenticated inputs.}\end{figure}'])
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text('\n\n'.join(lines)+'\n')

def figures(summary,folder):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    rows={(x['scheme'],x['operation'],x['cache_policy']):x for x in summary}
    plt.rcParams.update({'font.size':10,'pdf.fonttype':42,'svg.fonttype':'none'})
    folder.mkdir(parents=True,exist_ok=True)
    schemes=['lrdas_a','lrdas_b','lrdas_supplied']
    fig,ax=plt.subplots(figsize=(6.8,3.6))
    for shift,cache,color in [(-.18,'cold','#346ca6'),(.18,'warm','#bb7830')]:
        rr=[rows[s,'variant_light_client',cache] for s in schemes]
        ax.bar([i+shift for i in range(3)],[x['mean_ms'] for x in rr],width=.36,
               yerr=[x['ci95_halfwidth_ms'] or 0 for x in rr],capsize=3,label=cache,color=color)
    ax.set_xticks(range(3),['Derived A','Derived B','Supplied'])
    ax.set(ylabel='Client computation (ms)',ylim=(0,None));ax.legend();fig.tight_layout()
    for ext in ['pdf','svg']:fig.savefig(folder/f'commitment_tradeoffs.{ext}',metadata={'Creator':'LR-DAS artifact'})
    plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(8,3.5))
    for ax,op,cache,title in zip(axes,['diagonal_decode_authenticate','diagonal_recover_serve'],
        ['accepted_values','accepted_helpers'],['Restore and authenticate all data','Recover and serve one erased value']):
        rr=[rows[s,op,cache] for s in ['lrdas_a','product_a']]
        ax.bar(range(2),[x['mean_ms'] for x in rr],yerr=[x['ci95_halfwidth_ms'] or 0 for x in rr],
               capsize=3,color=['#346ca6','#bb7830'])
        ax.set_xticks(range(2),['LR global fallback','Product rows'])
        upper=max(x['mean_ms']+(x['ci95_halfwidth_ms'] or 0) for x in rr)*1.17
        for i,x in enumerate(rr):
            ax.text(i,x['mean_ms']+(x['ci95_halfwidth_ms'] or 0)+upper*.025,
                    f"{x['mean_ms']:,.1f} ms",ha='center',va='bottom',fontsize=9)
        ax.set(ylabel='Time (ms)',title=title,ylim=(0,upper))
    fig.tight_layout()
    for ext in ['pdf','svg']:fig.savefig(folder/f'recovery_tradeoffs.{ext}',metadata={'Creator':'LR-DAS artifact'})
    plt.close(fig)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=pathlib.Path,required=True)
    ap.add_argument('--output',type=pathlib.Path,default=ROOT/'results/processed/tradeoffs')
    ap.add_argument('--tex',type=pathlib.Path,default=ROOT/'paper/tradeoffs.tex')
    ap.add_argument('--figures',type=pathlib.Path,default=ROOT/'paper/figures')
    ap.add_argument('--no-figures',action='store_true')
    args=ap.parse_args()
    env,manifests,records=analyze.load_runs(args.input)
    if manifests[0]['config'].get('suite')!='tradeoffs' or env.get('filter'):
        raise ValueError('the full unfiltered tradeoffs suite is required')
    summary=analyze.summarize(records)
    args.output.mkdir(parents=True,exist_ok=True)
    payload={'schema_version':1,'raw_dataset':args.input.name,'source_sha256':env['source']['sha256'],
             'analysis_source_sha256':analysis_sources(),'environment':env,
             'confidence_method':'95% Student t interval across independent process means','summary':summary}
    (args.output/'summary.json').write_text(json.dumps(payload,indent=2)+'\n')
    with (args.output/'summary.csv').open('w',newline='') as f:
        fields=['scheme','operation','input_size','cache_policy','mean_ms','ci95_halfwidth_ms','samples','processes']
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(summary)
    write_tex(args.tex,env,manifests,summary,args.input.name)
    if not args.no_figures:figures(summary,args.figures)
    print(f'Validated {len(records)} measured samples, {len(summary)} workloads and {len(manifests)} processes; wrote {args.tex}')
if __name__=='__main__':main()
