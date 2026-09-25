"""Deterministic report and publication-figure generation for the scenario extension."""
from pathlib import Path
import analyze
from analyze_scenarios import index, cpu_model, PATTERNS

LABELS=["사각형","사각형에서 심벌 1개 복원","동일 삭제량 무작위"]
EN_LABELS=["Rectangle","Rectangle minus one symbol","Uniform, matched loss count"]

def cell(r):
    value=f'{r["mean_ms"]:.3f}'
    half=r["ci95_halfwidth_ms"]
    return value+(f" ± {half:.3f}" if half is not None else "")
def mdtable(head,rows):
    return "\n".join(["| "+" | ".join(head)+" |","| "+" | ".join(["---"]*len(head))+" |"]+
                     ["| "+" | ".join(map(str,row))+" |" for row in rows])
def selected_scenarios(data):
    return [x for x in data["cpu_scenarios"] if x["clients"] in (1,5,100) and x["reconstructions"] in (0,1,10)]

def markdown(data):
    rows=index(data["measured_recovery"]);p=data["separation_parameters"];n=p["ell"]*p["m"]
    e=(p["ell"]-p["a"]+1)*(p["m"]-p["r"]+1)
    degree=(p["a"]-1)*p["m"]+p["r"]-1
    runs=data["sources"]["recovery"]["processes"]
    lines=["# LR-DAS 추가 검증: 복구 가능성, 운영 비용, Profile B","",
        "새로 실행한 복구 실험, 기존 실측으로 계산한 조건부 비용 모델, 기존 A/B 결과의 재분석을 구분한다. "
        "논문 원고에 자동 반영하지 않는 검토용 보고서다.","",
        "## 1. 더 큰 최소거리가 실제 복구에 도움이 되는가","",
        f"파라미터: {p}. 새 측정은 {runs}개 독립 프로세스, {len(rows)}개 workload, {data['recovery_samples']}개 표본을 사용한다. "
        "프로세스마다 메시지와 손실 위치를 바꾸고 코드 및 패턴 실행 순서를 교대했다. 두 코드에 같은 손실 인덱스를 적용했다.",
        f"사각형은 {p['ell']-p['a']+1}개 그룹의 공통 내부 인덱스 {p['m']-p['r']+1}개를 지운다. "
        f"삭제량 {e:,}개는 product 최소거리와 같으며 LR-DAS 최소거리 {n-degree:,}보다 작다. "
        "지울 그룹·내부 인덱스 집합도 각 프로세스에서 새로 선택한다.","",
        mdtable(["패턴","삭제 심벌","LR-DAS","Product"],[
            [LABELS[0],f"{e:,}","전체 복구·인증 성공","생존 부호 심벌만으로 유일 복구 불가능"],
            [LABELS[1],f"{e-1:,}","전체 복구·인증 성공","전체 복구·인증 성공"],
            [LABELS[2],f"{e:,}",f"측정한 {runs}개 패턴 모두 성공",f"측정한 {runs}개 패턴 모두 성공"]]),"",
        "**Product 실패의 근거:** 삭제 사각형에만 0이 아닌 값을 갖는 유효한 비영 부호어를 구성했다. "
        "이를 원래 메시지에 더해 두 메시지를 실제로 인코딩하고, 모든 생존 위치에서 값이 같음을 확인했다. "
        "따라서 단순한 디코더 오류 반환을 복구 불가능으로 해석한 것이 아니다.",
        "이 두 메시지의 header는 다르다. 증거는 생존 부호 심벌의 정보 부족에 관한 것이며, "
        "같은 commitment의 두 유효 opening이나 binding 공격을 주장하지 않는다.",
        "소규모 독립 Gaussian elimination 테스트에서 사각형 생존 행렬의 rank는 product k−1, LR-DAS k였다. "
        "심벌 하나를 복원하면 양쪽 모두 k가 됐다. 실제 크기에서는 거대한 행렬 대신 위 비영 부호어 증거를 검증한다.","",
        "### 전체 복구 및 header 인증 시간 (ms)","",
        mdtable(["패턴","LR-DAS 평균 ± 95% CI 반폭","Product 평균 ± 95% CI 반폭"],[
            [label,cell(rows["lrdas",pattern+"_decode_authenticate","accepted_values"]),
             "해당 없음: 유일 복구 불가능" if pattern=="rectangle" else cell(rows["product",pattern+"_decode_authenticate","accepted_values"])]
            for label,pattern in zip(LABELS,PATTERNS)]),"",
        "동일 삭제량 무작위 대조군은 전체 위치에서 균등 비복원 추출했다. 유리한 결과만 고르기 위한 재추출은 하지 않았다.",
        "양쪽 모두 a개 그룹에 각각 r개 이상이 남으면 공통 그룹 복구 경로를 사용한다. "
        "원래 source groups에 한정하지 않고 임의의 a개 그룹의 로컬 다항식을 보간하고, 외부 계수 보간으로 전체를 복원한다. "
        f"사각형에서는 a−1개 그룹만 완성 가능하므로 LR-DAS는 {degree+1:,}개 위치의 전역 보간을 사용한다.",
        "입력은 이미 인증된 심벌과 검증된 header다. 출력은 원래 메시지·전체 부호어·로컬 다항식이며, "
        "인증 시간에는 공개 SRS의 실제 MSM을 통한 header 대조를 포함한다. "
        "보간 전처리·전체 생존 값의 일치 확인·출력 할당은 타이머에 포함되고 디코더 행렬은 캐시하지 않는다. "
        "수신 증명 검증·network·fixture 생성은 제외한다.",
        "각 workload는 process당 한 번 실행했다. 별도의 untimed 정확성 검사는 있으며 타이머 calibration은 없다. "
        "통계는 process별 시간을 동등 가중한 평균과 Student-t 95% 구간 반폭이다.",
        "**해석:** 큰 최소거리가 실제 복구 가능성의 이점으로 나타났다. 경계·무작위 대조군의 실행 시간은 가까운 평균을 보였지만 "
        "통계적 동등성 검정을 수행한 것은 아니다. 무작위 실험은 삭제량 한 점의 소수 패턴이므로 "
        "전체 손실률 범위의 성공 확률이나 평균 복구 우위를 추정하지 않는다.","",
        "## 2. 샘플링과 복구를 합치면 언제 유리한가","",
        "이 절은 새로운 end-to-end 실험이 아닌 **측정된 성분의 조건부 CPU 비용 모델**이다. "
        "기존 tradeoffs-paper에서 같은 소스·프로세스의 Profile A 성분만 사용하며, 위의 새 복구 시간과 섞지 않는다.","",
        "§T = 인코딩·커밋 생산 1회 + N × cold client 계산 + R × 대각선 전체 복구·인증§","",
        "N은 객체당 client 요청 수, R은 객체당 전체 복구 횟수 또는 가정한 기대 횟수다. "
        "다른 역할의 단일 스레드 wall-clock 성분을 합한 계산 비용 대용 지표다. "
        "동시 실행의 사용자 지연시간이나 완전한 시스템 비용은 아니다. "
        "응답 proof 생성·복구 입력 인증·네트워크·setup ceremony·저장 비용은 제외된다.","",
        mdtable(["대각선 복구 R","평균 성분 기반 실수 임계 N","LR이 더 작은 첫 정수 N"],[
            [x["reconstructions"],f'{x["clients_real_threshold"]:.3f}',x["first_strictly_better_integer_clients"]]
            for x in data["break_even"]]),"",
        "임계값은 이 모델의 평균 성분에서 계산했으며, 관측된 배포 경계나 모든 복구 패턴에 대한 기준이 아니다. "
        "구간은 같은 process의 성분을 합한 뒤 process 간 변동에서 계산한다. "
        "누락된 비용이나 실제 사건 빈도의 불확실성까지 나타내지는 않는다.","",
        mdtable(["N","R","LR 비용 합계(s)","Product 비용 합계(s)","paired Product/LR"],[
            [x["clients"],x["reconstructions"],f'{x["lrdas_ms"]/1000:.3f}',f'{x["product_ms"]/1000:.3f}',f'{x["product_over_lr"]:.3f}']
            for x in selected_scenarios(data)]),"",
        "Header를 매 요청에 포함한 client payload는 reference Profile A에서 LR 21,376 bytes, product 83,216 bytes다. "
        "N에 비례해 집계할 수 있지만 네트워크 지연으로 환산하지 않았다. "
        "복구 불가능한 사례에 0ms나 무한 속도비를 부여하지 않는다.","",
        "## 3. Profile B에서도 샘플링 이점이 유지되는가","",
        "기존 tradeoffs-paper의 A/A 및 B/B를 동일한 탐지 목표로 직접 비교했다. 새로운 측정으로 표시하지 않는다.","",
        mdtable(["Profile","LR client(ms)","Product client(ms)","paired Product/LR","LR 생산(ms)","Product 생산(ms)"],[
            [x["profile"],cell(x["lrdas_client"]),cell(x["product_client"]),
             f'{x["product_over_lr_client"]["mean"]:.3f} ± {x["product_over_lr_client"]["ci95_halfwidth"]:.3f}',
             cell(x["lrdas_producer"]),cell(x["product_producer"])] for x in data["profile_comparison"]]),"",
        "**B에서도 측정된 sampling 이점은 유지된다.** B의 복구 시간을 측정하지 않았으므로 "
        "A의 복구 시간을 B에 대입한 종합 비용 결과는 만들지 않는다.","",
        "### 실제 setup 조건","",
        "- A: G1 powers 0..r−1, G2 powers 0..r의 전용 setup이 필요하다. 같은 tau의 높은 G1 powers가 공개되면 A의 전제가 깨진다. 긴 SRS를 단순히 자르는 것으로 해결되지 않는다.",
        "- B: 긴 G1 SRS와 로컬 검증용 G2 powers 외에 tau^(L−r+1)의 G2 원소가 필요하다. b>0이면 tau^(L−b+1)의 별도 residual shift도 필요하다.",
        "- Reference b=0, L=83,711이면 source shift 지수는 82,944다. 긴 G1 SRS만으로 이 G2 원소가 자동 제공된다고 가정할 수 없다.",
        "- 실제 SRS 제공 방식이 이 조건을 만족하는지는 배포 검토 사항이다. 현재는 독립 deterministic fixture를 사용하며 실제 ceremony의 가용성·보안·비용을 검증하지 않는다.","",
        "## 4. 재현성","",
        f'- 새 복구 실험: §{data["sources"]["recovery"]["dataset"]}§; 소스 SHA-256 §{data["sources"]["recovery"]["source_sha256"]}§.',
        f'- 기존 모델/A·B 자료: §{data["sources"]["model"]["dataset"]}§; 소스 SHA-256 §{data["sources"]["model"]["source_sha256"]}§.',
        "- 변경 전 측정 소스: §code/provenance/tradeoffs-paper-source/§.",
        "- 새 원시 기록: §code/results/raw/separation-paper/§. 각 process 상태에 mask 해시, 삭제 집합, 복구 경로, ambiguity 증거 결과를 기록했다.",
        "- 분석 결과: §code/results/processed/scenarios/§의 JSON/CSV. 그래프와 TeX는 이 데이터로 자동 생성한다.",
        "- 한 host/backend의 단일 스레드 측정이다. CPU frequency·background load·hardware cache는 통제하지 않았다.",
        "- 새 소스의 debug/release 정확성 검사와 기존 회귀 검사 22개, clippy 정적 검사를 통과했다. 분석 테스트 11개(기존 7개와 새 4개)도 통과했다. 새 독립 rank 검증은 세 개의 추가 Rust 테스트에 포함된다.",
        ""]
    return "\n\n".join(lines).replace("§",chr(96))

def tex(data):
    rows=index(data["measured_recovery"]);p=data["separation_parameters"];n=p["ell"]*p["m"]
    e=(p["ell"]-p["a"]+1)*(p["m"]-p["r"]+1);degree=(p["a"]-1)*p["m"]+p["r"]-1
    env=data["recovery_environment"];runs=data["sources"]["recovery"]["processes"]
    tc=lambda r:"$"+cell(r).replace(" ± ",r"\pm ")+"$"
    lines=[
        r"\section{Recovery separation, workload costs, and long-SRS deployment}",
        r"\paragraph{Evidence categories.} We distinguish new recovery measurements, a conditional cost model from the existing tradeoffs-paper archive, and a reanalysis of its Profile A/B observations. Different source versions and measurement processes are not pooled.",
        r"\subsection{Constructive separation in erasure recoverability}",
        f"At $(\\ell,m,r,a,b)=({p['ell']},{p['m']},{p['r']},{p['a']},0)$, product distance is {e:,} and LR-DAS distance is {n-degree:,}. "
        f"Erase $\\ell-a+1={p['ell']-p['a']+1}$ groups at $m-r+1={p['m']-p['r']+1}$ common within-group indices: {e:,} symbols.",
        r"Let $J,I$ be these group and index sets. For the product code,",
        r"\[q(Y)=\prod_{j\notin J}(Y-\gamma_j),\qquad p(X)=\prod_{i\notin I}(X-h_i).\]",
        r"The product $q(Y)p(X)$ has outer degree $a-1$ and inner degree $r-1$. It is a nonzero valid product codeword supported exactly on $J\times I$. Adding it to an encoded message preserves all surviving symbols. The implementation verifies two distinct source messages, their encodings, exact support and direct factor evaluation. This establishes coding ambiguity rather than just failure of a chosen decoder.",
        r"The two headers differ. No same-header collision, binding attack or conflicting valid openings are claimed. The witness concerns surviving field symbols. Small independent Gaussian-elimination tests give survivor rank $k-1$ for product and $k$ for LR-DAS. Restoring one erased symbol gives rank $k$ for both. The large experiment uses the witness rather than a full generator matrix.",
        f"For LR-DAS, {n-e:,} survivors exceed the $D+1={degree+1:,}$ interpolation requirement. It restores the original message, entire codeword and local serving polynomials and authenticates them against the header.",
        r"\paragraph{Controls and recovery policy.} We restore one rectangle symbol, reducing erasures below product distance, and separately draw a uniform subset of the same number of erasures from all positions without replacement. Both codes use the same message and coordinate mask. Messages, rectangle subsets and random masks change between processes; no rejection sampling selects favorable outcomes.",
        r"Both codes first use the same group-reconstruction path when at least $a$ groups retain $r$ values each. Local polynomials are interpolated, coefficients are interpolated over the outer labels, and all groups and received values are checked. This new path supports arbitrary qualifying groups. Otherwise LR-DAS uses its existing global interpolation and product may use row recovery. The rectangle leaves only $a-1$ completeable groups. This policy is not claimed to be optimal.",
        r"\paragraph{Method.} "+f"{runs} independent sequential processes produce {data['recovery_samples']} samples across {len(rows)} workloads. "
        "Each workload executes once per process without calibration. Separate fixture correctness checks are untimed. Scheme and pattern order reverse in alternating processes.",
        "The host is "+analyze.escape(next((x.split(':',1)[1].strip() for x in env["cpu"].splitlines() if x.startswith("Model name:")),"unknown"))+
        f", with one timed thread pinned to logical CPU {env['cpu_affinity']}. "+analyze.escape(env["rustc"].splitlines()[0])+
        " uses release optimization, thin LTO and one codegen unit. The backend is arkworks 0.4 over BLS12-381 with parallel features disabled. Frequency, hardware caches and background load are uncontrolled.",
        r"Inputs are already authenticated field symbols and a verified header. Timed work includes interpolation preprocessing, allocations and checks against every received value. Output authentication adds actual public-SRS MSMs against the source header. Incoming-proof verification, setup, fixture generation and networking are excluded. Means weight processes equally; $\pm$ denotes an approximate 95\% Student-$t$ interval half-width across processes.",
    ]
    def table(caption,cols,head,body):
        lines.extend([r"\begin{table}[htbp]\centering\small",r"\caption{"+caption+"}",
                      r"\begin{tabular}{"+cols+"}",r"\toprule",head+r"\\",r"\midrule",
                      *[row+r"\\" for row in body],r"\bottomrule\end{tabular}\end{table}"])
    for suffix,label in [("decode_authenticate","Full reconstruction and header authentication"),("decode","Decoding without output authentication")]:
        table(label+" (ms). Coding ambiguity is not assigned a recovery latency.",
              r"@{}p{.35\linewidth}rr@{}","Loss pattern & LR-DAS & Product",[
                  label+" & "+tc(rows["lrdas",pattern+"_"+suffix,"accepted_values"])+" & "+
                  ("Not unique" if pattern=="rectangle" else tc(rows["product",pattern+"_"+suffix,"accepted_values"]))
                  for label,pattern in zip(EN_LABELS,PATTERNS)])
    lines.extend([
        r"\begin{figure}[htbp]\centering\includegraphics[width=.96\linewidth]{separation_recovery.pdf}",
        r"\caption{New reconstruction measurements. Product has no successful recovery time on the rectangle; coding ambiguity is verified constructively.}\end{figure}",
        r"\paragraph{Interpretation.} The larger distance manifests as recoverability on a concrete pattern. Both codes succeed in all measured controls and have close mean times there, without an equivalence test. The uniform experiment uses one loss count and a small number of masks; it does not estimate a broad success-rate curve or establish average-case superiority.",
        r"\subsection{Conditional workload cost model}",
        r"We use only contemporaneous Profile A observations from the existing tradeoffs-paper archive:",
        r"\[T_s(N,R)=P_s+N C_s+R G_s,\quad s\in\{\mathrm{LR},\mathrm{Product}\}.\]",
        r"$P_s$ is one encoding and commitment production, $C_s$ one cold client at the matched detection target, and $G_s$ one full reconstruction and header authentication under the diagonal pattern. $N$ counts client requests per object; $R$ is a count or assumed expected count of reconstructions.",
        r"This sums single-thread wall-clock components as a CPU-work proxy across roles, not a measured service latency, concurrency model or complete system cost. Response-proof generation, recovery input authentication, networking, storage and setup ceremonies are excluded. New recovery measurements are not inserted into this old-source model.",
    ])
    table("Calculated thresholds from mean components, not observed deployment boundaries.",
          "rrr",r"$R$ & Real threshold for $N$ & First integer $N$ favoring LR-DAS",[
              f'{x["reconstructions"]:g} & {x["clients_real_threshold"]:.3f} & {x["first_strictly_better_integer_clients"]}'
              for x in data["break_even"]])
    table("Modeled CPU subtotals (seconds), including one publication per object.",
          "rrrrr",r"$N$ & $R$ & LR-DAS & Product & Paired Product/LR",[
              f'{x["clients"]} & {x["reconstructions"]:g} & {x["lrdas_ms"]/1000:.3f} & {x["product_ms"]/1000:.3f} & {x["product_over_lr"]:.3f}'
              for x in selected_scenarios(data)])
    lines.extend([
        r"\begin{figure}[htbp]\centering\includegraphics[width=.94\linewidth]{scenario_cpu_ratio.pdf}",
        r"\caption{Conditional Profile A CPU subtotal ratios from the old diagonal-recovery dataset. Values above one favor LR-DAS within this model. Shading reflects process-level variation, not uncertainty about frequencies or omitted costs.}\end{figure}",
        r"Intervals are computed from matched process-level sums. Fresh-header sampling payload is 21,376 bytes per LR client and 83,216 bytes per product client, before framing and indices. These counts are not network latency measurements. Coding failure is not assigned zero time or infinite speedup.",
        r"\subsection{Profile B and setup requirements}",
        r"The existing dataset includes both codes under B: 218 LR queries and 991 product queries at the same detection target. This is reanalysis, not a new benchmark.",
    ])
    table("Existing cold client observations (ms); ratios use paired process means.","lrrr",
          "Profile & LR-DAS & Product & Product/LR",[
              x["profile"]+" & "+tc(x["lrdas_client"])+" & "+tc(x["product_client"])+
              " & $"+f'{x["product_over_lr_client"]["mean"]:.3f}\\pm {x["product_over_lr_client"]["ci95_halfwidth"]:.3f}'+"$"
              for x in data["profile_comparison"]])
    table("Existing encoding and commitment production (ms).","lrr","Profile & LR-DAS & Product",[
        x["profile"]+" & "+tc(x["lrdas_producer"])+" & "+tc(x["product_producer"]) for x in data["profile_comparison"]])
    lines.extend([
        r"The measured sampling benefit persists under B. Reconstruction under B was not measured, so A recovery values are not reused to claim a B total-cost result.",
        r"A requires dedicated G1 powers through $r-1$ and G2 powers through $r$. Higher G1 powers under the same trapdoor violate its premise; truncating a public longer string does not remove those powers.",
        r"B requires a long G1 string, local G2 verification powers and $[\tau^{L-r+1}]_2$ for the source degree check. If $b>0$, the separate residual shift $[\tau^{L-b+1}]_2$ is needed. At reference $b=0$, $L=83{,}711$ and the source-shift index is $82{,}944$. A long G1 string alone does not automatically supply this G2 point.",
        r"The intended deployment must supply these elements under the required setup assumptions. The experiment uses independently seeded deterministic fixtures, not a production ceremony. Ceremony availability, cost and security are not measured.",
        r"\subsection{Reproducibility}",
        "Source SHA-256 prefixes: new recovery "+r"\texttt{"+data["sources"]["recovery"]["source_sha256"][:16]+"}; existing model/A/B "+r"\texttt{"+data["sources"]["model"]["source_sha256"][:16]+"}. Full digests are retained in the JSON summary and raw environment manifests.",
        r"The earlier measured source is preserved in \path{code/provenance/tradeoffs-paper-source/}. Raw masks, seeds, outcomes, timings and source/binary hashes are retained. Analysis validates workload and outcome completeness and generates JSON, CSV, Markdown, figures and this text.",
        r"Twenty-two Rust tests pass in debug and release, including independent rank checks, arbitrary-group recovery and altered-input rejection; clippy passes with warnings denied. Eleven analysis tests pass, including four new model/evidence checks. Tests do not replace cryptographic proofs. Results concern the stated algorithms on one host; the cost model remains conditional on its frequencies and exclusions.",
        r"\clearpage",
    ])
    return "\n\n".join(lines).replace(r"\subsection", r"\FloatBarrier"+"\n\n"+r"\subsection")+"\n"

def plots(folder,data):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    folder.mkdir(parents=True,exist_ok=True);rows=index(data["measured_recovery"])
    fig,ax=plt.subplots(figsize=(8,4.3),layout="constrained");x=np.arange(3);w=.34
    lr=[rows["lrdas",p+"_decode_authenticate","accepted_values"] for p in PATTERNS]
    pr=[rows["product",p+"_decode_authenticate","accepted_values"] for p in PATTERNS[1:]]
    ax.bar(x-w/2,[r["mean_ms"]/1000 for r in lr],w,yerr=[(r["ci95_halfwidth_ms"] or 0)/1000 for r in lr],label="LR-DAS",color="#2864a5",capsize=3)
    ax.bar(x[1:]+w/2,[r["mean_ms"]/1000 for r in pr],w,yerr=[(r["ci95_halfwidth_ms"] or 0)/1000 for r in pr],label="Product",color="#cb7931",capsize=3)
    ax.annotate("Product:\nnot uniquely\nrecoverable",xy=(w/2,.15),ha="center",va="bottom",fontsize=9)
    ax.set_xticks(x,["Rectangle","Rectangle minus one","Uniform matched count"])
    ax.set_ylabel("Complete reconstruction + authentication (s)")
    ax.legend();ax.grid(axis="y",alpha=.2);ax.set_axisbelow(True)
    fig.savefig(folder/"separation_recovery.pdf",metadata={"Creator":"LR-DAS scenario analysis","CreationDate":None})
    plt.close(fig)
    fig,ax=plt.subplots(figsize=(7.5,4.3),layout="constrained");ns=np.geomspace(1,1000,150)
    for r in (0,1,10):
        points=[cpu_model(data["scenario_components"],float(n),r) for n in ns]
        y=np.array([v["product_over_lr"] for v in points]);h=np.array([v["ratio_ci95_halfwidth"] or 0 for v in points])
        line,=ax.plot(ns,y,label=f"R = {r}")
        ax.fill_between(ns,y-h,y+h,alpha=.12,color=line.get_color())
    ax.axhline(1,color="black",linestyle=":",linewidth=1)
    ax.set_xscale("log");ax.set_xlabel("Cold client requests per object, N")
    ax.set_ylabel("Modeled Product / LR-DAS CPU subtotal")
    ax.set_title("Conditional model: Profile A, diagonal reconstruction")
    ax.grid(alpha=.2);ax.legend(title="Reconstructions / object")
    fig.savefig(folder/"scenario_cpu_ratio.pdf",metadata={"Creator":"LR-DAS scenario analysis","CreationDate":None})
    plt.close(fig)

def write_outputs(data,paper,figures):
    paper.mkdir(parents=True,exist_ok=True)
    (paper/"SCENARIOS.md").write_text(markdown(data))
    (paper/"scenarios.tex").write_text(tex(data))
    plots(figures,data)
    (paper/"scenarios_report.tex").write_text(r"""\documentclass[11pt,a4paper]{article}
\usepackage[T1]{fontenc}
\usepackage[margin=22mm]{geometry}
\usepackage{amsmath,amssymb,booktabs,array,graphicx,placeins}
\usepackage[hidelinks]{hyperref}
\graphicspath{{figures/scenarios/}}
\title{LR-DAS: Additional Recovery and Workload Evaluation}
\author{Research artifact}
\date{}
\begin{document}
\maketitle
\input{scenarios.tex}
\end{document}
""")
