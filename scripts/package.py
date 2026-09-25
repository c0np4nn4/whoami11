#!/usr/bin/env python3
"""Package all immutable experiments with their corresponding measured source versions."""
import argparse,hashlib,json,pathlib,tarfile
import analyze
import analyze_tradeoffs
ROOT=pathlib.Path(__file__).resolve().parents[1]
RAW={'reference-paper','tradeoffs-paper','separation-paper','separation-smoke'}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def selected_files():
    keep=[]
    for p in ROOT.rglob('*'):
        if not p.is_file():continue
        rel=p.relative_to(ROOT);parts=rel.parts
        if p.is_symlink() or any(part.startswith('.') for part in parts):continue
        if parts[0] in ['target','dist','logs'] or '__pycache__' in parts or p.suffix=='.pyc':continue
        if rel.name=='RELEASE_MANIFEST.json' or p.suffix in ['.aux','.log','.out','.fls','.fdb_latexmk']:continue
        if parts[:2]==('results','raw') and len(parts)>2 and parts[2] not in RAW:continue
        if parts[:2]==('results','processed') and len(parts)>2 and parts[2] not in ['summary.json','summary.csv','tradeoffs','scenarios']:continue
        keep.append(p)
    return sorted(keep)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=pathlib.Path,default=ROOT/'dist/lrdas-fc27-scenarios.tar.gz')
    args=ap.parse_args()
    datasets={}
    for name,source_root,summary_path in [
        ('reference-paper',ROOT/'provenance/reference-paper-source',ROOT/'results/processed/summary.json'),
        ('tradeoffs-paper',ROOT/'provenance/tradeoffs-paper-source',ROOT/'results/processed/tradeoffs/summary.json')]:
        env,manifests,records=analyze.load_runs(ROOT/'results/raw'/name)
        for rel,expected in env['source']['files'].items():
            if sha(source_root/rel)!=expected:raise SystemExit(f'{name} measured source mismatch: '+rel)
        summary=json.loads(summary_path.read_text())
        if summary['source_sha256']!=env['source']['sha256'] or summary['raw_dataset']!=name:
            raise SystemExit('summary/dataset mismatch: '+name)
        if summary['summary']!=analyze.summarize(records):
            raise SystemExit('stored numerical summary does not match raw observations: '+name)
        historical=ROOT/'provenance/tradeoffs-paper-analysis'
        if name=='reference-paper':
            if summary['analysis_sha256']!=sha(historical/'analyze.py'):
                raise SystemExit('historical initial analyzer mismatch')
        else:
            for path,expected in summary['analysis_source_sha256'].items():
                if sha(historical/pathlib.Path(path).name)!=expected:
                    raise SystemExit('historical extended analyzer mismatch')
        datasets[name]={'source_sha256':env['source']['sha256'],
            'source_root':str(source_root.relative_to(ROOT)) or '.',
            'processes':len(manifests),'samples':len(records),'summary':str(summary_path.relative_to(ROOT))}
    import analyze_scenarios
    fresh=analyze_scenarios.make_analysis(ROOT/'results/raw/separation-paper',ROOT/'results/raw/tradeoffs-paper')
    stored=json.loads((ROOT/'results/processed/scenarios/summary.json').read_text())
    if stored!=fresh:raise SystemExit('regenerate scenario analysis after changes')
    env,manifests,records=analyze.load_runs(ROOT/'results/raw/separation-paper')
    for rel,expected in env['source']['files'].items():
        if sha(ROOT/rel)!=expected:raise SystemExit('new measured source mismatch: '+rel)
    datasets['separation-paper']={'source_sha256':env['source']['sha256'],'source_root':'.',
        'processes':len(manifests),'samples':len(records),'summary':'results/processed/scenarios/summary.json'}
    files=selected_files()
    for p in files:
        if p.suffix in ['.json','.jsonl','.md','.tex','.csv','.log']:
            data=p.read_bytes()
            for marker in [str(pathlib.Path.home()).encode()+b'/',b'file://']:
                if marker in data:raise SystemExit('private path in archive member: '+str(p.relative_to(ROOT)))
    manifest={'schema_version':3,'package':'LR-DAS FC 2027 recovery and scenario research artifact',
        'datasets':datasets,'selected_raw_datasets':sorted(RAW),
        'license_status':'author decision pending; local review packet only',
        'files':{str(p.relative_to(ROOT)):sha(p) for p in files}}
    mf=ROOT/'RELEASE_MANIFEST.json';mf.write_text(json.dumps(manifest,indent=2)+'\n');files.append(mf)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(args.output,'w:gz') as tar:
        for p in files:
            info=tar.gettarinfo(str(p),arcname='code/'+str(p.relative_to(ROOT)))
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
            with p.open('rb') as f:tar.addfile(info,f)
    checksum=sha(args.output)
    args.output.with_suffix(args.output.suffix+'.sha256').write_text(checksum+'  '+args.output.name+'\n')
    print(str(args.output));print(checksum)
if __name__=='__main__':main()
