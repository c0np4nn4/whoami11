import copy,json,pathlib,tempfile,unittest
import analyze

def sample():
    return dict(schema_version=1,run_id='test',process_run_id=0,scheme='primitive',backend='arkworks-0.4',profile='smoke',operation='g1_msm',workload_id='test',input_size=82,sample_id=0,iterations=4,elapsed_ns=2000000,threads=1,cache_policy='none',seed=0,fixture_id='test',status='ok',measurement_kind='measured',timing_scope='wall_clock_library_or_role_as_documented',warmup_ms=0,pilot_ns=0)

class AnalysisTests(unittest.TestCase):
    def test_units(self):self.assertEqual(analyze.per_op_ms(sample()),0.5)
    def test_invalid(self):
        for key,value in [('iterations',0),('iterations',-1),('elapsed_ns',-1),('elapsed_ns',float('nan')),('elapsed_ns',0),('threads',8),('status','failed'),('measurement_kind','estimated')]:
            with self.subTest(key=key,value=value):
                row=sample();row[key]=value
                with self.assertRaises(ValueError):analyze.per_op_ms(row)
        row=sample();del row['seed']
        with self.assertRaises(ValueError):analyze.per_op_ms(row)
    def test_process_uncertainty(self):
        mean,half=analyze.confidence([1,2,3]);self.assertEqual(mean,2);self.assertAlmostEqual(half,4.3026527299/(3**0.5))
        self.assertEqual(analyze.confidence([4]),(4,None))
    def test_process_means_not_pseudoreplicates(self):
        records=[]
        for process,values in enumerate([[1,3],[4],[5,5,5]]):
            for i,ms in enumerate(values):
                row=sample();row.update(process_run_id=process,sample_id=i,iterations=1,elapsed_ns=ms*1000000);records.append(row)
        result=analyze.summarize(records)[0];self.assertEqual(result['processes'],3);self.assertAlmostEqual(result['mean_ms'],11/3)
    def test_strict_json(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'bad.json'
            for s in ['{','{"x":NaN}','{"x":1,"x":2}']:
                p.write_text(s)
                with self.assertRaises(ValueError):analyze.load_json(p)
    def test_matrix_and_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d);env={'runs_requested':1};(p/'environment.json').write_text(json.dumps(env))
            config={'name':'smoke','params':{'ell':6,'m':16,'r':12,'a':4,'b':0},'samples':1,'slow_samples':1,'seed':0,'include_streaming':True}
            rows=[]
            for size in [1,16,64,82,128,256,512,767,768,1024]:
                r=sample();r['input_size']=size;r['run_id']='smoke-0';r['workload_id']=f'primitive/g1_msm/{size}/none';r['fixture_id']='chacha20-v1-0';rows.append(r)
            manifest={'status':'complete','process_run_id':0,'environment':env,'config':config,'rows':len(rows),'filter':'g1_msm'}
            def save():
                (p/'run-0.status.json').write_text(json.dumps(manifest));(p/'run-0.jsonl').write_text('\n'.join(map(json.dumps,rows)))
            save();self.assertEqual(len(analyze.load_runs(p)[2]),10)
            rows.append(copy.deepcopy(rows[0]));manifest['rows']+=1;save()
            with self.assertRaisesRegex(ValueError,'duplicate'):analyze.load_runs(p)
            rows.pop();manifest['rows']-=1;rows[0]['backend']='blst';save()
            with self.assertRaises(ValueError):analyze.load_runs(p)
    def test_latex_escape(self):self.assertEqual(analyze.escape('a_b%'),r'a\_b\%')
if __name__=='__main__':unittest.main()
