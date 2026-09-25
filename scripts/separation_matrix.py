"""Exact timed-workload matrix; constructive ambiguity has no recovery latency."""
def expected_workloads(config):
    p=config['params'];n=p['ell']*p['m']
    erased=(p['ell']-p['a']+1)*(p['m']-p['r']+1)
    return {(scheme,pattern+'_'+op,n-erased+(pattern=='rectangle_minus_one'),'accepted_values')
            for scheme in ['lrdas','product']
            for pattern in ['rectangle','rectangle_minus_one','random_matched']
            if not (scheme=='product' and pattern=='rectangle')
            for op in ['decode','decode_authenticate']}
