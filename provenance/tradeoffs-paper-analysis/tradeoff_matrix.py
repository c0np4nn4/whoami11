"""Explicit completeness matrix for the added experiments."""
SLOW = {'variant_header_commit','variant_encode_total','supplied_one_aux','supplied_all_aux',
        'diagonal_full_decode','diagonal_decode_authenticate','diagonal_recover_serve'}

def expected_workloads(config):
    p=config['params'];a,r,m,ell=(p[k] for k in ['a','r','m','ell'])
    n=ell*m;k=a*r;degree=(a-1)*m+r-1
    reference=p==dict(ell=123,m=1024,r=768,a=82,b=0)
    expected=set()
    for scheme in ['lrdas_a','lrdas_b','product_a','product_b','lrdas_supplied']:
        supplied=scheme=='lrdas_supplied'
        q=(991 if scheme.startswith('product') else 218) if reference else 8
        ops=[
            ('variant_header_commit',degree+1 if supplied else a,'expanded_global_polynomial' if supplied else 'public_srs'),
            ('variant_encode_total',n,'public_parameters'),
            ('variant_header_verify',1 if supplied else a,'cold'),
            ('variant_group_auth',a,'verified_header'),
            ('variant_group_certify',r,'verified_header'),
            ('variant_serve_fresh',1,'certified_group'),
            ('variant_fresh_peer_serve',1,'certified_group'),
            ('variant_certify_serve',r,'verified_header'),
            ('variant_light_client',q,'cold'),('variant_light_client',q,'warm'),
        ]
        if supplied:
            ops += [('global_polynomial_expand',k,'message'),
                    ('supplied_one_aux',degree+1,'global_and_local_polynomials'),
                    ('supplied_all_aux',ell,'global_and_local_polynomials')]
        expected.update((scheme,*op) for op in ops)
    survivors=ell*(r-1)
    for scheme in ['lrdas_a','product_a']:
        expected.update([
            (scheme,'diagonal_full_decode',survivors,'accepted_values'),
            (scheme,'diagonal_decode_authenticate',survivors,'accepted_values'),
            (scheme,'diagonal_recover_serve',degree+1 if scheme=='lrdas_a' else a,'accepted_helpers')])
    expected.add(('product_a','diagonal_row_receive_repair',a,'response_bytes'))
    return expected
