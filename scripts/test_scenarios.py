"""Checks for model arithmetic and evidence validation, independent of plot generation."""
import copy, pathlib, unittest
import analyze, analyze_scenarios as scenarios
ROOT=pathlib.Path(__file__).resolve().parents[1]

def row(*values):
    return {"process_means_ms":{str(i):v for i,v in enumerate(values)}}

class ScenarioTests(unittest.TestCase):
    def components(self):
        return {"lrdas_publish":row(10,12),"product_publish":row(10,12),
                "lrdas_client":row(1,2),"product_client":row(3,5),
                "lrdas_recovery":row(10,20),"product_recovery":row(2,4)}
    def test_hand_computed_role_subtotals_and_strict_threshold(self):
        c=self.components();v=scenarios.cpu_model(c,4,1)
        # process totals: LR [24,40], Product [24,36]; mean difference -2.
        self.assertEqual(v["lrdas_ms"],32)
        self.assertEqual(v["product_ms"],30)
        self.assertEqual(v["product_minus_lr_ms"],-2)
        self.assertAlmostEqual(v["product_over_lr"],.95)
        self.assertAlmostEqual(scenarios.break_even(c,1)["clients_real_threshold"],4.8)
        self.assertEqual(scenarios.break_even(c,1)["first_strictly_better_integer_clients"],5)
        for n in (0,1,4,5,20):
            x=scenarios.cpu_model(c,n,1)
            self.assertEqual(x["measurement_kind"],"model_from_measured_components")
        # An exact tie is not counted as strictly better.
        c={k:row(*(v["process_means_ms"]["0"],)*2) for k,v in c.items()}
        self.assertEqual(scenarios.break_even(c,1)["first_strictly_better_integer_clients"],5)
    def test_invalid_counts_components_and_pairing_rejected(self):
        for bad in (-1,float("nan"),float("inf"),True,"3"):
            with self.assertRaises(ValueError):scenarios.cpu_model(self.components(),bad,1)
            with self.assertRaises(ValueError):scenarios.break_even(self.components(),bad)
        c=self.components();c["lrdas_client"]=row(1)
        with self.assertRaises(ValueError):scenarios.cpu_model(c,3,1)
        c=self.components();c["product_client"]=row(.1,.1)
        with self.assertRaises(ValueError):scenarios.break_even(c,1)
        c=self.components();c["lrdas_client"]=row(float("nan"),1)
        with self.assertRaises(ValueError):scenarios.cpu_model(c,1,1)
    def test_actual_archive_and_constructive_evidence_contract(self):
        env,manifests,records=analyze.load_runs(ROOT/"results/raw/separation-smoke")
        self.assertEqual(len(records),10)
        self.assertEqual(len(scenarios.validate_separation(env,manifests)),3)
        mutations=(
            ("witness_verified",False),("same_header_claimed",True),
            ("witness_nonzero_symbols",0),("outcome","recovered_and_authenticated"))
        for key,value in mutations:
            bad=copy.deepcopy(manifests)
            witness=next(r for r in bad[0]["roles"] if r["scheme"]=="product" and r["pattern"]=="rectangle")
            witness[key]=value
            with self.assertRaises(ValueError):scenarios.validate_separation(env,bad)
        bad=copy.deepcopy(manifests);bad[0]["roles"].pop()
        with self.assertRaises(ValueError):scenarios.validate_separation(env,bad)
    def test_same_mask_is_required_and_ambiguity_has_no_timing_row(self):
        env,manifests,records=analyze.load_runs(ROOT/"results/raw/separation-smoke")
        self.assertFalse(any(r["scheme"]=="product" and r["operation"].startswith("rectangle_")
                             and not r["operation"].startswith("rectangle_minus_one") for r in records))
        bad=copy.deepcopy(manifests);bad[0]["roles"][0]["mask_sha256"]="different"
        with self.assertRaises(ValueError):scenarios.validate_separation(env,bad)

if __name__=="__main__":unittest.main()
