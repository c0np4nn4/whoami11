import json
from pathlib import Path
import shutil
import tempfile
import unittest

import paper_results


class PaperResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("results/raw/tradeoffs-paper", "provenance/tradeoffs-paper-source",
                     "results_table3/table3-case-1", "results_table3/table3-case-2",
                     "results_table3/table3-case-3"):
            shutil.copytree(paper_results.ROOT / name, self.root / name)
        self.raw = self.root / "results/raw/tradeoffs-paper/run-0.jsonl"
        self.status = self.raw.with_suffix(".status.json")

    def records(self):
        return [json.loads(line) for line in self.raw.read_text().splitlines()]

    def save_records(self, records):
        self.raw.write_text("".join(json.dumps(row) + "\n" for row in records))

    def test_published_numbers(self):
        table2, table7, _ = paper_results.aggregate(self.root)
        self.assertEqual([row[2:4] for row in table2[1:]],
                         [["864.6", "863.8"], ["414.3", "1650.0"],
                          ["6247.1", "552.9"], ["519, 2", "2065, 2"]])
        self.assertEqual(table2[-1][-1], "analytic")
        self.assertEqual(table7[1][2:], ["864.6", "863.8", "1732.0", "1728.6"])
        self.assertEqual(table7[2][2:], ["414.3", "1650.0", "427.3", "1663.1"])
        self.assertEqual([row[2:4] for row in table7[-3:]],
                         [["2746.8", "271.3"], ["6247.1", "552.9"], ["14037.2", "1102.8"]])

    def test_missing_process(self):
        self.raw.unlink()
        with self.assertRaisesRegex(ValueError, "three sample files"):
            paper_results.aggregate(self.root)

    def test_incomplete_process(self):
        status = json.loads(self.status.read_text())
        status["status"] = "running"
        self.status.write_text(json.dumps(status))
        with self.assertRaisesRegex(ValueError, "incomplete process"):
            paper_results.aggregate(self.root)

    def test_truncated_file(self):
        self.save_records(self.records()[:-1])
        with self.assertRaisesRegex(ValueError, "row count mismatch"):
            paper_results.aggregate(self.root)

    def test_missing_target_even_if_row_count_updated(self):
        self.save_records(self.records()[1:])
        status = json.loads(self.status.read_text())
        status["rows"] -= 1
        self.status.write_text(json.dumps(status))
        with self.assertRaisesRegex(ValueError, "target samples"):
            paper_results.aggregate(self.root)

    def test_duplicate_sample_with_unchanged_row_count(self):
        rows = self.records()
        rows[3] = rows[2]
        self.save_records(rows)
        with self.assertRaisesRegex(ValueError, "duplicate sample"):
            paper_results.aggregate(self.root)

    def test_wrong_sample_identity(self):
        rows = self.records()
        rows[0]["seed"] += 1
        self.save_records(rows)
        with self.assertRaisesRegex(ValueError, "sample identity"):
            paper_results.aggregate(self.root)

    def test_nonpositive_measurement(self):
        for field in ("elapsed_ns", "iterations"):
            with self.subTest(field=field):
                original = self.records()
                rows = self.records()
                rows[0][field] = 0
                self.save_records(rows)
                with self.assertRaisesRegex(ValueError, "nonpositive"):
                    paper_results.aggregate(self.root)
                self.save_records(original)

    def test_changed_archived_source(self):
        source = self.root / "provenance/tradeoffs-paper-source/src/lib.rs"
        source.write_text(source.read_text() + "\n \n")
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            paper_results.aggregate(self.root)

    def test_missing_comment_stripped_manifest(self):
        manifest = self.root / "provenance/tradeoffs-paper-source/COMMENT_STRIPPED_MANIFEST.json"
        manifest.unlink()
        with self.assertRaises(FileNotFoundError):
            paper_results.aggregate(self.root)

    def test_missing_comment_stripped_file_mapping(self):
        path = self.root / "provenance/tradeoffs-paper-source/COMMENT_STRIPPED_MANIFEST.json"
        manifest = json.loads(path.read_text())
        del manifest["files"]["src/lib.rs"]
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "file set mismatch"):
            paper_results.aggregate(self.root)

    def test_tampered_comment_stripped_file_mapping(self):
        path = self.root / "provenance/tradeoffs-paper-source/COMMENT_STRIPPED_MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["files"]["src/lib.rs"] = "0" * 64
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "manifest hash"):
            paper_results.aggregate(self.root)

    def test_wrong_original_source_digest(self):
        path = self.root / "provenance/tradeoffs-paper-source/COMMENT_STRIPPED_MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["original_source_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "original source digest mismatch"):
            paper_results.aggregate(self.root)

    def test_wrong_parameters(self):
        status = json.loads(self.status.read_text())
        status["config"]["params"]["a"] = 81
        self.status.write_text(json.dumps(status))
        with self.assertRaisesRegex(ValueError, "paper parameters"):
            paper_results.aggregate(self.root)

    def test_output_is_new_and_never_overwrites(self):
        output = self.root / "output"
        paper_results.write_results(self.root, output)
        table = output / "table2.csv"
        original = table.read_bytes()
        with self.assertRaises(FileExistsError):
            paper_results.write_results(self.root, output)
        self.assertEqual(table.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
