from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DataContextTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "fixtures/household_linkage.json").read_text(encoding="utf-8"))

    def test_anchor_references_and_unknown_fields(self):
        records = {row["registration_id"] for row in self.data["registrations"]}
        self.assertEqual(len(records), len(self.data["registrations"]))
        self.assertTrue(all(row["left"] in records and row["right"] in records for row in self.data["anchors"]))
        self.assertTrue(any(row["contact_key"] is None for row in self.data["registrations"]))

    def test_validation_families_not_in_training_anchors(self):
        development = {row["registration_id"] for row in self.data["registrations"] if row["cohort"] == "development"}
        self.assertTrue(all(row["left"] in development and row["right"] in development for row in self.data["anchors"]))
        self.assertTrue(self.data["split_events"])
        self.assertTrue(self.data["conflict_updates"])

