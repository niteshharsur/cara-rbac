import unittest
from fp_engine.__main__ import classify_permission, calculate_threat_score

class TestFPEngine(unittest.TestCase):
    def test_classify_permission(self):
        # 1. CEP (Confirmed Excess Permission)
        klass, conf, band, rationale = classify_permission(has_static=False, has_runtime=False, is_startup=False)
        self.assertEqual(klass, "CEP")
        self.assertEqual(conf, 1.0)
        self.assertEqual(band, "HIGH")

        # 2. SFP (Static False Positive)
        klass, conf, band, rationale = classify_permission(has_static=True, has_runtime=False, is_startup=False)
        self.assertEqual(klass, "SFP")
        self.assertEqual(conf, 0.70)
        self.assertEqual(band, "MEDIUM")

        # 3. SOP (Startup-Only Permission)
        klass, conf, band, rationale = classify_permission(has_static=True, has_runtime=True, is_startup=True)
        self.assertEqual(klass, "SOP")
        self.assertEqual(conf, 0.90)
        self.assertEqual(band, "HIGH")

        # 4. RP (Required Permission)
        klass, conf, band, rationale = classify_permission(has_static=True, has_runtime=True, is_startup=False)
        self.assertEqual(klass, "RP")
        self.assertEqual(conf, 1.0)
        self.assertEqual(band, "HIGH")

        # 5. DRP (Dynamic Runtime Startup Permission)
        klass, conf, band, rationale = classify_permission(has_static=False, has_runtime=True, is_startup=True)
        self.assertEqual(klass, "DRP")
        self.assertEqual(conf, 0.50)
        self.assertEqual(band, "LOW")

        # 6. DP (Dynamic Steady-State Permission)
        klass, conf, band, rationale = classify_permission(has_static=False, has_runtime=True, is_startup=False)
        self.assertEqual(klass, "DP")
        self.assertEqual(conf, 0.50)
        self.assertEqual(band, "LOW")

    def test_calculate_threat_score(self):
        # RP gets threat score 0
        score = calculate_threat_score("RP", "get", "pods")
        self.assertEqual(score, 0.0)

        # CEP with sensitive verb and sensitive resource gets high score (1.0)
        score_sensitive = calculate_threat_score("CEP", "delete", "secrets")
        self.assertEqual(score_sensitive, 1.0)

        # CEP with regular resource/verb gets lower score
        score_regular = calculate_threat_score("CEP", "get", "configmaps")
        self.assertEqual(score_regular, 0.76)

if __name__ == "__main__":
    unittest.main()
