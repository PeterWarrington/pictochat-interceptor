import unittest
from unittest.mock import MagicMock

from pictochat_ui import UiMetrics


class UiMetricsTests(unittest.TestCase):
    def test_macos_aqua_keeps_original_metrics(self):
        root = MagicMock()
        root.tk.call.return_value = "aqua"
        root.winfo_fpixels.return_value = 72.0

        metrics = UiMetrics.from_root(root)

        self.assertFalse(metrics.compact)
        root.winfo_fpixels.assert_not_called()

    def test_low_dpi_uses_compact_metrics(self):
        metrics = UiMetrics.for_dpi(96.0)
        self.assertTrue(metrics.compact)
        self.assertEqual(metrics.geometry(1100, 780), "880x624")
        self.assertEqual(metrics.preview_scale, 2)

    def test_high_dpi_keeps_original_metrics(self):
        metrics = UiMetrics.for_dpi(144.0)
        self.assertFalse(metrics.compact)
        self.assertEqual(metrics.geometry(1100, 780), "1100x780")
        self.assertEqual(metrics.preview_scale, 3)


if __name__ == "__main__":
    unittest.main()
