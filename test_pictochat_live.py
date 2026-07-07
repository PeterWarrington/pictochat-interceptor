import unittest
from unittest.mock import patch

from pictochat_decode import BASE_OFFSET, CHUNK_PAYLOAD_LEN, ChunkCandidate, ChunkStream
from pictochat_live import LAST_CHUNK_OFFSET, PictoChatLiveApp, fitted_preview_scale


class LiveSessionDetectionTests(unittest.TestCase):
    def _app_with_active_stream(self, stream: ChunkStream) -> PictoChatLiveApp:
        app = PictoChatLiveApp.__new__(PictoChatLiveApp)
        app.last_candidate_offset = LAST_CHUNK_OFFSET
        app.last_candidate_time = 99.0
        app.pending_cycle = []
        app.pending_baseline = None
        app.pending_changed_offsets = set()
        app.pending_started_after_pause = False
        app._selected_stream = lambda: stream
        return app

    def test_new_cycle_with_only_first_chunk_changed_is_detected(self):
        old_payload = bytes(CHUNK_PAYLOAD_LEN)
        new_payload = bytes([0, 0, 0, 0, 1]) + bytes(CHUNK_PAYLOAD_LEN - 5)
        stream = ChunkStream(0, 63, {BASE_OFFSET: old_payload}, {BASE_OFFSET}, {}, 64)
        app = self._app_with_active_stream(stream)
        candidate = ChunkCandidate(64, BASE_OFFSET, new_payload, True)

        with patch("pictochat_live.time.monotonic", return_value=100.0):
            self.assertTrue(app._detect_new_drawing(candidate))

    def test_new_cycle_with_single_left_edge_chunk_changed_is_detected(self):
        old_payload = bytes(CHUNK_PAYLOAD_LEN)
        new_payload = bytes([1]) + bytes(CHUNK_PAYLOAD_LEN - 1)
        left_edge_offset = BASE_OFFSET + 6 * CHUNK_PAYLOAD_LEN
        stream = ChunkStream(
            0,
            63,
            {
                BASE_OFFSET: old_payload,
                left_edge_offset: old_payload,
            },
            {BASE_OFFSET, left_edge_offset},
            {},
            64,
        )
        app = self._app_with_active_stream(stream)

        with patch("pictochat_live.time.monotonic", return_value=100.0):
            self.assertFalse(
                app._detect_new_drawing(
                    ChunkCandidate(64, BASE_OFFSET, old_payload, True)
                )
            )
            self.assertTrue(
                app._detect_new_drawing(
                    ChunkCandidate(70, left_edge_offset, new_payload, True)
                )
            )

    def test_new_cycle_with_only_final_chunk_changed_is_not_detected(self):
        old_payload = bytes(CHUNK_PAYLOAD_LEN)
        new_payload = bytes([1]) + bytes(CHUNK_PAYLOAD_LEN - 1)
        app = self._app_with_active_stream(ChunkStream(0, 63))
        app.last_candidate_offset = LAST_CHUNK_OFFSET - CHUNK_PAYLOAD_LEN
        app.pending_baseline = {LAST_CHUNK_OFFSET: old_payload}
        app.pending_started_after_pause = True
        candidate = ChunkCandidate(64, LAST_CHUNK_OFFSET, new_payload, True)

        with patch("pictochat_live.time.monotonic", return_value=100.0):
            self.assertFalse(app._detect_new_drawing(candidate))


class LivePreviewScaleTests(unittest.TestCase):
    def test_preview_scale_uses_maximum_when_viewport_is_unmapped(self):
        self.assertEqual(fitted_preview_scale(1, 1, 3), 3)

    def test_preview_scale_shrinks_to_fit_narrow_viewport(self):
        self.assertEqual(fitted_preview_scale(660, 451, 3), 2)

    def test_preview_scale_keeps_full_size_when_it_fits(self):
        self.assertEqual(fitted_preview_scale(768, 451, 3), 3)


if __name__ == "__main__":
    unittest.main()
