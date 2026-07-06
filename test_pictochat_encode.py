import tempfile
import unittest
from pathlib import Path

from PIL import Image

from pictochat_decode import (
    CANVAS_H,
    CANVAS_W,
    compose_canvas_row_major,
    decode_4bpp_tiles,
    extract_chunk_candidates_from_packet,
    write_chunk_to_image_buffer,
)
from pictochat_encode import (
    add_radiotap_and_fcs,
    build_message_chunks,
    build_transmission,
    encode_4bpp_tiles,
    image_to_indices,
    parse_mac,
    write_pcap,
)
from pictochat_live import EXPECTED_CHUNKS, LAST_CHUNK_OFFSET


class EncoderTests(unittest.TestCase):
    def test_live_nintendo_wire_format_remains_64_chunks(self):
        # Real DS/DSi captures stop at 0x2800. The encoder's optional 65th tail
        # chunk is useful for lossless local round-trips, but must not redefine
        # receiver completion or automatic session boundaries.
        self.assertEqual(EXPECTED_CHUNKS, 64)
        self.assertEqual(LAST_CHUNK_OFFSET, 0x2800)

    def test_encoder_round_trip_preserves_every_pixel(self):
        indices = [[(x + y * 3) % 16 for x in range(CANVAS_W)] for y in range(CANVAS_H)]
        encoded = encode_4bpp_tiles(indices)
        decoded = compose_canvas_row_major(decode_4bpp_tiles(encoded))
        self.assertEqual(decoded, indices)

    def test_prefix_requires_65_chunks_and_keeps_last_pixels(self):
        data = bytes((index % 251 for index in range(0x2800)))
        chunks = build_message_chunks(data)
        self.assertEqual(len(chunks), 65)
        reconstructed = b"".join(chunk.payload for chunk in chunks)
        self.assertEqual(reconstructed[4:4 + len(data)], data)
        self.assertEqual(chunks[-1].offset, 0x28A0)

    def test_decoder_accepts_final_four_bytes(self):
        indices = [[(x + y) % 2 for x in range(CANVAS_W)] for y in range(CANVAS_H)]
        encoded = encode_4bpp_tiles(indices)
        frames = build_transmission(indices, parse_mac("02:00:00:00:00:01"), 1, 1)
        output = bytearray(len(encoded))
        for packet_index, frame in enumerate(frames):
            packet = list(add_radiotap_and_fcs(frame))
            candidates = extract_chunk_candidates_from_packet(packet, packet_index)
            self.assertEqual(len(candidates), 1)
            write_chunk_to_image_buffer(output, candidates[0].chunk_offset, candidates[0].payload)
        self.assertEqual(bytes(output), encoded)

    def test_frame_matches_observed_shape(self):
        blank = [[0] * CANVAS_W for _ in range(CANVAS_H)]
        frames = build_transmission(blank, parse_mac("a4:c0:e1:e5:a5:9b"), 0x11BA, 0xCD0)
        self.assertEqual(len(frames), 65)
        self.assertTrue(all(len(frame) == 206 for frame in frames))
        self.assertEqual(frames[0][0:2], bytes.fromhex("28 02"))
        self.assertEqual(frames[0][4:10], bytes.fromhex("03 09 bf 00 00 00"))
        self.assertEqual(frames[0][38:40], bytes.fromhex("a0 00"))
        self.assertEqual(len(add_radiotap_and_fcs(frames[0])), 220)

    def test_image_import_and_pcap_export(self):
        source = Image.new("RGB", (20, 20), "black")
        indices = image_to_indices(source)
        self.assertTrue(any(any(row) for row in indices))
        frames = build_transmission(indices, parse_mac("02:00:00:00:00:01"), 1, 1)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "drawing.pcap"
            write_pcap(output, frames)
            self.assertGreater(output.stat().st_size, 65 * 220)


if __name__ == "__main__":
    unittest.main()
