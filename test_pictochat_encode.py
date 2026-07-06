import tempfile
import unittest
from queue import Queue
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    build_dot11_frame,
    build_client_transfer_header,
    build_message_chunks,
    build_transmission,
    encode_4bpp_tiles,
    extract_host_relay,
    find_pictochat_host,
    image_to_indices,
    parse_mac,
    write_pcap,
)
from pictochat_live import EXPECTED_CHUNKS, LAST_CHUNK_OFFSET
from pictochat_send import (
    InjectionWorker,
    linux_injection_radiotap,
    linux_monitor_commands,
    linux_wiphy_name,
)


class EncoderTests(unittest.TestCase):
    def test_worker_rejects_adapter_that_ignores_noack(self):
        client = parse_mac("a4:c0:e1:19:b8:79")
        host = parse_mac("a4:c0:e1:e5:a5:9b")
        frames = []
        for index in range(65):
            frame = bytearray(200)
            frame[0:2] = bytes.fromhex("18 11")
            frame[4:10] = host
            frame[10:16] = client
            frame[24:28] = bytes.fromhex("56 8e 02 00")
            frame[34:36] = (index * 0xA0).to_bytes(2, "little")
            frames.append(bytes(frame))
        events = Queue()
        radio_socket = MagicMock()
        fake_scapy = MagicMock(RadioTap=MagicMock(), Raw=MagicMock(), conf=MagicMock())
        fake_scapy.conf.L2socket.return_value = radio_socket

        sniffers = []

        class RetrySniffer:
            def __init__(self, prn, **_kwargs):
                self.prn = prn
                sniffers.append(self)

            def start(self):
                pass

            def stop(self):
                pass

        fake_scapy.AsyncSniffer = RetrySniffer
        def send_with_retry(_packet):
            retry = bytearray(frames[0])
            retry[0:2] = bytes.fromhex("18 19")
            sniffers[0].prn(bytes(retry))

        radio_socket.send.side_effect = send_with_retry
        worker = InjectionWorker(events, "wlan0", lambda _host: frames, host, 1, 0)

        with (
            patch.dict("sys.modules", {"scapy": MagicMock(), "scapy.all": fake_scapy}),
            patch("pictochat_send.sys.platform", "test"),
        ):
            worker.run()

        emitted = []
        while not events.empty():
            emitted.append(events.get_nowait())
        self.assertTrue(
            any(kind == "error" and "despite the NOACK" in text for kind, text in emitted)
        )
        self.assertEqual(radio_socket.send.call_count, 1)

    def test_worker_rejects_spoofing_the_host_as_its_own_client(self):
        host = parse_mac("a4:c0:e1:e5:a5:9b")
        frames = []
        for _index in range(65):
            frame = bytearray(200)
            frame[4:10] = host
            frame[10:16] = host
            frames.append(bytes(frame))
        events = Queue()
        fake_scapy = MagicMock(
            AsyncSniffer=MagicMock(),
            RadioTap=MagicMock(),
            Raw=MagicMock(),
            conf=MagicMock(),
        )
        worker = InjectionWorker(events, "wlan0", lambda _host: frames, host, 1, 0)

        with (
            patch.dict("sys.modules", {"scapy": MagicMock(), "scapy.all": fake_scapy}),
            patch("pictochat_send.sys.platform", "darwin"),
        ):
            worker.run()

        emitted = []
        while not events.empty():
            emitted.append(events.get_nowait())
        self.assertTrue(
            any(kind == "error" and "room host MAC" in text for kind, text in emitted)
        )
        fake_scapy.conf.L2socket.assert_not_called()

    def test_linux_injection_socket_does_not_pass_capture_only_monitor_option(self):
        radio_socket = MagicMock()
        scapy_conf = MagicMock()
        scapy_conf.L2socket.return_value = radio_socket
        radio_tap = MagicMock()
        radio_tap.return_value.__truediv__.return_value = object()
        async_sniffer = MagicMock()
        frames = [bytes(200)]
        for index in range(64):
            frame = bytearray(200)
            frame[34:36] = (0xA0 + index * 0xA0).to_bytes(2, "little")
            frames.append(bytes(frame))
        fake_scapy = MagicMock(
            AsyncSniffer=async_sniffer,
            RadioTap=radio_tap,
            Raw=MagicMock(),
            conf=scapy_conf,
        )
        worker = InjectionWorker(
            Queue(),
            "wlan0",
            lambda _host: frames,
            parse_mac("a4:c0:e1:e5:a5:9b"),
            1,
            0,
        )

        with (
            patch.dict("sys.modules", {"scapy": MagicMock(), "scapy.all": fake_scapy}),
            patch("pictochat_send.sys.platform", "linux"),
            patch.object(worker, "_configure_linux_injection_constraints") as constraints,
        ):
            worker.run()

        constraints.assert_called_once_with()
        scapy_conf.L2socket.assert_called_once_with(iface="wlan0")
        self.assertEqual(radio_tap.call_count, 65)
        radio_tap.assert_called_with(linux_injection_radiotap())
        self.assertEqual(radio_socket.send.call_count, 65)
        radio_socket.close.assert_called_once()
        async_sniffer.return_value.start.assert_called_once()
        async_sniffer.return_value.stop.assert_called_once()

    def test_linux_monitor_setup_uses_argument_lists(self):
        paths = {"ip": "/usr/sbin/ip", "iw": "/usr/sbin/iw"}
        with patch("pictochat_send.shutil.which", side_effect=paths.get):
            commands = linux_monitor_commands("wlan1", 6)
        self.assertEqual(
            commands,
            [
                ["/usr/sbin/ip", "link", "set", "dev", "wlan1", "down"],
                ["/usr/sbin/iw", "dev", "wlan1", "set", "type", "monitor"],
                ["/usr/sbin/ip", "link", "set", "dev", "wlan1", "up"],
                ["/usr/sbin/iw", "dev", "wlan1", "set", "channel", "6"],
            ],
        )

    def test_linux_injection_radiotap_is_byte_exact(self):
        self.assertEqual(
            linux_injection_radiotap(),
            bytes.fromhex("00 00 0c 00 06 80 00 00 02 04 08 00"),
        )

    def test_linux_wiphy_name_is_extracted_from_iw_info(self):
        self.assertEqual(
            linux_wiphy_name("Interface wlan1mon\n\twiphy 3\n\ttype monitor\n"),
            "phy3",
        )

    def test_linux_wiphy_name_rejects_missing_phy(self):
        with self.assertRaisesRegex(ValueError, "wiphy number"):
            linux_wiphy_name("Interface wlan1mon\n\ttype monitor\n")

    def test_linux_driver_constraint_failures_are_nonfatal(self):
        events = Queue()
        worker = InjectionWorker(events, "wlan0", lambda _host: [], None, 1, 0)
        bitrate_failure = MagicMock(
            returncode=1,
            stderr="command failed: Input/output error (-5)",
            stdout="",
        )
        info_success = MagicMock(returncode=0, stderr="", stdout="wiphy 2\n")
        retry_failure = MagicMock(
            returncode=1,
            stderr="command failed: Operation not supported (-95)",
            stdout="",
        )

        with (
            patch("pictochat_send.shutil.which", return_value="/usr/sbin/iw"),
            patch(
                "pictochat_send.subprocess.run",
                side_effect=(bitrate_failure, info_success, retry_failure),
            ),
        ):
            worker._configure_linux_injection_constraints()

        messages = []
        while not events.empty():
            messages.append(events.get_nowait()[1])
        self.assertTrue(any("fixed 2 Mbps" in message for message in messages))
        self.assertTrue(any("retry tuning" in message for message in messages))

    def test_linux_monitor_setup_reports_missing_tools(self):
        with patch("pictochat_send.shutil.which", return_value=None):
            with self.assertRaisesRegex(FileNotFoundError, "iproute2 and iw"):
                linux_monitor_commands("wlan0", 1)

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

    def test_host_relay_shape_can_round_trip_final_four_bytes(self):
        indices = [[(x + y) % 2 for x in range(CANVAS_W)] for y in range(CANVAS_H)]
        encoded = encode_4bpp_tiles(indices)
        chunks = build_message_chunks(encoded)
        frames = [
            build_dot11_frame(
                chunk,
                parse_mac("a4:c0:e1:e5:a5:9b"),
                index + 1,
                index + 1,
            )
            for index, chunk in enumerate(chunks)
        ]
        output = bytearray(len(encoded))
        for packet_index, frame in enumerate(frames):
            packet = list(add_radiotap_and_fcs(frame))
            candidates = extract_chunk_candidates_from_packet(packet, packet_index)
            self.assertEqual(len(candidates), 1)
            write_chunk_to_image_buffer(output, candidates[0].chunk_offset, candidates[0].payload)
        self.assertEqual(bytes(output), encoded)

    def test_client_frame_matches_observed_upload_shape(self):
        blank = [[0] * CANVAS_W for _ in range(CANVAS_H)]
        client = parse_mac("a4:c0:e1:19:b8:79")
        host = parse_mac("a4:c0:e1:e5:a5:9b")
        frames = build_transmission(blank, client, host, 0x0911, 0xDBF)
        self.assertEqual(len(frames), 65)
        self.assertTrue(all(len(frame) == 200 for frame in frames))
        self.assertEqual(frames[1][0:2], bytes.fromhex("18 11"))
        self.assertEqual(frames[1][4:10], host)
        self.assertEqual(frames[1][10:16], client)
        self.assertEqual(frames[1][16:22], bytes.fromhex("03 09 bf 00 00 10"))
        self.assertEqual(frames[1][24:34], bytes.fromhex("56 8e 02 00 ac 00 01 04 a0 00"))
        self.assertEqual(frames[1][34:38], bytes.fromhex("a0 00 00 00"))
        self.assertEqual(frames[1][-2:], bytes.fromhex("12 09"))
        self.assertEqual(add_radiotap_and_fcs(frames[1])[-4:], bytes.fromhex("21 2d 22 79"))
        self.assertEqual(frames[-1][34:36], bytes.fromhex("00 28"))
        self.assertEqual(len(add_radiotap_and_fcs(frames[0])), 214)

    def test_transfer_header_matches_observed_nintendo_announcement(self):
        client = parse_mac("a4:c0:e1:19:b8:79")
        host = parse_mac("a4:c0:e1:e5:a5:9b")
        frame = build_client_transfer_header(client, host, 0xDBF, 0x0911)
        self.assertEqual(len(frame), 200)
        self.assertEqual(frame[22:24], bytes.fromhex("f0 db"))
        self.assertEqual(frame[24:34], bytes.fromhex("56 8e 02 00 ac 00 01 97 a0 00"))
        self.assertEqual(frame[34:38], bytes(4))
        self.assertEqual(
            frame[38:60],
            bytes.fromhex(
                "03 02 c0 a4 19 e1 79 b8 00 05 00 00 00 00 03 06 08 0d 08 0d 12 1b"
            ),
        )
        self.assertEqual(frame[-2:], bytes.fromhex("11 09"))
        self.assertEqual(add_radiotap_and_fcs(frame)[-4:], bytes.fromhex("ef e8 fd e8"))

    def test_host_relay_is_discovered_and_acknowledges_payload(self):
        data = bytes(index % 251 for index in range(0x2800))
        chunk = build_message_chunks(data)[0]
        host = parse_mac("a4:c0:e1:e5:a5:9b")
        relay = build_dot11_frame(chunk, host, 0xCD0, 0x11BA)
        packet = add_radiotap_and_fcs(relay)
        self.assertEqual(find_pictochat_host(packet), host)
        self.assertEqual(extract_host_relay(packet, host), (chunk.offset, chunk.payload))

    def test_image_import_and_pcap_export(self):
        source = Image.new("RGB", (20, 20), "black")
        indices = image_to_indices(source)
        self.assertTrue(any(any(row) for row in indices))
        frames = build_transmission(
            indices,
            parse_mac("02:00:00:00:00:01"),
            parse_mac("a4:c0:e1:e5:a5:9b"),
            1,
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "drawing.pcap"
            write_pcap(output, frames)
            self.assertGreater(output.stat().st_size, 65 * 214)


if __name__ == "__main__":
    unittest.main()
