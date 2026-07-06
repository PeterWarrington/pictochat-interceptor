import unittest
from queue import Queue
from unittest.mock import MagicMock, patch

from pictochat_live import CaptureWorker, available_interfaces


class WindowsCompatibilityTests(unittest.TestCase):
    def test_windows_interfaces_come_from_scapy_npcap_names(self):
        fake_scapy = MagicMock()
        fake_scapy.get_if_list.return_value = ["Wi-Fi", "Ethernet"]

        with (
            patch("pictochat_live.sys.platform", "win32"),
            patch.dict("sys.modules", {"scapy.all": fake_scapy}),
        ):
            self.assertEqual(available_interfaces(), ["Wi-Fi", "Ethernet"])

    def test_windows_interfaces_fall_back_when_npcap_is_unavailable(self):
        fake_scapy = MagicMock()
        fake_scapy.get_if_list.side_effect = RuntimeError("Npcap is missing")

        with (
            patch("pictochat_live.sys.platform", "win32"),
            patch("pictochat_live.socket.if_nameindex", return_value=[(7, "Wi-Fi")]),
            patch.dict("sys.modules", {"scapy.all": fake_scapy}),
        ):
            self.assertEqual(available_interfaces(), ["Wi-Fi"])

    def test_windows_capture_uses_npcap_monitor_socket(self):
        events = Queue()
        worker = CaptureWorker(events, "Wi-Fi", "wlan type data")
        capture_socket = MagicMock()
        conf = MagicMock()
        conf.L2listen.return_value = capture_socket

        def sniff_once(**options):
            options["prn"](b"\x00\x01\x02")
            worker.stop_event.set()

        fake_scapy = MagicMock(conf=conf, sniff=MagicMock(side_effect=sniff_once))
        with patch.dict("sys.modules", {"scapy.all": fake_scapy}):
            worker._run_windows_capture()

        self.assertTrue(conf.use_pcap)
        conf.L2listen.assert_called_once_with(
            iface="Wi-Fi",
            monitor=True,
            filter="wlan type data",
        )
        capture_socket.close.assert_called_once_with()
        self.assertEqual(events.get_nowait()[0], "info")
        self.assertEqual(events.get_nowait(), ("packet", [0, 1, 2]))


if __name__ == "__main__":
    unittest.main()
