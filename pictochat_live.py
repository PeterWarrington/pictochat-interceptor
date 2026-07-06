#!/usr/bin/env python3
"""Live PictoChat wireless capture and drawing viewer."""

from __future__ import annotations

import json
import os
import queue
import shlex
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageDraw, ImageTk

from pictochat_decode import (
    BASE_OFFSET,
    CANVAS_H,
    CANVAS_W,
    CHUNK_PAYLOAD_LEN,
    IMAGE_BUFFER_SIZE,
    ChunkCandidate,
    ChunkStream,
    build_chunk_streams,
    canvas_to_image,
    compose_canvas_row_major,
    decode_4bpp_tiles,
    extract_chunk_candidates_from_packet,
    parse_hexdump_packets,
    write_chunk_to_image_buffer,
)


BG = "#10131a"
PANEL = "#191e28"
PANEL_2 = "#222936"
INK = "#f3f5f7"
MUTED = "#9099aa"
ACCENT = "#70e1c2"
ACCENT_DARK = "#236b5e"
WARNING = "#ffbd69"
ERROR = "#ff6b7a"
# Nintendo's real PictoChat broadcasts contain 64 chunks, ending at 0x2800.
# The experimental encoder can emit an optional 65th tail chunk to round-trip
# the final four storage bytes, but live completion/session boundaries must be
# based on the observed wire protocol or every normal cycle looks incomplete.
EXPECTED_CHUNKS = IMAGE_BUFFER_SIZE // CHUNK_PAYLOAD_LEN
LAST_CHUNK_OFFSET = BASE_OFFSET + (EXPECTED_CHUNKS - 1) * CHUNK_PAYLOAD_LEN
PREVIEW_SCALE = 3


def resource_path(filename: str) -> Path:
    """Return a project resource path in source and PyInstaller builds."""
    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return bundle_dir / filename


def available_interfaces() -> list[str]:
    """Return interface names without requiring Scapy to be installed."""
    try:
        return [name for _, name in socket.if_nameindex()]
    except OSError:
        return []


class FlatButton(tk.Label):
    """A predictable cross-platform button that Aqua cannot restyle."""

    def __init__(
        self,
        parent: tk.Widget,
        text: str,
        command: object,
        background: str,
        foreground: str,
    ) -> None:
        super().__init__(
            parent,
            text=text,
            bg=background,
            fg=foreground,
            padx=10,
            pady=9,
            cursor="hand2",
            font=("TkDefaultFont", 10, "bold"),
        )
        self.command = command
        self.normal_background = background
        self.normal_foreground = foreground
        if background == ACCENT:
            self.hover_background = "#8cebd1"
            self.pressed_background = "#58c9ab"
        else:
            self.hover_background = "#303949"
            self.pressed_background = "#3a4558"
        self.enabled = True
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<ButtonRelease-1>", self._release)

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        if enabled:
            self.configure(
                bg=self.normal_background,
                fg=self.normal_foreground,
                cursor="hand2",
            )
        else:
            self.configure(bg=PANEL_2, fg="#626b7a", cursor="arrow")

    def _enter(self, _event: tk.Event) -> None:
        if self.enabled:
            self.configure(bg=self.hover_background)

    def _leave(self, _event: tk.Event) -> None:
        if self.enabled:
            self.configure(bg=self.normal_background)

    def _press(self, _event: tk.Event) -> None:
        if self.enabled:
            self.configure(bg=self.pressed_background)

    def _release(self, event: tk.Event) -> None:
        if not self.enabled:
            return
        inside = 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height()
        self.configure(
            bg=self.hover_background if inside else self.normal_background
        )
        if inside and callable(self.command):
            self.command()


class CaptureWorker(threading.Thread):
    """Run Scapy's blocking sniffer away from Tk's event loop."""

    def __init__(
        self,
        output: queue.Queue[tuple[str, object]],
        interface: str,
        capture_filter: str,
    ) -> None:
        super().__init__(daemon=True)
        self.output = output
        self.interface = interface
        self.capture_filter = capture_filter
        self.stop_event = threading.Event()

    def run(self) -> None:
        try:
            from scapy.all import sniff
        except ImportError:
            self.output.put(("error", "Scapy is not installed. Run: pip install scapy"))
            self.output.put(("stopped", None))
            return

        def received(packet: object) -> None:
            try:
                self.output.put(("packet", list(bytes(packet))))
            except Exception as exc:  # a malformed packet should not end capture
                self.output.put(("warning", f"Skipped one packet: {exc}"))

        try:
            while not self.stop_event.is_set():
                kwargs: dict[str, object] = {
                    "iface": self.interface or None,
                    "prn": received,
                    "store": False,
                    "timeout": 1,
                }
                if self.capture_filter.strip():
                    kwargs["filter"] = self.capture_filter.strip()
                sniff(**kwargs)
        except PermissionError:
            self.output.put(
                ("error", "Packet capture was denied. Re-run this app with capture privileges.")
            )
        except Exception as exc:
            self.output.put(("error", f"Capture stopped: {exc}"))
        finally:
            self.output.put(("stopped", None))

    def stop(self) -> None:
        self.stop_event.set()


class MacOSCaptureWorker(CaptureWorker):
    """Use Apple's tcpdump to put Wi-Fi into real 802.11 monitor mode."""

    def __init__(
        self,
        output: queue.Queue[tuple[str, object]],
        interface: str,
        capture_filter: str,
    ) -> None:
        super().__init__(output, interface, capture_filter)
        self.process: subprocess.Popen[bytes] | None = None

    def run(self) -> None:
        try:
            from scapy.utils import PcapReader
        except ImportError:
            self.output.put(("error", "Scapy is not installed. Run: pip install scapy"))
            self.output.put(("stopped", None))
            return

        command = [
            "/usr/sbin/tcpdump",
            "-I",
            "-i",
            self.interface,
            "-y",
            "IEEE802_11_RADIO",
            "-B",
            "4096",
            "-s",
            "0",
            "--immediate-mode",
            "-U",
            "-w",
            "-",
        ]
        try:
            if self.capture_filter.strip():
                command.extend(shlex.split(self.capture_filter))
        except ValueError as exc:
            self.output.put(("error", f"Invalid capture filter: {exc}"))
            self.output.put(("stopped", None))
            return

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if self.process.stdout is None:
                raise RuntimeError("tcpdump did not provide a packet stream")

            with PcapReader(self.process.stdout) as packets:
                for packet in packets:
                    if self.stop_event.is_set():
                        break
                    self.output.put(("packet", list(bytes(packet))))

            return_code = self.process.wait(timeout=3)
            error_text = ""
            if self.process.stderr is not None:
                error_text = self.process.stderr.read().decode("utf-8", errors="replace").strip()
            if return_code and not self.stop_event.is_set():
                if "Operation not permitted" in error_text or "Permission denied" in error_text:
                    message = (
                        "Monitor capture was denied. Launch with sudo or grant BPF capture access."
                    )
                else:
                    message = f"macOS monitor capture stopped: {error_text or 'tcpdump failed'}"
                self.output.put(("error", message))
        except FileNotFoundError:
            self.output.put(("error", "Apple tcpdump was not found at /usr/sbin/tcpdump."))
        except Exception as exc:
            if not self.stop_event.is_set():
                detail = str(exc)
                process = self.process
                if process is not None and process.poll() is not None and process.stderr is not None:
                    tcpdump_error = process.stderr.read().decode(
                        "utf-8", errors="replace"
                    ).strip()
                    if tcpdump_error:
                        detail = tcpdump_error
                if "Operation not permitted" in detail or "Permission denied" in detail:
                    detail = "Monitor capture was denied. Launch with sudo or grant BPF capture access."
                self.output.put(("error", f"macOS monitor capture stopped: {detail}"))
        finally:
            process = self.process
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            self.output.put(("stopped", None))

    def stop(self) -> None:
        super().stop()
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()


class MacOSChannelCaptureWorker(MacOSCaptureWorker):
    """Retune Apple Wi-Fi through CoreWLAN, then start monitor capture."""

    def __init__(
        self,
        output: queue.Queue[tuple[str, object]],
        interface: str,
        capture_filter: str,
        channel: int,
    ) -> None:
        super().__init__(output, interface, capture_filter)
        self.channel = channel

    def run(self) -> None:
        try:
            helper = self._build_channel_helper()
            result = self._run_channel_helper(helper)
            if result.returncode:
                detail = result.stderr.strip() or result.stdout.strip()
                raise RuntimeError(detail or f"CoreWLAN helper exited with status {result.returncode}")
            self.output.put(("info", f"Wi-Fi locked to channel {self.channel}; capturing frames…"))
        except Exception as exc:
            self.output.put(("error", f"macOS channel setup failed: {exc}"))
            self.output.put(("stopped", None))
            return

        super().run()

    def _run_channel_helper(self, helper: Path) -> subprocess.CompletedProcess[str]:
        command = [str(helper), self.interface, str(self.channel)]
        if os.geteuid() == 0:
            return subprocess.run(command, capture_output=True, text=True, timeout=8)

        # Elevate only the tiny helper in /tmp. Keeping the GUI in the user's
        # session preserves macOS privacy access to Documents and file dialogs.
        shell_command = " ".join(shlex.quote(part) for part in command)
        apple_script = (
            f"do shell script {json.dumps(shell_command)} "
            "with administrator privileges"
        )
        return subprocess.run(
            ["/usr/bin/osascript", "-e", apple_script],
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _build_channel_helper() -> Path:
        project_dir = Path(__file__).resolve().parent
        source = project_dir / "macos_wifi_channel.m"
        build_dir = Path("/tmp/pictochat-interceptor")
        helper = build_dir / "macos_wifi_channel"
        module_cache = build_dir / "module-cache"
        build_dir.mkdir(parents=True, exist_ok=True)
        module_cache.mkdir(parents=True, exist_ok=True)

        if helper.exists() and helper.stat().st_mtime_ns >= source.stat().st_mtime_ns:
            return helper

        environment = dict(os.environ)
        environment["CLANG_MODULE_CACHE_PATH"] = str(module_cache)
        result = subprocess.run(
            [
                "/usr/bin/clang",
                "-fobjc-arc",
                str(source),
                "-framework",
                "Foundation",
                "-framework",
                "CoreWLAN",
                "-o",
                str(helper),
            ],
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "could not compile CoreWLAN helper")
        return helper


class PictoChatLiveApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PictoChat Interceptor")
        self.app_icon = tk.PhotoImage(file=resource_path("icon.png"))
        self.root.iconphoto(True, self.app_icon)
        self.root.geometry("1040x800")
        self.root.minsize(900, 650)
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker: CaptureWorker | None = None
        self.packet_count = 0
        self.candidates: list[ChunkCandidate] = []
        self.streams: list[ChunkStream] = []
        self.current_image: Image.Image | None = None
        self.preview_photo: ImageTk.PhotoImage | None = None
        self.dirty = False
        self.capture_had_error = False
        self.last_candidate_offset: int | None = None
        self.last_candidate_time: float | None = None
        self.pending_cycle: list[ChunkCandidate] = []
        self.pending_baseline: dict[int, bytes] | None = None
        self.pending_changed_offsets: set[int] = set()
        self.pending_started_after_pause = False

        self.interface_var = tk.StringVar()
        self.channel_var = tk.StringVar(value="1")
        self.filter_var = tk.StringVar()
        self.stream_var = tk.StringVar(value="Auto")
        self.status_var = tk.StringVar(value="Ready to listen")
        self.candidate_var = tk.StringVar(value="0")
        self.stream_count_var = tk.StringVar(value="0")
        self.progress_var = tk.DoubleVar(value=0)
        self.coverage_var = tk.StringVar(value=f"0 / {EXPECTED_CHUNKS} chunks")

        self._configure_styles()
        self._build_ui()
        self._show_empty_preview()
        self.root.after(80, self._drain_events)

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground=PANEL_2, background=PANEL_2,
                        foreground=INK, arrowcolor=INK, bordercolor="#343d4d",
                        lightcolor="#343d4d", darkcolor="#343d4d", padding=7)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL_2)],
                  foreground=[("readonly", INK)])
        style.configure("Air.Horizontal.TProgressbar", troughcolor=PANEL_2,
                        background=ACCENT, bordercolor=PANEL_2, lightcolor=ACCENT,
                        darkcolor=ACCENT, thickness=8)

    def _build_ui(self) -> None:
        shell = tk.Frame(self.root, bg=BG, padx=28, pady=24)
        shell.pack(fill="both", expand=True)

        header = tk.Frame(shell, bg=BG)
        header.pack(fill="x", pady=(0, 20))
        tk.Label(header, text="PICTOCHAT", bg=BG, fg=ACCENT,
                 font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        tk.Label(header, text="Interceptor", bg=BG, fg=INK,
                 font=("TkDefaultFont", 28, "bold")).pack(anchor="w")
        tk.Label(header, text="Watch Nintendo DS drawings assemble over the air.",
                 bg=BG, fg=MUTED, font=("TkDefaultFont", 11)).pack(anchor="w", pady=(3, 0))

        body = tk.Frame(shell, bg=BG)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        controls = tk.Frame(body, bg=PANEL, padx=18, pady=18, width=275)
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        controls.grid_propagate(False)

        self._section_label(controls, "CAPTURE SOURCE").pack(anchor="w")
        interfaces = available_interfaces()
        self.interface_box = ttk.Combobox(controls, textvariable=self.interface_var,
                                          values=interfaces, state="readonly")
        self.interface_box.pack(fill="x", pady=(8, 12))
        if interfaces:
            preferred = next(
                (x for x in ("en0", "wlan0", "wlp0s0") if x in interfaces),
                next((x for x in interfaces if x.startswith(("en", "wl"))), interfaces[0]),
            )
            self.interface_var.set(preferred)

        tk.Label(controls, text="2.4 GHz channel", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 9)).pack(anchor="w")
        channel_values = [str(channel) for channel in range(1, 14)] + ["Current"]
        self.channel_box = ttk.Combobox(controls, textvariable=self.channel_var,
                                        values=channel_values, state="readonly")
        self.channel_box.pack(fill="x", pady=(5, 12))

        filter_label = "Optional BPF filter"
        if sys.platform == "darwin":
            filter_label += " (Current only)"
        tk.Label(controls, text=filter_label, bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 9)).pack(anchor="w")
        filter_entry = tk.Entry(controls, textvariable=self.filter_var, bg=PANEL_2,
                                fg=INK, insertbackground=INK, relief="flat",
                                highlightthickness=1, highlightbackground="#343d4d",
                                highlightcolor=ACCENT, font=("TkFixedFont", 10))
        filter_entry.pack(fill="x", ipady=8, pady=(5, 14))

        self.start_button = self._button(controls, "Start listening", self.start_capture, ACCENT, "#071b17")
        self.start_button.pack(fill="x", pady=(0, 8))
        self.stop_button = self._button(controls, "Stop", self.stop_capture, PANEL_2, INK)
        self.stop_button.set_enabled(False)
        self.stop_button.pack(fill="x", pady=(0, 8))
        self._button(controls, "Open a saved hex dump", self.open_dump, PANEL_2, INK).pack(fill="x")

        tk.Frame(controls, bg="#303746", height=1).pack(fill="x", pady=18)
        self._section_label(controls, "DRAWING STREAM").pack(anchor="w")
        self.stream_box = ttk.Combobox(controls, textvariable=self.stream_var,
                                       values=["Auto"], state="readonly")
        self.stream_box.pack(fill="x", pady=(8, 12))
        self.stream_box.bind("<<ComboboxSelected>>", lambda _event: self._render_selected())
        self._button(controls, "Save drawing as PNG", self.save_image, PANEL_2, INK).pack(fill="x", pady=(0, 8))
        self._button(controls, "Clear session", self.reset_session, PANEL_2, WARNING).pack(fill="x")

        note = ("You MUST have a live PictoChat session between two or more connected DS systems! Only one system does not work :(\n\n"
                "Tip: the Wi-Fi interface must expose raw 802.11 frames. "
                "Monitor mode and capture permission are usually required.")
        tk.Label(controls, text=note, wraplength=235, justify="left", bg=PANEL,
                 fg=MUTED, font=("TkDefaultFont", 9)).pack(side="bottom", anchor="w")

        workspace = tk.Frame(body, bg=BG)
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_columnconfigure(0, weight=1)
        workspace.grid_rowconfigure(1, weight=1)

        stats = tk.Frame(workspace, bg=BG)
        stats.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        for column in range(2):
            stats.grid_columnconfigure(column, weight=1)
        self._stat_card(stats, "PICTOCHAT CHUNKS", self.candidate_var).grid(
            row=0, column=0, sticky="ew", padx=(0, 7)
        )
        self._stat_card(stats, "STREAMS", self.stream_count_var).grid(
            row=0, column=1, sticky="ew", padx=(7, 0)
        )

        viewer = tk.Frame(workspace, bg=PANEL, padx=22, pady=20)
        viewer.grid(row=1, column=0, sticky="nsew")
        viewer.grid_columnconfigure(0, weight=1)
        viewer.grid_rowconfigure(1, weight=1)

        title_row = tk.Frame(viewer, bg=PANEL)
        title_row.grid(row=0, column=0, sticky="ew")
        tk.Label(title_row, text="Live canvas", bg=PANEL, fg=INK,
                 font=("TkDefaultFont", 15, "bold")).pack(side="left")
        self.status_label = tk.Label(title_row, textvariable=self.status_var, bg=PANEL,
                                     fg=MUTED, font=("TkDefaultFont", 10))
        self.status_label.pack(side="right")

        canvas_frame = tk.Frame(viewer, bg="#080a0e", padx=14, pady=14)
        canvas_frame.grid(row=1, column=0, sticky="nsew", pady=16)
        self.preview = tk.Label(canvas_frame, bg="#080a0e", bd=0)
        self.preview.place(relx=.5, rely=.5, anchor="center")

        footer = tk.Frame(viewer, bg=PANEL)
        footer.grid(row=2, column=0, sticky="ew")
        ttk.Progressbar(footer, variable=self.progress_var, maximum=100,
                        style="Air.Horizontal.TProgressbar").pack(fill="x")
        tk.Label(footer, textvariable=self.coverage_var, bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 9)).pack(anchor="e", pady=(6, 0))

    @staticmethod
    def _section_label(parent: tk.Widget, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=PANEL, fg=MUTED,
                        font=("TkDefaultFont", 9, "bold"))

    @staticmethod
    def _button(parent: tk.Widget, text: str, command: object,
                background: str, foreground: str) -> FlatButton:
        return FlatButton(parent, text, command, background, foreground)

    @staticmethod
    def _stat_card(parent: tk.Widget, title: str, variable: tk.StringVar) -> tk.Frame:
        card = tk.Frame(parent, bg=PANEL, padx=15, pady=12)
        tk.Label(card, text=title, bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 8, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=variable, bg=PANEL, fg=INK,
                 font=("TkDefaultFont", 18, "bold")).pack(anchor="w", pady=(3, 0))
        return card

    def _show_empty_preview(self) -> None:
        image = Image.new("RGB", (CANVAS_W * PREVIEW_SCALE, CANVAS_H * PREVIEW_SCALE), "#f5f3ed")
        draw = ImageDraw.Draw(image)
        step = 8 * PREVIEW_SCALE
        for x in range(0, image.width, step):
            draw.line((x, 0, x, image.height), fill="#e8e5dd")
        for y in range(0, image.height, step):
            draw.line((0, y, image.width, y), fill="#e8e5dd")
        draw.text((image.width // 2, image.height // 2), "waiting for a drawing…",
                  fill="#8e918f", anchor="mm")
        self.preview_photo = ImageTk.PhotoImage(image)
        self.preview.configure(image=self.preview_photo)

    def start_capture(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if not self.interface_var.get():
            messagebox.showwarning("Choose an interface", "Select a Wi-Fi capture interface first.")
            return
        if sys.platform == "darwin":
            confirmed = messagebox.askokcancel(
                "Wi-Fi will be temporarily unavailable",
                "PictoChat capture must disconnect this Mac from its Wi-Fi network "
                "and lock the wireless radio to the selected channel.\n\n"
                "Wi-Fi should reconnect automatically after you press Stop or close "
                "the application. Continue?",
                icon="warning",
            )
            if not confirmed:
                return
        self.capture_had_error = False
        if sys.platform == "darwin" and self.channel_var.get() != "Current":
            self.worker = MacOSChannelCaptureWorker(
                self.events,
                self.interface_var.get(),
                self.filter_var.get(),
                int(self.channel_var.get()),
            )
        elif sys.platform == "darwin":
            self.worker = MacOSCaptureWorker(
                self.events, self.interface_var.get(), self.filter_var.get()
            )
        else:
            self.worker = CaptureWorker(
                self.events, self.interface_var.get(), self.filter_var.get()
            )
        self.worker.start()
        if sys.platform == "darwin":
            if self.channel_var.get() == "Current":
                self.status_var.set("Listening on the current Wi-Fi channel…")
            else:
                self.status_var.set(f"Retuning Wi-Fi to channel {self.channel_var.get()}…")
        else:
            self.status_var.set("Listening…")
        self.status_label.configure(fg=ACCENT)
        self.start_button.set_enabled(False)
        self.stop_button.set_enabled(True)

    def stop_capture(self) -> None:
        if self.worker:
            self.worker.stop()
        self.status_var.set("Stopping…")

    def _drain_events(self) -> None:
        processed = 0
        while processed < 1000:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if kind == "packet":
                self._ingest_packet(payload)  # type: ignore[arg-type]
            elif kind == "error":
                self.capture_had_error = True
                error_message = str(payload)
                self.status_var.set(error_message)
                self.status_label.configure(fg=ERROR)
                messagebox.showerror("Capture stopped", error_message)
            elif kind == "warning":
                self.status_var.set(str(payload))
                self.status_label.configure(fg=WARNING)
            elif kind == "stopped":
                self.start_button.set_enabled(True)
                self.stop_button.set_enabled(False)
                if not self.capture_had_error:
                    self.status_var.set("Stopped")
                    self.status_label.configure(fg=MUTED)

        if self.dirty:
            self._refresh_streams()
            self.dirty = False
        self.root.after(80, self._drain_events)

    def _ingest_packet(self, packet: list[int]) -> None:
        packet_index = self.packet_count
        self.packet_count += 1
        # Keep damaged-FCS copies as provisional recovery material. Verified
        # retransmissions replace them automatically in build_chunk_streams().
        found = extract_chunk_candidates_from_packet(
            packet, packet_index, accept_bad_fcs=True
        )
        for candidate in found:
            if self._detect_new_drawing(candidate):
                self._adopt_pending_drawing()
            else:
                self.candidates.append(candidate)
        self.candidate_var.set(f"{len(self.candidates):,}")
        self.dirty = self.dirty or bool(found)

    def _detect_new_drawing(self, candidate: ChunkCandidate) -> bool:
        """Track transmission cycles and identify a genuinely changed canvas."""
        now = time.monotonic()
        previous_time = self.last_candidate_time
        starts_cycle = (
            self.last_candidate_offset is not None
            and candidate.chunk_offset < self.last_candidate_offset
            and candidate.chunk_offset <= BASE_OFFSET + 3 * CHUNK_PAYLOAD_LEN
        )

        if starts_cycle:
            active = self._selected_stream()
            self.pending_cycle = [candidate]
            self.pending_changed_offsets.clear()
            self.pending_started_after_pause = (
                previous_time is not None and now - previous_time >= 1.5
            )
            self.pending_baseline = dict(active.chunks) if active is not None else None
        elif self.pending_baseline is not None:
            self.pending_cycle.append(candidate)

        if self.pending_baseline is not None and candidate.fcs_valid:
            old_payload = self.pending_baseline.get(candidate.chunk_offset)
            if old_payload is not None and old_payload != candidate.payload:
                self.pending_changed_offsets.add(candidate.chunk_offset)

        self.last_candidate_offset = candidate.chunk_offset
        self.last_candidate_time = now

        if len(self.pending_changed_offsets) >= 2:
            return True
        if (
            self.pending_started_after_pause
            and self.pending_changed_offsets
            and self.pending_changed_offsets != {LAST_CHUNK_OFFSET}
        ):
            return True
        return False

    def _adopt_pending_drawing(self) -> None:
        """Replace the displayed session while leaving packet capture running."""
        self.candidates = list(self.pending_cycle)
        self.streams.clear()
        self.current_image = None
        self.stream_var.set("Auto")
        self.stream_box.configure(values=["Auto"])
        self.progress_var.set(0)
        self.coverage_var.set(f"0 / {EXPECTED_CHUNKS} chunks")
        self.status_var.set("New drawing detected — clearing previous canvas")
        self.status_label.configure(fg=ACCENT)
        self.pending_cycle.clear()
        self.pending_baseline = None
        self.pending_changed_offsets.clear()
        self.pending_started_after_pause = False

    def _refresh_streams(self) -> None:
        old_values = tuple(self.stream_box["values"])
        self.streams = build_chunk_streams(self.candidates)
        values = ["Auto"] + [f"Stream {i + 1}" for i in range(len(self.streams))]
        self.stream_box.configure(values=values)
        if self.stream_var.get() not in values:
            self.stream_var.set("Auto")
        self.stream_count_var.set(str(len(self.streams)))
        if tuple(values) != old_values and self.stream_var.get() == "Auto":
            self.status_var.set("Drawing detected")
            self.status_label.configure(fg=ACCENT)
        self._render_selected()

    def _selected_stream(self) -> ChunkStream | None:
        if not self.streams:
            return None
        if self.stream_var.get() == "Auto":
            return max(self.streams, key=lambda stream: (len(stream.chunks), stream.packet_hits))
        try:
            index = int(self.stream_var.get().split()[-1]) - 1
            return self.streams[index]
        except (ValueError, IndexError):
            return None

    def _render_selected(self) -> None:
        stream = self._selected_stream()
        if stream is None:
            self.progress_var.set(0)
            self.coverage_var.set(f"0 / {EXPECTED_CHUNKS} chunks")
            return
        buffer = bytearray(IMAGE_BUFFER_SIZE)
        for offset, payload in stream.chunks.items():
            write_chunk_to_image_buffer(buffer, offset, payload)
        indices = compose_canvas_row_major(decode_4bpp_tiles(buffer))
        self.current_image = canvas_to_image(indices)
        display = self.current_image.resize(
            (CANVAS_W * PREVIEW_SCALE, CANVAS_H * PREVIEW_SCALE), Image.Resampling.NEAREST
        ).convert("RGB")
        self.preview_photo = ImageTk.PhotoImage(display)
        self.preview.configure(image=self.preview_photo)
        chunks = len(stream.chunks)
        recovered = chunks - len(stream.valid_offsets)
        self.progress_var.set(min(chunks / EXPECTED_CHUNKS * 100, 100))
        recovery_note = f" · {recovered} recovered" if recovered else ""
        self.coverage_var.set(
            f"{chunks} / {EXPECTED_CHUNKS} chunks{recovery_note}"
        )
        if chunks >= EXPECTED_CHUNKS:
            if recovered:
                self.status_var.set(
                    f"Drawing complete ({recovered} provisional chunk"
                    f"{'s' if recovered != 1 else ''})"
                )
                self.status_label.configure(fg=WARNING)
            else:
                self.status_var.set("Drawing complete")
                self.status_label.configure(fg=ACCENT)

    def open_dump(self) -> None:
        filename = filedialog.askopenfilename(
            title="Open Wi-Fi hex dump",
            filetypes=[("Text hex dumps", "*.txt"), ("All files", "*")],
        )
        if not filename:
            return
        try:
            packets = parse_hexdump_packets(Path(filename).read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            messagebox.showerror("Could not open dump", str(exc))
            return
        for packet in packets:
            self._ingest_packet(packet)
        self._refresh_streams()
        self.dirty = False
        self.status_var.set(f"Loaded {len(packets):,} saved frames")
        self.status_label.configure(fg=ACCENT if self.candidates else WARNING)

    def save_image(self) -> None:
        if self.current_image is None:
            messagebox.showinfo("Nothing to save", "No PictoChat drawing has been detected yet.")
            return
        filename = filedialog.asksaveasfilename(
            title="Save drawing",
            defaultextension=".png",
            initialfile="pictochat_drawing.png",
            filetypes=[("PNG image", "*.png")],
        )
        if filename:
            try:
                self.current_image.save(filename)
                self.status_var.set(f"Saved {Path(filename).name}")
                self.status_label.configure(fg=ACCENT)
            except OSError as exc:
                messagebox.showerror("Could not save image", str(exc))

    def reset_session(self) -> None:
        self.packet_count = 0
        self.candidates.clear()
        self.streams.clear()
        self.current_image = None
        self.candidate_var.set("0")
        self.stream_count_var.set("0")
        self.stream_var.set("Auto")
        self.stream_box.configure(values=["Auto"])
        self.progress_var.set(0)
        self.coverage_var.set(f"0 / {EXPECTED_CHUNKS} chunks")
        self.status_var.set("Session cleared")
        self.status_label.configure(fg=MUTED)
        self.last_candidate_offset = None
        self.last_candidate_time = None
        self.pending_cycle.clear()
        self.pending_baseline = None
        self.pending_changed_offsets.clear()
        self.pending_started_after_pause = False
        self._show_empty_preview()

    def close(self) -> None:
        if self.worker:
            self.worker.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    PictoChatLiveApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
