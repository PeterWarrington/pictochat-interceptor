#!/usr/bin/env python3
"""Cross-platform GUI for drawing, importing and experimentally sending images."""

from __future__ import annotations

import queue
import random
import platform
import shutil
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from PIL import Image, ImageTk

from pictochat_decode import CANVAS_H, CANVAS_W, PICTOCHAT_PALETTE
from pictochat_encode import (
    build_transmission,
    extract_host_relay,
    find_pictochat_host,
    image_to_indices,
    indices_to_image,
    parse_mac,
    write_pcap,
)
from pictochat_live import (
    ACCENT,
    BG,
    INK,
    MUTED,
    PANEL,
    PANEL_2,
    WARNING,
    FlatButton,
    available_interfaces,
)
from pictochat_ui import UiMetrics


PREVIEW_SCALE = 3
DEFAULT_MAC = ""
PEN_COLOURS: tuple[tuple[str, int], ...] = (
    ("Black", 1),
    ("Pink", 3),
    ("Deep pink", 4),
    ("Red", 5),
    ("Red-orange", 6),
    ("Orange", 7),
    ("Amber", 8),
    ("Yellow", 9),
    ("Lime", 10),
    ("Green", 11),
    ("Teal", 12),
    ("Cyan", 13),
    ("Blue", 14),
    ("Indigo", 15),
)
PEN_INDICES = dict(PEN_COLOURS)


def linux_monitor_commands(interface: str, channel: int) -> list[list[str]]:
    """Commands required to prepare a Linux mac80211 interface for injection."""
    ip = shutil.which("ip")
    iw = shutil.which("iw")
    if not ip or not iw:
        missing = ", ".join(name for name, path in (("ip", ip), ("iw", iw)) if not path)
        raise FileNotFoundError(
            f"Linux wireless setup requires {missing}; install the iproute2 and iw packages"
        )
    return [
        [ip, "link", "set", "dev", interface, "down"],
        [iw, "dev", interface, "set", "type", "monitor"],
        [ip, "link", "set", "dev", interface, "up"],
        [iw, "dev", interface, "set", "channel", str(channel)],
    ]


class InjectionWorker(threading.Thread):
    def __init__(self, events: queue.Queue[tuple[str, str]], interface: str,
                 frame_builder: Callable[[bytes], list[bytes]], host_mac: bytes | None,
                 attempts: int, interval: float, channel: int = 1,
                 configure_linux: bool = False, discovery_timeout: float = 3.0) -> None:
        super().__init__(daemon=True)
        self.events = events
        self.interface = interface
        self.frame_builder = frame_builder
        self.host_mac = host_mac
        self.attempts = attempts
        self.interval = interval
        self.channel = channel
        self.configure_linux = configure_linux
        self.discovery_timeout = discovery_timeout

    def run(self) -> None:
        radio_socket = None
        sniffer = None
        attempt = 0
        frame_index = 0
        discovered_host = self.host_mac
        host_found = threading.Event()
        relay_seen = threading.Event()
        acknowledged: set[int] = set()
        sent_offsets: set[int] = set()
        expected_payloads: dict[int, bytes] = {}

        def observe(packet: object) -> None:
            nonlocal discovered_host
            raw = bytes(packet)
            found = find_pictochat_host(raw)
            if discovered_host is None and found is not None:
                discovered_host = found
                host_found.set()
            relay = extract_host_relay(raw, discovered_host)
            if relay is None:
                return
            offset, payload = relay
            if offset in sent_offsets and expected_payloads.get(offset) == payload:
                acknowledged.add(offset)
                relay_seen.set()

        try:
            from scapy.all import AsyncSniffer, RadioTap, Raw, conf
            if sys.platform.startswith("linux") and self.configure_linux:
                self._configure_linux_monitor()
            sniffer = AsyncSniffer(iface=self.interface, prn=observe, store=False)
            sniffer.start()
            if discovered_host is None:
                self.events.put(("progress", "Listening for a PictoChat room host…"))
                if not host_found.wait(self.discovery_timeout) or discovered_host is None:
                    raise TimeoutError(
                        "No PictoChat host was heard. Check the channel, or enter the host MAC manually."
                    )
            self.events.put(
                (
                    "progress",
                    f"Using room host {discovered_host.hex(':')} — preparing transfer header and 64 chunks…",
                )
            )
            frames = self.frame_builder(discovered_host)
            if len(frames) != 65:
                raise ValueError(
                    f"Client transmission must contain one transfer header and 64 chunks, "
                    f"got {len(frames)} frames"
                )
            transfer_header = frames[0]
            chunk_frames = frames[1:]
            expected_payloads = {
                int.from_bytes(frame[34:36], "little"): frame[38:198]
                for frame in chunk_frames
            }
            transfer_packet = RadioTap() / Raw(transfer_header)
            chunk_packets = [RadioTap() / Raw(frame) for frame in chunk_frames]
            # Opening and writing the L2 socket ourselves lets us identify the
            # exact frame whose BPF/driver write failed. sendp() otherwise
            # collapses the whole batch into one fairly opaque exception.
            # Linux's native Scapy L2Socket does not accept the ``monitor``
            # keyword (it is supported by some capture socket backends).  The
            # interface has already been put into monitor mode with iw above,
            # so passing only its name works on Linux as well as macOS/BPF.
            radio_socket = conf.L2socket(iface=self.interface)
            for attempt in range(self.attempts):
                pending = [
                    (index, packet)
                    for index, (frame, packet) in enumerate(zip(chunk_frames, chunk_packets))
                    if int.from_bytes(frame[34:36], "little") not in acknowledged
                ]
                if not pending:
                    break
                relay_seen.clear()
                # The 0x97 transfer header is not optional: the host relays it
                # before it treats subsequent 0x04 frames as drawing chunks.
                # Reannounce it on each retry, as Nintendo clients do.
                written = radio_socket.send(transfer_packet)
                if isinstance(written, int) and written <= 0:
                    raise OSError(f"driver accepted only {written} bytes for transfer header")
                time.sleep(max(0.01, self.interval * 3))
                for frame_index, packet in pending:
                    sent_offsets.add(
                        int.from_bytes(chunk_frames[frame_index][34:36], "little")
                    )
                    written = radio_socket.send(packet)
                    if isinstance(written, int) and written <= 0:
                        raise OSError(f"driver accepted only {written} bytes")
                    if self.interval:
                        time.sleep(self.interval)
                # Host relays arrive shortly after uploads.  Waiting here makes
                # subsequent attempts selective instead of repeating the whole image.
                settle_deadline = time.monotonic() + max(0.25, self.interval * 64)
                while len(acknowledged) < 64:
                    remaining = settle_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    relay_seen.wait(min(0.05, remaining))
                    relay_seen.clear()
                self.events.put(
                    (
                        "progress",
                        f"Attempt {attempt + 1}/{self.attempts}: "
                        f"{len(acknowledged)}/64 chunks relayed by host",
                    )
                )
            if len(acknowledged) == 64:
                message = "Host relayed all 64 drawing chunks"
            else:
                message = (
                    f"Host relayed {len(acknowledged)}/64 chunks after {self.attempts} attempts; "
                    "unconfirmed chunks may require another send"
                )
            print(f"[PictoChat Airwriter] {message}", flush=True)
            self.events.put(("done", message))
        except Exception as exc:
            detail = self._error_detail(exc, attempt, frame_index)
            print(detail, file=sys.stderr, flush=True)
            self.events.put(("error", detail))
        finally:
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            if radio_socket is not None:
                try:
                    radio_socket.close()
                except Exception as exc:
                    print(
                        f"[PictoChat Airwriter] Could not close injection socket: {exc!r}",
                        file=sys.stderr,
                        flush=True,
                    )

    def _configure_linux_monitor(self) -> None:
        self.events.put(
            ("progress", f"Configuring {self.interface} for monitor mode on channel {self.channel}…")
        )
        for command in linux_monitor_commands(self.interface, self.channel):
            result = subprocess.run(command, capture_output=True, text=True, timeout=8)
            if result.returncode:
                detail = (result.stderr or result.stdout).strip()
                rendered = " ".join(command)
                raise RuntimeError(
                    f"Linux monitor setup failed ({rendered}): "
                    f"{detail or f'exit status {result.returncode}'}"
                )

    def _error_detail(self, exc: Exception, attempt: int, frame_index: int) -> str:
        lines = [
            "PictoChat Airwriter — raw injection failure",
            f"Platform: {platform.platform()}",
            f"Interface: {self.interface}",
            f"Attempt/frame: {attempt + 1}/{frame_index + 1}",
            f"Exception: {type(exc).__name__}: {exc}",
        ]
        error_number = getattr(exc, "errno", None)
        if error_number is not None:
            lines.append(f"errno: {error_number}")
        lines.extend(("", "Python traceback:", traceback.format_exc().rstrip()))
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["/sbin/ifconfig", self.interface],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                interface_state = (result.stdout or result.stderr).strip()
                if interface_state:
                    lines.extend(("", "Interface state:", interface_state))
            except Exception as diagnostic_error:
                lines.extend(("", f"Could not read interface state: {diagnostic_error!r}"))
            lines.extend(
                (
                    "",
                    "Note: macOS may report no error after a successful BPF write and still "
                    "discard an unsupported raw frame inside the Wi-Fi firmware. That silent "
                    "drop cannot be detected through Scapy.",
                )
            )
        elif sys.platform.startswith("linux"):
            diagnostics = (
                (
                    "Linux link state",
                    [shutil.which("ip") or "ip", "-details", "link", "show", "dev", self.interface],
                ),
                (
                    "Linux wireless state",
                    [shutil.which("iw") or "iw", "dev", self.interface, "info"],
                ),
            )
            for heading, command in diagnostics:
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=3)
                    state = (result.stdout or result.stderr).strip()
                    if state:
                        lines.extend(("", f"{heading}:", state))
                except Exception as diagnostic_error:
                    lines.extend(("", f"Could not read {heading.lower()}: {diagnostic_error!r}"))
            lines.extend(
                (
                    "",
                    "Linux setup needs CAP_NET_ADMIN to change monitor mode/channel and "
                    "CAP_NET_RAW to open the injection socket. Running as root supplies both.",
                )
            )
        return "\n".join(lines)

def resource_path(filename: str) -> Path:
    """Return a project resource path in source and PyInstaller builds."""
    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return bundle_dir / filename

class PictoChatSendApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.ui = UiMetrics.from_root(root)
        self.preview_scale = self.ui.preview_scale
        self.root.title("PictoChat Airwriter")
        self.app_icon = tk.PhotoImage(file=resource_path("icon.png"))
        self.root.iconphoto(True, self.app_icon)
        self.root.geometry(self.ui.geometry(1100, 780))
        self.root.minsize(self.ui.px(940), self.ui.px(680))
        self.root.configure(bg=BG)
        self.indices = [[0 for _ in range(CANVAS_W)] for _ in range(CANVAS_H)]
        self.preview_photo: ImageTk.PhotoImage | None = None
        self.last_point: tuple[int, int] | None = None
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()

        self.interface_var = tk.StringVar()
        self.mac_var = tk.StringVar(value=DEFAULT_MAC)
        self.host_mac_var = tk.StringVar()
        self.tool_var = tk.StringVar(value="Pen")
        self.pen_colour_var = tk.StringVar(value="Black")
        self.brush_var = tk.IntVar(value=2)
        self.repetitions_var = tk.IntVar(value=3)
        self.interval_var = tk.StringVar(value="0.003")
        self.channel_var = tk.IntVar(value=1)
        self.configure_linux_var = tk.BooleanVar(value=sys.platform.startswith("linux"))
        self.status_var = tk.StringVar(value="Ready — draw something or import an image")
        self._configure_styles()
        self._build_ui()
        self._render()
        self.root.after(80, self._drain_events)

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground=PANEL_2, background=PANEL_2,
                        foreground=INK, arrowcolor=INK, bordercolor="#343d4d", padding=self.ui.px(7))
        style.map("TCombobox", fieldbackground=[("readonly", PANEL_2)],
                  foreground=[("readonly", INK)])

    def _build_ui(self) -> None:
        u = self.ui
        shell = tk.Frame(self.root, bg=BG, padx=u.px(28), pady=u.px(24))
        shell.pack(fill="both", expand=True)
        tk.Label(shell, text="PICTOCHAT", bg=BG, fg=ACCENT,
                 font=("TkDefaultFont", u.font(10), "bold")).pack(anchor="w")
        tk.Label(shell, text="Airwriter", bg=BG, fg=INK,
                 font=("TkDefaultFont", u.font(12), "bold")).pack(anchor="w")
        tk.Label(shell, text="Compose a DS-sized drawing and prepare it for the air.",
                 bg=BG, fg=MUTED, font=("TkDefaultFont", u.font(9))).pack(anchor="w", pady=(u.px(3), u.px(20)))

        body = tk.Frame(shell, bg=BG)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        controls = tk.Frame(body, bg=PANEL, padx=u.px(18), pady=u.px(18), width=u.px(285))
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, u.px(18)))
        controls.grid_propagate(False)

        self._label(controls, "DRAWING").pack(anchor="w")
        row = tk.Frame(controls, bg=PANEL)
        row.pack(fill="x", pady=(u.px(8), u.px(8)))
        ttk.Combobox(row, textvariable=self.tool_var, values=("Pen", "Eraser"),
                     state="readonly", width=12).pack(side="left", fill="x", expand=True)
        ttk.Combobox(row, textvariable=self.brush_var, values=(1, 2, 3, 4, 6),
                     state="readonly", width=5).pack(side="left", padx=(u.px(8), 0))
        colour_row = tk.Frame(controls, bg=PANEL)
        colour_row.pack(fill="x", pady=(0, u.px(8)))
        tk.Label(colour_row, text="Pen colour", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", u.font(9))).pack(side="left")
        self.colour_swatch = tk.Label(colour_row, width=2, relief="flat")
        self.colour_swatch.pack(side="right", padx=(u.px(8), 0), ipady=u.px(5))
        colour_box = ttk.Combobox(
            colour_row,
            textvariable=self.pen_colour_var,
            values=tuple(name for name, _index in PEN_COLOURS),
            state="readonly",
            width=13,
        )
        colour_box.pack(side="right", fill="x", expand=True, padx=(u.px(8), 0))
        colour_box.bind("<<ComboboxSelected>>", self._select_pen_colour)
        self._update_colour_swatch()
        self._button(controls, "Import image…", self.import_image, PANEL_2, INK).pack(fill="x", pady=(0, u.px(8)))
        self._button(controls, "Clear canvas", self.clear, PANEL_2, WARNING).pack(fill="x")

        tk.Frame(controls, bg="#303746", height=1).pack(fill="x", pady=u.px(18))
        self._label(controls, "RAW RADIO").pack(anchor="w")
        interfaces = available_interfaces()
        tk.Label(controls, text="Injection interface", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", u.font(9))).pack(anchor="w", pady=(u.px(8), 0))
        box = ttk.Combobox(controls, textvariable=self.interface_var,
                           values=interfaces, state="readonly")
        box.pack(fill="x", pady=(u.px(5), u.px(8)))
        if interfaces:
            preferred = next(
                (x for x in ("wlan1mon", "wlan0mon", "wlan1", "wlan0", "en0") if x in interfaces),
                next((x for x in interfaces if x.startswith("wl")), interfaces[0]),
            )
            self.interface_var.set(preferred)
        radio_row = tk.Frame(controls, bg=PANEL)
        radio_row.pack(fill="x", pady=(0, u.px(8)))
        tk.Label(radio_row, text="2.4 GHz channel", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", u.font(9))).pack(side="left")
        ttk.Combobox(
            radio_row,
            textvariable=self.channel_var,
            values=tuple(range(1, 14)),
            state="readonly",
            width=4,
        ).pack(side="right")
        if sys.platform.startswith("linux"):
            tk.Checkbutton(
                controls,
                text="Configure monitor mode automatically",
                variable=self.configure_linux_var,
                bg=PANEL,
                fg=INK,
                activebackground=PANEL,
                activeforeground=INK,
                selectcolor=PANEL_2,
                highlightthickness=0,
            ).pack(anchor="w", pady=(0, u.px(8)))
        tk.Label(controls, text="Joined client MAC", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", u.font(9))).pack(anchor="w")
        self._entry(controls, self.mac_var).pack(fill="x", ipady=u.px(7), pady=(u.px(5), u.px(8)))
        tk.Label(controls, text="Host MAC (blank = discover)", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", u.font(9))).pack(anchor="w")
        self._entry(controls, self.host_mac_var).pack(fill="x", ipady=u.px(7), pady=(u.px(5), u.px(8)))
        spinrow = tk.Frame(controls, bg=PANEL)
        spinrow.pack(fill="x", pady=(0, u.px(10)))
        tk.Label(spinrow, text="Attempts", bg=PANEL, fg=MUTED).pack(side="left")
        tk.Spinbox(spinrow, from_=1, to=20, textvariable=self.repetitions_var, width=4,
                   bg=PANEL_2, fg=INK, buttonbackground=PANEL_2, relief="flat").pack(side="left", padx=(u.px(6), u.px(14)))
        tk.Label(spinrow, text="Gap (s)", bg=PANEL, fg=MUTED).pack(side="left")
        self._entry(spinrow, self.interval_var, width=7).pack(side="left", padx=(u.px(6), 0), ipady=u.px(4))
        self.send_button = self._button(controls, "Send experimentally", self.send, ACCENT, "#071b17")
        self.send_button.pack(fill="x", pady=(0, u.px(8)))
        self._button(controls, "Export packets as PCAP…", self.export_pcap, PANEL_2, INK).pack(fill="x", pady=(0, u.px(8)))
        self._button(controls, "Save drawing as PNG…", self.save_png, PANEL_2, INK).pack(fill="x")

        if sys.platform.startswith("linux"):
            note = ("Use the MAC of a DS already joined to the room. Linux auto-setup needs "
                    "CAP_NET_ADMIN/CAP_NET_RAW and leaves the adapter in monitor mode.")
        else:
            note = ("Use the MAC of a DS already joined to the room. Requires an injection-capable "
                    "monitor adapter; built-in macOS Wi-Fi normally cannot inject.")
        tk.Label(controls, text=note, wraplength=u.px(245), justify="left", bg=PANEL,
                 fg=MUTED, font=("TkDefaultFont", u.font(9))).pack(side="bottom", anchor="w")

        workspace = tk.Frame(body, bg=PANEL, padx=u.px(22), pady=u.px(20))
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_columnconfigure(0, weight=1)
        workspace.grid_rowconfigure(1, weight=1)
        title = tk.Frame(workspace, bg=PANEL)
        title.grid(row=0, column=0, sticky="ew")
        tk.Label(title, text="Drawing canvas", bg=PANEL, fg=INK,
                 font=("TkDefaultFont", u.font(15), "bold")).pack(side="left")
        tk.Label(title, text="256 × 80 · 4bpp tiles", bg=PANEL, fg=MUTED).pack(side="right")
        canvas_shell = tk.Frame(workspace, bg="#080a0e", padx=u.px(14), pady=u.px(14))
        canvas_shell.grid(row=1, column=0, sticky="nsew", pady=u.px(16))
        self.canvas = tk.Canvas(canvas_shell, width=CANVAS_W * self.preview_scale,
                                height=CANVAS_H * self.preview_scale, bg="white",
                                highlightthickness=0, cursor="crosshair")
        self.canvas.place(relx=.5, rely=.5, anchor="center")
        self.canvas.bind("<Button-1>", self._draw_event)
        self.canvas.bind("<B1-Motion>", self._draw_event)
        self.canvas.bind("<ButtonRelease-1>", lambda _event: setattr(self, "last_point", None))
        tk.Label(workspace, textvariable=self.status_var, bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", u.font(10))).grid(row=2, column=0, sticky="w")

    def _label(self, parent: tk.Widget, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=PANEL, fg=MUTED,
                        font=("TkDefaultFont", self.ui.font(9), "bold"))

    def _button(self, parent: tk.Widget, text: str, command: object,
                background: str, foreground: str) -> FlatButton:
        return FlatButton(parent, text, command, background, foreground, self.ui)

    def _entry(self, parent: tk.Widget, variable: tk.Variable, width: int | None = None) -> tk.Entry:
        return tk.Entry(parent, textvariable=variable, width=width, bg=PANEL_2, fg=INK,
                        insertbackground=INK, relief="flat", highlightthickness=1,
                        highlightbackground="#343d4d", highlightcolor=ACCENT,
                        font=("TkFixedFont", self.ui.font(10)))

    def _draw_event(self, event: tk.Event) -> None:
        point = (max(0, min(CANVAS_W - 1, event.x // self.preview_scale)),
                 max(0, min(CANVAS_H - 1, event.y // self.preview_scale)))
        value = (
            0
            if self.tool_var.get() == "Eraser"
            else PEN_INDICES[self.pen_colour_var.get()]
        )
        radius = self.brush_var.get()
        start = self.last_point or point
        steps = max(abs(point[0] - start[0]), abs(point[1] - start[1]), 1)
        for step in range(steps + 1):
            x = round(start[0] + (point[0] - start[0]) * step / steps)
            y = round(start[1] + (point[1] - start[1]) * step / steps)
            for yy in range(max(0, y - radius + 1), min(CANVAS_H, y + radius)):
                for xx in range(max(0, x - radius + 1), min(CANVAS_W, x + radius)):
                    if (xx - x) ** 2 + (yy - y) ** 2 < radius ** 2:
                        self.indices[yy][xx] = value
        self.last_point = point
        self._render()

    def _select_pen_colour(self, _event: tk.Event | None = None) -> None:
        self.tool_var.set("Pen")
        self._update_colour_swatch()

    def _update_colour_swatch(self) -> None:
        red, green, blue = PICTOCHAT_PALETTE[PEN_INDICES[self.pen_colour_var.get()]]
        self.colour_swatch.configure(bg=f"#{red:02x}{green:02x}{blue:02x}")

    def _render(self) -> None:
        display = indices_to_image(self.indices, self.preview_scale)
        self.preview_photo = ImageTk.PhotoImage(display)
        self.canvas.delete("all")
        self.canvas.create_image(0, 0, image=self.preview_photo, anchor="nw")

    def import_image(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.tif *.tiff"), ("All files", "*")])
        if not filename:
            return
        try:
            with Image.open(filename) as image:
                self.indices = image_to_indices(image)
            self._render()
            self.status_var.set(f"Imported {Path(filename).name}")
        except Exception as exc:
            messagebox.showerror("Could not import image", str(exc))

    def clear(self) -> None:
        self.indices = [[0 for _ in range(CANVAS_W)] for _ in range(CANVAS_H)]
        self._render()
        self.status_var.set("Canvas cleared")

    def _frames(self, host_mac: bytes | None = None) -> list[bytes]:
        if host_mac is None:
            if not self.host_mac_var.get().strip():
                raise ValueError("Enter a host MAC before exporting a PCAP")
            host_mac = parse_mac(self.host_mac_var.get())
        return build_transmission(
            self.indices,
            parse_mac(self.mac_var.get()),
            host_mac,
            message_id=random.randrange(0x10000),
            sequence_start=random.randrange(0x1000),
        )

    def send(self) -> None:
        if not self.interface_var.get():
            messagebox.showwarning("Choose an interface", "Select an injection interface first.")
            return
        try:
            interval = float(self.interval_var.get())
            if not 0 <= interval <= 1:
                raise ValueError("Frame gap must be between 0 and 1 second")
            source_mac = parse_mac(self.mac_var.get())
            configured_host = (
                parse_mac(self.host_mac_var.get())
                if self.host_mac_var.get().strip()
                else None
            )
            indices = [row[:] for row in self.indices]
            message_id = random.randrange(0x10000)
            sequence_start = random.randrange(0x1000)
        except ValueError as exc:
            messagebox.showerror("Invalid radio setting", str(exc))
            return
        warning = "This sends experimental raw 802.11 frames on the selected interface. Continue?"
        if sys.platform == "darwin":
            warning += "\n\nApple's built-in Wi-Fi adapter is expected to reject injection."
        elif sys.platform.startswith("linux") and self.configure_linux_var.get():
            warning += (
                f"\n\n{self.interface_var.get()} will be taken down, changed to monitor mode, "
                f"and tuned to channel {self.channel_var.get()}."
            )
        if not messagebox.askokcancel("Experimental transmission", warning, icon="warning"):
            return
        self.send_button.set_enabled(False)
        self.status_var.set(f"Finding room and sending 64 chunks on {self.interface_var.get()}…")

        def frame_builder(host_mac: bytes) -> list[bytes]:
            return build_transmission(
                indices,
                source_mac,
                host_mac,
                message_id=message_id,
                sequence_start=sequence_start,
            )

        InjectionWorker(
            self.events,
            self.interface_var.get(),
            frame_builder,
            configured_host,
            self.repetitions_var.get(),
            interval,
            self.channel_var.get(),
            self.configure_linux_var.get(),
        ).start()

    def export_pcap(self) -> None:
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("Packet capture", "*.pcap")])
        if not filename:
            return
        try:
            write_pcap(Path(filename), self._frames(), float(self.interval_var.get()))
            self.status_var.set(
                f"Wrote transfer header and 64 client chunks to {Path(filename).name}"
            )
        except Exception as exc:
            messagebox.showerror("Could not export packets", str(exc))

    def save_png(self) -> None:
        filename = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")])
        if filename:
            indices_to_image(self.indices, PREVIEW_SCALE).save(filename)
            self.status_var.set(f"Saved {Path(filename).name}")

    def _drain_events(self) -> None:
        try:
            while True:
                kind, text = self.events.get_nowait()
                self.status_var.set(text)
                if kind == "error":
                    self._show_transmission_error(text)
                    self.send_button.set_enabled(True)
                elif kind == "done":
                    self.send_button.set_enabled(True)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_events)

    def _show_transmission_error(self, detail: str) -> None:
        self.status_var.set(detail.splitlines()[0])
        dialog = tk.Toplevel(self.root)
        dialog.title("Transmission diagnostic")
        dialog.geometry(self.ui.geometry(760, 500))
        dialog.minsize(580, 340)
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        shell = tk.Frame(dialog, bg=BG, padx=self.ui.px(18), pady=self.ui.px(18))
        shell.pack(fill="both", expand=True)
        tk.Label(
            shell,
            text="The transmission could not complete",
            bg=BG,
            fg=WARNING,
            font=("TkDefaultFont", self.ui.font(13), "bold"),
        ).pack(anchor="w", pady=(0, self.ui.px(10)))
        text = tk.Text(
            shell,
            bg=PANEL,
            fg=INK,
            insertbackground=INK,
            wrap="word",
            relief="flat",
            padx=self.ui.px(12),
            pady=self.ui.px(12),
            font=("TkFixedFont", self.ui.font(10)),
        )
        text.insert("1.0", detail)
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)

        def copy_detail() -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(detail)

        buttons = tk.Frame(shell, bg=BG)
        buttons.pack(fill="x", pady=(self.ui.px(10), 0))
        self._button(buttons, "Copy diagnostic", copy_detail, PANEL_2, INK).pack(side="left")
        self._button(buttons, "Close", dialog.destroy, PANEL_2, INK).pack(side="right")


def main() -> None:
    root = tk.Tk()
    PictoChatSendApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
