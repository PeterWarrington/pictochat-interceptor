#!/usr/bin/env python3
"""Cross-platform GUI for drawing, importing and experimentally sending images."""

from __future__ import annotations

import queue
import random
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from pictochat_decode import CANVAS_H, CANVAS_W
from pictochat_encode import (
    build_transmission,
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


PREVIEW_SCALE = 3
DEFAULT_MAC = "02:00:00:00:00:01"


class InjectionWorker(threading.Thread):
    def __init__(self, events: queue.Queue[tuple[str, str]], interface: str,
                 frames: list[bytes], repetitions: int, interval: float) -> None:
        super().__init__(daemon=True)
        self.events = events
        self.interface = interface
        self.frames = frames
        self.repetitions = repetitions
        self.interval = interval

    def run(self) -> None:
        try:
            from scapy.all import RadioTap, Raw, sendp
            packets = [RadioTap() / Raw(frame) for frame in self.frames]
            for repetition in range(self.repetitions):
                sendp(packets, iface=self.interface, inter=self.interval, verbose=False)
                self.events.put(("progress", f"Pass {repetition + 1}/{self.repetitions} sent"))
            self.events.put(("done", f"Sent {len(self.frames) * self.repetitions} raw frames"))
        except PermissionError:
            self.events.put(("error", "Injection was denied; grant packet privileges to Python."))
        except Exception as exc:
            self.events.put(("error", f"Injection failed: {exc}"))

def resource_path(filename: str) -> Path:
    """Return a project resource path in source and PyInstaller builds."""
    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return bundle_dir / filename

class PictoChatSendApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PictoChat Airwriter")
        self.app_icon = tk.PhotoImage(file=resource_path("icon.png"))
        self.root.iconphoto(True, self.app_icon)
        self.root.geometry("1100x780")
        self.root.minsize(940, 680)
        self.root.configure(bg=BG)
        self.indices = [[0 for _ in range(CANVAS_W)] for _ in range(CANVAS_H)]
        self.preview_photo: ImageTk.PhotoImage | None = None
        self.last_point: tuple[int, int] | None = None
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()

        self.interface_var = tk.StringVar()
        self.mac_var = tk.StringVar(value=DEFAULT_MAC)
        self.tool_var = tk.StringVar(value="Pen")
        self.brush_var = tk.IntVar(value=2)
        self.repetitions_var = tk.IntVar(value=3)
        self.interval_var = tk.StringVar(value="0.003")
        self.status_var = tk.StringVar(value="Ready — draw something or import an image")
        self._configure_styles()
        self._build_ui()
        self._render()
        self.root.after(80, self._drain_events)

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground=PANEL_2, background=PANEL_2,
                        foreground=INK, arrowcolor=INK, bordercolor="#343d4d", padding=7)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL_2)],
                  foreground=[("readonly", INK)])

    def _build_ui(self) -> None:
        shell = tk.Frame(self.root, bg=BG, padx=28, pady=24)
        shell.pack(fill="both", expand=True)
        tk.Label(shell, text="PICTOCHAT", bg=BG, fg=ACCENT,
                 font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        tk.Label(shell, text="Airwriter", bg=BG, fg=INK,
                 font=("TkDefaultFont", 28, "bold")).pack(anchor="w")
        tk.Label(shell, text="Compose a DS-sized drawing and prepare it for the air.",
                 bg=BG, fg=MUTED, font=("TkDefaultFont", 11)).pack(anchor="w", pady=(3, 20))

        body = tk.Frame(shell, bg=BG)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        controls = tk.Frame(body, bg=PANEL, padx=18, pady=18, width=285)
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        controls.grid_propagate(False)

        self._label(controls, "DRAWING").pack(anchor="w")
        row = tk.Frame(controls, bg=PANEL)
        row.pack(fill="x", pady=(8, 8))
        ttk.Combobox(row, textvariable=self.tool_var, values=("Pen", "Eraser"),
                     state="readonly", width=12).pack(side="left", fill="x", expand=True)
        ttk.Combobox(row, textvariable=self.brush_var, values=(1, 2, 3, 4, 6),
                     state="readonly", width=5).pack(side="left", padx=(8, 0))
        self._button(controls, "Import image…", self.import_image, PANEL_2, INK).pack(fill="x", pady=(0, 8))
        self._button(controls, "Clear canvas", self.clear, PANEL_2, WARNING).pack(fill="x")

        tk.Frame(controls, bg="#303746", height=1).pack(fill="x", pady=18)
        self._label(controls, "RAW RADIO").pack(anchor="w")
        interfaces = available_interfaces()
        tk.Label(controls, text="Injection interface", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 9)).pack(anchor="w", pady=(8, 0))
        box = ttk.Combobox(controls, textvariable=self.interface_var,
                           values=interfaces, state="readonly")
        box.pack(fill="x", pady=(5, 8))
        if interfaces:
            preferred = next((x for x in ("wlan1mon", "wlan0mon", "en0") if x in interfaces), interfaces[0])
            self.interface_var.set(preferred)
        tk.Label(controls, text="Source MAC / room identity", bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 9)).pack(anchor="w")
        self._entry(controls, self.mac_var).pack(fill="x", ipady=7, pady=(5, 8))
        spinrow = tk.Frame(controls, bg=PANEL)
        spinrow.pack(fill="x", pady=(0, 10))
        tk.Label(spinrow, text="Passes", bg=PANEL, fg=MUTED).pack(side="left")
        tk.Spinbox(spinrow, from_=1, to=20, textvariable=self.repetitions_var, width=4,
                   bg=PANEL_2, fg=INK, buttonbackground=PANEL_2, relief="flat").pack(side="left", padx=(6, 14))
        tk.Label(spinrow, text="Gap (s)", bg=PANEL, fg=MUTED).pack(side="left")
        self._entry(spinrow, self.interval_var, width=7).pack(side="left", padx=(6, 0), ipady=4)
        self.send_button = self._button(controls, "Send experimentally", self.send, ACCENT, "#071b17")
        self.send_button.pack(fill="x", pady=(0, 8))
        self._button(controls, "Export packets as PCAP…", self.export_pcap, PANEL_2, INK).pack(fill="x", pady=(0, 8))
        self._button(controls, "Save drawing as PNG…", self.save_png, PANEL_2, INK).pack(fill="x")

        note = ("Requires an injection-capable adapter in monitor mode. The built-in macOS "
                "Wi-Fi driver normally cannot inject. PictoChat session participation remains experimental.")
        tk.Label(controls, text=note, wraplength=245, justify="left", bg=PANEL,
                 fg=MUTED, font=("TkDefaultFont", 9)).pack(side="bottom", anchor="w")

        workspace = tk.Frame(body, bg=PANEL, padx=22, pady=20)
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_columnconfigure(0, weight=1)
        workspace.grid_rowconfigure(1, weight=1)
        title = tk.Frame(workspace, bg=PANEL)
        title.grid(row=0, column=0, sticky="ew")
        tk.Label(title, text="Drawing canvas", bg=PANEL, fg=INK,
                 font=("TkDefaultFont", 15, "bold")).pack(side="left")
        tk.Label(title, text="256 × 80 · 4bpp tiles", bg=PANEL, fg=MUTED).pack(side="right")
        canvas_shell = tk.Frame(workspace, bg="#080a0e", padx=14, pady=14)
        canvas_shell.grid(row=1, column=0, sticky="nsew", pady=16)
        self.canvas = tk.Canvas(canvas_shell, width=CANVAS_W * PREVIEW_SCALE,
                                height=CANVAS_H * PREVIEW_SCALE, bg="white",
                                highlightthickness=0, cursor="crosshair")
        self.canvas.place(relx=.5, rely=.5, anchor="center")
        self.canvas.bind("<Button-1>", self._draw_event)
        self.canvas.bind("<B1-Motion>", self._draw_event)
        self.canvas.bind("<ButtonRelease-1>", lambda _event: setattr(self, "last_point", None))
        tk.Label(workspace, textvariable=self.status_var, bg=PANEL, fg=MUTED,
                 font=("TkDefaultFont", 10)).grid(row=2, column=0, sticky="w")

    @staticmethod
    def _label(parent: tk.Widget, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=PANEL, fg=MUTED, font=("TkDefaultFont", 9, "bold"))

    @staticmethod
    def _button(parent: tk.Widget, text: str, command: object,
                background: str, foreground: str) -> FlatButton:
        return FlatButton(parent, text, command, background, foreground)

    @staticmethod
    def _entry(parent: tk.Widget, variable: tk.Variable, width: int | None = None) -> tk.Entry:
        return tk.Entry(parent, textvariable=variable, width=width, bg=PANEL_2, fg=INK,
                        insertbackground=INK, relief="flat", highlightthickness=1,
                        highlightbackground="#343d4d", highlightcolor=ACCENT,
                        font=("TkFixedFont", 10))

    def _draw_event(self, event: tk.Event) -> None:
        point = (max(0, min(CANVAS_W - 1, event.x // PREVIEW_SCALE)),
                 max(0, min(CANVAS_H - 1, event.y // PREVIEW_SCALE)))
        value = 0 if self.tool_var.get() == "Eraser" else 1
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

    def _render(self) -> None:
        display = indices_to_image(self.indices, PREVIEW_SCALE)
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

    def _frames(self) -> list[bytes]:
        return build_transmission(self.indices, parse_mac(self.mac_var.get()),
                                  message_id=random.randrange(0x10000),
                                  sequence_start=random.randrange(0x1000))

    def send(self) -> None:
        if not self.interface_var.get():
            messagebox.showwarning("Choose an interface", "Select an injection interface first.")
            return
        try:
            interval = float(self.interval_var.get())
            if not 0 <= interval <= 1:
                raise ValueError("Frame gap must be between 0 and 1 second")
            frames = self._frames()
        except ValueError as exc:
            messagebox.showerror("Invalid radio setting", str(exc))
            return
        warning = "This sends experimental raw 802.11 frames on the selected interface. Continue?"
        if sys.platform == "darwin":
            warning += "\n\nApple's built-in Wi-Fi adapter is expected to reject injection."
        if not messagebox.askokcancel("Experimental transmission", warning, icon="warning"):
            return
        self.send_button.set_enabled(False)
        self.status_var.set(f"Sending 65 chunks on {self.interface_var.get()}…")
        InjectionWorker(self.events, self.interface_var.get(), frames,
                        self.repetitions_var.get(), interval).start()

    def export_pcap(self) -> None:
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("Packet capture", "*.pcap")])
        if not filename:
            return
        try:
            write_pcap(Path(filename), self._frames(), float(self.interval_var.get()))
            self.status_var.set(f"Wrote 65 frames to {Path(filename).name}")
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
                    messagebox.showerror("Transmission stopped", text)
                    self.send_button.set_enabled(True)
                elif kind == "done":
                    self.send_button.set_enabled(True)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_events)


def main() -> None:
    root = tk.Tk()
    PictoChatSendApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
