"""Shared adaptive sizing helpers for the Tk applications."""

from __future__ import annotations

from dataclasses import dataclass
import tkinter as tk


LOW_DPI_CUTOFF = 120.0
COMPACT_SCALE = 0.8


@dataclass(frozen=True)
class UiMetrics:
    """Pixel and font sizing selected from Tk's effective display DPI."""

    dpi: float
    scale: float

    @classmethod
    def from_root(cls, root: tk.Misc) -> "UiMetrics":
        # Aqua commonly reports 72 DPI even on Retina displays. Tk already
        # accounts for macOS display scaling, so applying compact mode here
        # would shrink an otherwise correctly sized interface.
        try:
            if root.tk.call("tk", "windowingsystem") == "aqua":
                return cls.for_dpi(LOW_DPI_CUTOFF)
        except (tk.TclError, AttributeError):
            pass
        try:
            dpi = float(root.winfo_fpixels("1i"))
        except (tk.TclError, TypeError, ValueError):
            dpi = 96.0
        return cls.for_dpi(dpi)

    @classmethod
    def for_dpi(cls, dpi: float) -> "UiMetrics":
        return cls(dpi=dpi, scale=COMPACT_SCALE if dpi < LOW_DPI_CUTOFF else 1.0)

    @property
    def compact(self) -> bool:
        return self.scale < 1.0

    @property
    def preview_scale(self) -> int:
        return 2 if self.compact else 3

    def px(self, value: int) -> int:
        return max(1, round(value * self.scale))

    def font(self, value: int) -> int:
        return max(7, round(value * self.scale))

    def geometry(self, width: int, height: int) -> str:
        return f"{self.px(width)}x{self.px(height)}"
