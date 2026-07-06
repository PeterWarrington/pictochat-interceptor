#!/usr/bin/env python3
"""Encode images and construct experimental PictoChat 802.11 frames."""

from __future__ import annotations

import struct
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from PIL import Image

from pictochat_decode import (
    BASE_OFFSET,
    CANVAS_H,
    CANVAS_W,
    CHUNK_PAYLOAD_LEN,
    IMAGE_BUFFER_SIZE,
    PICTOCHAT_PALETTE,
    TILE_H,
    TILES_X,
    TILE_W,
)


MESSAGE_PREFIX = b"\x00\x00\x00\x00"
PICTOCHAT_GROUP = bytes.fromhex("03 09 bf 00 00 00")
PROTOCOL_PREFIX = bytes.fromhex("e6 03 02 00 56 1e 02 00 ac 00 01 04 a0 00")
RADIOTAP_F_FCS = 0x10


def parse_mac(value: str) -> bytes:
    """Convert a conventional MAC address to six bytes."""
    parts = value.strip().replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("MAC address must contain six hexadecimal bytes")
    try:
        result = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise ValueError("MAC address contains a non-hexadecimal byte") from exc
    if any(len(part) != 2 for part in parts):
        raise ValueError("Each MAC-address byte must use two hex digits")
    return result


def image_to_indices(image: Image.Image, threshold: int = 180) -> list[list[int]]:
    """Fit an image to the canvas and reduce it to PictoChat paper/black ink."""
    source = image.convert("RGBA")
    source.thumbnail((CANVAS_W, CANVAS_H), Image.Resampling.LANCZOS)
    fitted = Image.new("RGBA", (CANVAS_W, CANVAS_H), (255, 255, 255, 255))
    fitted.alpha_composite(
        source,
        ((CANVAS_W - source.width) // 2, (CANVAS_H - source.height) // 2),
    )
    rgb = fitted.convert("RGB")
    raw_pixels = rgb.tobytes()
    return [
        [
            1
            if sum(raw_pixels[(y * CANVAS_W + x) * 3 : (y * CANVAS_W + x + 1) * 3]) // 3
            < threshold
            else 0
            for x in range(CANVAS_W)
        ]
        for y in range(CANVAS_H)
    ]


def indices_to_image(indices: Sequence[Sequence[int]], scale: int = 1) -> Image.Image:
    image = Image.new("RGB", (CANVAS_W, CANVAS_H))
    image.putdata(
        [PICTOCHAT_PALETTE[indices[y][x] & 0x0F] for y in range(CANVAS_H) for x in range(CANVAS_W)]
    )
    if scale > 1:
        image = image.resize((CANVAS_W * scale, CANVAS_H * scale), Image.Resampling.NEAREST)
    return image


def encode_4bpp_tiles(indices: Sequence[Sequence[int]]) -> bytes:
    """Inverse of the decoder: row-major 8x8 tiles, low nibble first."""
    if len(indices) != CANVAS_H or any(len(row) != CANVAS_W for row in indices):
        raise ValueError(f"Canvas must be exactly {CANVAS_W}x{CANVAS_H}")
    output = bytearray()
    tile_rows = CANVAS_H // TILE_H
    for tile_y in range(tile_rows):
        for tile_x in range(TILES_X):
            values: list[int] = []
            for y in range(TILE_H):
                values.extend(
                    indices[tile_y * TILE_W + y][tile_x * TILE_W : (tile_x + 1) * TILE_W]
                )
            for position in range(0, TILE_W * TILE_W, 2):
                output.append((values[position] & 0x0F) | ((values[position + 1] & 0x0F) << 4))
    if len(output) != IMAGE_BUFFER_SIZE:
        raise AssertionError(f"Encoded {len(output)} bytes, expected {IMAGE_BUFFER_SIZE}")
    return bytes(output)


@dataclass(frozen=True)
class MessageChunk:
    index: int
    offset: int
    payload: bytes


def build_message_chunks(tile_data: bytes) -> list[MessageChunk]:
    """Split the four-byte envelope plus tile data into padded radio chunks."""
    if len(tile_data) != IMAGE_BUFFER_SIZE:
        raise ValueError(f"Tile data must contain {IMAGE_BUFFER_SIZE} bytes")
    message = MESSAGE_PREFIX + tile_data
    chunks: list[MessageChunk] = []
    for index, start in enumerate(range(0, len(message), CHUNK_PAYLOAD_LEN)):
        payload = message[start : start + CHUNK_PAYLOAD_LEN]
        payload += bytes(CHUNK_PAYLOAD_LEN - len(payload))
        chunks.append(MessageChunk(index, BASE_OFFSET + start, payload))
    return chunks


def build_dot11_frame(
    chunk: MessageChunk,
    source_mac: bytes,
    sequence: int,
    message_id: int,
    retry_phase: bool = False,
) -> bytes:
    """Build the 206-byte pre-FCS frame observed in the supplied capture."""
    if len(source_mac) != 6:
        raise ValueError("source_mac must contain six bytes")
    frame_control = 0x0228
    duration = 0x04E0
    sequence_control = (sequence & 0x0FFF) << 4
    header = struct.pack("<HH", frame_control, duration)
    header += PICTOCHAT_GROUP + source_mac + source_mac
    header += struct.pack("<H", sequence_control)
    protocol = bytearray(PROTOCOL_PREFIX)
    if retry_phase:
        protocol[5] |= 0x80
    protocol += struct.pack("<HH", chunk.offset, 0)
    footer = struct.pack("<HH", (message_id + chunk.index) & 0xFFFF, 2)
    return header + bytes(protocol) + chunk.payload + footer


def add_radiotap_and_fcs(dot11_frame: bytes) -> bytes:
    """Wrap a frame for a PCAP. Injection normally lets the adapter add FCS."""
    # version, pad, length, present bitmap (Flags), Flags(FCS present), padding
    radiotap = struct.pack("<BBHI", 0, 0, 10, 1 << 1) + bytes((RADIOTAP_F_FCS, 0))
    fcs = struct.pack("<I", zlib.crc32(dot11_frame) & 0xFFFFFFFF)
    return radiotap + dot11_frame + fcs


def build_transmission(
    indices: Sequence[Sequence[int]],
    source_mac: bytes,
    message_id: int | None = None,
    sequence_start: int = 0,
) -> list[bytes]:
    if message_id is None:
        message_id = int(time.time() * 1000) & 0xFFFF
    chunks = build_message_chunks(encode_4bpp_tiles(indices))
    return [
        build_dot11_frame(chunk, source_mac, sequence_start + index, message_id)
        for index, chunk in enumerate(chunks)
    ]


def write_pcap(path: Path, frames: Iterable[bytes], interval: float = 0.003) -> None:
    """Write radiotap packets using only the standard library."""
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        now = time.time()
        for index, dot11_frame in enumerate(frames):
            packet = add_radiotap_and_fcs(dot11_frame)
            timestamp = now + index * interval
            seconds = int(timestamp)
            micros = int((timestamp - seconds) * 1_000_000)
            output.write(struct.pack("<IIII", seconds, micros, len(packet), len(packet)))
            output.write(packet)
