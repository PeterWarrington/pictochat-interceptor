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
PICTOCHAT_CLIENT_GROUP = bytes.fromhex("03 09 bf 00 00 10")
HOST_RELAY_PREFIX = bytes.fromhex("e6 03 02 00 56 1e 02 00 ac 00 01 04 a0 00")
CLIENT_UPLOAD_PREFIX = bytes.fromhex("56 8e 02 00 ac 00 01 04 a0 00")
CLIENT_TRANSFER_PREFIX = bytes.fromhex("56 8e 02 00 ac 00 01 97 a0 00")
RADIOTAP_F_FCS = 0x10
WIRE_CHUNK_COUNT = IMAGE_BUFFER_SIZE // CHUNK_PAYLOAD_LEN


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
    """Fit an image to the canvas and reduce it to PictoChat colour."""
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
        # match the palette index to closest colour if the pixel is dark enough, otherwise use white (index 0)
        # with alpha to white
        [
            PICTOCHAT_PALETTE.index(min(PICTOCHAT_PALETTE, key=lambda c: sum(abs(c[i] - raw_pixels[(y * CANVAS_W + x) * 3 + i]) for i in range(3))))
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
    protocol = bytearray(HOST_RELAY_PREFIX)
    if retry_phase:
        protocol[5] |= 0x80
    protocol += struct.pack("<HH", chunk.offset, 0)
    footer = struct.pack("<HH", (message_id + chunk.index) & 0xFFFF, 2)
    return header + bytes(protocol) + chunk.payload + footer


def build_client_dot11_frame(
    chunk: MessageChunk,
    source_mac: bytes,
    host_mac: bytes,
    sequence: int,
    message_id: int,
) -> bytes:
    """Build the 200-byte pre-FCS client upload frame seen on the wire.

    A participant uploads this shape to the room host.  The host subsequently
    wraps it in the longer ``e6 03`` relay envelope built by
    :func:`build_dot11_frame`; transmitting that relay shape as a client was the
    original sender's central protocol error.
    """
    if len(source_mac) != 6 or len(host_mac) != 6:
        raise ValueError("source_mac and host_mac must each contain six bytes")
    frame_control = 0x1118
    duration = 0x0146
    sequence_control = (sequence & 0x0FFF) << 4
    header = struct.pack("<HH", frame_control, duration)
    header += host_mac + source_mac + PICTOCHAT_CLIENT_GROUP
    header += struct.pack("<H", sequence_control)
    protocol = CLIENT_UPLOAD_PREFIX + struct.pack("<HH", chunk.offset, 0)
    # Client uploads carry only their two-byte message ID.  The host adds the
    # trailing 02 00 when it rebroadcasts the chunk to the room.
    footer = struct.pack("<H", message_id & 0xFFFF)
    return header + protocol + chunk.payload + footer


def build_client_transfer_header(
    source_mac: bytes,
    host_mac: bytes,
    sequence: int,
    message_id: int,
) -> bytes:
    """Build the transfer-announcement frame sent before the image chunks.

    The room host does not accept standalone ``0x04`` chunks.  A real client
    first announces a drawing with an ``0x97`` frame containing its MAC in
    little-endian 16-bit words and a short, capture-observed capability block.
    """
    if len(source_mac) != 6 or len(host_mac) != 6:
        raise ValueError("source_mac and host_mac must each contain six bytes")
    word_swapped_mac = b"".join(
        source_mac[index : index + 2][::-1] for index in range(0, 6, 2)
    )
    payload = (
        bytes.fromhex("03 02")
        + word_swapped_mac
        + bytes.fromhex("00 05 00 00 00 00 03 06 08 0d 08 0d 12 1b")
    )
    payload += bytes(CHUNK_PAYLOAD_LEN - len(payload))
    frame_control = 0x1118
    duration = 0x0146
    sequence_control = (sequence & 0x0FFF) << 4
    header = struct.pack("<HH", frame_control, duration)
    header += host_mac + source_mac + PICTOCHAT_CLIENT_GROUP
    header += struct.pack("<H", sequence_control)
    return (
        header
        + CLIENT_TRANSFER_PREFIX
        + bytes(4)  # transfer offset and reserved field
        + payload
        + struct.pack("<H", message_id & 0xFFFF)
    )


def add_radiotap_and_fcs(dot11_frame: bytes) -> bytes:
    """Wrap a frame for a PCAP. Injection normally lets the adapter add FCS."""
    # version, pad, length, present bitmap (Flags), Flags(FCS present), padding
    radiotap = struct.pack("<BBHI", 0, 0, 10, 1 << 1) + bytes((RADIOTAP_F_FCS, 0))
    fcs = struct.pack("<I", zlib.crc32(dot11_frame) & 0xFFFFFFFF)
    return radiotap + dot11_frame + fcs


def dot11_bytes(packet: bytes) -> bytes:
    """Return the 802.11 portion of a raw or radiotap-wrapped packet."""
    if len(packet) >= 4 and packet[0:2] == b"\x00\x00":
        radiotap_len = int.from_bytes(packet[2:4], "little")
        if 8 <= radiotap_len <= len(packet):
            return packet[radiotap_len:]
    return packet


def find_pictochat_host(packet: bytes) -> bytes | None:
    """Identify a room host from a Nintendo beacon or host relay frame."""
    frame = dot11_bytes(packet)
    if len(frame) < 24:
        return None
    frame_control = int.from_bytes(frame[0:2], "little")
    address_1, address_2, address_3 = frame[4:10], frame[10:16], frame[16:22]
    is_beacon = frame_control & 0x00FC == 0x0080
    if is_beacon and address_1 == b"\xff" * 6 and address_2 == address_3:
        # Nintendo's vendor information element begins with the 00:09:bf OUI.
        if b"\xdd\x20\x00\x09\xbf" in frame[24:]:
            return address_2
    if (
        frame_control == 0x0228
        and address_1 == PICTOCHAT_GROUP
        and address_2 == address_3
        and len(frame) >= 42
        and frame[24:29] == HOST_RELAY_PREFIX[:5]
        and frame[29] & 0x7F == HOST_RELAY_PREFIX[5]
        and frame[30:38] == HOST_RELAY_PREFIX[6:]
    ):
        return address_2
    return None


def extract_host_relay(packet: bytes, host_mac: bytes | None = None) -> tuple[int, bytes] | None:
    """Return ``(chunk offset, payload)`` from a host image relay."""
    frame = dot11_bytes(packet)
    if len(frame) < 42 + CHUNK_PAYLOAD_LEN:
        return None
    if find_pictochat_host(packet) is None:
        return None
    if host_mac is not None and frame[10:16] != host_mac:
        return None
    if frame[24:29] != HOST_RELAY_PREFIX[:5]:
        return None
    # Bit 7 of this byte marks the host's retry phase in the supplied capture.
    if frame[29] & 0x7F != HOST_RELAY_PREFIX[5] or frame[30:38] != HOST_RELAY_PREFIX[6:]:
        return None
    offset = int.from_bytes(frame[38:40], "little")
    return offset, frame[42 : 42 + CHUNK_PAYLOAD_LEN]


def build_transmission(
    indices: Sequence[Sequence[int]],
    source_mac: bytes,
    host_mac: bytes,
    message_id: int | None = None,
    sequence_start: int = 0,
) -> list[bytes]:
    """Build one capture-compatible transfer header and client upload cycle.

    Nintendo sends 64 chunks, ending at logical offset 0x2800.  Although the
    four-byte message envelope makes a 65th chunk useful for lossless local
    round trips, that 0x28a0 tail does not occur in the live protocol.
    """
    if message_id is None:
        message_id = int(time.time() * 1000) & 0xFFFF
    chunks = build_message_chunks(encode_4bpp_tiles(indices))[:WIRE_CHUNK_COUNT]
    transfer_header = build_client_transfer_header(
        source_mac,
        host_mac,
        sequence_start,
        message_id,
    )
    chunk_frames = [
        build_client_dot11_frame(
            chunk,
            source_mac,
            host_mac,
            sequence_start + index + 1,
            message_id + index + 1,
        )
        for index, chunk in enumerate(chunks)
    ]
    return [transfer_header, *chunk_frames]


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
