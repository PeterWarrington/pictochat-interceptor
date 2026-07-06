#!/usr/bin/env python3
"""
pictochat_decode.py
===================

Decode the PictoChat image payload from a wireless sniff hex dump (`test.txt`)
and render it as a PictoChat-sized canvas image.

This script intentionally mirrors the process used to generate `cand_tile.png`:

1. Parse Wi-Fi packet bytes from hexdump lines (e.g. "0040  aa bb cc ...").
2. Keep only long data packets (246 bytes in this capture).
3. Skip the message header and four-byte image prefix, then reassemble using:
   - chunk stream base:   0x0A0
   - image data base:     0x0A4
   - payload size:        0x2800 bytes
   - per-packet chunk:    160 bytes at packet offset 0x4E
4. Interpret the buffer as 320 DS-style 4bpp tiles (32 bytes per tile, 8x8 pixels).
5. Decode nibbles in Nintendo order (low nibble first, then high nibble).
6. Place tiles in their transmitted (row-major) order into a 32x10 tile grid.
7. Render the resulting 256x80 PictoChat message.
8. Render the fixed PictoChat palette, including DSi rainbow-pen indices 3..15.

The 0x2800-byte size is not arbitrary: 256 * 80 pixels * 4 bits per pixel is
exactly 0x2800 bytes.  Earlier versions decoded only 0x0A00 bytes and reshaped
that quarter-image into a 10x8 grid, which made correctly ordered tiles appear
jumbled.
"""

from __future__ import annotations

import argparse
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List

from PIL import Image


# -----------------------------------------------------------------------------
# Capture-specific constants discovered during reverse engineering
# -----------------------------------------------------------------------------

# Chunk offsets begin at 0xA0, but the first four reconstructed bytes belong to
# the PictoChat message envelope. Actual 4bpp tile bytes begin at 0xA4. Treating
# those four bytes as pixels rotates every tile by one row and creates regular
# horizontal seams at each 8-pixel boundary.
BASE_OFFSET = 0x0A0
IMAGE_DATA_PREFIX_LEN = 4

# 256 x 80 pixels at 4 bits per pixel.
IMAGE_BUFFER_SIZE = 0x2800  # 10240 bytes

# Packet structure (for these 246-byte "long" frames in test.txt):
# - chunk logical offset is stored at bytes 0x4A..0x4B (little-endian)
# - payload starts at 0x4E and is 160 bytes long
CHUNK_OFFSET_POS = 0x4A
CHUNK_PAYLOAD_POS = 0x4E
CHUNK_PAYLOAD_LEN = 160
LONG_PACKET_LEN = 246
CHUNK_ALIGN = CHUNK_PAYLOAD_LEN
STREAM_MAX_PACKET_GAP = 600
REFERENCE_RADIOTAP_LEN = 0x24

# Tile format:
# 0x2800 bytes / 32 bytes per 8x8 4bpp tile = 320 tiles
TILE_BYTE_SIZE = 32
TILE_COUNT = IMAGE_BUFFER_SIZE // TILE_BYTE_SIZE  # 320
TILE_W = 8
TILE_H = 8

# Tile grid dimensions.
TILES_X = 32
TILES_Y = 10

# PictoChat canvas dimensions.
CANVAS_W = 256
CANVAS_H = 80

# Tiles are already stored at the canvas's native resolution.
PIXEL_SCALE_X = CANVAS_W // (TILES_X * TILE_W)
PIXEL_SCALE_Y = CANVAS_H // (TILES_Y * TILE_H)

# PictoChat's packed pixels are palette indices rather than grayscale values.
# Captures establish 0 as paper, 1 as normal ink, and 3..15 as the DSi rainbow
# cycle. The rainbow hues follow the observed pen order, with intermediate
# shades for the thirteen encoded steps. Index 2 has not appeared in captures;
# render it as normal ink until its role is identified.
PICTOCHAT_PALETTE: tuple[tuple[int, int, int], ...] = (
    (255, 255, 255),  # 0: paper / erased
    (0, 0, 0),        # 1: black pen
    (0, 0, 0),        # 2: reserved / unknown
    (255, 82, 164),   # 3: pink
    (255, 51, 102),   # 4: deep pink
    (244, 42, 55),    # 5: red
    (255, 91, 40),    # 6: red-orange
    (255, 145, 34),   # 7: orange
    (255, 195, 35),   # 8: amber
    (255, 224, 45),   # 9: yellow
    (174, 224, 55),   # A: light green
    (65, 183, 76),    # B: green
    (22, 151, 166),   # C: teal-blue
    (62, 205, 224),   # D: light blue
    (49, 139, 220),   # E: medium blue
    (46, 75, 190),    # F: dark blue
)


def parse_hexdump_packets(text: str) -> List[List[int]]:
    """
    Parse packets from hexdump text.

    Input format expectation:
      - Packet dumps are separated by blank lines.
      - Data lines start with a 4-hex-digit offset, then hex bytes:
            0040  aa bb cc dd ...

    Returns:
      A list of packets, where each packet is a list of integer bytes [0..255].
    """
    packets: List[List[int]] = []
    current: List[int] = []

    # Match lines like:
    #   "00a0  11 22 33 44 ..."
    line_re = re.compile(r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s+)+)")

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")

        # Blank line => packet boundary.
        if not line.strip():
            if current:
                packets.append(current)
                current = []
            continue

        m = line_re.match(line)
        if not m:
            # Ignore non-hexdump lines.
            continue

        current.extend(int(b, 16) for b in m.group(1).split())

    if current:
        packets.append(current)

    return packets


def reconstruct_pictochat_buffer(packets: Iterable[List[int]]) -> bytearray:
    """
    Reassemble the PictoChat tile buffer from long packets.

    Method copied from the `cand_tile.png` generation approach:
      - use only packets of length 246 bytes
      - read chunk logical offset from bytes 0x4A..0x4B
      - copy the 160-byte chunk from 0x4E..0xED into the image buffer at:
            (chunk_offset - BASE_OFFSET - IMAGE_DATA_PREFIX_LEN)
      - skip the first four logical bytes, which are message prefix data
      - deduplicate retransmissions by chunk offset (first copy wins)
    """
    _, buffer = reconstruct_pictochat_buffer_with_metadata(list(packets))
    return buffer


@dataclass
class ChunkCandidate:
    packet_index: int
    chunk_offset: int
    payload: bytes
    fcs_valid: bool = True


@dataclass
class ChunkStream:
    first_packet_index: int
    last_packet_index: int
    chunks: dict[int, bytes] = field(default_factory=dict)
    valid_offsets: set[int] = field(default_factory=set)
    recovery_votes: dict[int, Counter[bytes]] = field(default_factory=dict)
    packet_hits: int = 0


def is_plausible_chunk_offset(chunk_offset: int) -> bool:
    """
    Validate that a chunk offset is in-image and aligned like known PictoChat chunks.
    """
    logical_start = chunk_offset - BASE_OFFSET
    image_write_start = logical_start - IMAGE_DATA_PREFIX_LEN
    # The 0x2800-byte image follows a four-byte envelope. Consequently a full
    # transfer has a 65th chunk at 0x28A0 containing its final four image bytes.
    return (
        logical_start >= 0
        and logical_start % CHUNK_ALIGN == 0
        and image_write_start < IMAGE_BUFFER_SIZE
    )


def radiotap_flags(packet: List[int]) -> int | None:
    """Read the radiotap Flags field when the packet exposes one."""
    if len(packet) < 8 or packet[0] != 0:
        return None

    present_words: List[int] = []
    position = 4
    while position + 4 <= len(packet):
        word = int.from_bytes(bytes(packet[position : position + 4]), "little")
        present_words.append(word)
        position += 4
        if not word & (1 << 31):
            break
    else:
        return None

    if not present_words or not present_words[0] & (1 << 1):
        return None

    # Fields occur in bit order. TSFT (bit 0), when present, is 8-byte aligned
    # and eight bytes long; Flags (bit 1) immediately follows it.
    if present_words[0] & 1:
        position = (position + 7) & ~7
        position += 8
    return packet[position] if position < len(packet) else None


def has_valid_wifi_fcs(packet: List[int]) -> bool:
    """Reject frames marked bad, or whose included 802.11 FCS does not match."""
    if len(packet) < 8 or packet[0] != 0:
        return True
    radiotap_len = packet[2] | (packet[3] << 8)
    if not 8 <= radiotap_len <= len(packet):
        return True

    flags = radiotap_flags(packet)
    if flags is None:
        return True
    if flags & 0x40:  # IEEE80211_RADIOTAP_F_BADFCS
        return False
    if not flags & 0x10:  # IEEE80211_RADIOTAP_F_FCS
        return True
    if len(packet) < radiotap_len + 4:
        return False

    expected = int.from_bytes(bytes(packet[-4:]), "little")
    actual = zlib.crc32(bytes(packet[radiotap_len:-4])) & 0xFFFFFFFF
    return actual == expected


def extract_chunk_candidates_from_packet(
    packet: List[int],
    packet_index: int,
    accept_bad_fcs: bool = False,
) -> List[ChunkCandidate]:
    """
    Extract a PictoChat chunk from its known packet fields.

    The offset is structural metadata, so searching arbitrary payload bytes for
    values that merely look like offsets is unsafe.
    """
    candidates: List[ChunkCandidate] = []
    seen_keys: set[tuple[int, bytes]] = set()
    fcs_valid = has_valid_wifi_fcs(packet)
    if not fcs_valid and not accept_bad_fcs:
        return candidates

    def try_add(offset_pos: int, payload_pos: int) -> None:
        if offset_pos + 1 >= len(packet):
            return
        if payload_pos + CHUNK_PAYLOAD_LEN > len(packet):
            return
        chunk_offset = packet[offset_pos] | (packet[offset_pos + 1] << 8)
        if not is_plausible_chunk_offset(chunk_offset):
            return
        payload = bytes(packet[payload_pos : payload_pos + CHUNK_PAYLOAD_LEN])
        key = (chunk_offset, payload)
        if key in seen_keys:
            return
        seen_keys.add(key)
        candidates.append(
            ChunkCandidate(
                packet_index=packet_index,
                chunk_offset=chunk_offset,
                payload=payload,
                fcs_valid=fcs_valid,
            )
        )

    # Radiotap headers are variable-length. The original sniff used a 0x24-byte
    # header, but live drivers (notably Apple's) may prepend a different number
    # of radio metadata bytes. A valid radiotap packet must use only this
    # relative layout: also trying the old absolute positions can manufacture a
    # plausible-looking, shifted ghost stream from unrelated bytes.
    if len(packet) >= 4 and packet[0] == 0:
        radiotap_len = packet[2] | (packet[3] << 8)
        if 8 <= radiotap_len <= len(packet):
            shift = radiotap_len - REFERENCE_RADIOTAP_LEN
            try_add(CHUNK_OFFSET_POS + shift, CHUNK_PAYLOAD_POS + shift)
            return candidates

    # Fallback for legacy dumps without a recognizable radiotap header.
    try_add(CHUNK_OFFSET_POS, CHUNK_PAYLOAD_POS)

    return candidates


def write_chunk_to_image_buffer(
    buffer: bytearray,
    chunk_offset: int,
    payload: bytes,
) -> None:
    """Copy a logical message chunk into the prefix-free tile image buffer."""
    write_start = chunk_offset - BASE_OFFSET - IMAGE_DATA_PREFIX_LEN
    source_start = max(0, -write_start)
    write_start = max(0, write_start)
    writable = min(len(payload) - source_start, len(buffer) - write_start)
    if writable > 0:
        buffer[write_start : write_start + writable] = payload[
            source_start : source_start + writable
        ]


def build_chunk_streams(
    chunk_candidates: List[ChunkCandidate],
    max_packet_gap: int = STREAM_MAX_PACKET_GAP,
) -> List[ChunkStream]:
    """
    Cluster chunk candidates into likely transmission streams.
    """
    streams: List[ChunkStream] = []

    for candidate in chunk_candidates:
        best_stream_index: int | None = None
        best_stream_score = -1

        for stream_index, stream in enumerate(streams):
            if candidate.packet_index - stream.last_packet_index > max_packet_gap:
                continue

            existing_payload = stream.chunks.get(candidate.chunk_offset)
            if existing_payload is not None and existing_payload != candidate.payload:
                existing_is_valid = candidate.chunk_offset in stream.valid_offsets
                # Two checksum-valid payloads at one logical offset indicate a
                # different drawing. A damaged copy, however, can safely stay
                # in this stream as recovery material.
                if existing_is_valid and candidate.fcs_valid:
                    continue

            score = len(stream.chunks)
            if score > best_stream_score:
                best_stream_score = score
                best_stream_index = stream_index

        if best_stream_index is None:
            stream = ChunkStream(
                first_packet_index=candidate.packet_index,
                last_packet_index=candidate.packet_index,
            )
            stream.chunks[candidate.chunk_offset] = candidate.payload
            if candidate.fcs_valid:
                stream.valid_offsets.add(candidate.chunk_offset)
            else:
                stream.recovery_votes[candidate.chunk_offset] = Counter(
                    {candidate.payload: 1}
                )
            stream.packet_hits = 1
            streams.append(stream)
            continue

        stream = streams[best_stream_index]
        stream.last_packet_index = candidate.packet_index
        stream.packet_hits += 1
        existing_payload = stream.chunks.get(candidate.chunk_offset)
        existing_is_valid = candidate.chunk_offset in stream.valid_offsets
        if existing_payload is None:
            stream.chunks[candidate.chunk_offset] = candidate.payload
            if candidate.fcs_valid:
                stream.valid_offsets.add(candidate.chunk_offset)
            else:
                stream.recovery_votes[candidate.chunk_offset] = Counter(
                    {candidate.payload: 1}
                )
        elif candidate.fcs_valid and not existing_is_valid:
            # A verified retransmission always replaces provisional recovery.
            stream.chunks[candidate.chunk_offset] = candidate.payload
            stream.valid_offsets.add(candidate.chunk_offset)
            stream.recovery_votes.pop(candidate.chunk_offset, None)
        elif not candidate.fcs_valid and not existing_is_valid:
            votes = stream.recovery_votes.setdefault(candidate.chunk_offset, Counter())
            votes[candidate.payload] += 1
            stream.chunks[candidate.chunk_offset] = votes.most_common(1)[0][0]

    return streams


def reconstruct_pictochat_buffer_with_metadata(
    packets: List[List[int]],
    stream_index: int = -1,
) -> tuple[dict[str, int], bytearray]:
    """
    Reassemble a PictoChat tile buffer and expose reconstruction stats.

    stream_index:
      -1 => auto-select best stream by coverage then packet hits
      >=0 => use explicit stream index
    """
    chunk_candidates: List[ChunkCandidate] = []
    for packet_index, packet in enumerate(packets):
        chunk_candidates.extend(extract_chunk_candidates_from_packet(packet, packet_index))

    streams = build_chunk_streams(chunk_candidates)
    if not streams:
        return (
            {
                "stream_count": 0,
                "selected_stream_index": -1,
                "selected_stream_chunks": 0,
                "selected_stream_packets": 0,
                "candidate_count": 0,
            },
            bytearray([0x00] * IMAGE_BUFFER_SIZE),
        )

    if stream_index < 0:
        selected_stream_index, selected_stream = max(
            enumerate(streams),
            key=lambda item: (len(item[1].chunks), item[1].packet_hits),
        )
    else:
        selected_stream_index = min(max(stream_index, 0), len(streams) - 1)
        selected_stream = streams[selected_stream_index]

    buffer = bytearray([0x00] * IMAGE_BUFFER_SIZE)
    for chunk_offset, payload in selected_stream.chunks.items():
        write_chunk_to_image_buffer(buffer, chunk_offset, payload)

    metadata = {
        "stream_count": len(streams),
        "selected_stream_index": selected_stream_index,
        "selected_stream_chunks": len(selected_stream.chunks),
        "selected_stream_packets": selected_stream.packet_hits,
        "candidate_count": len(chunk_candidates),
    }
    return metadata, buffer


def decode_4bpp_tiles(buffer: bytes) -> List[List[List[int]]]:
    """
    Decode buffer into a list of 8x8 tiles of 4bpp indices.

    Returns:
      tiles[tile_index][y][x] = palette index (0..15)
    """
    tiles: List[List[List[int]]] = []

    for tile_i in range(TILE_COUNT):
        tile_bytes = buffer[tile_i * TILE_BYTE_SIZE : (tile_i + 1) * TILE_BYTE_SIZE]
        indices: List[int] = []
        for value in tile_bytes:
            low_nibble = value & 0x0F
            high_nibble = (value >> 4) & 0x0F
            indices.append(low_nibble)
            indices.append(high_nibble)

        tile = [indices[row * TILE_W : (row + 1) * TILE_W] for row in range(TILE_H)]
        tiles.append(tile)

    return tiles


def compose_canvas_row_major(tiles: List[List[List[int]]]) -> List[List[int]]:
    """
    Place tiles row-major and expand to PictoChat canvas dimensions.
    """
    canvas = [[0 for _ in range(CANVAS_W)] for _ in range(CANVAS_H)]

    for tile_index, tile in enumerate(tiles):
        tile_x = tile_index % TILES_X
        tile_y = tile_index // TILES_X

        for y in range(TILE_H):
            for x in range(TILE_W):
                value = tile[y][x]
                dst_x = (tile_x * TILE_W + x) * PIXEL_SCALE_X
                dst_y = (tile_y * TILE_H + y) * PIXEL_SCALE_Y
                for dy in range(PIXEL_SCALE_Y):
                    for dx in range(PIXEL_SCALE_X):
                        canvas[dst_y + dy][dst_x + dx] = value

    return canvas


def canvas_to_image(
    canvas_indices: List[List[int]],
    scale: int = 1,
) -> Image.Image:
    """Convert decoded palette indices into a displayable Pillow image."""
    if scale < 1:
        raise ValueError("scale must be at least 1")

    pixels: List[tuple[int, int, int]] = []
    for y in range(CANVAS_H):
        for x in range(CANVAS_W):
            idx = canvas_indices[y][x]
            pixels.append(PICTOCHAT_PALETTE[idx & 0x0F])

    image = Image.new("RGB", (CANVAS_W, CANVAS_H))
    image.putdata(pixels)

    if scale > 1:
        image = image.resize(
            (CANVAS_W * scale, CANVAS_H * scale),
            Image.Resampling.NEAREST,
        )
    return image


def render_canvas(
    canvas_indices: List[List[int]],
    output_path: Path,
    scale: int = 1,
) -> None:
    """
    Render palette indices to an RGB image.

    Mapping:
      - index 0 => white background
      - index 1 => black ink
      - indices 3..15 => DSi rainbow pen
    """
    canvas_to_image(canvas_indices, scale=scale).save(output_path)


def main() -> None:
    """
    CLI entry point.

    Defaults are intentionally aligned with your current working files:
      - input:  test.txt
      - output: cand_tile.png
    """
    parser = argparse.ArgumentParser(
        description=(
            "Decode PictoChat image data from a wireless sniff hexdump and "
            "render the reconstructed PictoChat canvas."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("test.txt"),
        help="Path to hexdump input text (default: test.txt)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("cand_tile.png"),
        help="Output PNG path (default: cand_tile.png)",
    )
    parser.add_argument(
        "--scale",
        type=int,
        default=1,
        help="Nearest-neighbor additional upscale factor (default: 1)",
    )
    parser.add_argument(
        "--stream-index",
        type=int,
        default=-1,
        help=(
            "Chunk stream index to decode (-1 auto-selects best stream by coverage)"
        ),
    )
    args = parser.parse_args()

    hexdump_text = args.input.read_text(encoding="utf-8")
    packets = parse_hexdump_packets(hexdump_text)
    stream_meta, tile_buffer = reconstruct_pictochat_buffer_with_metadata(
        packets,
        stream_index=args.stream_index,
    )
    tiles = decode_4bpp_tiles(tile_buffer)

    canvas = compose_canvas_row_major(tiles)
    render_canvas(canvas, args.output, scale=args.scale)
    print(f"Wrote {args.output}")

    print(
        "Stream selection: "
        f"{stream_meta['selected_stream_index']}/{stream_meta['stream_count']} "
        f"(chunks={stream_meta['selected_stream_chunks']}, "
        f"packets={stream_meta['selected_stream_packets']}, "
        f"candidates={stream_meta['candidate_count']})"
    )


if __name__ == "__main__":
    main()
