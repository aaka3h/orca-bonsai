"""Bounded local image/video preparation for the Orca visual sidecar.

Native image/video decoders run in a short-lived worker. Video decoding is limited
to seeks around a small number of sample times; audio is never transcribed here.
"""
from __future__ import annotations

import io
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

_ROOT = Path(__file__).resolve().parent.parent
_DEPS = _ROOT / "work" / "media-deps"
_TEMP = _ROOT / "work" / "media-tmp"
_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}
_VIDEO_FORMATS = {".mp4": "mov", ".m4v": "mov", ".mov": "mov", ".mkv": "matroska", ".webm": "matroska", ".avi": "avi"}
_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP", "BMP", "GIF"}
_MAX_PIXELS = 40_000_000
_MAX_IMAGE_BYTES = 50 * 1024 * 1024
_MAX_VIDEO_BYTES = 2 * 1024 * 1024 * 1024
_MAX_EDGE = 1024
_DECODE_TIMEOUT = 45
_MAX_DECODED_PER_SEEK = 900


class MediaPreparationError(ValueError):
    """The selected file cannot be prepared for visual analysis."""


def _validated_file(path):
    if not isinstance(path, str) or not path.strip() or "\x00" in path or "://" in path:
        raise MediaPreparationError("Choose a local image or video file; URLs are not supported.")
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise MediaPreparationError("The selected local file could not be opened.") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise MediaPreparationError("Choose a regular image or video file, not a directory or device.")
    extension = resolved.suffix.lower()
    if extension in _IMAGE_EXTENSIONS:
        kind, maximum = "image", _MAX_IMAGE_BYTES
    elif extension in _VIDEO_FORMATS:
        kind, maximum = "video", _MAX_VIDEO_BYTES
    else:
        raise MediaPreparationError("Supported files: JPEG, PNG, WEBP, BMP, GIF, MP4, MKV, MOV, WEBM, AVI and M4V.")
    if metadata.st_size == 0:
        raise MediaPreparationError("The selected file is empty.")
    if metadata.st_size > maximum:
        raise MediaPreparationError("Images must be at most 50 MiB and videos at most 2 GiB.")
    return resolved, extension, kind, maximum


def _write_manifest(directory, data):
    temporary = directory / "frames.json.tmp"
    temporary.write_text(json.dumps(data, allow_nan=False), encoding="utf-8")
    temporary.replace(directory / "frames.json")


def _clean_jpeg(image):
    from PIL import Image, ImageOps
    if image.width * image.height > _MAX_PIXELS:
        raise MediaPreparationError("The image exceeds the 40-megapixel processing limit.")
    image = ImageOps.exif_transpose(image)
    if image.mode in {"RGBA", "LA", "P"} or "transparency" in image.info:
        rgba = image.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (128, 128, 128, 255))
        image = Image.alpha_composite(background, rgba).convert("RGB")
    else:
        image = image.convert("RGB")
    image.thumbnail((_MAX_EDGE, _MAX_EDGE), Image.Resampling.LANCZOS)
    # A new pixel-only image ensures EXIF, comments and other source metadata are
    # excluded even if Pillow propagated info while transforming the input.
    clean = Image.new("RGB", image.size)
    clean.paste(image)
    encoded = io.BytesIO()
    clean.save(encoded, format="JPEG", quality=85, optimize=True)
    return encoded.getvalue(), clean.width, clean.height


def _emit_frame(image, timestamp, directory, result):
    jpeg, width, height = _clean_jpeg(image)
    name = f"frame-{len(result['frames']):03d}.jpg"
    (directory / name).write_bytes(jpeg)
    result["frames"].append({"timestamp_seconds": timestamp, "file": name, "width": width, "height": height})
    _write_manifest(directory, result)


def _decode_image(fd, directory, result):
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = _MAX_PIXELS
    with os.fdopen(os.dup(fd), "rb") as source, Image.open(source) as image:
        if image.format not in _IMAGE_FORMATS:
            raise MediaPreparationError("The file contents are not a supported image format.")
        if image.width * image.height > _MAX_PIXELS:
            raise MediaPreparationError("The image exceeds the 40-megapixel processing limit.")
        if image.format == "GIF":
            image.seek(0)
            result["limits"].append("Only the first GIF frame is analyzed; animation and timing are not included.")
        elif getattr(image, "n_frames", 1) > 1:
            image.seek(0)
            result["limits"].append("Only the first frame of this animated/multipage image is analyzed.")
        _emit_frame(image, None, directory, result)
        result["limits"].append("The image is resized to a maximum 1024-pixel edge; metadata is removed and transparency is flattened onto neutral gray.")


def _finite_positive(value):
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return value if math.isfinite(value) and value > 0 else None


def _decode_video(fd, extension, maximum_frames, directory, result):
    sys.path.insert(0, str(_DEPS))
    try:
        import av
    except ImportError as exc:
        raise MediaPreparationError("Video support is unavailable. Run outputs/setup_orca_media.py once to install the local decoder.") from exc
    # Force the supported container demuxer. A file merely renamed .mp4 cannot
    # auto-select a playlist/network demuxer. MOV external data references stay off.
    options = {"protocol_whitelist": "file", "enable_drefs": "0", "use_absolute_path": "0", "threads": "1"}
    input_name = f"/proc/self/fd/{fd}"
    with av.open(input_name, mode="r", format=_VIDEO_FORMATS[extension], options=options) as container:
        if not container.streams.video:
            raise MediaPreparationError("The selected file contains no decodable video stream.")
        stream = container.streams.video[0]
        stream.thread_type = "NONE"
        stream.codec_context.thread_count = 1
        if stream.width * stream.height > _MAX_PIXELS:
            raise MediaPreparationError("Video frames exceed the 40-megapixel processing limit.")
        time_base = float(stream.time_base) if stream.time_base is not None else None
        start = float(stream.start_time or 0) * (time_base or 0)
        duration = _finite_positive(float(stream.duration) * time_base) if stream.duration is not None and time_base else None
        if duration is None and container.duration is not None:
            duration = _finite_positive(float(container.duration) / av.time_base)
        result["duration_seconds"] = duration
        result["limits"].append("Only sampled video frames are analyzed; actions between frames can be missed. Audio and subtitles are not analyzed.")
        if duration is None or not time_base:
            desired = [0.0]
            if maximum_frames > 1:
                result["status"] = "partial"
            result["limits"].append("Reliable duration or seek timing was unavailable; only an initial frame was sampled.")
        else:
            fps = _finite_positive(stream.average_rate)
            step = 1 / fps if fps else 0.04
            end = max(0.0, duration - step)
            desired = [0.0] if maximum_frames == 1 else [end * index / (maximum_frames - 1) for index in range(maximum_frames)]
        _write_manifest(directory, result)
        observed = set()
        deadline = time.monotonic() + (_DECODE_TIMEOUT - 2)
        for index, offset in enumerate(desired):
            if time.monotonic() >= deadline:
                result["status"] = "partial"
                result["limits"].append("Video sampling reached its decoding time limit; completed frames are retained.")
                break
            try:
                if time_base:
                    container.seek(int((start + offset) / time_base), stream=stream, backward=True, any_frame=False)
                elif index:
                    break
            except Exception as exc:
                if index:
                    result["status"] = "partial"
                    result["limits"].append(f"Seeking to {offset:.3f}s failed ({type(exc).__name__}); completed frames are retained.")
                    break
                # A nonseekable container may still provide an initial frame.
            selected, selected_time = None, None
            try:
                for decoded, frame in enumerate(container.decode(stream)):
                    if time.monotonic() >= deadline or decoded >= _MAX_DECODED_PER_SEEK:
                        result["status"] = "partial"
                        result["limits"].append(f"Sampling near {offset:.3f}s reached a decoding limit; later frames were not exhaustively decoded.")
                        break
                    absolute = frame.time
                    actual = float(absolute) - start if absolute is not None else None
                    if actual is not None and (not math.isfinite(actual) or actual < -0.001):
                        continue
                    selected, selected_time = frame, max(0.0, actual) if actual is not None else None
                    if actual is None or actual + 0.00001 >= offset:
                        break
                if selected is None:
                    result["status"] = "partial"
                    result["limits"].append(f"No frame was obtained near {offset:.3f}s.")
                    continue
                # Very short videos may map several samples to the same frame.
                identity = selected.pts if selected.pts is not None else (index, selected_time)
                if identity in observed:
                    continue
                observed.add(identity)
                timestamp = round(selected_time, 6) if selected_time is not None else None
                if selected.width * selected.height > _MAX_PIXELS:
                    result["status"] = "partial"
                    result["limits"].append("A decoded video frame exceeded the 40-megapixel limit and was skipped.")
                    continue
                _emit_frame(selected.to_image(), timestamp, directory, result)
            except Exception as exc:
                result["status"] = "partial"
                result["limits"].append(f"Decoding near {offset:.3f}s failed ({type(exc).__name__}); completed frames are retained.")
        if len(result["frames"]) < maximum_frames:
            result["limits"].append(f"Returned {len(result['frames'])} distinct frame(s) from a maximum of {maximum_frames} requested samples.")
        rotation = stream.metadata.get("rotate")
        if rotation and rotation not in {"0", "0.0"}:
            result["limits"].append("Container video rotation metadata is not applied; sample orientation may differ from playback.")


def _worker(fd, extension, kind, maximum_frames, directory):
    result = {"duration_seconds": None, "frames": [], "limits": [], "status": "complete"}
    _write_manifest(directory, result)
    try:
        if kind == "image":
            _decode_image(fd, directory, result)
        else:
            _decode_video(fd, extension, maximum_frames, directory, result)
    except Exception as exc:
        result["error"] = str(exc)[:400] if isinstance(exc, MediaPreparationError) else f"The {kind} could not be decoded ({type(exc).__name__})."
        result["status"] = "partial" if result["frames"] else "error"
    _write_manifest(directory, result)
    return 0 if result["frames"] else 1


def prepare_media(path: str, max_frames: int = 6) -> dict:
    """Return clean JPEG samples of a local file; never fetch a URL or upload data.

    Invalid inputs raise MediaPreparationError. If a video fails partway through,
    completed frames are returned with explicit limits. At most 12 samples and 45
    seconds of native decoding are allowed, including container inspection.
    """
    if isinstance(max_frames, bool) or not isinstance(max_frames, int) or not 1 <= max_frames <= 12:
        raise MediaPreparationError("max_frames must be an integer between 1 and 12.")
    resolved, extension, kind, maximum_size = _validated_file(path)
    _TEMP.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = None
    try:
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum_size:
            raise MediaPreparationError("The selected file changed or no longer meets the media limits.")
        with tempfile.TemporaryDirectory(prefix="decode-", dir=_TEMP) as temporary:
            directory = Path(temporary)
            timed_out = False
            try:
                # No new process group: the app's Stop action reaches the decoder.
                completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--decode", str(descriptor),
                                            extension, kind, str(max_frames), str(directory)],
                                           pass_fds=(descriptor,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, timeout=_DECODE_TIMEOUT, check=False)
                returncode = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out, returncode = True, None
            manifest_path = directory / "frames.json"
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise MediaPreparationError("The media decoder timed out or stopped before producing a usable frame.") from None
            result = {"path": str(resolved), "name": resolved.name, "kind": kind,
                      "duration_seconds": data.get("duration_seconds"), "frames": [], "limits": data.get("limits", []),
                      "status": data.get("status", "complete")}
            for frame in data.get("frames", [])[:max_frames]:
                frame_path = directory / frame["file"]
                if frame_path.parent != directory or not re_frame_filename(frame["file"]):
                    continue
                try:
                    jpeg = frame_path.read_bytes()
                except OSError:
                    continue
                result["frames"].append({"timestamp_seconds": frame.get("timestamp_seconds"), "jpeg": jpeg,
                                         "width": frame["width"], "height": frame["height"]})
            if timed_out:
                result["status"] = "partial"
                result["limits"].append("The decoder stopped after 45 seconds; completed samples are retained.")
            elif returncode and result["frames"]:
                result["status"] = "partial"
                result["limits"].append("The decoder exited before finishing; completed samples are retained.")
            if data.get("error"):
                result["status"] = "partial"
                result["limits"].append(data["error"])
            if not result["frames"]:
                raise MediaPreparationError(data.get("error") or "No usable video/image frame could be decoded.")
            return result
    except OSError as exc:
        raise MediaPreparationError("The local media file or decoder could not be opened.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def re_frame_filename(value):
    return isinstance(value, str) and len(value) == len("frame-000.jpg") and value.startswith("frame-") and value[6:9].isdigit() and value.endswith(".jpg")


if __name__ == "__main__":
    # sys.argv contains program plus six worker arguments.
    if len(sys.argv) == 7 and sys.argv[1] == "--decode":
        raise SystemExit(_worker(int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), Path(sys.argv[6])))
    raise SystemExit("Import prepare_media(path) to prepare a local image or video.")
