"""Local image and real short-video fixtures; no network media or model requests."""
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "outputs"))
sys.path.insert(0, str(ROOT / "work" / "media-deps"))
from PIL import Image
import av
import orca_media_files as media


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="media-test-", dir=ROOT / "work")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def image(self, name="image.png", mode="RGB", size=(100, 80), color="red", **kwargs):
        path = self.directory / name
        Image.new(mode, size, color).save(path, **kwargs)
        return path

    def test_rejects_urls_directories_devices_missing_unknown_empty_and_sizes(self):
        empty = self.directory / "empty.png"
        empty.touch()
        unknown = self.directory / "file.txt"
        unknown.write_text("hello")
        for path in ("https://example.test/a.png", "file:///tmp/a.png", str(self.directory), "/dev/null", str(self.directory / "missing.jpg"), str(empty), str(unknown)):
            with self.subTest(path=path), self.assertRaises(media.MediaPreparationError):
                media.prepare_media(path)
        for suffix, size in ((".png", media._MAX_IMAGE_BYTES), (".mp4", media._MAX_VIDEO_BYTES)):
            path = self.directory / ("large" + suffix)
            with path.open("wb") as file:
                file.truncate(size + 1)
            with self.assertRaises(media.MediaPreparationError):
                media.prepare_media(str(path))
        valid = self.image()
        for count in (0, -1, 13, True, 1.5, "6"):
            with self.subTest(count=count), self.assertRaises(media.MediaPreparationError):
                media.prepare_media(str(valid), max_frames=count)

    def test_exif_rotation_resize_and_metadata_removal(self):
        exif = Image.Exif()
        exif[274] = 6
        exif[270] = "Private original description"
        path = self.image(name="rotated.jpg", size=(2048, 1000), exif=exif)
        result = media.prepare_media(str(path))
        self.assertEqual((result["kind"], result["path"], result["name"]), ("image", str(path.resolve()), "rotated.jpg"))
        frame = result["frames"][0]
        self.assertEqual((frame["width"], frame["height"]), (500, 1024))
        self.assertIsNone(frame["timestamp_seconds"])
        self.assertIsNone(result["duration_seconds"])
        with Image.open(io.BytesIO(frame["jpeg"])) as cleaned:
            self.assertEqual(cleaned.format, "JPEG")
            self.assertEqual(len(cleaned.getexif()), 0)
            self.assertNotIn("exif", cleaned.info)
        self.assertNotIn(b"Private original description", frame["jpeg"])

    def test_alpha_flattens_to_gray_and_gif_only_first_frame(self):
        transparent = self.image(mode="RGBA", color=(255, 0, 0, 0))
        frame = media.prepare_media(str(transparent))["frames"][0]
        with Image.open(io.BytesIO(frame["jpeg"])) as flattened:
            pixel = flattened.getpixel((0, 0))
            self.assertTrue(all(126 <= channel <= 130 for channel in pixel))
        gif = self.directory / "animation.gif"
        Image.new("RGB", (64, 64), "red").save(gif, save_all=True, append_images=[Image.new("RGB", (64, 64), "blue")], duration=200, loop=0)
        result = media.prepare_media(str(gif))
        self.assertEqual(len(result["frames"]), 1)
        self.assertIn("first GIF frame", " ".join(result["limits"]))
        with Image.open(io.BytesIO(result["frames"][0]["jpeg"])) as first:
            red, green, blue = first.getpixel((0, 0))
            self.assertGreater(red, 240)
            self.assertLess(blue, 20)

    def test_huge_image_header_and_disguised_playlist_are_rejected(self):
        def chunk(name, data):
            return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data) & 0xffffffff)
        image = self.directory / "huge.png"
        header = struct.pack(">2I5B", 10000, 10000, 8, 2, 0, 0, 0)
        image.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b""))
        with self.assertRaises(media.MediaPreparationError):
            media.prepare_media(str(image))
        playlist = self.directory / "playlist.mp4"
        playlist.write_text("#EXTM3U\n#EXTINF:10,\nhttp://127.0.0.1:1/never-request\n")
        with self.assertRaises(media.MediaPreparationError):
            media.prepare_media(str(playlist))

    def test_actual_short_video_uniform_frames_and_timestamps(self):
        video = self.directory / "clip.mp4"
        with av.open(str(video), mode="w", format="mp4") as container:
            stream = container.add_stream("mpeg4", rate=10)
            stream.width, stream.height = 160, 96
            stream.pix_fmt = "yuv420p"
            for index in range(30):
                image = Image.new("RGB", (160, 96), (index * 8, 10, 240 - index * 7))
                frame = av.VideoFrame.from_image(image)
                for packet in stream.encode(frame):
                    container.mux(packet)
            for packet in stream.encode():
                container.mux(packet)
        result = media.prepare_media(str(video))
        self.assertEqual(result["kind"], "video")
        self.assertAlmostEqual(result["duration_seconds"], 3.0, places=1)
        self.assertEqual(len(result["frames"]), 6)
        timestamps = [frame["timestamp_seconds"] for frame in result["frames"]]
        self.assertEqual(timestamps, sorted(set(timestamps)))
        self.assertAlmostEqual(timestamps[0], 0, places=3)
        self.assertGreaterEqual(timestamps[-1], 2.8)
        for index, timestamp in enumerate(timestamps):
            self.assertLessEqual(abs(timestamp - index * 2.9 / 5), 0.101)
        colors = []
        for frame in result["frames"]:
            self.assertEqual((frame["width"], frame["height"]), (160, 96))
            with Image.open(io.BytesIO(frame["jpeg"])) as image:
                colors.append(image.getpixel((0, 0))[0])
        self.assertGreater(colors[-1], colors[0] + 150)
        self.assertIn("Audio", " ".join(result["limits"]))
        self.assertEqual(len(media.prepare_media(str(video), max_frames=1)["frames"]), 1)

    def test_completed_frame_survives_worker_timeout_and_temporary_files_are_cleaned(self):
        image = self.image()
        before = set(media._TEMP.glob("decode-*")) if media._TEMP.exists() else set()
        def timeout(command, **kwargs):
            self.assertNotIn("start_new_session", kwargs)
            self.assertEqual(kwargs["timeout"], 45)
            self.assertTrue(kwargs["pass_fds"])
            directory = Path(command[-1])
            (directory / "frame-000.jpg").write_bytes(b"already completed jpeg")
            (directory / "frames.json").write_text(json.dumps({"duration_seconds": 10, "frames": [{"timestamp_seconds": 0, "file": "frame-000.jpg", "width": 100, "height": 80}], "limits": []}))
            raise subprocess.TimeoutExpired(command, 45)
        with patch.object(media.subprocess, "run", side_effect=timeout):
            result = media.prepare_media(str(image))
        self.assertEqual(result["frames"][0]["jpeg"], b"already completed jpeg")
        self.assertIn("45 seconds", " ".join(result["limits"]))
        self.assertEqual(set(media._TEMP.glob("decode-*")), before)


if __name__ == "__main__":
    unittest.main()
