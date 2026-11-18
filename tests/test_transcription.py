"""
SCAM KILLER — Comprehensive Tests for Audio Transcription Service
Validates FFmpeg/FFprobe discovery, universal audio format conversion (OPUS, OGG, MP3, M4A, WAV, FLAC, AAC),
corrupted audio handling, zero audio stream rejection, Tamil (ta-IN) default routing, and zero-storage cleanup.
"""

import os
import unittest
from unittest.mock import patch, MagicMock
from services.transcription_service import (
    TranscriptionService,
    get_ffmpeg_path,
    get_ffprobe_path
)


class TestTranscriptionService(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.service = TranscriptionService()
        cls.samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scratch", "test_samples")

    def test_engine_available(self):
        """Verifies speech recognition engine is detected."""
        self.assertTrue(self.service.is_engine_available())

    def test_ffmpeg_and_ffprobe_available(self):
        """Verifies FFmpeg and FFprobe binaries are discovered on the system."""
        self.assertIsNotNone(get_ffmpeg_path(), "ffmpeg executable should be found")
        self.assertIsNotNone(get_ffprobe_path(), "ffprobe executable should be found")
        self.assertTrue(self.service.is_ffmpeg_available())
        self.assertTrue(self.service.is_ffprobe_available())

    def test_empty_audio_rejected(self):
        """Empty audio bytes must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.transcribe(b"", "empty.mp3")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_unsupported_format_rejected(self):
        """Unsupported file extensions must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.transcribe(b"fake data", "file.exe")
        self.assertIn("unsupported", str(ctx.exception).lower())

    def test_file_size_limit(self):
        """Files exceeding MAX_FILE_SIZE_BYTES must be rejected."""
        oversized = b"0" * (self.service.MAX_FILE_SIZE_BYTES + 1024)
        with self.assertRaises(ValueError) as ctx:
            self.service.transcribe(oversized, "huge.wav")
        self.assertIn("exceeds maximum limit", str(ctx.exception).lower())

    def test_supported_languages_and_default(self):
        """Verifies default language is Tamil (ta-IN) and locales are registered."""
        self.assertEqual(self.service.DEFAULT_LANGUAGE, "ta-IN")
        self.assertIn("ta-IN", self.service.SUPPORTED_LANGUAGES)
        self.assertIn("en-IN", self.service.SUPPORTED_LANGUAGES)
        self.assertIn("en-US", self.service.SUPPORTED_LANGUAGES)
        self.assertIn("hi-IN", self.service.SUPPORTED_LANGUAGES)

    def test_corrupted_audio_rejected(self):
        """Random binary garbage named .mp3 must be rejected by ffprobe format inspection."""
        corrupted_bytes = b"CORRUPTED_NOT_REAL_AUDIO_HEADER" * 10
        with self.assertRaises(ValueError) as ctx:
            self.service.transcribe(corrupted_bytes, "broken.mp3")
        err_msg = str(ctx.exception).lower()
        self.assertTrue("invalid" in err_msg or "corrupted" in err_msg or "no audio" in err_msg)

    def test_spoofed_text_as_mp3_rejected(self):
        """Text file with .mp3 extension must be rejected because it lacks an audio stream."""
        text_bytes = b"Hello, this is a plain text file pretending to be audio.mp3"
        with self.assertRaises(ValueError) as ctx:
            self.service.transcribe(text_bytes, "scam_spoofed.mp3")
        err_msg = str(ctx.exception).lower()
        self.assertTrue("no audio stream" in err_msg or "invalid" in err_msg or "corrupted" in err_msg)

    def test_ffprobe_probe_audio_on_real_opus(self):
        """Tests probe_audio on real OPUS audio."""
        opus_path = os.path.join(self.samples_dir, "sample.opus")
        if os.path.exists(opus_path):
            info = self.service.probe_audio(opus_path)
            self.assertEqual(info["codec_name"], "opus")
            self.assertGreater(info["duration"], 0.0)
            self.assertEqual(info["channels"], 1)

    def test_multi_format_conversion_and_transcription(self):
        """
        Tests universal conversion for OPUS, OGG, MP3, M4A, WAV, FLAC, AAC.
        Uses mocked recognizer to test speech-to-text pipeline without external Google network calls.
        """
        formats = ["sample.opus", "sample.ogg", "sample.mp3", "sample.m4a", "sample.wav", "sample.flac", "sample.aac"]

        for filename in formats:
            sample_path = os.path.join(self.samples_dir, filename)
            if not os.path.exists(sample_path):
                continue

            with open(sample_path, "rb") as f:
                file_bytes = f.read()

            with patch("speech_recognition.Recognizer.recognize_google", return_value="வணக்கம் உங்கள் கணக்கு முடக்கப்பட்டுள்ளது"):
                result = self.service.transcribe(file_bytes, filename=filename, language="ta-IN")
                self.assertTrue(result["success"])
                self.assertTrue(result["has_speech"])
                self.assertEqual(result["language"], "ta-IN")
                self.assertEqual(result["transcript"], "வணக்கம் உங்கள் கணக்கு முடக்கப்பட்டுள்ளது")
                self.assertIn("detected_codec", result)
                self.assertIn("duration_seconds", result)

    def test_testing1_opus_file(self):
        """Verifies transcription on the testing1.opus sample file."""
        opus_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scratch", "testing1.opus")
        if os.path.exists(opus_path):
            with open(opus_path, "rb") as f:
                opus_bytes = f.read()

            with patch("speech_recognition.Recognizer.recognize_google", return_value="கணக்கு சரிபார்ப்பு உடனடியாக தேவை"):
                result = self.service.transcribe(opus_bytes, filename="testing1.opus", language="ta-IN")
                self.assertTrue(result["success"])
                self.assertEqual(result["language"], "ta-IN")
                self.assertEqual(result["detected_codec"], "opus")
                self.assertEqual(result["transcript"], "கணக்கு சரிபார்ப்பு உடனடியாக தேவை")

    def test_tamil_default_and_english_routing(self):
        """Verifies that Tamil (ta-IN) is used by default and English (en-IN) is used when requested."""
        wav_path = os.path.join(self.samples_dir, "sample.wav")
        if not os.path.exists(wav_path):
            return

        with open(wav_path, "rb") as f:
            wav_bytes = f.read()

        # 1. Default language should be ta-IN
        with patch("speech_recognition.Recognizer.recognize_google") as mock_rec:
            mock_rec.return_value = "வணக்கம்"
            res = self.service.transcribe(wav_bytes, filename="sample.wav")
            mock_rec.assert_called_once()
            _, kwargs = mock_rec.call_args
            self.assertEqual(kwargs.get("language"), "ta-IN")
            self.assertEqual(res["language"], "ta-IN")

        # 2. Explicit en-IN should be respected
        with patch("speech_recognition.Recognizer.recognize_google") as mock_rec_en:
            mock_rec_en.return_value = "Your bank account has been compromised"
            res_en = self.service.transcribe(wav_bytes, filename="sample.wav", language="en-IN")
            mock_rec_en.assert_called_once()
            _, kwargs_en = mock_rec_en.call_args
            self.assertEqual(kwargs_en.get("language"), "en-IN")
            self.assertEqual(res_en["language"], "en-IN")


if __name__ == "__main__":
    unittest.main()

