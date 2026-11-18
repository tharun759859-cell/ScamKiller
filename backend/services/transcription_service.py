"""
SCAM KILLER — Universal Audio Transcription Service
Universal audio format conversion (OPUS, OGG, MP3, M4A, AAC, WAV, FLAC, WEBM, MP4, AIFF, AMR, 3GP)
using FFmpeg and FFprobe for call recordings and voice messages.
Defaults to Tamil (India) — ta-IN, with English (India) — en-IN and multilingual support.
Enforces zero-storage policy: temporary audio and converted WAV files are immediately deleted.
"""

import os
import json
import logging
import tempfile
import subprocess
import shutil
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger("scam_killer.transcription")


def get_ffmpeg_path() -> Optional[str]:
    """Locates the ffmpeg executable on the system."""
    env_path = os.environ.get("FFMPEG_PATH")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    which_path = shutil.which("ffmpeg")
    if which_path:
        return which_path

    for candidate in [
        "/opt/homebrew/bin/ffmpeg",
        "/usr/local/bin/ffmpeg",
        "/usr/bin/ffmpeg"
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def get_ffprobe_path() -> Optional[str]:
    """Locates the ffprobe executable on the system."""
    env_path = os.environ.get("FFPROBE_PATH")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    which_path = shutil.which("ffprobe")
    if which_path:
        return which_path

    for candidate in [
        "/opt/homebrew/bin/ffprobe",
        "/usr/local/bin/ffprobe",
        "/usr/bin/ffprobe"
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


class TranscriptionService:
    """Manages universal audio inspection, conversion via FFmpeg, and speech recognition."""

    DEFAULT_LANGUAGE = "ta-IN"

    SUPPORTED_EXTENSIONS = {
        ".opus", ".ogg", ".oga", ".mp3", ".m4a", ".aac", ".wav",
        ".flac", ".webm", ".weba", ".mp4", ".aiff", ".aif", ".amr",
        ".3gp", ".3gpp", ".caf", ".m4r"
    }

    MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024  # 32MB limit

    SUPPORTED_LANGUAGES = {
        "ta-IN": "Tamil (India)",
        "en-IN": "English (India)",
        "en-US": "English (United States)",
        "en-GB": "English (United Kingdom)",
        "hi-IN": "Hindi (India)",
        "ta-LK": "Tamil (Sri Lanka)"
    }

    def __init__(self):
        self._sr_module = None
        try:
            import speech_recognition as sr
            self._sr_module = sr
        except ImportError:
            self._sr_module = None

    def is_engine_available(self) -> bool:
        """Returns True if speech_recognition is installed."""
        return self._sr_module is not None

    def is_ffmpeg_available(self) -> bool:
        """Returns True if ffmpeg executable is discovered."""
        return get_ffmpeg_path() is not None

    def is_ffprobe_available(self) -> bool:
        """Returns True if ffprobe executable is discovered."""
        return get_ffprobe_path() is not None

    def _infer_extension(self, file_bytes: bytes) -> str:
        """Infers audio extension from header magic bytes for extensionless uploads."""
        if len(file_bytes) < 12:
            return ""

        if file_bytes.startswith(b"RIFF") and file_bytes[8:12] == b"WAVE":
            return ".wav"
        if file_bytes.startswith(b"ID3") or file_bytes[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
            return ".mp3"
        if file_bytes[4:8] == b"ftyp":
            brand = file_bytes[8:12].lower()
            if brand.startswith(b"3gp"):
                return ".3gp"
            return ".m4a"
        if file_bytes.startswith(b"OggS"):
            return ".opus" if b"OpusHead" in file_bytes[:100] else ".ogg"
        if file_bytes.startswith(b"fLaC"):
            return ".flac"
        if file_bytes.startswith(b"#!AMR"):
            return ".amr"
        if file_bytes.startswith(b"FORM") and file_bytes[8:12] in (b"AIFF", b"AIFC"):
            return ".aiff"
        if file_bytes.startswith(b"caff"):
            return ".caf"
        if file_bytes.startswith(b"\x1a\x45\xdf\xa3"):
            return ".webm"

        return ""

    def validate_audio(self, file_bytes: bytes, filename: str) -> Tuple[bool, str, str]:
        """
        Validates file size and extension.
        Returns: (is_valid, error_message, file_extension)
        """
        if not file_bytes:
            return False, "Uploaded audio recording is empty.", ""

        if len(file_bytes) > self.MAX_FILE_SIZE_BYTES:
            size_mb = len(file_bytes) / (1024 * 1024)
            return False, f"Audio file exceeds maximum limit of 32MB (uploaded size: {size_mb:.1f}MB). Please upload a shorter clip.", ""

        _, ext = os.path.splitext(filename.lower())
        if not ext or ext == ".":
            ext = self._infer_extension(file_bytes)

        if not ext or ext not in self.SUPPORTED_EXTENSIONS:
            supported_list = ", ".join(sorted(self.SUPPORTED_EXTENSIONS))
            return False, f"Unsupported audio format '{ext}'. Supported formats: {supported_list}", ""

        return True, "", ext

    def probe_audio(self, file_path: str) -> Dict[str, Any]:
        """
        Inspects actual container and codec using ffprobe.
        Does not assume that changing a file extension changes the format.
        """
        ffprobe_bin = get_ffprobe_path()
        if not ffprobe_bin:
            return {
                "format_name": "unknown",
                "codec_name": "unknown",
                "duration": 0.0,
                "channels": 1,
                "sample_rate": 16000
            }

        cmd = [
            ffprobe_bin,
            "-v", "error",
            "-show_entries", "format=format_name,duration,size,bit_rate:stream=index,codec_name,codec_type,channels,sample_rate",
            "-print_format", "json",
            file_path
        ]

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                shell=False
            )
            if res.returncode != 0:
                err_text = res.stderr.strip() or "Invalid audio stream"
                raise ValueError(f"The uploaded file is not a valid audio recording or is corrupted ({err_text}).")

            probe_data = json.loads(res.stdout or "{}")
            streams = probe_data.get("streams", [])
            audio_streams = [s for s in streams if s.get("codec_type") == "audio"]

            if not audio_streams:
                raise ValueError("No audio stream found in the uploaded file.")

            audio_stream = audio_streams[0]
            format_info = probe_data.get("format", {})

            duration_raw = audio_stream.get("duration") or format_info.get("duration") or 0.0
            try:
                duration_sec = float(duration_raw)
            except (ValueError, TypeError):
                duration_sec = 0.0

            if duration_sec < 0:
                raise ValueError("Uploaded audio recording contains invalid or zero duration.")

            return {
                "format_name": format_info.get("format_name", "unknown"),
                "codec_name": audio_stream.get("codec_name", "unknown"),
                "duration": duration_sec,
                "channels": int(audio_stream.get("channels", 1)),
                "sample_rate": int(audio_stream.get("sample_rate", 16000))
            }

        except subprocess.TimeoutExpired:
            raise RuntimeError("Audio format inspection timed out.")
        except json.JSONDecodeError:
            raise ValueError("Failed to inspect audio metadata: invalid ffprobe response.")

    def convert_to_pcm_wav(self, src_path: str, dst_path: str) -> str:
        """
        Converts any supported input audio format into standardized PCM WAV:
        - WAV container
        - PCM signed 16-bit audio (pcm_s16le)
        - 16 kHz sample rate (-ar 16000)
        - Mono channel (-ac 1)
        """
        ffmpeg_bin = get_ffmpeg_path()
        if ffmpeg_bin:
            cmd = [
                ffmpeg_bin,
                "-y",
                "-i", src_path,
                "-vn",                 # strip video streams (e.g. 3GP/MP4/WEBM)
                "-c:a", "pcm_s16le",   # PCM signed 16-bit
                "-ar", "16000",        # 16 kHz sample rate
                "-ac", "1",            # Mono channel
                dst_path
            ]
            try:
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                    shell=False
                )
                if res.returncode == 0 and os.path.exists(dst_path) and os.path.getsize(dst_path) > 44:
                    return dst_path
                else:
                    err_msg = res.stderr.strip() or "FFmpeg conversion returned non-zero code."
                    logger.warning(f"FFmpeg conversion failed: {err_msg}")
            except subprocess.TimeoutExpired:
                raise RuntimeError("Audio conversion timed out after 30 seconds.")
            except Exception as exc:
                logger.warning(f"FFmpeg conversion exception: {exc}")

        # Fallback to macOS native afconvert for native audio formats
        if os.path.exists("/usr/bin/afconvert"):
            cmd = ["/usr/bin/afconvert", "-f", "WAVE", "-d", "LEI16", "-c", "1", "-r", "16000", src_path, dst_path]
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
                if res.returncode == 0 and os.path.exists(dst_path) and os.path.getsize(dst_path) > 44:
                    return dst_path
            except Exception as exc:
                logger.warning(f"afconvert failed: {exc}")

        # If already a valid wav and tools failed, check if SpeechRecognition can read it
        if src_path.lower().endswith(".wav"):
            return src_path

        raise RuntimeError(
            "Unable to transcode audio file into PCM WAV. Please verify that FFmpeg is installed and the audio codec is valid."
        )

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str = "audio.wav",
        language: str = DEFAULT_LANGUAGE
    ) -> Dict[str, Any]:
        """
        Universal audio transcription pipeline:
        Upload audio -> Validate file -> Detect actual format -> Convert using FFmpeg -> Speech-to-text -> Return transcription.
        Guarantees zero persistent audio storage by removing all temporary files in finally.
        """
        # 1. Validate size and extension
        is_valid, err_msg, ext = self.validate_audio(file_bytes, filename)
        if not is_valid:
            raise ValueError(err_msg)

        if not self.is_engine_available():
            raise RuntimeError("Speech recognition engine is not installed in the environment (missing SpeechRecognition package).")

        # Resolve selected language (Defaults strictly to ta-IN: Tamil India)
        target_lang = language if language in self.SUPPORTED_LANGUAGES else self.DEFAULT_LANGUAGE

        temp_dir = tempfile.mkdtemp(prefix="scam_audio_")
        input_file = os.path.join(temp_dir, f"input{ext}")
        wav_file = os.path.join(temp_dir, "normalized.wav")

        try:
            # Write uploaded bytes to secure ephemeral temp file
            with open(input_file, "wb") as f:
                f.write(file_bytes)

            # 2. Inspect actual container and codec using ffprobe
            format_info = self.probe_audio(input_file)

            # 3. Convert to standard 16-bit PCM single-channel 16kHz WAV using FFmpeg
            target_wav = self.convert_to_pcm_wav(input_file, wav_file)

            # 4. Perform Speech Recognition
            sr = self._sr_module
            recognizer = sr.Recognizer()

            with sr.AudioFile(target_wav) as source:
                # Capture audio data
                audio_data = recognizer.record(source)

            # Transcribe via Speech Recognition API with selected language code
            try:
                transcript = recognizer.recognize_google(audio_data, language=target_lang)
            except sr.UnknownValueError:
                return {
                    "success": True,
                    "transcript": "",
                    "has_speech": False,
                    "language": target_lang,
                    "language_label": self.SUPPORTED_LANGUAGES.get(target_lang, target_lang),
                    "filename": filename,
                    "detected_format": format_info.get("format_name", "unknown"),
                    "detected_codec": format_info.get("codec_name", "unknown"),
                    "duration_seconds": round(format_info.get("duration", 0.0), 2),
                    "engine": "Google Speech Recognition (FFmpeg Universal Converter)",
                    "message": "No intelligible speech was detected in the audio file. The recording may be silent, muffled, or spoken in another language."
                }
            except sr.RequestError as req_err:
                raise RuntimeError(f"Speech recognition service request error: {str(req_err)}")

            clean_transcript = str(transcript or "").strip()
            word_count = len(clean_transcript.split()) if clean_transcript else 0

            return {
                "success": True,
                "transcript": clean_transcript,
                "has_speech": word_count > 0,
                "word_count": word_count,
                "character_count": len(clean_transcript),
                "language": target_lang,
                "language_label": self.SUPPORTED_LANGUAGES.get(target_lang, target_lang),
                "filename": filename,
                "detected_format": format_info.get("format_name", "unknown"),
                "detected_codec": format_info.get("codec_name", "unknown"),
                "duration_seconds": round(format_info.get("duration", 0.0), 2),
                "engine": "Google Speech Recognition (FFmpeg Universal Converter)",
                "message": "Audio recording transcribed successfully."
            }

        finally:
            # 5. Zero-Storage Policy: Purge temporary files immediately
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

