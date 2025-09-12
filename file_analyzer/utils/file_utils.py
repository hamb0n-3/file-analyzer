#!/usr/bin/env python3
# File handling utilities

import logging
import json
from pathlib import Path
from typing import Tuple, Optional


def _looks_like_text(sample: bytes, threshold: float = 0.30) -> bool:
    """
    Heuristic to determine if a byte sample looks like text.

    - Reject if NUL bytes present
    - Compute ratio of non-printable bytes; consider text if below threshold
    """
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    # bytes considered printable (ASCII range + common whitespace)
    printable = set(range(32, 127)) | {9, 10, 13}
    nonprintable = sum(1 for b in sample if b not in printable)
    ratio = nonprintable / max(1, len(sample))
    return ratio <= threshold

def read_file_content(file_path: Path) -> Tuple[str, bool]:
    """
    Read the content of a file with proper error handling and binary detection.

    Returns (content, is_binary). For binary files, returns an empty string for
    content to avoid producing meaningless blob output downstream.
    """
    try:
        # Read a small sample to detect binary content reliably
        with open(file_path, 'rb') as fb:
            head = fb.read(8192)
        if not _looks_like_text(head):
            # Treat as binary; do not return hex dumps that create noisy matches
            return "", True

        # Looks like text: decode whole file as UTF-8 with replacement for safety
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as ft:
            content = ft.read()

        # Special handling for JSON files: pretty round-trip to normalize
        if file_path.suffix.lower() == '.json':
            try:
                json_content = json.loads(content)
                content = json.dumps(json_content)
            except json.JSONDecodeError as json_err:
                logging.info(
                    f"File {file_path} has invalid JSON syntax at {json_err}. Processing as text."
                )
        return content, False
    except Exception as e:
        # As a last resort, try text read; if that fails, treat as binary
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as ft:
                return ft.read(), False
        except Exception:
            logging.debug(f"Failed to read {file_path} as text: {e}")
            return "", True

def is_text_like_file(file_path: Path, sample_size: int = 8192) -> bool:
    """Quickly determine if a file appears to be text using a small sample.

    Returns True for text-like files, False for likely-binary files.
    """
    try:
        with open(file_path, 'rb') as fb:
            head = fb.read(sample_size)
        return _looks_like_text(head)
    except Exception:
        return False

def detect_file_type(file_path: Path) -> str:
    """
    Detect file type using magic numbers and file extensions.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Detected file type as a string
    """
    try:
        import magic
        file_type = magic.from_file(str(file_path))
        
        # Categorize the file type
        if "PE32" in file_type or "PE32+" in file_type:
            return "executable"
        elif "ELF" in file_type:
            return "executable"
        elif "Mach-O" in file_type:
            return "executable"
        elif any(x in file_type for x in ["text", "JSON", "XML", "ASCII"]):
            return "text"
        elif "data" in file_type or "binary" in file_type:
            return "binary"
        else:
            return file_type
    except ImportError:
        # Fallback to extension-based detection
        suffix = file_path.suffix.lower()
        if suffix in ['.exe', '.dll', '.sys', '.so', '.dylib']:
            return "executable"
        elif suffix in ['.txt', '.json', '.xml', '.html', '.js', '.py', '.java', '.c', '.cpp']:
            return "text"
        else:
            return "unknown"

def calculate_entropy(string: str) -> float:
    """
    Calculate Shannon entropy of a string to help identify randomness.
    Higher entropy suggests more randomness, which is typical of hashes.
    
    Args:
        string: The string to analyze
        
    Returns:
        The calculated entropy value
    """
    import math
    
    if not string:
        return 0.0
        
    # Handle both string and bytes input
    if isinstance(string, bytes):
        string = string.decode('utf-8', errors='ignore')
        
    freq_dict = {}
    for c in string:
        freq_dict[c] = freq_dict.get(c, 0) + 1
        
    length = len(string)
    entropy = 0
    
    for freq in freq_dict.values():
        probability = freq / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def is_valid_base64(string: str) -> bool:
    """
    Validate if a string is valid base64 encoded.
    
    Args:
        string: String to check
        
    Returns:
        True if valid base64, False otherwise
    """
    import base64
    import re
    
    if not string or len(string) < 40:
        return False
    # Must be multiple of 4 to be valid standard base64
    if len(string) % 4 != 0:
        return False
    # Valid alphabet and padding (validate=True enforces it too)
    if not re.fullmatch(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', string):
        return False
    try:
        decoded = base64.b64decode(string, validate=True)
        # Re-encode and compare (ignoring trailing '=' differences)
        reenc = base64.b64encode(decoded).decode('ascii').rstrip('=')
        return reenc == string.rstrip('=')
    except Exception:
        return False 
