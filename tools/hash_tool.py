"""
hash_tool — 常见密码哈希识别与弱口令尝试。
"""
from __future__ import annotations

import hashlib
from typing import Any

from tools.web_utils import normalize_string_list

_COMMON_WORDS = [
    "admin", "administrator", "password", "123456", "12345678",
    "qwerty", "welcome", "letmein", "passw0rd", "secret",
    "changeme", "root", "toor", "test", "guest",
]


def hash_crack(
    hash_value: str,
    extra_words: list[str] | str | None = None,
    salt: str = "",
) -> dict[str, Any]:
    """
    识别常见 MD5/SHA1/SHA256/SHA512 哈希，并尝试用内置弱口令字典破解。
    """
    hash_value = hash_value.strip()
    algorithms = _guess_algorithms(hash_value)
    words = _COMMON_WORDS + normalize_string_list(extra_words)

    for algorithm in algorithms:
        for word in words:
            for candidate in _candidates(word, salt):
                digest = hashlib.new(algorithm, candidate.encode()).hexdigest()
                if digest.lower() == hash_value.lower():
                    return {
                        "matched": True,
                        "algorithm": algorithm,
                        "plaintext": word,
                        "tested_words": len(words),
                        "salt_used": salt,
                    }

    return {
        "matched": False,
        "algorithms": algorithms,
        "tested_words": len(words),
        "salt_used": salt,
    }


def _guess_algorithms(hash_value: str) -> list[str]:
    length_map = {
        32: ["md5"],
        40: ["sha1"],
        64: ["sha256"],
        128: ["sha512"],
    }
    return length_map.get(len(hash_value), ["md5", "sha1", "sha256"])


def _candidates(word: str, salt: str) -> list[str]:
    if not salt:
        return [word]
    return [word, f"{salt}{word}", f"{word}{salt}"]
