"""Small trust-oriented adapter around the existing HexWarden analyzers."""

from .scanner import analyze_firmware

__all__ = ["analyze_firmware"]