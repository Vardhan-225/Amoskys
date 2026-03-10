"""AMOSKYS Shared Agents — Platform-agnostic agent implementations.

These agents work on any platform (macOS, Linux, Windows) using cross-platform
data sources (psutil, socket, os module). On macOS, Observatory agents in
agents/os/macos/ provide ground-truth verified implementations with higher
probe counts. These shared implementations serve as the default for Linux
and Windows until platform-specific Observatory agents are built.
"""
