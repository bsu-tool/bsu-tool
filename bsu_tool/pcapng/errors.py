"""Exceptions raised by the pcap-ng parser.

All parser-level exceptions inherit from :class:`PcapNgError`, so callers that
just want to report parse failures can catch a single base class.
"""

from __future__ import annotations


class PcapNgError(Exception):
    """Base class for all pcap-ng parser errors."""


class TruncatedFileError(PcapNgError):
    """Raised when the input stream ends in the middle of a block.

    This is distinct from a clean end-of-stream between blocks, which the
    reader signals via normal iterator termination (``StopIteration``).
    """


class InvalidBlockError(PcapNgError):
    """Raised when a block is structurally invalid.

    Examples include: a block-total-length that is not a multiple of 4,
    a leading and trailing total-length that disagree, an option whose
    declared length runs off the end of the block, or a Section Header
    Block with an unrecognized byte-order magic.
    """


class UnsupportedVersionError(PcapNgError):
    """Raised when a Section Header Block declares a major version we do not support.

    We accept pcap-ng major version 1; any other value raises this.
    """
