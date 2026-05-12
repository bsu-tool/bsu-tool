"""pcap-ng parsing for bsu-tool.

The parser is intentionally layered: this module decodes pcap-ng *block*
structure only. URB-level decoding of packet payloads belongs in a
separate module so the two layers can be tested independently.

Typical use::

    from pcapng.parser import PcapNgReader, EnhancedPacketBlock

    with open("capture.pcapng", "rb") as fp:
        for block in PcapNgReader(fp):
            if isinstance(block, EnhancedPacketBlock):
                ...  # do something with block.packet_data
"""

from __future__ import annotations

from .blocks import (
    Block,
    ByteOrder,
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    InterfaceStatisticsBlock,
    Option,
    SectionHeaderBlock,
    SimplePacketBlock,
    UnknownBlock,
)
from .errors import (
    InvalidBlockError,
    PcapNgError,
    TruncatedFileError,
    UnsupportedVersionError,
)
from .reader import PcapNgReader

__all__ = [
    "Block",
    "ByteOrder",
    "EnhancedPacketBlock",
    "InterfaceDescriptionBlock",
    "InterfaceStatisticsBlock",
    "InvalidBlockError",
    "Option",
    "PcapNgError",
    "PcapNgReader",
    "SectionHeaderBlock",
    "SimplePacketBlock",
    "TruncatedFileError",
    "UnknownBlock",
    "UnsupportedVersionError",
]
