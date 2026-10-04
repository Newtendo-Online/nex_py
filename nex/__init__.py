"""nex — port Python de PretendoNetwork/nex-go (branche `splatoon`).

Convention de nommage : méthodes Go `Bytes()` -> `to_bytes()`, getters/setters
-> attributs publics, `(valeur, error)` -> exceptions `NexError`.
"""
from .client import Client
from .compression import DummyCompression, ZLibCompression
from .counter import Counter
from .errors import ERROR_MASK, ERROR_NAMES, Errors, NexError, error_name_from_code
from .kerberos import (KerberosEncryption, Ticket, TicketInternalData,
                       derive_kerberos_key)
from .nex_types import (Data, DataHolder, DateTime, Result, ResultRange,
                        RVConnectionData, StationURL, Structure,
                        register_data_holder_type)
from .packet import Packet
from .packet_flags import (FLAG_ACK, FLAG_HAS_SIZE, FLAG_MULTI_ACK,
                           FLAG_NEEDS_ACK, FLAG_RELIABLE)
from .packet_types import (CONNECT_PACKET, DATA_PACKET, DISCONNECT_PACKET,
                           PING_PACKET, SYN_PACKET)
from .packet_v0 import PacketV0
from .packet_v1 import (OPTION_ALL_FUNCTIONS, OPTION_CONNECTION_SIGNATURE,
                        OPTION_FRAGMENT_ID, OPTION_INITIAL_SEQUENCE_ID,
                        OPTION_MAX_SUBSTREAM_ID, OPTION_SUPPORTED_FUNCTIONS,
                        PacketV1)
from .rc4 import RC4
from .rmc import RMCRequest, RMCResponse
from .server import Server
from .stream_in import StreamIn
from .stream_out import StreamOut
from .utils import logger, md5_hash, sum_bytes
