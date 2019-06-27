# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class DashSignProUpServTx(p.MessageType):
    MESSAGE_WIRE_TYPE = 751

    def __init__(
        self,
        outputs_count: int = None,
        inputs_count: int = None,
        coin_name: str = None,
        lock_time: int = None,
        payload_version: int = None,
        protx_hash: bytes = None,
        ip_address: bytes = None,
        port: int = None,
        script_payout: bytes = None,
        payload_sig: bytes = None,
    ) -> None:
        self.outputs_count = outputs_count
        self.inputs_count = inputs_count
        self.coin_name = coin_name
        self.lock_time = lock_time
        self.payload_version = payload_version
        self.protx_hash = protx_hash
        self.ip_address = ip_address
        self.port = port
        self.script_payout = script_payout
        self.payload_sig = payload_sig

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('outputs_count', p.UVarintType, 0),  # required
            2: ('inputs_count', p.UVarintType, 0),  # required
            3: ('coin_name', p.UnicodeType, 0),  # default=Dash
            4: ('lock_time', p.UVarintType, 0),  # default=0
            5: ('payload_version', p.UVarintType, 0),  # default=1
            6: ('protx_hash', p.BytesType, 0),
            7: ('ip_address', p.BytesType, 0),
            8: ('port', p.UVarintType, 0),
            9: ('script_payout', p.BytesType, 0),
            10: ('payload_sig', p.BytesType, 0),
        }
