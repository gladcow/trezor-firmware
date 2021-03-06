# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class NEMProvisionNamespace(p.MessageType):

    def __init__(
        self,
        namespace: str = None,
        parent: str = None,
        sink: str = None,
        fee: int = None,
    ) -> None:
        self.namespace = namespace
        self.parent = parent
        self.sink = sink
        self.fee = fee

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('namespace', p.UnicodeType, 0),
            2: ('parent', p.UnicodeType, 0),
            3: ('sink', p.UnicodeType, 0),
            4: ('fee', p.UVarintType, 0),
        }
