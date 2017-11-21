# Automatically generated by pb2py
import protobuf as p
from .MultisigRedeemScriptType import MultisigRedeemScriptType


class GetAddress(p.MessageType):
    FIELDS = {
        1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
        2: ('coin_name', p.UnicodeType, 0),  # default='Bitcoin'
        3: ('show_display', p.BoolType, 0),
        4: ('multisig', MultisigRedeemScriptType, 0),
        5: ('script_type', p.UVarintType, 0),  # default=0
    }
    MESSAGE_WIRE_TYPE = 29