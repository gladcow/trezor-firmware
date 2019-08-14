from trezor import wire
from trezor.messages import MessageType


def boot():
    ns = [["secp256k1"]]
    wire.add(MessageType.DashSignProRegTx, __name__, "sign_dip2_tx", ns)
    wire.add(MessageType.DashSignProUpServTx, __name__, "sign_dip2_tx", ns)
    wire.add(MessageType.DashSignProUpRegTx, __name__, "sign_dip2_tx", ns)
    wire.add(MessageType.DashSignProUpRevTx, __name__, "sign_dip2_tx", ns)
