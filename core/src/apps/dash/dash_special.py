import gc
from micropython import const
from ustruct import pack

from trezor import utils
from trezor.crypto import base58, bip32, cashaddr, der
from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import blake256, sha256
from trezor.messages import ButtonRequestType, FailureType, InputScriptType, OutputScriptType
from trezor.messages.TxInputType import TxInputType
from trezor.messages.TxOutputBinType import TxOutputBinType
from trezor.messages.TxOutputType import TxOutputType
from trezor.messages.TxRequest import TxRequest
from trezor.messages.TxRequestDetailsType import TxRequestDetailsType
from trezor.messages.TxRequestSerializedType import TxRequestSerializedType
from trezor import ui
from trezor.ui.text import Text
from trezor.utils import obj_eq

from apps.common import address_type, coininfo, coins, confirm, seed
from apps.wallet.sign_tx import (
    addresses,
    decred,
    helpers,
    multisig,
    progress,
    scripts,
    segwit_bip143,
    tx_weight,
    writers,
    zcash,
)

# the number of bip32 levels used in a wallet (chain and address)
_BIP32_WALLET_DEPTH = const(2)

# the chain id used for change
_BIP32_CHANGE_CHAIN = const(1)

# the maximum allowed change address.  this should be large enough for normal
# use and still allow to quickly brute-force the correct bip32 path
_BIP32_MAX_LAST_ELEMENT = const(1000000)


class SigningError(ValueError):
    pass


def _to_hex(data: bytes) -> str:
    return "".join("{:02x}".format(x) for x in data)


def _encode_compact_int(n):
    w = bytearray()
    if n < 253:
        w.append(n & 0xFF)
    elif n < 0x10000:
        w.append(253)
        w.append(n & 0xFF)
        w.append((n >> 8) & 0xFF)
    else:
        w.append(254)
        w.append(n & 0xFF)
        w.append((n >> 8) & 0xFF)
        w.append((n >> 16) & 0xFF)
        w.append((n >> 24) & 0xFF)
    return bytes(w)


def _get_proregtx_payload(tx, inputs_hash):
    r = bytes()
    r += pack("<H", tx.payload_version)
    r += pack('<H', tx.mn_type or 0)
    r += pack('<H', tx.mn_mode or 0)
    # collateral
    if tx.collateral_hash is None:
        for i in range(0, 32):
            r += b'\x00'
    else:
        r += bytes(reversed(tx.collateral_hash))
    r += pack('<I', tx.collateral_index or 0)
    if tx.ip_address is None:
        for i in range(0, 16):
            r += b'\x00'
    else:
        r += tx.ip_address
    r += pack(">H", tx.port or 0)
    r += tx.key_id_owner
    r += tx.pub_key_operator
    r += tx.key_id_voting
    r += pack("<H", tx.operator_reward or 0)
    r += _encode_compact_int(len(tx.script_payout))
    r += tx.script_payout
    r += inputs_hash
    if tx.payload_sig is not None:
        r += _encode_compact_int(tx.payload_sig)
        r += tx.payload_sig
    else:
        r += b"\x00"
    payload_size = len(r)
    r = _encode_compact_int(payload_size) + r
    return r


def _get_extra_payload(tx,  version, inputs_hash):
    tx_type = version >> 16
    if tx_type == 1:
        return _get_proregtx_payload(tx, inputs_hash)
    raise SigningError(
        FailureType.ProcessError,
        "Unknown Special Dash Transaction type"
    )


# Transaction signing
# ===
# see https://github.com/trezor/trezor-mcu/blob/master/firmware/signing.c#L84
# for pseudo code overview
# ===


class UIConfirmTxDetail:
    def __init__(self, title: str, data: str):
        self.title = title
        self.data = data

    __eq__ = obj_eq


async def confirm_tx_detail(ctx, title, data):
    text = Text(title, ui.ICON_SEND, icon_color=ui.GREEN)
    text.bold(data)
    return await confirm.require_confirm(ctx, text, ButtonRequestType.SignTx)


async def confirm_special_params(tx, version, coin):
    tx_type = version >> 16
    if tx_type == 1: # ProRegTx
        if not tx.payload_version == 1:
            raise SigningError(
                FailureType.ProcessError,
                "Unknown Dash Provider Register format version"
            )
        yield UIConfirmTxDetail(
            "Masternode type",
            "Type: {}, mode: {}".format(tx.mn_type, tx.mn_mode)
        )
        if tx.collateral_hash is None:
            yield UIConfirmTxDetail(
                "External collateral",
                "Empty"
            )
        else:
            yield UIConfirmTxDetail(
                "External collateral",
                "{}:{}".format(_to_hex(tx.collateral_hash), tx.collateral_index)
            )


# Phase 1
# - check inputs, previous transactions, and outputs
# - ask for confirmations
# - check fee
async def check_tx_fee(tx, version, keychain: seed.Keychain):
    coin = coins.by_name(tx.coin_name)

    # h_first is used to make sure the inputs and outputs streamed in Phase 1
    # are the same as in Phase 2.  it is thus not required to fully hash the
    # tx, as the SignTx info is streamed only once
    h_first = utils.HashWriter(sha256())  # not a real tx hash

    multifp = multisig.MultisigFingerprint()  # control checksum of multisig inputs
    weight = tx_weight.TxWeightCalculator(tx.inputs_count, tx.outputs_count)

    total_in = 0  # sum of input amounts
    total_out = 0  # sum of output amounts
    change_out = 0  # change output amount
    wallet_path = []  # common prefix of input paths

    # output structures
    txo_bin = TxOutputBinType()
    tx_req = TxRequest()
    tx_req.details = TxRequestDetailsType()

    h_inputs = utils.HashWriter(sha256())
    for i in range(tx.inputs_count):
        progress.advance()
        # STAGE_REQUEST_1_INPUT
        txi = await helpers.request_tx_input(tx_req, i)
        wallet_path = input_extract_wallet_path(txi, wallet_path)
        writers.write_tx_input_check(h_first, txi)
        weight.add_input(txi)
        writers.write_bytes_reversed(h_inputs, txi.prev_hash)
        writers.write_uint32(h_inputs, txi.prev_index)

        if not addresses.validate_full_path(txi.address_n, coin, txi.script_type):
            await helpers.confirm_foreign_address(txi.address_n)

        if txi.multisig:
            multifp.add(txi.multisig)

        if txi.script_type in (
            InputScriptType.SPENDADDRESS,
            InputScriptType.SPENDMULTISIG,
        ):
            total_in += await get_prevtx_output_value(
                coin, tx_req, txi.prev_hash, txi.prev_index
            )

        else:
            raise SigningError(FailureType.DataError, "Wrong input script type")

    for o in range(tx.outputs_count):
        # STAGE_REQUEST_3_OUTPUT
        txo = await helpers.request_tx_output(tx_req, o)
        txo_bin.amount = txo.amount
        txo_bin.script_pubkey = output_derive_script(txo, coin, keychain)
        weight.add_output(txo_bin.script_pubkey)
        if not txo.address_n:
            raise SigningError(
                FailureType.ActionCancelled,
                "Cannot send Dash special transaction to external address",
            )

        if change_out == 0 and output_is_change(txo, wallet_path, False, multifp):
            # output is change and does not need confirmation
            change_out = txo.amount
        elif not await helpers.confirm_output(txo, coin):
            raise SigningError(FailureType.ActionCancelled, "Output cancelled")

        writers.write_tx_output(h_first, txo_bin)
        total_out += txo_bin.amount

    fee = total_in - total_out
    if fee < 0:
        raise SigningError(FailureType.NotEnoughFunds, "Not enough funds")

    # fee > (coin.maxfee per byte * tx size)
    if fee > (coin.maxfee_kb / 1000) * (weight.get_total() / 4):
        if not await helpers.confirm_feeoverthreshold(fee, coin):
            raise SigningError(FailureType.ActionCancelled, "Signing cancelled")

    if tx.lock_time > 0:
        if not await helpers.confirm_nondefault_locktime(tx.lock_time):
            raise SigningError(FailureType.ActionCancelled, "Locktime cancelled")

    await confirm_special_params(tx, version, coin)
    # inputs hash should be double-sha256 hash
    h_double = utils.HashWriter(sha256())
    writers.write_bytes(h_double, h_inputs.get_digest())
    extra_payload = _get_extra_payload(tx, version, h_double.get_digest())
    # add extra_data to hash
    writers.write_bytes(h_first, bytes(extra_payload))

    if not await helpers.confirm_total(total_in - change_out, fee, coin):
        raise SigningError(FailureType.ActionCancelled, "Total cancelled")

    return h_first, h_double, total_in, wallet_path


async def sign_tx(tx, keychain: seed.Keychain):
    version = 3 | (1 << 16)
    tx.lock_time = tx.lock_time if tx.lock_time is not None else 0
    progress.init(tx.inputs_count, tx.outputs_count)

    # Phase 1

    h_first, h_inputs, authorized_in, wallet_path = await check_tx_fee(tx, version, keychain)

    # Phase 2
    # - sign inputs
    # - check that nothing changed

    coin = coins.by_name(tx.coin_name)
    tx_ser = TxRequestSerializedType()

    txo_bin = TxOutputBinType()
    tx_req = TxRequest()
    tx_req.details = TxRequestDetailsType()
    tx_req.serialized = None

    for i_sign in range(tx.inputs_count):
        progress.advance()
        txi_sign = None
        key_sign = None
        key_sign_pub = None

        # hash of what we are signing with this input
        h_sign = utils.HashWriter(sha256())
        # same as h_first, checked before signing the digest
        h_second = utils.HashWriter(sha256())

        writers.write_uint32(h_sign, version)  # nVersion
        writers.write_varint(h_sign, tx.inputs_count)

        for i in range(tx.inputs_count):
            # STAGE_REQUEST_4_INPUT
            txi = await helpers.request_tx_input(tx_req, i)
            input_check_wallet_path(txi, wallet_path)
            writers.write_tx_input_check(h_second, txi)
            if i == i_sign:
                txi_sign = txi
                key_sign = keychain.derive(txi.address_n, coin.curve_name)
                key_sign_pub = key_sign.public_key()
                # for the signing process the script_sig is equal
                # to the previous tx's scriptPubKey (P2PKH) or a redeem script (P2SH)
                if txi_sign.script_type == InputScriptType.SPENDMULTISIG:
                    txi_sign.script_sig = scripts.output_script_multisig(
                        multisig.multisig_get_pubkeys(txi_sign.multisig),
                        txi_sign.multisig.m,
                    )
                elif txi_sign.script_type == InputScriptType.SPENDADDRESS:
                    txi_sign.script_sig = scripts.output_script_p2pkh(
                        addresses.ecdsa_hash_pubkey(key_sign_pub, coin)
                    )
                else:
                    raise SigningError(
                        FailureType.ProcessError, "Unknown transaction type"
                    )
            else:
                txi.script_sig = bytes()
            writers.write_tx_input(h_sign, txi)

        writers.write_varint(h_sign, tx.outputs_count)

        for o in range(tx.outputs_count):
            # STAGE_REQUEST_4_OUTPUT
            txo = await helpers.request_tx_output(tx_req, o)
            txo_bin.amount = txo.amount
            txo_bin.script_pubkey = output_derive_script(txo, coin, keychain)
            writers.write_tx_output(h_second, txo_bin)
            writers.write_tx_output(h_sign, txo_bin)

        writers.write_uint32(h_sign, tx.lock_time)
        # add extra_data to hash
        extra_payload = _get_extra_payload(tx, version, h_inputs.get_digest())
        writers.write_bytes(h_second, bytes(extra_payload))
        writers.write_bytes(h_sign, bytes(extra_payload))
        writers.write_uint32(h_sign, get_hash_type(coin))

        # check the control digests
        if writers.get_tx_hash(h_first, False) != writers.get_tx_hash(h_second):
            raise SigningError(
                FailureType.ProcessError, "Transaction has changed during signing"
            )

        # if multisig, check if signing with a key that is included in multisig
        if txi_sign.multisig:
            multisig.multisig_pubkey_index(txi_sign.multisig, key_sign_pub)

        # compute the signature from the tx digest
        signature = ecdsa_sign(
            key_sign, writers.get_tx_hash(h_sign, double=coin.sign_hash_double)
        )
        tx_ser.signature_index = i_sign
        tx_ser.signature = signature

        # serialize input with correct signature
        gc.collect()
        txi_sign.script_sig = input_derive_script(
            coin, txi_sign, key_sign_pub, signature
        )
        w_txi_sign = writers.empty_bytearray(
            5 + len(txi_sign.prev_hash) + 4 + len(txi_sign.script_sig) + 4
        )
        if i_sign == 0:  # serializing first input => prepend headers
            writers.write_bytes(w_txi_sign, get_tx_header(tx, version))
        writers.write_tx_input(w_txi_sign, txi_sign)
        tx_ser.serialized_tx = w_txi_sign

        tx_req.serialized = tx_ser

    for o in range(tx.outputs_count):
        progress.advance()
        # STAGE_REQUEST_5_OUTPUT
        txo = await helpers.request_tx_output(tx_req, o)
        txo_bin.amount = txo.amount
        txo_bin.script_pubkey = output_derive_script(txo, coin, keychain)

        # serialize output
        w_txo_bin = writers.empty_bytearray(5 + 8 + 5 + len(txo_bin.script_pubkey) + 4)
        if o == 0:  # serializing first output => prepend outputs count
            writers.write_varint(w_txo_bin, tx.outputs_count)
        writers.write_tx_output(w_txo_bin, txo_bin)

        tx_ser.signature_index = None
        tx_ser.signature = None
        tx_ser.serialized_tx = w_txo_bin

        tx_req.serialized = tx_ser

    for i in range(tx.inputs_count):
        progress.advance()
        tx_req.serialized = tx_ser

    writers.write_uint32(tx_ser.serialized_tx, tx.lock_time)

    # add extra_data to serialized tx
    writers.write_bytes(tx_ser.serialized_tx, extra_payload)
    tx_req.serialized = tx_ser

    await helpers.request_tx_finish(tx_req)


async def get_prevtx_output_value(
    coin: coininfo.CoinInfo, tx_req: TxRequest, prev_hash: bytes, prev_index: int
) -> int:
    total_out = 0  # sum of output amounts

    # STAGE_REQUEST_2_PREV_META
    tx = await helpers.request_tx_meta(tx_req, prev_hash)

    txh = utils.HashWriter(sha256())

    writers.write_uint32(txh, tx.version)  # nVersion
    if tx.timestamp:
        writers.write_uint32(txh, tx.timestamp)

    writers.write_varint(txh, tx.inputs_cnt)

    for i in range(tx.inputs_cnt):
        # STAGE_REQUEST_2_PREV_INPUT
        txi = await helpers.request_tx_input(tx_req, i, prev_hash)
        writers.write_tx_input(txh, txi)

    writers.write_varint(txh, tx.outputs_cnt)

    for o in range(tx.outputs_cnt):
        # STAGE_REQUEST_2_PREV_OUTPUT
        txo_bin = await helpers.request_tx_output(tx_req, o, prev_hash)
        writers.write_tx_output(txh, txo_bin)
        if o == prev_index:
            total_out += txo_bin.amount

    writers.write_uint32(txh, tx.lock_time)

    ofs = 0
    while ofs < tx.extra_data_len:
        size = min(1024, tx.extra_data_len - ofs)
        data = await helpers.request_tx_extra_data(tx_req, ofs, size, prev_hash)
        writers.write_bytes(txh, data)
        ofs += len(data)

    if (
        writers.get_tx_hash(txh, double=coin.sign_hash_double, reverse=True)
        != prev_hash
    ):
        raise SigningError(FailureType.ProcessError, "Encountered invalid prev_hash")

    return total_out


# TX Helpers
# ===


def get_hash_type(coin: coininfo.CoinInfo) -> int:
    SIGHASH_FORKID = const(0x40)
    SIGHASH_ALL = const(0x01)
    hashtype = SIGHASH_ALL
    if coin.fork_id is not None:
        hashtype |= (coin.fork_id << 8) | SIGHASH_FORKID
    return hashtype


def get_tx_header(tx, version):
    w_txi = bytearray()
    writers.write_uint32(w_txi, version)
    writers.write_varint(w_txi, tx.inputs_count)
    return w_txi


# TX Outputs
# ===


def output_derive_script(
    o: TxOutputType, coin: coininfo.CoinInfo, keychain: seed.Keychain
) -> bytes:

    if o.script_type == OutputScriptType.PAYTOOPRETURN:
        # op_return output
        if o.amount != 0:
            raise SigningError(
                FailureType.DataError, "OP_RETURN output with non-zero amount"
            )
        return scripts.output_script_paytoopreturn(o.op_return_data)

    if o.address_n:
        # change output
        if o.address:
            raise SigningError(FailureType.DataError, "Address in change output")
        o.address = get_address_for_change(o, coin, keychain)
    else:
        if not o.address:
            raise SigningError(FailureType.DataError, "Missing address")

    if coin.cashaddr_prefix is not None and o.address.startswith(
        coin.cashaddr_prefix + ":"
    ):
        prefix, addr = o.address.split(":")
        version, data = cashaddr.decode(prefix, addr)
        if version == cashaddr.ADDRESS_TYPE_P2KH:
            version = coin.address_type
        elif version == cashaddr.ADDRESS_TYPE_P2SH:
            version = coin.address_type_p2sh
        else:
            raise ValueError("Unknown cashaddr address type")
        raw_address = bytes([version]) + data
    else:
        raw_address = base58.decode_check(o.address, coin.b58_hash)

    if address_type.check(coin.address_type, raw_address):
        # p2pkh
        pubkeyhash = address_type.strip(coin.address_type, raw_address)
        script = scripts.output_script_p2pkh(pubkeyhash)
        return script

    elif address_type.check(coin.address_type_p2sh, raw_address):
        # p2sh
        scripthash = address_type.strip(coin.address_type_p2sh, raw_address)
        script = scripts.output_script_p2sh(scripthash)
        if coin.bip115:
            script += scripts.script_replay_protection_bip115(
                o.block_hash_bip115, o.block_height_bip115
            )
        return script

    raise SigningError(FailureType.DataError, "Invalid address type")


def get_address_for_change(
    o: TxOutputType, coin: coininfo.CoinInfo, keychain: seed.Keychain
):
    if o.script_type == OutputScriptType.PAYTOADDRESS:
        input_script_type = InputScriptType.SPENDADDRESS
    elif o.script_type == OutputScriptType.PAYTOMULTISIG:
        input_script_type = InputScriptType.SPENDMULTISIG
    else:
        raise SigningError(FailureType.DataError, "Invalid script type")
    node = keychain.derive(o.address_n, coin.curve_name)
    return addresses.get_address(input_script_type, coin, node, o.multisig)


def output_is_change(
    o: TxOutputType,
    wallet_path: list,
    segwit_in: int,
    multifp: multisig.MultisigFingerprint,
) -> bool:
    if o.multisig and not multifp.matches(o.multisig):
        return False
    return (
        wallet_path is not None
        and wallet_path == o.address_n[:-_BIP32_WALLET_DEPTH]
        and o.address_n[-2] <= _BIP32_CHANGE_CHAIN
        and o.address_n[-1] <= _BIP32_MAX_LAST_ELEMENT
    )


# Tx Inputs
# ===


def input_derive_script(
    coin: coininfo.CoinInfo, i: TxInputType, pubkey: bytes, signature: bytes = None
) -> bytes:
    if i.script_type == InputScriptType.SPENDADDRESS:
        # p2pkh or p2sh
        return scripts.input_script_p2pkh_or_p2sh(
            pubkey, signature, get_hash_type(coin)
        )

    elif i.script_type == InputScriptType.SPENDMULTISIG:
        # p2sh multisig
        signature_index = multisig.multisig_pubkey_index(i.multisig, pubkey)
        return scripts.input_script_multisig(
            i.multisig, signature, signature_index, get_hash_type(coin), coin
        )

    else:
        raise SigningError(FailureType.ProcessError, "Invalid script type")


def input_extract_wallet_path(txi: TxInputType, wallet_path: list) -> list:
    if wallet_path is None:
        return None  # there was a mismatch in previous inputs
    address_n = txi.address_n[:-_BIP32_WALLET_DEPTH]
    if not address_n:
        return None  # input path is too short
    if not wallet_path:
        return address_n  # this is the first input
    if wallet_path == address_n:
        return address_n  # paths match
    return None  # paths don't match


def input_check_wallet_path(txi: TxInputType, wallet_path: list) -> list:
    if wallet_path is None:
        return  # there was a mismatch in Phase 1, ignore it now
    address_n = txi.address_n[:-_BIP32_WALLET_DEPTH]
    if wallet_path != address_n:
        raise SigningError(
            FailureType.ProcessError, "Transaction has changed during signing"
        )


def ecdsa_sign(node: bip32.HDNode, digest: bytes) -> bytes:
    sig = secp256k1.sign(node.private_key(), digest)
    sigder = der.encode_seq((sig[1:33], sig[33:65]))
    return sigder
