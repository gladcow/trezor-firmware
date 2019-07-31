# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from trezorlib import dash, messages as proto
from trezorlib.tools import parse_path

from ..support.tx_cache import tx_cache
from .common import TrezorTest

TX_API = tx_cache("Dash")


class TestMsgDashSignSpecial(TrezorTest):
    def test_send_dash_dip2_proregtx(self):
        self.setup_mnemonic_allallall()
        inp1 = proto.TxInputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            # dash testnet:ybQPZRHKifv9BDqMN2cieCsMzQQ1BuDoR5
            amount=100710000000,
            prev_hash=bytes.fromhex(
                "696e01be235c7d08da1ac4cafeb186185b6e222a62de31ad6f1a80cb8ff3c58d"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDADDRESS,
        )
        out1 = proto.TxOutputType(
            address_n=parse_path("44'/1'/0'/0/0/0"),
            amount=100000000000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=709999000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        txdata = proto.DashSignProRegTx(
            coin_name="Dash Testnet",
            payload_version=1,
            key_id_owner=bytes.fromhex("c5a2d505da4f03b2776f588e4fee0118248dc044"),
            pub_key_operator=bytes.fromhex("126d93a264c52fb494ed0eaa6ae71c2843fccf152e42b436193e16218256080339155421de6ecb19bede83b125ac0d50"),
            key_id_voting=bytes.fromhex("c5a2d505da4f03b2776f588e4fee0118248dc044"),
            script_payout=bytes.fromhex("76a914a579388225827d9f2fe9014add644487808c695d88ac")
        )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXMETA,
                        details=proto.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = dash.sign_special_tx(
                self.client,
                [inp1],
                [out1, out2],
                details=txdata,
                prev_txes=TX_API,
            )
        assert (
            serialized_tx.hex()
            == "03000100018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b483045022100f3ba5d64e79d68228de39f5ffd14d26324d5346f4808420fd90698267b598449022022bebdab8def40d07d4cce5df7d45420e656436bb3f48b95bbfc005ea40aabf10121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0200e87648170000001976a9149e87e0cb3156d46468dde382b57964a9810991c088ac98b9512a000000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000d1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5a2d505da4f03b2776f588e4fee0118248dc044126d93a264c52fb494ed0eaa6ae71c2843fccf152e42b436193e16218256080339155421de6ecb19bede83b125ac0d50c5a2d505da4f03b2776f588e4fee0118248dc04400001976a914a579388225827d9f2fe9014add644487808c695d88acc3803e9de251fdfe2f6fa200638ae4675511ec0bf0180983ea7a0ab2acd7a50000"
        )

    def test_send_dash_dip2_proregtx_external(self):
        self.setup_mnemonic_allallall()
        inp1 = proto.TxInputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            # dash testnet:ybQPZRHKifv9BDqMN2cieCsMzQQ1BuDoR5
            amount=100710000000,
            prev_hash=bytes.fromhex(
                "696e01be235c7d08da1ac4cafeb186185b6e222a62de31ad6f1a80cb8ff3c58d"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDADDRESS,
        )
        out1 = proto.TxOutputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=100709999750,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        collateral_hash = bytes.fromhex(
                "23464abc2f724de235e69e72ef5068f1b2701521b88e7b2740b93978ff54909b"
            )
        collateral_out = 1
        txdata = proto.DashSignProRegTx(
            coin_name="Dash Testnet",
            payload_version=1,
            collateral_hash=collateral_hash,
            collateral_index=collateral_out,
            ip_address=bytes.fromhex("00000000000000000000ffffc6c74af1"),
            port=19999,
            key_id_owner=bytes.fromhex("c5a2d505da4f03b2776f588e4fee0118248dc044"),
            pub_key_operator=bytes.fromhex("972f4481e23ea3b34a974349c44d8b96974ffb1e83cecb879564dcaa8b3ef58d84866dd672ad3d2db73904a9fa5c3b06"),
            key_id_voting=bytes.fromhex("c5a2d505da4f03b2776f588e4fee0118248dc044"),
            operator_reward=2315,
            script_payout=bytes.fromhex("76a914a579388225827d9f2fe9014add644487808c695d88ac"),
            payload_sig=bytes.fromhex("2008ed82d28a503a49dc925b99b386876921958cc528134280ea4d5de6935b6b342cba08fda8e25701ae5efa8baa3a1fae12c2f2a1e044a4f42161b429eb994f5d")
        )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXMETA,
                        details=proto.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=collateral_out,
                            tx_hash=collateral_hash
                        ),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = dash.sign_special_tx(
                self.client,
                [inp1],
                [out1],
                details=txdata,
                prev_txes=TX_API,
                external_txes=[collateral_hash],
            )
        assert (
            serialized_tx.hex()
            == "03000100018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b483045022100bcdd402ec925b970aac0cd903f8165d670567b0781dfbf256a46b55f95d58b2d022060924bf9723ffe4048525d0f4a7a306164cc6c5cd120b6db8b71c8ec90742a310121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0186a4c872170000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000fd12010100000000009b9054ff7839b940277b8eb8211570b2f16850ef729ee635e24d722fbc4a46230100000000000000000000000000ffffc6c74af14e1fc5a2d505da4f03b2776f588e4fee0118248dc044972f4481e23ea3b34a974349c44d8b96974ffb1e83cecb879564dcaa8b3ef58d84866dd672ad3d2db73904a9fa5c3b06c5a2d505da4f03b2776f588e4fee0118248dc0440b091976a914a579388225827d9f2fe9014add644487808c695d88acc3803e9de251fdfe2f6fa200638ae4675511ec0bf0180983ea7a0ab2acd7a500412008ed82d28a503a49dc925b99b386876921958cc528134280ea4d5de6935b6b342cba08fda8e25701ae5efa8baa3a1fae12c2f2a1e044a4f42161b429eb994f5d"
        )

