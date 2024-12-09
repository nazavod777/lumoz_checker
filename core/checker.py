import asyncio
from time import time

import aiohttp
from eth_account import Account
from eth_account.account import LocalAccount
from eth_account.messages import encode_defunct
from loguru import logger
from tenacity import retry

from utils import append_file
from utils import get_proxy
from utils import loader

Account.enable_unaudited_hdwallet_features()


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 client: aiohttp.ClientSession,
                 account: LocalAccount):
        self.client: aiohttp.ClientSession = client
        self.account: LocalAccount = account

    @retry(after=log_retry_error)
    async def _check_eligible(self) -> tuple[float, float, int, int, int]:
        response_text: None = None

        try:
            current_time: int = int(time())
            signed_message_hash: str = self.account.sign_message(
                signable_message=encode_defunct(
                    text=f'{current_time}GET/api/lumoz-airdrop?address={self.account.address}')).signature.hex()

            r: aiohttp.ClientResponse = await self.client.get(
                url=f'https://nfts-api.lumoz.org/api/nft/user_details',
                params={
                    'address': self.account.address
                },
                proxy=get_proxy(),
                headers={
                    'api-signature': signed_message_hash if signed_message_hash.startswith(
                        '0x') else f'0x{signed_message_hash}',
                    'timestamp': str(current_time),
                }
            )

            response_text: str = await r.text()
            response_json: dict = await r.json(content_type=None)

            return float(response_json['data']['esmoz']) / 10 ** 18, float(
                response_json['data']['moz']) / 10 ** 18, int(response_json['data']['unclaimed_nft']['nft_0']), int(
                response_json['data']['unclaimed_nft']['nft_1']), int(response_json['data']['unclaimed_nft']['nft_2'])

        except Exception as error:
            raise Exception(
                f'{self.account.address} | Unexpected Error When Checking Eligible: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def check_account(self) -> None:
        esmoz_balance, moz_balance, nft_0, nft_1, nft_2 = await self._check_eligible()

        if sum([esmoz_balance, moz_balance, nft_0, nft_1, nft_2]) <= 0:
            logger.error(f'{self.account.address} | Not Eligible')
            return

        async with asyncio.Lock():
            await append_file(
                file_path='result/eligible.txt',
                file_content=f'{self.account.key.hex()} | {esmoz_balance} $ESMOZ | {moz_balance} $MOZ | {nft_0} NFT 0 | {nft_1} NFT 1 | {nft_2} NFT 2\n'
            )

        logger.success(
            f'{self.account.key.hex()} | {esmoz_balance} $ESMOZ | {moz_balance} $MOZ | {nft_0} NFT 0 | {nft_1} NFT 1 | {nft_2} NFT 2')


async def check_account(
        client: aiohttp.ClientSession,
        account_data: str
) -> None:
    async with loader.semaphore:
        account: None = None

        try:
            account: LocalAccount = Account.from_key(private_key=account_data)

        except Exception:
            pass

        if not account:
            try:
                account: LocalAccount = Account.from_mnemonic(mnemonic=account_data)

            except Exception:
                pass

        if not account:
            logger.error(f'{account_data} | Not Mnemonic and not PKey')
            return

        checker: Checker = Checker(
            client=client,
            account=account
        )
        await checker.check_account()
