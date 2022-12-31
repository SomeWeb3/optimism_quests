from web3 import Web3
from web3.eth import AsyncEth
import asyncio
import json
from loguru import logger
import random
import time
from dotenv import load_dotenv
from os import environ

load_dotenv()
time_sleep = eval(environ["SLEEP"])

RPC = 'https://rpc.ankr.com/optimism'
web3 = Web3(Web3.AsyncHTTPProvider(RPC),
            modules={'eth': (AsyncEth,)}, middlewares=[])


async def check_approve(key, spender, CONTRACT_TOKEN):
    ADDRESS = web3.eth.account.from_key(key).address
    abi_token = json.loads(
        '[{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')
    contract_token = web3.eth.contract(
        address=web3.toChecksumAddress(CONTRACT_TOKEN), abi=abi_token)
    allow = await contract_token.functions.allowance(ADDRESS, web3.toChecksumAddress(spender)).call()
    if allow == 0:
        return True
    else:
        # logger.info(f'{ADDRESS} уже имеет approve')
        return False


async def approve_gas(key, SPENDER, token_contract):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'))
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress(token_contract),
        'data': contract.encodeABI('approve', args=[SPENDER,
                                                    115792089237316195423570985008687907853269984665640564039457584007913129639935])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.1)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'{hash.hex()}')
    return hash


async def verif_tx(tx_hash):
    try:
        data = await web3.eth.wait_for_transaction_receipt(tx_hash, timeout=200)
        if data.get('status') != None and data.get('status') == 1:
            # logger.success(f'{data.get("from")} успешно {tx_hash.hex()}')
            return True
        else:
            # logger.error(f'{data.get("from")} произошла ошибка {data.get("transactionHash").hex()}')
            return False
    except Exception as e:
        # logger.error(f'{tx_hash.hex()} произошла ошибка! Error: {e}')
        return False


async def balance_token(address, token):
    return await web3.eth.contract(address=web3.toChecksumAddress(token),
                                   abi=json.loads(
                                       '[{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')
                                   ).functions.balanceOf(address).call()


async def deposit(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"address","name":"onBehalfOf","type":"address"},{"internalType":"uint16","name":"referralCode","type":"uint16"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"}]'))

    NUM_DEP = int(random.uniform(50, 50.1) * 10 ** 6)
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x8fd4af47e4e63d1d2d45582c3286b4bd9bb95dfe'),
        'data': contract.encodeABI('deposit', args=['0x7F5c764cBc14f9669B88837ca1490cCa17c31607', NUM_DEP, ADDRESS, 0])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'deposit {ADDRESS} {hash.hex()}')
    return hash


async def borrow(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint256","name":"interestRateMode","type":"uint256"},{"internalType":"uint16","name":"referralCode","type":"uint16"},{"internalType":"address","name":"onBehalfOf","type":"address"}],"name":"borrow","outputs":[],"stateMutability":"nonpayable","type":"function"}]'))

    NUM_SWAP = int(random.randint(21, 23) * 10 ** 6)
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x8fd4af47e4e63d1d2d45582c3286b4bd9bb95dfe'),
        'data': contract.encodeABI('borrow', args=['0x7F5c764cBc14f9669B88837ca1490cCa17c31607', NUM_SWAP, 2, 0, ADDRESS])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'borrow {ADDRESS} {hash.hex()}')
    return hash


async def repay(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"address","name":"user","type":"address"}],"name":"rebalanceStableBorrowRate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint256","name":"rateMode","type":"uint256"},{"internalType":"address","name":"onBehalfOf","type":"address"}],"name":"repay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"}]'))

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x8fd4af47e4e63d1d2d45582c3286b4bd9bb95dfe'),
        'data': contract.encodeABI('repay', args=['0x7F5c764cBc14f9669B88837ca1490cCa17c31607', 115792089237316195423570985008687907853269984665640564039457584007913129639935, 2, ADDRESS])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'repay {ADDRESS} {hash.hex()}')
    return hash


async def withdraw(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"rateMode","type":"uint256"}],"name":"swapBorrowRateMode","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"address","name":"to","type":"address"}],"name":"withdraw","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"}]'))

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x8fd4af47e4e63d1d2d45582c3286b4bd9bb95dfe'),
        'data': contract.encodeABI('withdraw', args=['0x7F5c764cBc14f9669B88837ca1490cCa17c31607',
                                                     115792089237316195423570985008687907853269984665640564039457584007913129639935,
                                                     ADDRESS])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'withdraw {ADDRESS} {hash.hex()}')
    return hash


async def work_granary(key):
    ADDRESS = web3.eth.account.from_key(key).address

    tm = random.randint(3, 15)

    await asyncio.sleep(tm)

    if await balance_token(ADDRESS, '0x7f5c764cbc14f9669b88837ca1490cca17c31607') >= 50 * 10 ** 6 \
            or await balance_token(ADDRESS, '0x7a0fddba78ff45d353b1630b77f4d175a00df0c0') != 0 \
            or await balance_token(ADDRESS, '0xb271973b367e50fcde5ee5e426944c37045dd0bf') != 0:

        if await check_approve(key, '0x8FD4aF47E4E63d1D2D45582c3286b4BD9Bb95DfE',
                               '0x7f5c764cbc14f9669b88837ca1490cca17c31607'):
            gas = await approve_gas(key, '0x8FD4aF47E4E63d1D2D45582c3286b4BD9Bb95DfE',
                                    '0x7f5c764cbc14f9669b88837ca1490cca17c31607')
            await verif_tx(gas)
            await asyncio.sleep(random.randint(*time_sleep))

        if await balance_token(ADDRESS, '0x7a0fddba78ff45d353b1630b77f4d175a00df0c0') == 0:
            tx = await deposit(key)
            await verif_tx(tx)
            await asyncio.sleep(random.randint(*time_sleep))

        if await balance_token(ADDRESS, '0x7a0fddba78ff45d353b1630b77f4d175a00df0c0') != 0 and await balance_token(ADDRESS, '0xb271973b367E50fcDE5Ee5e426944C37045Dd0bf') == 0:
            tx = await borrow(key)
            await verif_tx(tx)
            await asyncio.sleep(random.randint(*time_sleep))

        if await balance_token(ADDRESS, '0xb271973b367e50fcde5ee5e426944c37045dd0bf') != 0 and await balance_token(ADDRESS, '0x7a0fddba78ff45d353b1630b77f4d175a00df0c0') != 0:
            tx = await repay(key)
            await verif_tx(tx)
            await asyncio.sleep(random.randint(*time_sleep))

        if await balance_token(ADDRESS, '0xb271973b367e50fcde5ee5e426944c37045dd0bf') == 0 and await balance_token(ADDRESS, '0x7a0fddba78ff45d353b1630b77f4d175a00df0c0') != 0:
            tx = await withdraw(key)
            if await verif_tx(tx):
                return True
            else:
                return False
        return False
