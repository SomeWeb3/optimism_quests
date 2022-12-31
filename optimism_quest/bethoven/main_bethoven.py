from web3 import Web3
from web3.eth import AsyncEth
import asyncio
import json
from loguru import logger
import random
import time
from os import environ
from dotenv import load_dotenv
from .check_task import verify_task

RPC = 'https://rpc.ankr.com/optimism'
web3 = Web3(Web3.AsyncHTTPProvider(RPC),
            modules={'eth': (AsyncEth,)}, middlewares=[])

# print(environ.keys())
load_dotenv()
time_sleep = eval(environ["SLEEP"])


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


def data_unit_6(value):
    abi = '[ { "inputs": [ { "internalType": "uint256", "name": "a", "type": "uint256" }, { "internalType": "uint256", "name": "b", "type": "uint256" }, { "internalType": "uint256", "name": "c", "type": "uint256" }, { "internalType": "uint256", "name": "d", "type": "uint256" }, { "internalType": "uint256", "name": "e", "type": "uint256" }, { "internalType": "uint256", "name": "f", "type": "uint256" } ], "name": "data6_uint", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]'
    contract = web3.eth.contract(abi=abi)
    return contract.encodeABI('data6_uint', args=[1, 96, int(value*round(random.uniform(0.85, 0.91), random.randint(3, 5))), 2, value, 0])[10:]


def data_unit_3(value):
    abi = '[ { "inputs": [ { "internalType": "uint256", "name": "a", "type": "uint256" }, { "internalType": "uint256", "name": "b", "type": "uint256" }, { "internalType": "uint256", "name": "c", "type": "uint256" } ], "name": "data3_uint", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]'
    contract = web3.eth.contract(abi=abi)
    return contract.encodeABI('data3_uint', args=[0, value, 0])[10:]


async def join_pool(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"bytes32","name":"poolId","type":"bytes32"},{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"components":[{"internalType":"contract IAsset[]","name":"assets","type":"address[]"},{"internalType":"uint256[]","name":"maxAmountsIn","type":"uint256[]"},{"internalType":"bytes","name":"userData","type":"bytes"},{"internalType":"bool","name":"fromInternalBalance","type":"bool"}],"internalType":"struct IVault.JoinPoolRequest","name":"request","type":"tuple"}],"name":"joinPool","outputs":[],"stateMutability":"payable","type":"function"}]'))
    VALUE = round(random.randint(50500000000000000,
                  52200000000000000), random.randint(-14, -13))
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0xba12222222228d8ba445958a75a0704d566bf2c8'),
        'data': contract.encodeABI('joinPool', args=[
            web3.toBytes(
                hexstr='0x4fd63966879300cafafbb35d157dc5229278ed2300020000000000000000002b'),
            ADDRESS,
            ADDRESS,
            (
                ['0x0000000000000000000000000000000000000000',
                    '0x9Bcef72be871e61ED4fBbc7630889beE758eb81D'],
                [VALUE, 0], web3.toBytes(hexstr=data_unit_6(VALUE)), False
            )
        ]),
        'value': VALUE
    }
    # print(tx)
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'join_pool {ADDRESS} {hash.hex()}')
    return hash


async def exit_pool(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"bytes32","name":"poolId","type":"bytes32"},{"internalType":"address","name":"sender","type":"address"},{"internalType":"address payable","name":"recipient","type":"address"},{"components":[{"internalType":"contract IAsset[]","name":"assets","type":"address[]"},{"internalType":"uint256[]","name":"minAmountsOut","type":"uint256[]"},{"internalType":"bytes","name":"userData","type":"bytes"},{"internalType":"bool","name":"toInternalBalance","type":"bool"}],"internalType":"struct IVault.ExitPoolRequest","name":"request","type":"tuple"}],"name":"exitPool","outputs":[],"stateMutability":"nonpayable","type":"function"}]'))

    bal_token = await balance_token(ADDRESS, '0x4fd63966879300cafafbb35d157dc5229278ed23')
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0xba12222222228d8ba445958a75a0704d566bf2c8'),
        'data': contract.encodeABI('exitPool', args=[
            web3.toBytes(
                hexstr='0x4fd63966879300cafafbb35d157dc5229278ed2300020000000000000000002b'),
            ADDRESS,
            ADDRESS,
            (
                ['0x4200000000000000000000000000000000000006',
                    '0x9Bcef72be871e61ED4fBbc7630889beE758eb81D'],
                [int(bal_token*.98), 0],
                web3.toBytes(hexstr=data_unit_3(bal_token)),
                False
            )
        ]),
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'exit_pool {ADDRESS} {hash.hex()}')
    return hash


async def deposit(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"stateMutability":"nonpayable","type":"function","name":"deposit","inputs":[{"name":"_value","type":"uint256"}],"outputs":[]},{"stateMutability":"nonpayable","type":"function","name":"deposit","inputs":[{"name":"_value","type":"uint256"},{"name":"_addr","type":"address"}],"outputs":[]},{"stateMutability":"nonpayable","type":"function","name":"deposit","inputs":[{"name":"_value","type":"uint256"},{"name":"_addr","type":"address"},{"name":"_claim_rewards","type":"bool"}],"outputs":[]}]'))

    bal_token = await balance_token(ADDRESS, '0x4fd63966879300cafafbb35d157dc5229278ed23')

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x38f79beffc211c6c439b0a3d10a0a673ee63afb4'),
        'data': contract.encodeABI('deposit', args=[bal_token]),
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'deposit {ADDRESS} {hash.hex()}')
    return hash


async def withdraw(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"stateMutability":"nonpayable","type":"function","name":"withdraw","inputs":[{"name":"_value","type":"uint256"}],"outputs":[]},{"stateMutability":"nonpayable","type":"function","name":"withdraw","inputs":[{"name":"_value","type":"uint256"},{"name":"_claim_rewards","type":"bool"}],"outputs":[]}]'))

    bal_token = await balance_token(ADDRESS, '0x38f79beffc211c6c439b0a3d10a0a673ee63afb4')

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x38f79beffc211c6c439b0a3d10a0a673ee63afb4'),
        'data': contract.encodeABI('withdraw', args=[bal_token, True]),
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'exit_pool {ADDRESS} {hash.hex()}')
    return hash


async def work_beth(key):
    ADDRESS = web3.eth.account.from_key(key).address

    tm = random.randint(3, 15)

    await asyncio.sleep(tm)

    if await balance_token(ADDRESS, '0x4fd63966879300cafafbb35d157dc5229278ed23') == 0 and await balance_token(ADDRESS, '0x38f79beffc211c6c439b0a3d10a0a673ee63afb4') == 0:
        bal_eth = await web3.eth.get_balance(ADDRESS)
        if bal_eth <= 0.053:
            logger.error(f'{ADDRESS} {bal_eth}')
            return
        await join_pool(key)
        await asyncio.sleep(random.randint(*time_sleep))

    if await check_approve(key, '0x38f79beFfC211c6c439b0A3d10A0A673EE63AFb4',
                           '0x4fd63966879300cafafbb35d157dc5229278ed23'):
        gas = await approve_gas(key, '0x38f79beFfC211c6c439b0A3d10A0A673EE63AFb4',
                                '0x4fd63966879300cafafbb35d157dc5229278ed23')
        await verif_tx(gas)
        await asyncio.sleep(random.randint(*time_sleep))

    if await balance_token(ADDRESS, '0x4fd63966879300cafafbb35d157dc5229278ed23') != 0:
        await deposit(key)
        await asyncio.sleep(random.randint(*time_sleep))

    if await balance_token(ADDRESS, '0x38f79beffc211c6c439b0a3d10a0a673ee63afb4') != 0:
        logger.info(f'START CHECK GALXY | {ADDRESS}')
        if await verify_task('193977443855015936', ADDRESS):
            logger.info(f'START WITHDRAW | {ADDRESS}')
            await withdraw(key)
            await asyncio.sleep(random.randint(*time_sleep))

    if await balance_token(ADDRESS, '0x4fd63966879300cafafbb35d157dc5229278ed23') != 0:
        tx = await exit_pool(key)
        if await verif_tx(tx):
            return True
        else:
            return False

            # logger.success(F'Success bethovem | {ADDRESS}')
        # else:
        #     logger.error(F'Error bethovem | {ADDRESS} {tx.hex()}')
    return False
