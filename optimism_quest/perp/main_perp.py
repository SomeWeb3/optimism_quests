from web3 import Web3
from web3.eth import AsyncEth
import asyncio
import json
from loguru import logger
import random
import time
import requests

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
            # logger.info(f'{data.get("from")} успешно {tx_hash.hex()}')
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


def eth_price():
    while True:
        try:
            r = requests.get(
                'https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=USD')
            return r.json()['USD']
        except Exception as e:
            logger.error(f'ERROR | {e}')
            time.sleep(15)


async def deposit_weth(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"}]'))
    bal_weth = await balance_token(ADDRESS, '0x4200000000000000000000000000000000000006')
    VALUE = bal_weth
    if bal_weth >= 52200000000000000:
        VALUE = round(random.randint(50500000000000000,
                      52200000000000000), random.randint(-14, -13))

    assert VALUE >= 40000000000000000

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0xad7b4c162707e0b2b5f6fddbd3f8538a5fba0d60'),
        'data': contract.encodeABI('deposit', args=['0x4200000000000000000000000000000000000006', VALUE])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'deposit_weth {ADDRESS} {hash.hex()}')
    return hash


async def open_pos(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"components":[{"internalType":"address","name":"baseToken","type":"address"},{"internalType":"bool","name":"isBaseToQuote","type":"bool"},{"internalType":"bool","name":"isExactInput","type":"bool"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint256","name":"oppositeAmountBound","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint160","name":"sqrtPriceLimitX96","type":"uint160"},{"internalType":"bytes32","name":"referralCode","type":"bytes32"}],"internalType":"struct IClearingHouse.OpenPositionParams","name":"params","type":"tuple"}],"name":"openPosition","outputs":[{"internalType":"uint256","name":"base","type":"uint256"},{"internalType":"uint256","name":"quote","type":"uint256"}],"stateMutability":"nonpayable","type":"function"}]'))
    VALUE = round(random.randint(102000000000000000000,
                  105000000000000000000), random.randint(-17, -16))
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x82ac2ce43e33683c58be4cdc40975e73aa50f459'),

        'data': contract.encodeABI('openPosition',
                                   args=[(web3.toChecksumAddress('0x8C835DFaA34e2AE61775e80EE29E2c724c6AE2BB'),
                                          False, True,
                                          VALUE,
                                          int((VALUE / eth_price()) * 0.99),
                                          115792089237316195423570985008687907853269984665640564039457584007913129639935,
                                          0,
                                          web3.toBytes(
                                              hexstr='0x0000000000000000000000000000000000000000000000000000000000000000'))])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'open_pos {ADDRESS} {hash.hex()}')
    return hash


async def clese_pos(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"components":[{"internalType":"address","name":"baseToken","type":"address"},{"internalType":"uint160","name":"sqrtPriceLimitX96","type":"uint160"},{"internalType":"uint256","name":"oppositeAmountBound","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bytes32","name":"referralCode","type":"bytes32"}],"internalType":"struct IClearingHouse.ClosePositionParams","name":"params","type":"tuple"}],"name":"closePosition","outputs":[{"internalType":"uint256","name":"base","type":"uint256"},{"internalType":"uint256","name":"quote","type":"uint256"}],"stateMutability":"nonpayable","type":"function"}]'))
    pos = await pos_size(ADDRESS)
    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x82ac2ce43e33683c58be4cdc40975e73aa50f459'),
        'data': contract.encodeABI('closePosition',
                                   args=[(web3.toChecksumAddress('0x8C835DFaA34e2AE61775e80EE29E2c724c6AE2BB'),
                                          0,
                                          int((pos * eth_price()) * 0.985),
                                          115792089237316195423570985008687907853269984665640564039457584007913129639935,
                                          web3.toBytes(
                                              hexstr='0x0000000000000000000000000000000000000000000000000000000000000000'))])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'clese_pos {ADDRESS} {hash.hex()}')
    return hash


async def get_balanced_by_token(address):
    return await web3.eth.contract(address=web3.toChecksumAddress('0xad7b4c162707e0b2b5f6fddbd3f8538a5fba0d60'),
                                   abi=json.loads(
                                       '[{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getBalanceByToken","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"}]')
                                   ).functions.getBalanceByToken(address,
                                                                 '0x4200000000000000000000000000000000000006').call()


async def get_balanced_by_token_usdc(address):
    return await web3.eth.contract(address=web3.toChecksumAddress('0xad7b4c162707e0b2b5f6fddbd3f8538a5fba0d60'),
                                   abi=json.loads(
                                       '[{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getBalanceByToken","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"}]')
                                   ).functions.getBalanceByToken(address,
                                                                 '0x7F5c764cBc14f9669B88837ca1490cCa17c31607').call()


async def pos_size(address):
    return await web3.eth.contract(address=web3.toChecksumAddress('0xa7f3fc32043757039d5e13d790ee43edbcba8b7c'),
                                   abi=json.loads(
                                       '[{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"baseToken","type":"address"}],"name":"getTakerPositionSize","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"}]')
                                   ).functions.getTakerPositionSize(address,
                                                                    web3.toChecksumAddress(
                                                                        '0x8c835dfaa34e2ae61775e80ee29e2c724c6ae2bb')).call()


async def usdc_debt(address):
    return await web3.eth.contract(address=web3.toChecksumAddress('0xcf10d17bad67ce190a94f08fdd7b4e51540fd860'),
                                   abi=json.loads(
                                       '[{"inputs":[],"name":"getAccountBalance","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getAccountValue","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"}]')
                                   ).functions.getAccountValue(address).call()


async def uniswap(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"components":[{"internalType":"address","name":"tokenIn","type":"address"},{"internalType":"address","name":"tokenOut","type":"address"},{"internalType":"uint24","name":"fee","type":"uint24"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMaximum","type":"uint256"},{"internalType":"uint160","name":"sqrtPriceLimitX96","type":"uint160"}],"internalType":"struct IV3SwapRouter.ExactOutputSingleParams","name":"params","type":"tuple"}],"name":"exactOutputSingle","outputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"previousBlockhash","type":"bytes32"},{"internalType":"bytes[]","name":"data","type":"bytes[]"}],"name":"multicall","outputs":[{"internalType":"bytes[]","name":"","type":"bytes[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bytes[]","name":"data","type":"bytes[]"}],"name":"multicall","outputs":[{"internalType":"bytes[]","name":"","type":"bytes[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes[]","name":"data","type":"bytes[]"}],"name":"multicall","outputs":[{"internalType":"bytes[]","name":"results","type":"bytes[]"}],"stateMutability":"payable","type":"function"}]'))
    USDC = random.randint(53, 54)
    VALUE = web3.to_wei((USDC / eth_price() * 1.05), 'ether')

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'),
        'data': contract.encodeABI('multicall', args=[int(time.time() + 300), [
            web3.toBytes(hexstr=contract.encodeABI('exactOutputSingle',
                                                   args=[(
                                                       '0x4200000000000000000000000000000000000006',
                                                       web3.toChecksumAddress(
                                                           '0x7F5c764cBc14f9669B88837ca1490cCa17c31607'),
                                                       500,
                                                       ADDRESS,
                                                       int(USDC * 10 ** 6),
                                                       VALUE,
                                                       0
                                                   )])), web3.toBytes(hexstr='0x12210e8a')]]),
        'value': VALUE
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'uniswap {ADDRESS} {hash.hex()}')
    return hash


async def deposit_usdc(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"}]'))

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0xad7b4c162707e0b2b5f6fddbd3f8538a5fba0d60'),
        'data': contract.encodeABI('deposit', args=['0x7F5c764cBc14f9669B88837ca1490cCa17c31607', (
            (-(await usdc_debt(ADDRESS)) + 1
             ))])
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 1.4)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'deposit_usdc {ADDRESS} {hash.hex()}')
    return hash


async def withdraw_all(key):
    ADDRESS = web3.eth.account.from_key(key).address
    contract = web3.eth.contract(abi=json.loads(
        '[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"BadDebtSettled","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"clearingHouse","type":"address"}],"name":"ClearingHouseChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":true,"internalType":"address","name":"collateralToken","type":"address"},{"indexed":true,"internalType":"address","name":"liquidator","type":"address"},{"indexed":false,"internalType":"uint256","name":"collateral","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"repaidSettlementWithoutInsuranceFundFeeX10_S","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"insuranceFundFeeX10_S","type":"uint256"},{"indexed":false,"internalType":"uint24","name":"discountRatio","type":"uint24"}],"name":"CollateralLiquidated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"collateralManager","type":"address"}],"name":"CollateralManagerChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"collateralToken","type":"address"},{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Deposited","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"account","type":"address"}],"name":"Paused","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"trustedForwarder","type":"address"}],"name":"TrustedForwarderChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"trustedForwarder","type":"address"}],"name":"TrustedForwarderUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"account","type":"address"}],"name":"Unpaused","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"WETH9","type":"address"}],"name":"WETH9Changed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"collateralToken","type":"address"},{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Withdrawn","type":"event"},{"inputs":[],"name":"candidate","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"depositEther","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"depositEtherFor","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"depositFor","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"getAccountBalance","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getAccountValue","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getBalance","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getBalanceByToken","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getClearingHouse","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getClearingHouseConfig","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getCollateralManager","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getCollateralMmRatio","outputs":[{"internalType":"uint24","name":"","type":"uint24"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getCollateralTokens","outputs":[{"internalType":"address[]","name":"","type":"address[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getExchange","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getFreeCollateral","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"uint24","name":"ratio","type":"uint24"}],"name":"getFreeCollateralByRatio","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getFreeCollateralByToken","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getInsuranceFund","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"settlementX10_S","type":"uint256"}],"name":"getLiquidatableCollateralBySettlement","outputs":[{"internalType":"uint256","name":"collateral","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getMarginRequirementForCollateralLiquidation","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getMaxRepaidSettlementAndLiquidatableCollateral","outputs":[{"internalType":"uint256","name":"maxRepaidSettlementX10_S","type":"uint256"},{"internalType":"uint256","name":"maxLiquidatableCollateral","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"collateral","type":"uint256"}],"name":"getRepaidSettlementByCollateral","outputs":[{"internalType":"uint256","name":"settlementX10_S","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getSettlementToken","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getSettlementTokenValue","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getTotalDebt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getTrustedForwarder","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getWETH9","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"insuranceFundArg","type":"address"},{"internalType":"address","name":"clearingHouseConfigArg","type":"address"},{"internalType":"address","name":"accountBalanceArg","type":"address"},{"internalType":"address","name":"exchangeArg","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"isLiquidatable","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"forwarder","type":"address"}],"name":"isTrustedForwarder","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bool","name":"isDenominatedInSettlementToken","type":"bool"}],"name":"liquidateCollateral","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pause","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"clearingHouseArg","type":"address"}],"name":"setClearingHouse","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"collateralManagerArg","type":"address"}],"name":"setCollateralManager","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"setOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"trustedForwarderArg","type":"address"}],"name":"setTrustedForwarder","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"WETH9Arg","type":"address"}],"name":"setWETH9","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"settleBadDebt","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"unpause","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"updateOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"versionRecipient","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"}],"name":"withdrawAll","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"withdrawAllEther","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdrawEther","outputs":[],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]'))

    tx = {
        'nonce': await web3.eth.get_transaction_count(ADDRESS),
        # web3.to_wei(0.1,'gwei'),  # web3.eth.gas_price,
        'gasPrice': await web3.eth.gas_price,
        'chainId': await web3.eth.chain_id,
        'from': ADDRESS,
        'to': web3.toChecksumAddress('0xad7b4c162707e0b2b5f6fddbd3f8538a5fba0d60'),
        'data': '0x31c91117'
    }
    tx['gas'] = int(await web3.eth.estimate_gas(tx) * 2)

    sign = web3.eth.account.sign_transaction(tx, key)
    hash = await web3.eth.send_raw_transaction(sign.rawTransaction)
    # logger.info(f'withdraw_all {ADDRESS} {hash.hex()}')
    return hash


async def get_free_col(address):
    contract = web3.eth.contract(address=web3.toChecksumAddress('0xad7b4c162707e0b2b5f6fddbd3f8538a5fba0d60'),
                                 abi=json.loads(
                                     '[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"BadDebtSettled","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"clearingHouse","type":"address"}],"name":"ClearingHouseChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":true,"internalType":"address","name":"collateralToken","type":"address"},{"indexed":true,"internalType":"address","name":"liquidator","type":"address"},{"indexed":false,"internalType":"uint256","name":"collateral","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"repaidSettlementWithoutInsuranceFundFeeX10_S","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"insuranceFundFeeX10_S","type":"uint256"},{"indexed":false,"internalType":"uint24","name":"discountRatio","type":"uint24"}],"name":"CollateralLiquidated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"collateralManager","type":"address"}],"name":"CollateralManagerChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"collateralToken","type":"address"},{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Deposited","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"account","type":"address"}],"name":"Paused","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"trustedForwarder","type":"address"}],"name":"TrustedForwarderChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"trustedForwarder","type":"address"}],"name":"TrustedForwarderUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"account","type":"address"}],"name":"Unpaused","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"WETH9","type":"address"}],"name":"WETH9Changed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"collateralToken","type":"address"},{"indexed":true,"internalType":"address","name":"trader","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Withdrawn","type":"event"},{"inputs":[],"name":"candidate","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"depositEther","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"depositEtherFor","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"depositFor","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"getAccountBalance","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getAccountValue","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getBalance","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getBalanceByToken","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getClearingHouse","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getClearingHouseConfig","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getCollateralManager","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getCollateralMmRatio","outputs":[{"internalType":"uint24","name":"","type":"uint24"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getCollateralTokens","outputs":[{"internalType":"address[]","name":"","type":"address[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getExchange","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getFreeCollateral","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"uint24","name":"ratio","type":"uint24"}],"name":"getFreeCollateralByRatio","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getFreeCollateralByToken","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getInsuranceFund","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"settlementX10_S","type":"uint256"}],"name":"getLiquidatableCollateralBySettlement","outputs":[{"internalType":"uint256","name":"collateral","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getMarginRequirementForCollateralLiquidation","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"}],"name":"getMaxRepaidSettlementAndLiquidatableCollateral","outputs":[{"internalType":"uint256","name":"maxRepaidSettlementX10_S","type":"uint256"},{"internalType":"uint256","name":"maxLiquidatableCollateral","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"collateral","type":"uint256"}],"name":"getRepaidSettlementByCollateral","outputs":[{"internalType":"uint256","name":"settlementX10_S","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getSettlementToken","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"getSettlementTokenValue","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getTotalDebt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getTrustedForwarder","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getWETH9","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"insuranceFundArg","type":"address"},{"internalType":"address","name":"clearingHouseConfigArg","type":"address"},{"internalType":"address","name":"accountBalanceArg","type":"address"},{"internalType":"address","name":"exchangeArg","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"isLiquidatable","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"forwarder","type":"address"}],"name":"isTrustedForwarder","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bool","name":"isDenominatedInSettlementToken","type":"bool"}],"name":"liquidateCollateral","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pause","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"clearingHouseArg","type":"address"}],"name":"setClearingHouse","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"collateralManagerArg","type":"address"}],"name":"setCollateralManager","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"setOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"trustedForwarderArg","type":"address"}],"name":"setTrustedForwarder","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"WETH9Arg","type":"address"}],"name":"setWETH9","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"trader","type":"address"}],"name":"settleBadDebt","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"unpause","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"updateOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"versionRecipient","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"}],"name":"withdrawAll","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"withdrawAllEther","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdrawEther","outputs":[],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]'))
    return await contract.functions.getFreeCollateralByToken(address, web3.toChecksumAddress(
        '0x7f5c764cbc14f9669b88837ca1490cca17c31607')).call()


async def work_perp(key):
    ADDRESS = web3.eth.account.from_key(key).address

    tm = random.randint(3, 15)

    await asyncio.sleep(tm)

    if await check_approve(key, '0xAD7b4C162707E0B2b5f6fdDbD3f8538A5fbA0d60',
                           '0x4200000000000000000000000000000000000006'):
        gas = await approve_gas(key, '0xAD7b4C162707E0B2b5f6fdDbD3f8538A5fbA0d60',
                                '0x4200000000000000000000000000000000000006')
        await verif_tx(gas)
        await asyncio.sleep(random.randint(10, 15))

    if await get_balanced_by_token(ADDRESS) == 0:
        await deposit_weth(key)
        await asyncio.sleep(random.randint(10, 15))

    if await pos_size(ADDRESS) == 0 and await usdc_debt(ADDRESS) >= 0:
        tx = await open_pos(key)
        if await verif_tx(tx):
            await asyncio.sleep(random.randint(5, 10))

    if await pos_size(ADDRESS) != 0:
        tx2 = await clese_pos(key)
        if await verif_tx(tx2):
            await asyncio.sleep(random.randint(10, 15))

    if await balance_token(ADDRESS, '0x7F5c764cBc14f9669B88837ca1490cCa17c31607') < -(await usdc_debt(ADDRESS)):
        await uniswap(key)
        await asyncio.sleep(random.randint(10, 15))

    if await check_approve(key, '0xAD7b4C162707E0B2b5f6fdDbD3f8538A5fbA0d60',
                           '0x7f5c764cbc14f9669b88837ca1490cca17c31607'):
        gas = await approve_gas(key, '0xAD7b4C162707E0B2b5f6fdDbD3f8538A5fbA0d60',
                                '0x7f5c764cbc14f9669b88837ca1490cca17c31607')
        await verif_tx(gas)
        await asyncio.sleep(random.randint(10, 15))

    if await usdc_debt(ADDRESS) < 0 and await get_free_col(ADDRESS) == 0:
        await deposit_usdc(key)
        await asyncio.sleep(random.randint(10, 15))

    if await get_free_col(ADDRESS) >= 0 and await get_balanced_by_token(ADDRESS) > 0:
        tx = await withdraw_all(key)
        if await verif_tx(tx):
            return True
        else:
            return False
            # logger.success(f'{ADDRESS}')
    return False
