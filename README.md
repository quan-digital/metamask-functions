# metamask-functions

Metamask Ethereum Network comprehsive function mapping. This repo is aimed at supporting other blockchains to interface with Metamask without having to fork the whole project. Based up to commit a49a4a066cf68895f32ec8a990f14f301cea33ff from the [official extension](https://github.com/MetaMask/metamask-extension/) on Nov 7th.

We focused on mapping the use of core network libs, leaving out more utility-focused functions/packages that are specific for Ethereum such as address formatting, decimal handling and so on.

Scripts analysed located at metamask-extension/app/scripts/.

# Root

# [ui.js](https://github.com/MetaMask/metamask-extension/blob/develop/app/scripts/ui.js#L141)
```javascript
Eth from 'ethjs'
EthQuery from 'eth-query'
StreamProvider from 'web3-stream-provider'
```
```javascript
function setupWeb3Connection(connectionStream) {
  const providerStream = new StreamProvider()
  providerStream.pipe(connectionStream).pipe(providerStream)
  connectionStream.on('error', console.error.bind(console))
  providerStream.on('error', console.error.bind(console))
  global.ethereumProvider = providerStream
  global.ethQuery = new EthQuery(providerStream)
  global.eth = new Eth(providerStream)
}
```

# [metamask-controller.js](https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/metamask-controller.js)
## [eth-query](https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/metamask-controller.js#L894)
```javascript
import EthQuery from 'eth-query'
```
```javascript
const ethQuery = new EthQuery(this.provider)
```

## [eth-contract-metadata](https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/metamask-controller.js#L984)
```javascript
import contractMap from 'eth-contract-metadata'
```
```javascript
Object.keys(accountTokens).forEach((address) => {
      const checksummedAddress = ethUtil.toChecksumAddress(address)
      filteredAccountTokens[checksummedAddress] = {}
      Object.keys(accountTokens[address]).forEach((networkType) => {
        filteredAccountTokens[checksummedAddress][networkType] =
          networkType === 'mainnet'
            ? accountTokens[address][networkType].filter(
                ({ address: tokenAddress }) => {
                  const checksumAddress = ethUtil.toChecksumAddress(
                    tokenAddress,
                  )
                  return contractMap[checksumAddress]
                    ? contractMap[checksumAddress].erc20
                    : true
                },
              )
            : accountTokens[address][networkType]
      })
    })
```

## [eth-json-rpc-*](https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/metamask-controller.js#L1924)
```javascript
import createFilterMiddleware from 'eth-json-rpc-filters'
import createSubscriptionManager from 'eth-json-rpc-filters/subscriptionManager'
import providerAsMiddleware from 'eth-json-rpc-middleware/providerAsMiddleware'
```
```javascript
setupProviderEngine({
    origin,
    location,
    extensionId,
    tabId,
    isInternal = false,
  }) {
    // setup json rpc engine stack
    const engine = new RpcEngine()
    const { provider, blockTracker } = this

    // create filter polyfill middleware
    const filterMiddleware = createFilterMiddleware({ provider, blockTracker })

    // create subscription polyfill middleware
    const subscriptionManager = createSubscriptionManager({
      provider,
      blockTracker,
    })
    subscriptionManager.events.on('notification', (message) =>
      engine.emit('notification', message),
    )

    // append origin to each request
    engine.push(createOriginMiddleware({ origin }))
    // append tabId to each request if it exists
    if (tabId) {
      engine.push(createTabIdMiddleware({ tabId }))
    }
    // logging
    engine.push(createLoggerMiddleware({ origin }))
    engine.push(
      createOnboardingMiddleware({
        location,
        registerOnboarding: this.onboardingController.registerOnboarding,
      }),
    )
    engine.push(
      createMethodMiddleware({
        origin,
        sendMetrics: this.trackMetaMetricsEvent,
      }),
    )
    // filter and subscription polyfills
    engine.push(filterMiddleware)
    engine.push(subscriptionManager.middleware)
    if (!isInternal) {
      // permissions
      engine.push(
        this.permissionsController.createMiddleware({ origin, extensionId }),
      )
    }
    // watch asset
    engine.push(
      this.preferencesController.requestWatchAsset.bind(
        this.preferencesController,
      ),
    )
    // forward to metamask primary provider
    engine.push(providerAsMiddleware(provider))
    return engine
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/metamask-controller.js#L227

```javascript
import KeyringController from 'eth-keyring-controller'
```
```javascript
this.keyringController = new KeyringController({
      keyringTypes: additionalKeyrings,
      initState: initState.KeyringController,
      encryptor: opts.encryptor || undefined,
    })
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/metamask-controller.js#L973

```javascript
import ethUtil from 'ethereumjs-util'
```
```javascript
 Object.keys(accountTokens).forEach((address) => {
      const checksummedAddress = ethUtil.toChecksumAddress(address)
      filteredAccountTokens[checksummedAddress] = {}
      Object.keys(accountTokens[address]).forEach((networkType) => {
        filteredAccountTokens[checksummedAddress][networkType] =
          networkType === 'mainnet'
            ? accountTokens[address][networkType].filter(
                ({ address: tokenAddress }) => {
                  const checksumAddress = ethUtil.toChecksumAddress(
                    tokenAddress,
                  )
                  return contractMap[checksumAddress]
                    ? contractMap[checksumAddress].erc20
                    : true
                },
              )
            : accountTokens[address][networkType]
      })
    })
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/account-import-strategies/index.js#L6

```javascript
import Wallet from 'ethereumjs-wallet'
import importers from 'ethereumjs-wallet/thirdparty'
import ethUtil from 'ethereumjs-util'
```
```javascript
const accountImporter = {
  importAccount(strategy, args) {
    try {
      const importer = this.strategies[strategy]
      const privateKeyHex = importer(...args)
      return Promise.resolve(privateKeyHex)
    } catch (e) {
      return Promise.reject(e)
    }
  },

  strategies: {
    'Private Key': (privateKey) => {
      if (!privateKey) {
        throw new Error('Cannot import an empty key.')
      }

      const prefixed = ethUtil.addHexPrefix(privateKey)
      const buffer = ethUtil.toBuffer(prefixed)

      if (!ethUtil.isValidPrivate(buffer)) {
        throw new Error('Cannot import invalid private key.')
      }

      const stripped = ethUtil.stripHexPrefix(prefixed)
      return stripped
    },
    'JSON File': (input, password) => {
      let wallet
      try {
        wallet = importers.fromEtherWallet(input, password)
      } catch (e) {
        log.debug('Attempt to import as EtherWallet format failed, trying V3')
        wallet = Wallet.fromV3(input, password, true)
      }

      return walletToPrivateKey(wallet)
    },
  },
}
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/typed-message-manager.js#L89

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
 addUnapprovedMessageAsync(msgParams, req, version) {
    return new Promise((resolve, reject) => {
      const msgId = this.addUnapprovedMessage(msgParams, req, version)
      this.once(`${msgId}:finished`, (data) => {
        switch (data.status) {
          case 'signed':
            return resolve(data.rawSig)
          case 'rejected':
            return reject(
              ethErrors.provider.userRejectedRequest(
                'MetaMask Message Signature: User denied message signature.',
              ),
            )
          case 'errored':
            return reject(
              new Error(`MetaMask Message Signature: ${data.error}`),
            )
          default:
            return reject(
              new Error(
                `MetaMask Message Signature: Unknown problem: ${JSON.stringify(
                  msgParams,
                )}`,
              ),
            )
        }
      })
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/typed-message-manager.js#L154

```javascript
import sigUtil from 'eth-sig-util'
```
```javascript
validateParams(params) {
    assert.ok(params && typeof params === 'object', 'Params must be an object.')
    assert.ok('data' in params, 'Params must include a "data" field.')
    assert.ok('from' in params, 'Params must include a "from" field.')
    assert.ok(
      typeof params.from === 'string' && isValidAddress(params.from),
      '"from" field must be a valid, lowercase, hexadecimal Ethereum address string.',
    )

    switch (params.version) {
      case 'V1':
        assert.ok(Array.isArray(params.data), '"params.data" must be an array.')
        assert.doesNotThrow(() => {
          sigUtil.typedSignatureHash(params.data)
        }, 'Signing data must be valid EIP-712 typed data.')
        break
      case 'V3':
      case 'V4': {
        assert.equal(
          typeof params.data,
          'string',
          '"params.data" must be a string.',
        )
        let data
        assert.doesNotThrow(() => {
          data = JSON.parse(params.data)
        }, '"data" must be a valid JSON string.')
        const validation = jsonschema.validate(
          data,
          sigUtil.TYPED_MESSAGE_SCHEMA,
        )
        assert.ok(
          data.primaryType in data.types,
          `Primary type of "${data.primaryType}" has no type definition.`,
        )
        assert.equal(
          validation.errors.length,
          0,
          'Signing data must conform to EIP-712 schema. See https://git.io/fNtcx.',
        )
        const { chainId } = data.domain
        if (chainId) {
          const activeChainId = parseInt(this._getCurrentChainId(), 16)
          assert.ok(
            !Number.isNaN(activeChainId),
            `Cannot sign messages for chainId "${chainId}", because MetaMask is switching networks.`,
          )
          assert.equal(
            chainId,
            activeChainId,
            `Provided chainId "${chainId}" must match the active chainId "${activeChainId}"`,
          )
        }
        break
      }
      default:
        assert.fail(`Unknown typed data version "${params.version}"`)
    }
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/typed-message-manager.js#L158

```javascript
import { isValidAddress } from 'ethereumjs-util'
```
```javascript
assert.ok(
      typeof params.from === 'string' && isValidAddress(params.from),
      '"from" field must be a valid, lowercase, hexadecimal Ethereum address string.',
    )
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/seed-phrase-verifier.js#L23

```javascript
import KeyringController from 'eth-keyring-controller'
```
```javascript
const keyringController = new KeyringController({})
const Keyring = keyringController.getKeyringClassForType('HD Key Tree')
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/personal-message-manager.js#L312

```javascript
import ethUtil from 'ethereumjs-util'
```
```javascript
normalizeMsgData(data) {
    try {
      const stripped = ethUtil.stripHexPrefix(data)
      if (stripped.match(hexRe)) {
        return ethUtil.addHexPrefix(stripped)
      }
    } catch (e) {
      log.debug(`Message was not hex encoded, interpreting as utf8.`)
    }

    return ethUtil.bufferToHex(Buffer.from(data, 'utf8'))
  }
}
```

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
ddUnapprovedMessageAsync(msgParams, req) {
    return new Promise((resolve, reject) => {
      if (!msgParams.from) {
        reject(new Error('MetaMask Message Signature: from field is required.'))
        return
      }
      const msgId = this.addUnapprovedMessage(msgParams, req)
      this.once(`${msgId}:finished`, (data) => {
        switch (data.status) {
          case 'signed':
            resolve(data.rawSig)
            return
          case 'rejected':
            reject(
              ethErrors.provider.userRejectedRequest(
                'MetaMask Message Signature: User denied message signature.',
              ),
            )
            return
          default:
            reject(
              new Error(
                `MetaMask Message Signature: Unknown problem: ${JSON.stringify(
                  msgParams,
                )}`,
              ),
            )
        }
      })
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/message-manager.js#L293

```javascript
import ethUtil from 'ethereumjs-util'
```
```javascript
function normalizeMsgData(data) {
  if (data.slice(0, 2) === '0x') {
    // data is already hex
    return data
  }
  // data is unicode, convert to hex
  return ethUtil.bufferToHex(Buffer.from(data, 'utf8'))
}
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/message-manager.js#L81

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
 addUnapprovedMessageAsync(msgParams, req) {
    return new Promise((resolve, reject) => {
      const msgId = this.addUnapprovedMessage(msgParams, req)
      // await finished
      this.once(`${msgId}:finished`, (data) => {
        switch (data.status) {
          case 'signed':
            return resolve(data.rawSig)
          case 'rejected':
            return reject(
              ethErrors.provider.userRejectedRequest(
                'MetaMask Message Signature: User denied message signature.',
              ),
            )
          default:
            return reject(
              new Error(
                `MetaMask Message Signature: Unknown problem: ${JSON.stringify(
                  msgParams,
                )}`,
              ),
            )
        }
      })
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/encryption-public-key-manager.js#L95

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
addUnapprovedMessageAsync(address, req) {
    return new Promise((resolve, reject) => {
      if (!address) {
        reject(new Error('MetaMask Message: address field is required.'))
        return
      }
      const msgId = this.addUnapprovedMessage(address, req)
      this.once(`${msgId}:finished`, (data) => {
        switch (data.status) {
          case 'received':
            resolve(data.rawData)
            return
          case 'rejected':
            reject(
              ethErrors.provider.userRejectedRequest(
                'MetaMask EncryptionPublicKey: User denied message EncryptionPublicKey.',
              ),
            )
            return
          default:
            reject(
              new Error(
                `MetaMask EncryptionPublicKey: Unknown problem: ${JSON.stringify(
                  address,
                )}`,
              ),
            )
        }
      })
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/lib/ens-ipfs/resolver.js#L8

```javascript
import namehash from 'eth-ens-namehash'
import Eth from 'ethjs-query'
import EthContract from 'ethjs-contract'
```
```javascript
export default async function resolveEnsToIpfsContentId({ provider, name }) {
  const eth = new Eth(provider)
  const hash = namehash.hash(name)
  const contract = new EthContract(eth)
  // lookup registry
  const chainId = Number.parseInt(await eth.net_version(), 10)
  const registryAddress = getRegistryForChainId(chainId)
  if (!registryAddress) {
    throw new Error(
      `EnsIpfsResolver - no known ens-ipfs registry for chainId "${chainId}"`,
    ) }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/token-rates.js#L45

```javascript
import { normalize as normalizeAddress } from 'eth-sig-util'
import ethUtil from 'ethereumjs-util'
```
```javascript
async updateExchangeRates() {
    const contractExchangeRates = {}
    const nativeCurrency = this.currency
      ? this.currency.state.nativeCurrency.toLowerCase()
      : 'eth'
    const pairs = this._tokens.map((token) => token.address).join(',')
    const query = `contract_addresses=${pairs}&vs_currencies=${nativeCurrency}`
    if (this._tokens.length > 0) {
      try {
        const response = await window.fetch(
          `https://api.coingecko.com/api/v3/simple/token_price/ethereum?${query}`,
        )
        const prices = await response.json()
        this._tokens.forEach((token) => {
          const price =
            prices[token.address.toLowerCase()] ||
            prices[ethUtil.toChecksumAddress(token.address)]
          contractExchangeRates[normalizeAddress(token.address)] = price
            ? price[nativeCurrency]
            : 0
        })
      } catch (error) {
        log.warn(
          `MetaMask - TokenRatesController exchange rate fetch failed.`,
          error,
        )
      }
    }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/threebox.js#L110

```javascript
import providerFromEngine from 'eth-json-rpc-middleware/providerFromEngine'
```
```javascript
_createProvider(providerOpts) {
    const metamaskMiddleware = createMetamaskMiddleware(providerOpts)
    const engine = new JsonRpcEngine()
    engine.push(createOriginMiddleware({ origin: '3Box' }))
    engine.push(metamaskMiddleware)
    const provider = providerFromEngine(engine)
    return provider
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/swaps.js#L94

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/swaps.js#L588

```javascript
import { ethers } from 'ethers'
```
```javascript
async _getERC20Allowance(contractAddress, walletAddress) {
    const contract = new ethers.Contract(
      contractAddress,
      abi,
      this.ethersProvider,
    )
    return await contract.allowance(walletAddress, METASWAP_ADDRESS)
  }

networkController.on('networkDidChange', (network) => {
      if (network !== 'loading' && network !== this._currentNetwork) {
        this._currentNetwork = network
        this.ethersProvider = new ethers.providers.Web3Provider(provider)
      }
    })
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/preferences.js#L177

```javascript
import { normalize as normalizeAddress } from 'eth-sig-util'
```
```javascript
addSuggestedERC20Asset(tokenOpts) {
    this._validateERC20AssetParams(tokenOpts)
    const suggested = this.getSuggestedTokens()
    const { rawAddress, symbol, decimals, image } = tokenOpts
    const address = normalizeAddress(rawAddress)
    const newEntry = { address, symbol, decimals, image }
    suggested[address] = newEntry
    this.store.updateState({ suggestedTokens: suggested })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/preferences.js#L796

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/preferences.js#L130

```javascript
import { isValidAddress, sha3, bufferToHex } from 'ethereumjs-util'
```
```javascript
_validateERC20AssetParams(opts) {
    const { rawAddress, symbol, decimals } = opts
    if (!rawAddress || !symbol || typeof decimals === 'undefined') {
      throw new Error(
        `Cannot suggest token without address, symbol, and decimals`,
      )
    }
    if (!(symbol.length < 7)) {
      throw new Error(`Invalid symbol ${symbol} more than six characters`)
    }
    const numDecimals = parseInt(decimals, 10)
    if (isNaN(numDecimals) || numDecimals > 36 || numDecimals < 0) {
      throw new Error(
        `Invalid decimals ${decimals} must be at least 0, and not over 36`,
      )
    }
    if (!isValidAddress(rawAddress)) {
      throw new Error(`Invalid address ${rawAddress}`)
    }
  }
}
```
```javascript
setParticipateInMetaMetrics(bool) {
    this.store.updateState({ participateInMetaMetrics: bool })
    let metaMetricsId = null
    if (bool && !this.store.getState().metaMetricsId) {
      metaMetricsId = bufferToHex(
        sha3(
          String(Date.now()) +
            String(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)),
        ),
      )
      this.store.updateState({ metaMetricsId })
    } else if (bool === false) {
      this.store.updateState({ metaMetricsId })
    }
    return metaMetricsId
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/detect-tokens.js#L37

```javascript
import contracts from 'eth-contract-metadata'
```
```javascript
async detectNewTokens() {
    if (!this.isActive) {
      return
    }
    if (this._network.store.getState().provider.type !== MAINNET) {
      return
    }

    const tokensToDetect = []
    this.web3.setProvider(this._network._provider)
    for (const contractAddress in contracts) {
      if (
        contracts[contractAddress].erc20 &&
        !this.tokenAddresses.includes(contractAddress.toLowerCase())
      ) {
        tokensToDetect.push(contractAddress)
      }
    }

    let result
    try {
      result = await this._getTokenBalances(tokensToDetect)
    } catch (error) {
      warn(
        `MetaMask - DetectTokensController single call balance fetch failed`,
        error,
      )
      return
    }

    tokensToDetect.forEach((tokenAddress, index) => {
      const balance = result[index]
      if (balance && !balance.isZero()) {
        this._preferences.addToken(
          tokenAddress,
          contracts[tokenAddress].symbol,
          contracts[tokenAddress].decimals,
        )
      }
    })
  }

  async _getTokenBalances(tokens) {
    const ethContract = this.web3.eth
      .contract(SINGLE_CALL_BALANCES_ABI)
      .at(SINGLE_CALL_BALANCES_ADDRESS)
    return new Promise((resolve, reject) => {
      ethContract.balances([this.selectedAddress], tokens, (error, result) => {
        if (error) {
          return reject(error)
        }
        return resolve(result)
      })
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/tx-gas-utils.js#L22

```javascript
import EthQuery from 'ethjs-query'
```
```javascript
export default class TxGasUtil {
  constructor(provider) {
    this.query = new EthQuery(provider)
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/pending-tx-tracker.js#L39

```javascript
import EthQuery from 'ethjs-query'
```
```javascript
constructor(config) {
    super()
    this.query = config.query || new EthQuery(config.provider)
    this.nonceTracker = config.nonceTracker
    this.getPendingTransactions = config.getPendingTransactions
    this.getCompletedTransactions = config.getCompletedTransactions
    this.publishTransaction = config.publishTransaction
    this.approveTransaction = config.approveTransaction
    this.confirmTransaction = config.confirmTransaction
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/index.js#L546

```javascript
import Transaction from 'ethereumjs-tx'
```
```javascript
const ethTx = new Transaction(txParams)
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/index.js#L73

```javascript
import EthQuery from 'ethjs-query'
```
```javascript
constructor(opts) {
    super()
    this.networkStore = opts.networkStore || new ObservableStore({})
    this._getCurrentChainId = opts.getCurrentChainId
    this.preferencesStore = opts.preferencesStore || new ObservableStore({})
    this.provider = opts.provider
    this.getPermittedAccounts = opts.getPermittedAccounts
    this.blockTracker = opts.blockTracker
    this.signEthTx = opts.signTransaction
    this.inProcessOfSigning = new Set()
    this._trackMetaMetricsEvent = opts.trackMetaMetricsEvent
    this._getParticipateInMetrics = opts.getParticipateInMetrics

    this.memStore = new ObservableStore({})
    this.query = new EthQuery(this.provider)

    this.txGasUtil = new TxGasUtil(this.provider)
    this._mapMethods()
    this.txStateManager = new TransactionStateManager({
      initState: opts.initState,
      txHistoryLimit: opts.txHistoryLimit,
      getNetwork: this.getNetwork.bind(this),
    })
    this._onBootCleanUp()

    this.store = this.txStateManager.store
    this.nonceTracker = new NonceTracker({
      provider: this.provider,
      blockTracker: this.blockTracker,
      getPendingTransactions: this.txStateManager.getPendingTransactions.bind(
        this.txStateManager,
      ),
      getConfirmedTransactions: this.txStateManager.getConfirmedTransactions.bind(
        this.txStateManager,
      ),
    })
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/index.js#L176

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
return new Promise((resolve, reject) => {
      this.txStateManager.once(
        `${initialTxMeta.id}:finished`,
        (finishedTxMeta) => {
          switch (finishedTxMeta.status) {
            case 'submitted':
              return resolve(finishedTxMeta.hash)
            case 'rejected':
              return reject(
                cleanErrorStack(
                  ethErrors.provider.userRejectedRequest(
                    'MetaMask Tx Signature: User denied transaction signature.',
                  ),
                ),
              )
            case 'failed':
              return reject(
                cleanErrorStack(
                  ethErrors.rpc.internal(finishedTxMeta.err.message),
                ),
              )
            default:
              return reject(
                cleanErrorStack(
                  ethErrors.rpc.internal(
                    `MetaMask Tx Signature: Unknown problem: ${JSON.stringify(
                      finishedTxMeta.txParams,
                    )}`,
                  ),
                ),
              )
          }
        },
      )
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/index.js#L26

```javascript
import { ethers } from 'ethers'
```
```javascript
const hstInterface = new ethers.utils.Interface(abi)
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/lib/util.js#L3

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/transactions/lib/util.js#L37

```javascript
import { addHexPrefix, isValidAddress } from 'ethereumjs-util'
```
```javascript
const normalizers = {
  from: (from) => addHexPrefix(from),
  to: (to, lowerCase) =>
    lowerCase ? addHexPrefix(to).toLowerCase() : addHexPrefix(to),
  nonce: (nonce) => addHexPrefix(nonce),
  value: (value) => addHexPrefix(value),
  data: (data) => addHexPrefix(data),
  gas: (gas) => addHexPrefix(gas),
  gasPrice: (gasPrice) => addHexPrefix(gasPrice),
}

export function validateTxParams(txParams) {
  validateFrom(txParams)
  validateRecipient(txParams)
  if ('value' in txParams) {
    const value = txParams.value.toString()
    if (value.includes('-')) {
      throw new Error(
        `Invalid transaction value of ${txParams.value} not a positive number.`,
      )
    }

    if (value.includes('.')) {
      throw new Error(
        `Invalid transaction value of ${txParams.value} number must be in wei`,
      )
    }
  }
}

/**
 * Validates the {@code from} field in the given tx params
 * @param {Object} txParams
 * @throws {Error} if the from address isn't valid
 */
export function validateFrom(txParams) {
  if (!(typeof txParams.from === 'string')) {
    throw new Error(`Invalid from address ${txParams.from} not a string`)
  }
  if (!isValidAddress(txParams.from)) {
    throw new Error('Invalid from address')
  }
}
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/permissions/index.js#L223

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
async approvePermissionsRequest(approved, accounts) {
    const { id } = approved.metadata
    const approval = this.pendingApprovals.get(id)

    if (!approval) {
      log.debug(`Permissions request with id '${id}' not found`)
      return
    }

    try {
      if (Object.keys(approved.permissions).length === 0) {
        approval.reject(
          ethErrors.rpc.invalidRequest({
            message: 'Must request at least one permission.',
          }),
        )
      } else {
        // attempt to finalize the request and resolve it,
        // settings caveats as necessary
        approved.permissions = await this.finalizePermissionsRequest(
          approved.permissions,
          accounts,
        )
        approval.resolve(approved.permissions)
      }
    } catch (err) {
      // if finalization fails, reject the request
      approval.reject(
        ethErrors.rpc.invalidRequest({
          message: err.message,
          data: err,
        }),
      )
    }
```

## https://github.com/MetaMask/metamask-extension/blob/2ebf8756a4c1023e45e4bd98367f384836cb464a/app/scripts/controllers/permissions/permissionsMethodMiddleware.js#L7

```javascript
import { ethErrors } from 'eth-json-rpc-errors'
```
```javascript
export default function createPermissionsMethodMiddleware({
  addDomainMetadata,
  getAccounts,
  getUnlockPromise,
  hasPermission,
  notifyAccountsChanged,
  requestAccountsPermission,
}) {
  let isProcessingRequestAccounts = false

  return createAsyncMiddleware(async (req, res, next) => {
    let responseHandler

    switch (req.method) {
      // Intercepting eth_accounts requests for backwards compatibility:
      // The getAccounts call below wraps the rpc-cap middleware, and returns
      // an empty array in case of errors (such as 4100:unauthorized)
      case 'eth_accounts': {
        res.result = await getAccounts()
        return
      }

      case 'eth_requestAccounts': {
        if (isProcessingRequestAccounts) {
          res.error = ethErrors.rpc.resourceUnavailable(
            'Already processing eth_requestAccounts. Please wait.',
          )
          return
        }

        if (hasPermission('eth_accounts')) {
          isProcessingRequestAccounts = true
          await getUnlockPromise()
          isProcessingRequestAccounts = false
        }

        // first, just try to get accounts
        let accounts = await getAccounts()
        if (accounts.length > 0) {
          res.result = accounts
          return
        }

        // if no accounts, request the accounts permission
        try {
          await requestAccountsPermission()
        } catch (err) {
          res.error = err
          return
        }

        // get the accounts again
        accounts = await getAccounts()
        /* istanbul ignore else: too hard to induce, see below comment */
        if (accounts.length > 0) {
          res.result = accounts
        } else {
          // this should never happen, because it should be caught in the
          // above catch clause
          res.error = ethErrors.rpc.internal(
            'Accounts unexpectedly unavailable. Please report this bug.',
          )
        }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/network/network.js#L245

```javascript
import providerFromEngine from 'eth-json-rpc-middleware/providerFromEngine'
```
```javascript
_setNetworkClient({ networkMiddleware, blockTracker }) {
    const metamaskMiddleware = createMetamaskMiddleware(
      this._baseProviderParams,
    )
    const engine = new JsonRpcEngine()
    engine.push(metamaskMiddleware)
    engine.push(networkMiddleware)
    const provider = providerFromEngine(engine)
    this._setProviderAndBlockTracker({ provider, blockTracker })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/network/network.js#L138

```javascript
import EthQuery from 'eth-query'
```
```javascript
lookupNetwork() {
    // Prevent firing when provider is not defined.
    if (!this._provider) {
      log.warn(
        'NetworkController - lookupNetwork aborted due to missing provider',
      )
      return
    }

    const chainId = this.getCurrentChainId()
    if (!chainId) {
      log.warn(
        'NetworkController - lookupNetwork aborted due to missing chainId',
      )
      this.setNetworkState('loading')
      return
    }

    // Ping the RPC endpoint so we can confirm that it works
    const ethQuery = new EthQuery(this._provider)
    const initialNetwork = this.getNetworkState()
    ethQuery.sendAsync({ method: 'net_version' }, (err, networkVersion) => {
      const currentNetwork = this.getNetworkState()
      if (initialNetwork === currentNetwork) {
        if (err) {
          this.setNetworkState('loading')
          return
        }

        this.setNetworkState(networkVersion)
      }
    })
  }
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/network/createMetamaskMiddleware.js#L29

```javascript
import createWalletSubprovider from 'eth-json-rpc-middleware/wallet'
```
```javascript
export default function createMetamaskMiddleware({
  version,
  getAccounts,
  processTransaction,
  processEthSignMessage,
  processTypedMessage,
  processTypedMessageV3,
  processTypedMessageV4,
  processPersonalMessage,
  processDecryptMessage,
  processEncryptionPublicKey,
  getPendingNonce,
  getPendingTransactionByHash,
}) {
  const metamaskMiddleware = mergeMiddleware([
    createScaffoldMiddleware({
      // staticSubprovider
      eth_syncing: false,
      web3_clientVersion: `MetaMask/v${version}`,
    }),
    createWalletSubprovider({
      getAccounts,
      processTransaction,
      processEthSignMessage,
      processTypedMessage,
      processTypedMessageV3,
      processTypedMessageV4,
      processPersonalMessage,
      processDecryptMessage,
      processEncryptionPublicKey,
    }),
    createPendingNonceMiddleware({ getPendingNonce }),
    createPendingTxMiddleware({ getPendingTransactionByHash }),
  ])
  return metamaskMiddleware
}
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/network/createJsonRpcClient.js#L17

```javascript
import createFetchMiddleware from 'eth-json-rpc-middleware/fetch'
import createBlockRefRewriteMiddleware from 'eth-json-rpc-middleware/block-ref-rewrite'
import createBlockCacheMiddleware from 'eth-json-rpc-middleware/block-cache'
import createInflightMiddleware from 'eth-json-rpc-middleware/inflight-cache'
import createBlockTrackerInspectorMiddleware from 'eth-json-rpc-middleware/block-tracker-inspector'
import providerFromMiddleware from 'eth-json-rpc-middleware/providerFromMiddleware'
import BlockTracker from 'eth-block-tracker'
```
```javascript
export default function createJsonRpcClient({ rpcUrl, chainId }) {
  const fetchMiddleware = createFetchMiddleware({ rpcUrl })
  const blockProvider = providerFromMiddleware(fetchMiddleware)
  const blockTracker = new BlockTracker({
    ...blockTrackerOpts,
    provider: blockProvider,
  })

  const networkMiddleware = mergeMiddleware([
    ...getTestMiddlewares(),
    createChainIdMiddleware(chainId),
    createBlockRefRewriteMiddleware({ blockTracker }),
    createBlockCacheMiddleware({ blockTracker }),
    createInflightMiddleware(),
    createBlockTrackerInspectorMiddleware({ blockTracker }),
    fetchMiddleware,
  ])

  return { networkMiddleware, blockTracker }
}
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/network/createInfuraClient.js#L13

```javascript
import createBlockReRefMiddleware from 'eth-json-rpc-middleware/block-ref'
import createRetryOnEmptyMiddleware from 'eth-json-rpc-middleware/retryOnEmpty'
import createBlockCacheMiddleware from 'eth-json-rpc-middleware/block-cache'
import createInflightMiddleware from 'eth-json-rpc-middleware/inflight-cache'
import createBlockTrackerInspectorMiddleware from 'eth-json-rpc-middleware/block-tracker-inspector'
import providerFromMiddleware from 'eth-json-rpc-middleware/providerFromMiddleware'
import createInfuraMiddleware from 'eth-json-rpc-infura'
import BlockTracker from 'eth-block-tracker'
```
```javascript
xport default function createInfuraClient({ network, projectId }) {
  const infuraMiddleware = createInfuraMiddleware({
    network,
    projectId,
    maxAttempts: 5,
    source: 'metamask',
  })
  const infuraProvider = providerFromMiddleware(infuraMiddleware)
  const blockTracker = new BlockTracker({ provider: infuraProvider })

  const networkMiddleware = mergeMiddleware([
    createNetworkAndChainIdMiddleware({ network }),
    createBlockCacheMiddleware({ blockTracker }),
    createInflightMiddleware(),
    createBlockReRefMiddleware({ blockTracker, provider: infuraProvider }),
    createRetryOnEmptyMiddleware({ blockTracker, provider: infuraProvider }),
    createBlockTrackerInspectorMiddleware({ blockTracker }),
    infuraMiddleware,
  ])
  return { networkMiddleware, blockTracker }
}
```

## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/ens/ens.js#L4

```javascript
import EthJsEns from 'ethjs-ens'
import ensNetworkMap from 'ethereum-ens-network-map'
```
```javascript
export default class Ens {
  static getNetworkEnsSupport(network) {
    return Boolean(ensNetworkMap[network])
  }

  constructor({ network, provider } = {}) {
    this._ethJsEns = new EthJsEns({
      network,
      provider,
    })
  }

  lookup(ensName) {
    return this._ethJsEns.lookup(ensName)
  }

  reverse(address) {
    return this._ethJsEns.reverse(address)
  }
}
```
## https://github.com/MetaMask/metamask-extension/blob/9095ae3f47cf507a7166048db6000d514510099e/app/scripts/controllers/ens/index.js#L42

```javascript
import ethUtil from 'ethereumjs-util'
```
```javascript
export default class EnsController {
  constructor({ ens, provider, networkStore } = {}) {
    const initState = {
      ensResolutionsByAddress: {},
    }

    this._ens = ens
    if (!this._ens) {
      const network = networkStore.getState()
      if (Ens.getNetworkEnsSupport(network)) {
        this._ens = new Ens({
          network,
          provider,
        })
      }
    }

    this.store = new ObservableStore(initState)
    networkStore.subscribe((network) => {
      this.store.putState(initState)
      if (Ens.getNetworkEnsSupport(network)) {
        this._ens = new Ens({
          network,
          provider,
        })
      } else {
        delete this._ens
      }
    })
  }

  reverseResolveAddress(address) {
    return this._reverseResolveAddress(ethUtil.toChecksumAddress(address))
  }
```
