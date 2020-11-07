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