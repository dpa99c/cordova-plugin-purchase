import '../www/store';

describe('native purchase bridge additions', () => {
  let exec: jest.Mock;

  beforeEach(() => {
    exec = jest.fn();
    (window as any).cordova = {
      platformId: 'ios',
      exec,
    };
  });

  afterEach(() => {
    delete (window as any).cordova;
  });

  test('registers native log callbacks with the iOS service', () => {
    const callback = jest.fn();

    CdvPurchase.store.registerNativeLogCallback(callback);

    expect(exec).toHaveBeenCalledWith(
      expect.any(Function),
      expect.any(Function),
      'InAppPurchase',
      'setLogListener',
      [],
    );

    const success = exec.mock.calls[0][0];
    success({ level: 'warning', message: '[native] warning' });
    expect(callback).toHaveBeenCalledWith({ level: 'warning', message: '[native] warning' });
  });

  test('allows a later native log callback registration to replace the previous callback', () => {
    const firstCallback = jest.fn();
    const secondCallback = jest.fn();

    CdvPurchase.store.registerNativeLogCallback(firstCallback);
    CdvPurchase.store.registerNativeLogCallback(secondCallback);

    expect(exec).toHaveBeenCalledTimes(2);
    exec.mock.calls[1][0]({ level: 'error', message: '[native] error' });
    expect(firstCallback).not.toHaveBeenCalled();
    expect(secondCallback).toHaveBeenCalledTimes(1);
  });

  test('does not throw when a native log callback throws', () => {
    const callback = jest.fn(() => {
      throw new Error('callback failed');
    });

    CdvPurchase.store.registerNativeLogCallback(callback);
    expect(() => exec.mock.calls[0][0]({ level: 'info', message: '[native] info' })).not.toThrow();
  });

  test('gets a cached raw receipt through the StoreKit 1 bridge', async () => {
    exec.mockImplementation((success: (value?: string) => void, _error: unknown,
                             _service: string, action: string) => {
      if (action === 'getAppStoreReceipt') success('cmF3LXJlY2VpcHQ=');
    });
    const bridge = new CdvPurchase.AppleAppStore.Bridge.Bridge();

    await expect(bridge.getAppStoreReceipt?.()).resolves.toBe('cmF3LXJlY2VpcHQ=');
  });

  test('sets a raw receipt through the StoreKit 1 bridge', async () => {
    exec.mockImplementation((success: () => void, _error: unknown,
                             _service: string, action: string) => {
      if (action === 'setAppStoreReceipt') success();
    });
    const bridge = new CdvPurchase.AppleAppStore.Bridge.Bridge();

    await bridge.setAppStoreReceipt?.('cmF3LXJlY2VpcHQ=');
    expect(exec).toHaveBeenCalledWith(
      expect.any(Function),
      expect.any(Function),
      'InAppPurchase',
      'setAppStoreReceipt',
      ['cmF3LXJlY2VpcHQ='],
    );
  });

  test('preserves the parsed receipt payload returned by native refresh', () => {
    const payload = {
      bundleIdentifier: 'com.example.app',
      appVersion: '1.0',
      originalAppVersion: '1.0',
      expirationDate: null,
      inAppPurchases: [{
        quantity: 1,
        productIdentifier: 'com.example.app.walk',
        transactionIdentifier: 'transaction-1',
        originalTransactionIdentifier: 'transaction-1',
        purchaseDate: '2026-09-11T10:14:02Z',
        originalPurchaseDate: '2026-09-11T10:14:02Z',
        subscriptionExpirationDate: null,
        cancellationDate: null,
        webOrderLineItemID: 0,
      }],
      verified: true,
    };
    exec.mockImplementation((success: (value: unknown[]) => void,
                             _error: unknown, _service: string, action: string) => {
      if (action === 'appStoreRefreshReceipt') {
        success(['base64-receipt', 'com.example.app', '1.0', 1, null, payload]);
      }
    });
    const bridge = new CdvPurchase.AppleAppStore.Bridge.Bridge();
    const success = jest.fn();

    bridge.refreshReceipts(success, jest.fn());

    expect(success).toHaveBeenCalledWith(expect.objectContaining({payload}));
  });
});
