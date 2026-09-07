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
});
