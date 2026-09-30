// Jest setup: native modules without a JS implementation get their official mocks.
jest.mock('@react-native-async-storage/async-storage', () =>
  // jest.mock factories must use require(): they run before ES imports are available.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
)
