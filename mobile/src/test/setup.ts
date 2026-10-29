// Jest setup: native modules without a JS implementation get their official mocks.
jest.mock('@react-native-async-storage/async-storage', () =>
  // jest.mock factories must use require(): they run before ES imports are available.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
)

// Phones upload images with expo-file-system's native uploader. In tests it sends the same multipart
// form through global.fetch, so tests observe (and can fail) uploads exactly like other requests.
jest.mock('expo-file-system', () => {
  class File {
    uri: string
    constructor(uri: string) {
      this.uri = uri
    }
    async upload(
      url: string,
      options: {
        httpMethod?: string
        fieldName?: string
        mimeType?: string
        parameters?: Record<string, string>
        headers?: Record<string, string>
        signal?: AbortSignal
      } = {},
    ) {
      const form = new FormData()
      form.append(options.fieldName ?? 'file', { uri: this.uri, name: 'upload', type: options.mimeType } as unknown as Blob)
      for (const [key, value] of Object.entries(options.parameters ?? {})) form.append(key, value)
      const response = await fetch(url, { method: options.httpMethod ?? 'POST', headers: options.headers, body: form, signal: options.signal })
      return { status: response.status, body: await response.text(), headers: {} }
    }
  }
  return { ...jest.requireActual('expo-file-system'), File, UploadType: { BINARY_CONTENT: 0, MULTIPART: 1 } }
})
