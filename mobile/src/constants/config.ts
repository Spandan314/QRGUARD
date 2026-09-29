// Public build-time settings (EXPO_PUBLIC_*). Never put secrets here.
export const API_BASE_URL = (process.env.EXPO_PUBLIC_API_BASE_URL || 'http://10.0.2.2:5000').replace(/\/+$/, '')
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024
export const MAX_MESSAGE_CHARS = 5000
export const MAX_URL_CHARS = 2048
