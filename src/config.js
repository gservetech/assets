import path from 'node:path'

function readBaseUrl() {
  const raw = (process.env.PUBLIC_BASE_URL || 'https://assets.gservetech.com').trim()
  let url
  try {
    url = new URL(raw)
  } catch {
    throw new Error(`PUBLIC_BASE_URL is not a valid URL: ${raw}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('PUBLIC_BASE_URL must start with http:// or https://')
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error('PUBLIC_BASE_URL must be an origin only, for example https://assets.gservetech.com')
  }
  return url.origin
}

function readInt(name, fallback, min, max) {
  const raw = process.env[name]
  if (raw === undefined || raw.trim() === '') return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`)
  }
  return value
}

const WEAK_PASSWORDS = new Set([
  'change-me',
  'password',
  'admin',
  'admin123',
  'replace-with-a-long-random-password',
  'local-dev-only-change-me',
  'set-this-only-in-coolify',
  'local-only-not-for-coolify',
])

export const config = {
  port: readInt('PORT', 3004, 1, 65535),
  host: process.env.HOST || '0.0.0.0',
  adminPassword: (process.env.ADMIN_PASSWORD || '').trim(),
  publicBaseUrl: readBaseUrl(),
  storageDir: path.resolve(process.env.STORAGE_DIR || path.join(process.cwd(), 'data')),
  maxUploadBytes: readInt('MAX_UPLOAD_BYTES', 32 * 1024 * 1024, 1, 512 * 1024 * 1024),
  cacheMaxAge: readInt('CACHE_MAX_AGE', 86400, 0, 31536000),
  uploadsPerMinute: readInt('UPLOADS_PER_MINUTE', 120, 1, 10000),
}

export function productionConfigError(env = process.env, adminPassword = config.adminPassword) {
  if (env.NODE_ENV !== 'production') return null
  const weak = !adminPassword
    || adminPassword.length < 8
    || WEAK_PASSWORDS.has(adminPassword)
    || adminPassword.toLowerCase().includes('change-me')
  if (weak) {
    return 'Set ADMIN_PASSWORD to a private password of at least 8 characters before starting in production.'
  }
  return null
}

export function publicUrl(rel) {
  const encoded = rel.split('/').map((part) => encodeURIComponent(part)).join('/')
  return `${config.publicBaseUrl}/${encoded}`
}
