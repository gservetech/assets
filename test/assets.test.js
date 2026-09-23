import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { after, before, test } from 'node:test'

const storage = await mkdtemp(path.join(os.tmpdir(), 'assets-'))
process.env.STORAGE_DIR = storage
process.env.ADMIN_PASSWORD = 'test-password-123456'
process.env.PUBLIC_BASE_URL = 'https://assets.gservetech.com'
process.env.NODE_ENV = 'test'
process.env.MAX_UPLOAD_BYTES = '1048576'
process.env.UPLOADS_PER_MINUTE = '1000'
process.env.CACHE_MAX_AGE = '86400'

const { createApp, ensureStorage } = await import('../src/server.js')
const { productionConfigError } = await import('../src/config.js')
const { sanitizeKey } = await import('../src/safe-path.js')

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64',
)

let server
let port
let cookie = ''

before(async () => {
  await ensureStorage()
  server = createApp()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = server.address().port
  const login = await request('POST', '/api/login', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'test-password-123456' }),
  })
  assert.equal(login.status, 200)
  cookie = sessionCookie(login)
})

after(async () => {
  await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
  await rm(storage, { recursive: true, force: true })
})

test('homepage is the password-protected manager', async () => {
  const response = await request('GET', '/')
  assert.equal(response.status, 200)
  assert.match(response.headers['content-type'], /text\/html/)
  assert.match(response.body.toString(), /Admin password/)
  assert.match(response.body.toString(), /gallery stays hidden until this sign-in succeeds/)
  assert.match(response.body.toString(), /id="login-form"/)
  assert.match(response.body.toString(), /id="gallery"/)
  assert.match(response.body.toString(), /id="app-view" hidden/)
  assert.match(response.body.toString(), /id="library"/)
  assert.match(response.body.toString(), /Search by saved name/)
  assert.match(response.body.toString(), /Copy URL/)
  assert.match(response.body.toString(), /Copy path/)
})

test('health reports the public asset origin', async () => {
  const response = await request('GET', '/health')
  assert.equal(response.status, 200)
  assert.equal(response.json.publicBaseUrl, 'https://assets.gservetech.com')
})

test('wrong password is rejected and a tampered session is rejected', async () => {
  const wrong = await request('POST', '/api/login', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'nope-nope-nope' }),
  })
  assert.equal(wrong.status, 401)

  const listed = await request('GET', '/api/files', { headers: { cookie: 'assets_session=1.forged' } })
  assert.equal(listed.status, 401)
})

test('login cookie is httpOnly and secure behind https', async () => {
  const response = await request('POST', '/api/login', {
    headers: {
      'content-type': 'application/json',
      'x-forwarded-proto': 'https',
    },
    body: JSON.stringify({ password: 'test-password-123456' }),
  })
  const header = cookieHeader(response)
  assert.match(header, /HttpOnly/)
  assert.match(header, /SameSite=Lax/)
  assert.match(header, /Secure/)
})

test('upload stores a public file under the asset domain', async () => {
  const denied = await request('POST', '/api/upload', form({
    fields: { directory: 'my photos' },
    file: { filename: 'A B.png', buffer: PNG },
  }))
  assert.equal(denied.status, 401)

  const created = await request('POST', '/api/upload', form({
    fields: { directory: 'my photos' },
    file: { filename: 'A B.png', buffer: PNG },
    cookie,
  }))
  assert.equal(created.status, 201)
  assert.equal(created.json.file.path, 'my-photos/A-B.png')
  assert.equal(created.json.file.url, 'https://assets.gservetech.com/my-photos/A-B.png')

  const stored = path.join(storage, 'my-photos', 'A-B.png')
  assert.equal((await stat(stored)).size, PNG.length)
  assert.equal(existsSync(path.join(storage, '..', 'escape.png')), false)

  const file = await request('GET', '/my-photos/A-B.png')
  assert.equal(file.status, 200)
  assert.equal(file.headers['content-type'], 'image/png')
  assert.equal(file.headers['x-content-type-options'], 'nosniff')
  assert.equal(file.headers['cross-origin-resource-policy'], 'cross-origin')
  assert.equal(file.headers['access-control-allow-origin'], '*')
  assert.ok(file.body.equals(PNG))
})

test('library, rename, replace, and delete require the admin session', async () => {
  const hidden = await request('GET', '/api/files')
  assert.equal(hidden.status, 401)

  const listed = await request('GET', '/api/files', { headers: { cookie } })
  assert.equal(listed.status, 200)
  assert.ok(listed.json.files.some((file) => file.name === 'A-B.png' && file.url === 'https://assets.gservetech.com/my-photos/A-B.png'))

  const byName = await request('GET', '/api/files?name=a-b', { headers: { cookie } })
  assert.equal(byName.status, 200)
  assert.deepEqual(byName.json.files.map((file) => file.name), ['A-B.png'])
  const missed = await request('GET', '/api/files?name=missing-name', { headers: { cookie } })
  assert.equal(missed.status, 200)
  assert.equal(missed.json.files.length, 0)

  const renamed = await request('POST', '/api/files/rename', {
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ from: 'my-photos/A-B.png', to: 'brand/logo.png' }),
  })
  assert.equal(renamed.status, 200)
  assert.equal(renamed.json.file.url, 'https://assets.gservetech.com/brand/logo.png')
  assert.equal((await request('GET', '/my-photos/A-B.png')).status, 404)
  assert.equal((await request('GET', '/brand/logo.png')).status, 200)

  const conflict = await request('POST', '/api/upload', form({
    fields: { path: 'brand/logo.png' },
    file: { filename: 'logo.png', buffer: PNG },
    cookie,
  }))
  assert.equal(conflict.status, 409)
  assert.equal(conflict.json.url, 'https://assets.gservetech.com/brand/logo.png')

  const replaced = await request('POST', '/api/upload', form({
    fields: { path: 'brand/logo.png', overwrite: 'true' },
    file: { filename: 'logo.png', buffer: Buffer.concat([PNG, Buffer.from('more')]) },
    cookie,
  }))
  assert.equal(replaced.status, 201)
  assert.equal((await request('GET', '/brand/logo.png')).body.length, PNG.length + 4)

  const blocked = await request('DELETE', '/api/files/brand/logo.png')
  assert.equal(blocked.status, 401)
  assert.equal((await request('GET', '/brand/logo.png')).status, 200)

  const removed = await request('DELETE', '/api/files/brand/logo.png', { headers: { cookie } })
  assert.equal(removed.status, 200)
  assert.equal((await request('GET', '/brand/logo.png')).status, 404)
})

test('a password header is not an admin login', async () => {
  const created = await request('POST', '/api/upload', form({
    fields: { path: 'script/dot.png' },
    file: { filename: 'dot.png', buffer: PNG },
    headers: { 'x-admin-password': 'test-password-123456' },
  }))
  assert.equal(created.status, 401)
})

test('rejects path escape, html disguised as png, and svg scripts', async () => {
  const escape = await request('POST', '/api/upload', form({
    fields: { path: '../escape.png' },
    file: { filename: 'escape.png', buffer: PNG },
    cookie,
  }))
  assert.equal(escape.status, 400)
  assert.equal(existsSync(path.resolve(storage, '..', 'escape.png')), false)

  const html = await request('POST', '/api/upload', form({
    fields: { path: 'bad.png' },
    file: { filename: 'bad.png', buffer: Buffer.from('<html></html>') },
    cookie,
  }))
  assert.equal(html.status, 415)

  const script = await request('POST', '/api/upload', form({
    fields: { path: 'bad.svg' },
    file: { filename: 'bad.svg', buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>') },
    cookie,
  }))
  assert.equal(script.status, 415)

  const svg = await request('POST', '/api/upload', form({
    fields: { path: 'mark.svg' },
    file: { filename: 'mark.svg', buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>') },
    cookie,
  }))
  assert.equal(svg.status, 201)
  const body = await request('GET', '/mark.svg')
  assert.equal(body.headers['content-type'], 'image/svg+xml')
  assert.match(body.headers['content-security-policy'], /sandbox/)
})

test('logout ends the management session', async () => {
  const fresh = await request('POST', '/api/login', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'test-password-123456' }),
  })
  const signedIn = sessionCookie(fresh)
  const gone = await request('POST', '/api/logout', { headers: { cookie: signedIn } })
  assert.match(cookieHeader(gone), /Max-Age=0/)
  const listed = await request('GET', '/api/files', { headers: { cookie: signedIn } })
  assert.equal(listed.status, 401)
})

test('names are sanitized and production refuses a placeholder password', () => {
  assert.equal(sanitizeKey('My Photos/Logo Final.PNG').rel, 'My-Photos/Logo-Final.png')
  assert.equal(productionConfigError({ NODE_ENV: 'test' }, 'short'), null)
  assert.match(productionConfigError({ NODE_ENV: 'production' }, 'short') || '', /ADMIN_PASSWORD/)
  assert.match(productionConfigError({ NODE_ENV: 'production' }, 'replace-with-a-long-random-password') || '', /ADMIN_PASSWORD/)
  assert.match(productionConfigError({ NODE_ENV: 'production' }, 'set-this-only-in-coolify') || '', /ADMIN_PASSWORD/)
  assert.equal(productionConfigError({ NODE_ENV: 'production' }, 'a-real-private-password'), null)
})

function sessionCookie(response) {
  const pair = cookieHeader(response).split(';')[0]
  return pair
}

function cookieHeader(response) {
  const raw = response.headers['set-cookie']
  const line = Array.isArray(raw) ? raw[0] : raw
  assert.ok(line)
  return line
}

function form({ fields = {}, file, cookie: cookieValue, headers = {} }) {
  const boundary = '----assetstest'
  const chunks = []
  for (const [name, value] of Object.entries(fields)) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`))
  }
  chunks.push(Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
  ))
  chunks.push(file.buffer)
  chunks.push(Buffer.from(`\r\n--${boundary}--\r\n`))
  const body = Buffer.concat(chunks)
  return {
    body,
    headers: {
      ...headers,
      'content-type': `multipart/form-data; boundary=${boundary}`,
      'content-length': String(body.length),
      ...(cookieValue ? { cookie: cookieValue } : {}),
    },
  }
}

function request(method, pathname, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path: pathname,
      headers,
    }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        const type = String(res.headers['content-type'] || '')
        let json = null
        if (type.includes('json') && raw.length) json = JSON.parse(raw.toString())
        resolve({ status: res.statusCode, headers: res.headers, body: raw, json })
      })
    })
    req.setTimeout(5000, () => req.destroy(new Error('request timed out')))
    req.on('error', reject)
    if (body) req.end(body)
    else req.end()
  })
}
