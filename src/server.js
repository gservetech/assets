import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { constants } from 'node:fs'
import {
  copyFile,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rm,
  rmdir,
  stat,
  unlink,
} from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import Busboy from 'busboy'
import { config, productionConfigError, publicUrl } from './config.js'
import {
  CONTENT_TYPES,
  HttpError,
  assertFileMagic,
  assertSvg,
  sanitizeDirectory,
  sanitizeFileName,
  sanitizeKey,
  strictKey,
} from './safe-path.js'

const indexHtml = readFileSync(new URL('./public/index.html', import.meta.url))
const hits = new Map()
const sessions = new Map()
const SESSION_MS = 7 * 24 * 60 * 60 * 1000

export async function ensureStorage() {
  const tmp = path.join(config.storageDir, '.tmp')
  await mkdir(config.storageDir, { recursive: true })
  await rm(tmp, { recursive: true, force: true })
  await mkdir(tmp, { recursive: true })
}

export function createApp() {
  const server = createServer((req, res) => {
    dispatch(req, res).catch((err) => {
      if (res.headersSent) {
        res.destroy()
        return
      }
      const error = normalizeError(err)
      if (error instanceof HttpError) {
        sendJson(res, error.status, {
          ok: false,
          error: error.message,
          ...(error.extra || {}),
        })
        return
      }
      console.error(error)
      sendJson(res, 500, { ok: false, error: 'Internal error' })
    })
  })
  server.requestTimeout = 5 * 60 * 1000
  return server
}

export async function start() {
  const problem = productionConfigError()
  if (problem) {
    console.error(problem)
    process.exit(1)
  }
  await ensureStorage()
  const server = createApp()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(config.port, config.host, resolve)
  })
  console.log(`Listening on ${config.host}:${config.port}`)
  console.log(`Public base URL: ${config.publicBaseUrl}`)
  console.log(`Storage directory: ${config.storageDir}`)
  if (!config.adminPassword) console.warn('ADMIN_PASSWORD is empty. The management page cannot change files.')
  const shutdown = () => {
    server.close(() => process.exit(0))
    setTimeout(() => process.exit(0), 5000).unref()
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
  return server
}

function normalizeError(err) {
  if (err && err.code === 'ENOSPC') return new HttpError(507, 'The storage disk is full')
  return err
}

async function dispatch(req, res) {
  const method = req.method || 'GET'
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, HEAD, POST, DELETE, OPTIONS',
      'access-control-allow-headers': 'authorization, content-type, x-api-key',
      'access-control-max-age': '86400',
      'content-length': '0',
    })
    res.end()
    return
  }

  let pathname = pathnameOf(req)
  if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1)

  if ((method === 'GET' || method === 'HEAD') && pathname === '/health') {
    sendBuffer(res, 200, JSON.stringify({ ok: true, publicBaseUrl: config.publicBaseUrl }), {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'access-control-allow-origin': '*',
    }, method)
    return
  }

  if ((method === 'GET' || method === 'HEAD') && pathname === '/robots.txt') {
    sendBuffer(res, 200, 'User-agent: *\nAllow: /\nDisallow: /api/\n', {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=3600',
      'x-content-type-options': 'nosniff',
    }, method)
    return
  }

  if ((method === 'GET' || method === 'HEAD') && pathname === '/') {
    sendBuffer(res, 200, indexHtml, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'x-robots-tag': 'noindex',
    }, method)
    return
  }

  if (method === 'GET' && pathname === '/api/session') {
    sendJson(res, 200, {
      ok: true,
      authenticated: authorized(req),
      publicBaseUrl: config.publicBaseUrl,
    })
    return
  }
  if (method === 'POST' && pathname === '/api/login') {
    await handleLogin(req, res)
    return
  }
  if (method === 'POST' && pathname === '/api/logout') {
    revokeSession(req)
    req.resume()
    sendJson(res, 200, { ok: true }, { 'set-cookie': clearCookie(req) })
    return
  }
  if (method === 'POST' && pathname === '/api/upload') {
    await handleUpload(req, res)
    return
  }
  if (method === 'GET' && pathname === '/api/files') {
    await handleList(req, res)
    return
  }
  if (method === 'POST' && pathname === '/api/files/rename') {
    await handleRename(req, res)
    return
  }
  if (method === 'DELETE' && pathname.startsWith('/api/files/')) {
    requireAuth(req)
    const deleted = await handleDelete(pathname.slice('/api/files/'.length))
    sendJson(res, 200, { ok: true, path: deleted })
    return
  }
  if (pathname === '/api' || pathname.startsWith('/api/')) throw new HttpError(404, 'Not found')
  if (method === 'GET' || method === 'HEAD') {
    await handleFile(req, res, pathname.slice(1), method)
    return
  }
  throw new HttpError(405, 'Method not allowed')
}

function pathnameOf(req) {
  const raw = String(req.url || '/').split('?')[0]
  if (!raw.startsWith('/') || raw.includes('\\') || raw.includes('\0')) {
    throw new HttpError(400, 'Invalid URL')
  }
  let decoded
  try {
    decoded = decodeURIComponent(raw)
  } catch {
    throw new HttpError(400, 'Invalid URL')
  }
  if (!decoded.startsWith('/') || decoded.includes('\\') || decoded.includes('\0')) {
    throw new HttpError(400, 'Invalid URL')
  }
  return decoded
}

async function handleFile(req, res, rawRel, method) {
  const { rel, ext } = strictKey(rawRel)
  const full = resolveInside(rel)
  let info
  try {
    info = await lstat(full)
  } catch (err) {
    if (err.code === 'ENOENT') throw new HttpError(404, 'Not found')
    throw err
  }
  if (info.isSymbolicLink() || !info.isFile()) throw new HttpError(404, 'Not found')
  sendStoredFile(req, res, full, info, CONTENT_TYPES[ext], method)
}

function sendStoredFile(req, res, full, info, contentType, method) {
  const etag = `W/"${info.size}-${Math.round(info.mtimeMs)}"`
  const headers = {
    'content-type': contentType,
    etag,
    'accept-ranges': 'bytes',
    'cache-control': `public, max-age=${config.cacheMaxAge}`,
    'x-content-type-options': 'nosniff',
    'cross-origin-resource-policy': 'cross-origin',
    'access-control-allow-origin': '*',
    'content-security-policy': contentType === 'image/svg+xml'
      ? "default-src 'none'; style-src 'unsafe-inline'; sandbox"
      : "default-src 'none'",
    'last-modified': info.mtime.toUTCString(),
  }
  const inm = req.headers['if-none-match']
  if (typeof inm === 'string' && inm.split(',').some((part) => part.trim() === etag)) {
    res.writeHead(304, headers)
    res.end()
    return
  }

  if (method === 'GET' && req.headers.range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range)
    const unsatisfiable = () => {
      res.writeHead(416, { ...headers, 'content-range': `bytes */${info.size}` })
      res.end()
    }
    if (!match || (match[1] === '' && match[2] === '') || info.size === 0) {
      unsatisfiable()
      return
    }
    let start
    let end
    if (match[1] === '') {
      const suffix = Number(match[2])
      start = Math.max(info.size - suffix, 0)
      end = info.size - 1
    } else {
      start = Number(match[1])
      end = match[2] === '' ? info.size - 1 : Number(match[2])
    }
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || start >= info.size) {
      unsatisfiable()
      return
    }
    end = Math.min(end, info.size - 1)
    headers['content-range'] = `bytes ${start}-${end}/${info.size}`
    headers['content-length'] = String(end - start + 1)
    res.writeHead(206, headers)
    pipeFile(res, createReadStream(full, { start, end }))
    return
  }

  headers['content-length'] = String(info.size)
  res.writeHead(200, headers)
  if (method === 'HEAD') {
    res.end()
    return
  }
  pipeFile(res, createReadStream(full))
}

function pipeFile(res, stream) {
  stream.on('error', () => {
    if (!res.headersSent) sendJson(res, 404, { ok: false, error: 'Not found' })
    else res.destroy()
  })
  res.on('close', () => stream.destroy())
  stream.pipe(res)
}

async function handleList(req, res) {
  requireAuth(req)
  const url = new URL(req.url || '/', 'http://127.0.0.1')
  const requested = url.searchParams.get('prefix')
  const prefix = requested && requested.trim() ? sanitizeDirectory(requested) : ''
  const nameQuery = (url.searchParams.get('name') || '').trim().toLowerCase()
  const files = []
  await walk(config.storageDir, '', files)
  const filtered = files.filter((file) => {
    if (prefix && file.path !== prefix && !file.path.startsWith(`${prefix}/`)) return false
    if (nameQuery && !file.name.toLowerCase().includes(nameQuery)) return false
    return true
  })
  filtered.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0))
  sendJson(res, 200, {
    ok: true,
    files: filtered.slice(0, 2000),
    truncated: filtered.length > 2000,
  })
}

async function walk(dir, prefix, out) {
  if (out.length >= 2000) return
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch (err) {
    if (err.code === 'ENOENT') return
    throw err
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name
    const full = path.join(dir, entry.name)
    if (entry.isSymbolicLink()) continue
    if (entry.isDirectory()) {
      await walk(full, rel, out)
      continue
    }
    if (!entry.isFile()) continue
    let key
    try {
      key = strictKey(rel)
    } catch {
      continue
    }
    const info = await stat(full)
    out.push(describeFile(key.rel, key.ext, info))
    if (out.length >= 2000) return
  }
}

async function handleDelete(rawRel) {
  let decoded
  try {
    decoded = decodeURIComponent(rawRel)
  } catch {
    throw new HttpError(400, 'Invalid URL')
  }
  const { rel } = strictKey(decoded)
  const full = resolveInside(rel)
  let info
  try {
    info = await lstat(full)
  } catch (err) {
    if (err.code === 'ENOENT') throw new HttpError(404, 'Not found')
    throw err
  }
  if (info.isSymbolicLink() || !info.isFile()) throw new HttpError(404, 'Not found')
  await unlink(full)
  await removeEmptyParents(path.dirname(full))
  console.log(`${new Date().toISOString()} deleted ${rel}`)
  return rel
}

async function handleRename(req, res) {
  requireAuth(req)
  const body = await readJson(req)
  if (typeof body.from !== 'string' || typeof body.to !== 'string') {
    throw new HttpError(400, 'Say which file to rename and its new path')
  }
  const from = strictKey(body.from)
  const to = sanitizeKey(body.to)
  const src = resolveInside(from.rel)
  let info
  try {
    info = await lstat(src)
  } catch (err) {
    if (err.code === 'ENOENT') throw new HttpError(404, 'Not found')
    throw err
  }
  if (info.isSymbolicLink() || !info.isFile()) throw new HttpError(404, 'Not found')
  if (from.rel === to.rel) {
    sendJson(res, 200, { ok: true, file: describeFile(to.rel, to.ext, info) })
    return
  }
  if (from.ext !== to.ext) await assertStoredMatches(src, to.ext)
  const dest = resolveInside(to.rel)
  let existing = null
  try {
    existing = await lstat(dest)
  } catch (err) {
    if (err.code !== 'ENOENT') throw err
  }
  if (existing) {
    if (body.overwrite !== true) {
      throw new HttpError(409, 'A file already exists at that path.', {
        url: publicUrl(to.rel),
        path: to.rel,
      })
    }
    if (existing.isSymbolicLink() || !existing.isFile()) throw new HttpError(400, 'Cannot replace that path')
    await unlink(dest)
  }
  await mkdir(path.dirname(dest), { recursive: true })
  await rename(src, dest)
  await removeEmptyParents(path.dirname(src))
  const updated = await stat(dest)
  console.log(`${new Date().toISOString()} renamed ${from.rel} -> ${to.rel}`)
  sendJson(res, 200, { ok: true, file: describeFile(to.rel, to.ext, updated) })
}

async function assertStoredMatches(full, ext) {
  if (ext === 'svg') {
    const svg = await readFile(full)
    if (svg.includes(0)) throw new HttpError(415, 'SVG must be text')
    assertSvg(svg.toString('utf8'))
    return
  }
  const handle = await open(full, 'r')
  try {
    const head = Buffer.alloc(4096)
    const { bytesRead } = await handle.read(head, 0, 4096, 0)
    assertFileMagic(ext, head.subarray(0, bytesRead))
  } finally {
    await handle.close()
  }
}

async function removeEmptyParents(start) {
  const root = path.resolve(config.storageDir)
  let dir = path.resolve(start)
  while (dir.startsWith(`${root}${path.sep}`)) {
    const entries = await readdir(dir)
    if (entries.length > 0) return
    await rmdir(dir)
    dir = path.dirname(dir)
  }
}

async function handleUpload(req, res) {
  requireAuth(req)
  rateLimit(req, 'upload', config.uploadsPerMinute)
  const length = Number(req.headers['content-length'] || 0)
  if (Number.isFinite(length) && length > config.maxUploadBytes + 64 * 1024) {
    req.resume()
    throw new HttpError(413, 'Upload is too large')
  }
  const type = String(req.headers['content-type'] || '')
  if (!type.toLowerCase().includes('multipart/form-data')) {
    req.resume()
    throw new HttpError(415, 'Send the file as multipart/form-data')
  }

  let tmpPath = ''
  try {
    const upload = await readUpload(req)
    tmpPath = upload.tmpPath
    if (upload.truncated || upload.bytes > config.maxUploadBytes) {
      throw new HttpError(413, 'Upload is too large')
    }
    if (!upload.bytes) throw new HttpError(400, 'File is empty')
    const { rel, ext } = destinationFrom(upload.fields, upload.originalName)
    assertFileMagic(ext, upload.head)
    if (ext === 'svg') {
      const svg = await readFile(tmpPath)
      if (svg.includes(0)) throw new HttpError(415, 'SVG must be text')
      assertSvg(svg.toString('utf8'))
    }
    const overwrite = ['true', '1', 'on', 'yes'].includes(String(upload.fields.overwrite || '').toLowerCase())
    const file = await publish(tmpPath, rel, ext, overwrite)
    console.log(`${new Date().toISOString()} stored ${file.path} (${file.size} bytes)`)
    sendJson(res, 201, { ok: true, file })
  } finally {
    if (tmpPath) await removeTemp(tmpPath)
  }
}

function destinationFrom(fields, originalName) {
  if (fields.path && String(fields.path).trim()) return sanitizeKey(fields.path)
  const name = sanitizeFileName(fields.filename || originalName)
  const directory = sanitizeDirectory(fields.directory || '')
  return sanitizeKey(directory ? `${directory}/${name}` : name)
}

async function publish(tmpPath, rel, ext, overwrite) {
  const full = resolveInside(rel)
  await mkdir(path.dirname(full), { recursive: true })
  if (overwrite) {
    await moveIntoPlace(tmpPath, full)
  } else {
    try {
      await copyFile(tmpPath, full, constants.COPYFILE_EXCL)
    } catch (err) {
      if (err.code === 'EEXIST') {
        throw new HttpError(409, 'A file already exists at that path. Turn on replace to overwrite it.', {
          url: publicUrl(rel),
          path: rel,
        })
      }
      throw err
    }
  }
  const info = await stat(full)
  return describeFile(rel, ext, info)
}

function describeFile(rel, ext, info) {
  return {
    path: rel,
    name: rel.split('/').pop(),
    url: publicUrl(rel),
    size: info.size,
    contentType: CONTENT_TYPES[ext],
    updatedAt: info.mtime.toISOString(),
  }
}

async function moveIntoPlace(from, to) {
  try {
    await rename(from, to)
  } catch (err) {
    if (err.code !== 'EEXIST' && err.code !== 'EPERM') throw err
    await unlink(to)
    await rename(from, to)
  }
}

function readUpload(req) {
  const tmpPath = path.join(config.storageDir, '.tmp', randomBytes(16).toString('hex'))
  return new Promise((resolve, reject) => {
    let settled = false
    let fileSeen = false
    let writeFinished = false
    let parserFinished = false
    let truncated = false
    let tooMany = false
    let bytes = 0
    let head = Buffer.alloc(0)
    let originalName = ''
    let incoming = null
    let outgoing = null
    const fields = {}

    const fail = (error) => {
      if (settled) return
      settled = true
      incoming?.destroy()
      outgoing?.destroy()
      removeTemp(tmpPath).finally(() => reject(error))
    }
    const succeed = (value) => {
      if (settled) return
      settled = true
      resolve(value)
    }
    const maybe = () => {
      if (settled || !parserFinished || !fileSeen || !writeFinished) return
      if (tooMany) {
        fail(new HttpError(400, 'Upload one file at a time'))
        return
      }
      succeed({ fields, originalName, bytes, head, tmpPath, truncated })
    }

    let parser
    try {
      parser = Busboy({
        headers: req.headers,
        limits: {
          files: 1,
          fileSize: config.maxUploadBytes,
          fields: 8,
          fieldSize: 1024,
          parts: 12,
        },
      })
    } catch {
      fail(new HttpError(400, 'Upload was not valid multipart data'))
      return
    }

    parser.on('field', (name, value) => {
      if (typeof value === 'string' && fields[name] === undefined) fields[name] = value
    })
    parser.on('file', (name, stream, info) => {
      if (fileSeen || name !== 'file') {
        stream.resume()
        return
      }
      fileSeen = true
      incoming = stream
      originalName = info && typeof info.filename === 'string' ? info.filename : ''
      outgoing = createWriteStream(tmpPath)
      outgoing.on('error', (err) => {
        fail(err.code === 'ENOSPC' ? new HttpError(507, 'The storage disk is full') : err)
      })
      outgoing.on('finish', () => {
        writeFinished = true
        maybe()
      })
      stream.on('data', (chunk) => {
        bytes += chunk.length
        if (head.length < 4096) head = Buffer.concat([head, chunk]).subarray(0, 4096)
      })
      stream.on('limit', () => {
        truncated = true
      })
      stream.on('error', () => fail(new HttpError(400, 'Upload was interrupted')))
      stream.pipe(outgoing)
    })
    parser.on('filesLimit', () => {
      tooMany = true
    })
    parser.on('error', () => fail(new HttpError(400, 'Upload was not valid multipart data')))
    const parserDone = () => {
      if (parserFinished || settled) return
      parserFinished = true
      if (!fileSeen) {
        fail(new HttpError(400, 'Choose a file to upload'))
        return
      }
      maybe()
    }
    parser.on('finish', parserDone)
    parser.on('close', parserDone)
    req.on('aborted', () => fail(new HttpError(400, 'Upload was interrupted')))
    req.pipe(parser)
  })
}

async function handleLogin(req, res) {
  rateLimit(req, 'login', 20)
  const body = await readJson(req)
  const password = typeof body.password === 'string' ? body.password : ''
  if (!passwordMatches(password)) throw new HttpError(401, 'Wrong password')
  sendJson(res, 200, { ok: true }, { 'set-cookie': sessionCookie(req, signSession()) })
}

function requireAuth(req) {
  if (!authorized(req)) {
    req.resume()
    throw new HttpError(401, 'Sign in required')
  }
}

function authorized(req) {
  if (!config.adminPassword) return false
  return sessionValid(req)
}

function passwordMatches(presented) {
  if (!config.adminPassword || !presented) return false
  const left = createHash('sha256').update(presented).digest()
  const right = createHash('sha256').update(config.adminPassword).digest()
  return timingSafeEqual(left, right)
}

function signSession() {
  pruneSessions()
  const exp = Date.now() + SESSION_MS
  const id = randomBytes(18).toString('base64url')
  const payload = `${exp}.${id}`
  const sig = createHmac('sha256', config.adminPassword).update(payload).digest('base64url')
  sessions.set(id, exp)
  return `${payload}.${sig}`
}

function readSession(req) {
  const token = readCookie(req, 'assets_session')
  if (!token || !config.adminPassword) return null
  const dot = token.lastIndexOf('.')
  if (dot <= 0) return null
  const payload = token.slice(0, dot)
  const sig = token.slice(dot + 1)
  const expected = createHmac('sha256', config.adminPassword).update(payload).digest('base64url')
  const left = Buffer.from(sig)
  const right = Buffer.from(expected)
  if (left.length !== right.length || !timingSafeEqual(left, right)) return null
  const split = payload.indexOf('.')
  if (split <= 0) return null
  const exp = Number(payload.slice(0, split))
  const id = payload.slice(split + 1)
  if (!Number.isFinite(exp) || !id) return null
  return { exp, id }
}

function sessionValid(req) {
  const session = readSession(req)
  if (!session) return false
  if (sessions.get(session.id) !== session.exp || session.exp <= Date.now()) {
    sessions.delete(session.id)
    return false
  }
  return true
}

function revokeSession(req) {
  const session = readSession(req)
  if (session) sessions.delete(session.id)
}

function pruneSessions() {
  const now = Date.now()
  for (const [id, exp] of sessions) {
    if (exp <= now) sessions.delete(id)
  }
}

function readCookie(req, name) {
  const raw = req.headers.cookie
  if (typeof raw !== 'string') return ''
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1).trim())
      } catch {
        return ''
      }
    }
  }
  return ''
}

function requestIsSecure(req) {
  if (req.socket && req.socket.encrypted) return true
  const proto = req.headers['x-forwarded-proto']
  return typeof proto === 'string' && proto.split(',')[0].trim().toLowerCase() === 'https'
}

function sessionCookie(req, token) {
  const secure = requestIsSecure(req) ? '; Secure' : ''
  return `assets_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_MS / 1000)}${secure}`
}

function clearCookie(req) {
  const secure = requestIsSecure(req) ? '; Secure' : ''
  return `assets_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`
}

function rateLimit(req, bucketName, limit) {
  const now = Date.now()
  const ip = `${bucketName}:${clientIp(req)}`
  let bucket = hits.get(ip)
  if (!bucket || now - bucket.start >= 60_000) {
    bucket = { start: now, count: 0 }
    hits.set(ip, bucket)
  }
  bucket.count += 1
  if (hits.size > 5000) {
    for (const [key, value] of hits) {
      if (now - value.start >= 60_000) hits.delete(key)
    }
  }
  if (bucket.count > limit) throw new HttpError(429, 'Too many attempts. Wait a minute and try again.')
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    let settled = false
    const fail = (error) => {
      if (settled) return
      settled = true
      reject(error)
    }
    const succeed = (value) => {
      if (settled) return
      settled = true
      resolve(value)
    }
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > 8192) {
        req.destroy()
        fail(new HttpError(413, 'Request is too large'))
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim()
      if (!raw) {
        succeed({})
        return
      }
      try {
        const value = JSON.parse(raw)
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
          fail(new HttpError(400, 'Expected a JSON object'))
          return
        }
        succeed(value)
      } catch {
        fail(new HttpError(400, 'Expected JSON'))
      }
    })
    req.on('error', () => fail(new HttpError(400, 'Request was interrupted')))
  })
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim()
  return req.socket.remoteAddress || 'unknown'
}

function resolveInside(rel) {
  const root = path.resolve(config.storageDir)
  const full = path.resolve(root, rel)
  const relative = path.relative(root, full)
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new HttpError(400, 'Invalid path')
  }
  return full
}

function sendJson(res, status, body, extraHeaders = {}) {
  sendBuffer(res, status, JSON.stringify(body), {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'access-control-allow-origin': '*',
    ...extraHeaders,
  }, 'GET')
}

function sendBuffer(res, status, body, headers, method) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body)
  res.writeHead(status, { 'content-length': payload.length, ...headers })
  res.end(method === 'HEAD' ? undefined : payload)
}

async function removeTemp(target) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rm(target, { force: true })
      return
    } catch (err) {
      if (attempt === 4 || (err.code !== 'EBUSY' && err.code !== 'EPERM')) return
      await new Promise((resolve) => setTimeout(resolve, 20 * (attempt + 1)))
    }
  }
}

const invokedDirectly = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href

if (invokedDirectly) {
  start().catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
