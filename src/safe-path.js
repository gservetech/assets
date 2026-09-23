export class HttpError extends Error {
  constructor(status, message, extra) {
    super(message)
    this.name = 'HttpError'
    this.status = status
    this.extra = extra
  }
}

export const CONTENT_TYPES = {
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  gif: 'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  svg: 'image/svg+xml',
  ico: 'image/x-icon',
  pdf: 'application/pdf',
  mp4: 'video/mp4',
  webm: 'video/webm',
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  ogg: 'audio/ogg',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  otf: 'font/otf',
  css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8',
}

const RESERVED_ROOTS = new Set(['api', 'health'])
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i

function cleanSegment(part) {
  if (part === '..') throw new HttpError(400, 'Invalid path')
  const segment = part
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-.]+/, '')
    .replace(/[-.]+$/, '')
  if (!segment || segment.length > 120 || !SEGMENT.test(segment)) {
    throw new HttpError(400, 'Use letters, numbers, dots, dashes, and underscores in the path')
  }
  const stem = segment.slice(0, segment.indexOf('.') === -1 ? segment.length : segment.indexOf('.'))
  if (WINDOWS_DEVICE.test(stem)) throw new HttpError(400, 'That file name is not allowed')
  return segment
}

function extensionOf(filename) {
  const dot = filename.lastIndexOf('.')
  if (dot <= 0) return ''
  return filename.slice(dot + 1).toLowerCase()
}

export function sanitizeDirectory(input) {
  const raw = String(input || '').trim().replace(/\\/g, '/')
  if (!raw) return ''
  const parts = []
  for (const part of raw.split('/')) {
    if (!part || part === '.') continue
    parts.push(cleanSegment(part))
  }
  if (!parts.length) return ''
  if (parts.length > 11) throw new HttpError(400, 'Path is too deep')
  if (RESERVED_ROOTS.has(parts[0].toLowerCase())) throw new HttpError(400, 'That path is reserved')
  return parts.join('/')
}

export function sanitizeFileName(input) {
  const raw = String(input || '').replace(/\\/g, '/').split('/').pop() || ''
  const segment = cleanSegment(raw.trim())
  const ext = extensionOf(segment)
  if (!CONTENT_TYPES[ext]) throw new HttpError(400, `Files of type .${ext || 'unknown'} are not allowed`)
  return `${segment.slice(0, segment.lastIndexOf('.'))}.${ext}`
}

export function sanitizeKey(input) {
  const raw = String(input || '').trim().replace(/\\/g, '/')
  const parts = []
  for (const part of raw.split('/')) {
    if (!part || part === '.') continue
    parts.push(cleanSegment(part))
  }
  if (!parts.length) throw new HttpError(400, 'Path is empty')
  if (parts.length > 12) throw new HttpError(400, 'Path is too deep')
  if (RESERVED_ROOTS.has(parts[0].toLowerCase())) throw new HttpError(400, 'That path is reserved')
  const ext = extensionOf(parts[parts.length - 1])
  if (!CONTENT_TYPES[ext]) throw new HttpError(400, `Files of type .${ext || 'unknown'} are not allowed`)
  const filename = parts[parts.length - 1]
  parts[parts.length - 1] = `${filename.slice(0, filename.lastIndexOf('.'))}.${ext}`
  const rel = parts.join('/')
  if (rel === 'robots.txt') throw new HttpError(400, 'That path is reserved')
  return { rel, ext }
}

export function strictKey(input) {
  const raw = String(input || '')
  if (!raw || raw.length > 512) throw new HttpError(404, 'Not found')
  const parts = raw.split('/')
  if (parts.length > 12) throw new HttpError(404, 'Not found')
  for (const part of parts) {
    if (!SEGMENT.test(part) || part.startsWith('.')) throw new HttpError(404, 'Not found')
  }
  if (RESERVED_ROOTS.has(parts[0].toLowerCase())) throw new HttpError(404, 'Not found')
  const ext = extensionOf(parts[parts.length - 1])
  if (!CONTENT_TYPES[ext]) throw new HttpError(404, 'Not found')
  const rel = parts.join('/')
  if (rel === 'robots.txt') throw new HttpError(404, 'Not found')
  return { rel, ext }
}

function ascii(buffer, start, length) {
  return buffer.subarray(start, start + length).toString('ascii')
}

function ftypBrands(buffer) {
  if (buffer.length < 12 || ascii(buffer, 4, 4) !== 'ftyp') return null
  const brands = [ascii(buffer, 8, 4)]
  for (let offset = 16; offset + 4 <= Math.min(buffer.length, 64); offset += 4) {
    brands.push(ascii(buffer, offset, 4))
  }
  return brands
}

export function assertFileMagic(ext, head) {
  if (!head || head.length === 0) throw new HttpError(415, 'File is empty')
  const fail = () => {
    throw new HttpError(415, `File contents do not look like a .${ext}`)
  }

  if (ext === 'svg' || ext === 'css' || ext === 'js' || ext === 'json') {
    if (head.includes(0)) fail()
  }

  if (ext === 'png') {
    const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    if (!head.subarray(0, 8).equals(signature)) fail()
    return
  }
  if (ext === 'jpg' || ext === 'jpeg') {
    if (!(head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff)) fail()
    return
  }
  if (ext === 'gif') {
    const tag = ascii(head, 0, 6)
    if (tag !== 'GIF87a' && tag !== 'GIF89a') fail()
    return
  }
  if (ext === 'webp') {
    if (ascii(head, 0, 4) !== 'RIFF' || ascii(head, 8, 4) !== 'WEBP') fail()
    return
  }
  if (ext === 'avif') {
    const brands = ftypBrands(head)
    if (!brands || !brands.some((brand) => brand === 'avif' || brand === 'avis')) fail()
    return
  }
  if (ext === 'ico') {
    if (!(head[0] === 0 && head[1] === 0 && head[2] === 1 && head[3] === 0)) fail()
    return
  }
  if (ext === 'pdf') {
    if (ascii(head, 0, 4) !== '%PDF') fail()
    return
  }
  if (ext === 'mp4') {
    const brands = ftypBrands(head)
    if (!brands || brands[0] === 'avif' || brands[0] === 'avis') fail()
    return
  }
  if (ext === 'webm') {
    if (!(head[0] === 0x1a && head[1] === 0x45 && head[2] === 0xdf && head[3] === 0xa3)) fail()
    return
  }
  if (ext === 'mp3') {
    const id3 = ascii(head, 0, 3) === 'ID3'
    const frame = head[0] === 0xff && (head[1] & 0xe0) === 0xe0
    if (!id3 && !frame) fail()
    return
  }
  if (ext === 'wav') {
    if (ascii(head, 0, 4) !== 'RIFF' || ascii(head, 8, 4) !== 'WAVE') fail()
    return
  }
  if (ext === 'ogg') {
    if (ascii(head, 0, 4) !== 'OggS') fail()
    return
  }
  if (ext === 'woff') {
    if (ascii(head, 0, 4) !== 'wOFF') fail()
    return
  }
  if (ext === 'woff2') {
    if (ascii(head, 0, 4) !== 'wOF2') fail()
    return
  }
  if (ext === 'otf') {
    if (ascii(head, 0, 4) !== 'OTTO') fail()
    return
  }
  if (ext === 'ttf') {
    const tag = ascii(head, 0, 4)
    const ttf = head[0] === 0 && head[1] === 1 && head[2] === 0 && head[3] === 0
    if (tag !== 'true' && tag !== 'ttcf' && !ttf) fail()
    return
  }
  if (ext === 'json') {
    const start = head.toString('utf8').trimStart()
    if (start[0] !== '{' && start[0] !== '[') fail()
    return
  }
  if (ext === 'css' || ext === 'js') {
    const start = head.toString('utf8').trimStart().slice(0, 16).toLowerCase()
    if (start.startsWith('<')) fail()
  }
}

export function assertSvg(text) {
  const sample = String(text || '')
  if (!/<svg[\s>]/i.test(sample)) throw new HttpError(415, 'File does not look like an SVG')
  if (
    /<script[\s>/]/i.test(sample) ||
    /javascript:/i.test(sample) ||
    /<foreignObject[\s>]/i.test(sample) ||
    /<iframe[\s>]/i.test(sample) ||
    /\son[a-z]+\s*=/i.test(sample)
  ) {
    throw new HttpError(415, 'SVG files cannot contain scripts or event handlers')
  }
}
