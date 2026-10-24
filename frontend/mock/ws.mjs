// SPDX-License-Identifier: Apache-2.0
// Minimal RFC 6455 server for the mock's /api/v1/ws: handshake, text frames in
// both directions, ping/close control frames. No dependency, enough for the
// subscribe/unsubscribe/ping protocol of architecture section 18.
import { createHash } from 'node:crypto'

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

function encodeFrame(text, opcode = 0x1) {
  const payload = Buffer.from(text)
  const len = payload.length
  let header
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len])
  } else if (len < 65536) {
    header = Buffer.alloc(4)
    header[0] = 0x80 | opcode
    header[1] = 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 0x80 | opcode
    header[1] = 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  return Buffer.concat([header, payload])
}

// Parses as many complete frames as `buffer` holds; returns { frames, rest }.
export function decodeFrames(buffer) {
  const frames = []
  let offset = 0
  while (buffer.length - offset >= 2) {
    const b0 = buffer[offset]
    const b1 = buffer[offset + 1]
    const opcode = b0 & 0x0f
    const masked = (b1 & 0x80) !== 0
    let len = b1 & 0x7f
    let pos = offset + 2
    if (len === 126) {
      if (buffer.length < pos + 2) break
      len = buffer.readUInt16BE(pos)
      pos += 2
    } else if (len === 127) {
      if (buffer.length < pos + 8) break
      len = Number(buffer.readBigUInt64BE(pos))
      pos += 8
    }
    const maskLen = masked ? 4 : 0
    if (buffer.length < pos + maskLen + len) break
    const mask = masked ? buffer.subarray(pos, pos + 4) : null
    pos += maskLen
    const payload = Buffer.from(buffer.subarray(pos, pos + len))
    if (mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4]
    frames.push({ opcode, payload })
    offset = pos + len
  }
  return { frames, rest: buffer.subarray(offset) }
}

export function createWsHub({ authenticate, nodeId }) {
  const clients = new Set()

  function handleUpgrade(req, socket) {
    const key = req.headers['sec-websocket-key']
    const user = authenticate(req)
    if (!key || !user) {
      socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      return
    }
    const accept = createHash('sha1').update(key + GUID).digest('base64')
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    )
    const client = { socket, topics: new Set(), user, buffer: Buffer.alloc(0) }
    clients.add(client)
    socket.on('data', (chunk) => {
      client.buffer = Buffer.concat([client.buffer, chunk])
      const { frames, rest } = decodeFrames(client.buffer)
      client.buffer = rest
      for (const frame of frames) {
        if (frame.opcode === 0x8) {
          socket.end(encodeFrame('', 0x8))
          clients.delete(client)
          return
        }
        if (frame.opcode === 0x9) {
          socket.write(encodeFrame(frame.payload.toString(), 0xa))
          continue
        }
        if (frame.opcode !== 0x1) continue
        let msg
        try {
          msg = JSON.parse(frame.payload.toString())
        } catch {
          continue
        }
        if (msg.action === 'subscribe') (msg.topics || []).forEach((t) => client.topics.add(t))
        else if (msg.action === 'unsubscribe') (msg.topics || []).forEach((t) => client.topics.delete(t))
        else if (msg.action === 'ping') send(client, { topic: 'system', event: 'pong', ts: new Date().toISOString(), node_id: nodeId, data: {} })
      }
    })
    const drop = () => clients.delete(client)
    socket.on('close', drop)
    socket.on('error', drop)
  }

  function send(client, message) {
    try {
      client.socket.write(encodeFrame(JSON.stringify(message)))
    } catch {
      clients.delete(client)
    }
  }

  function emit(topic, event, data) {
    const message = { topic, event, ts: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), node_id: nodeId, data }
    for (const client of clients) {
      if (topic === 'system' || client.topics.has(topic)) send(client, message)
    }
  }

  function closeAll() {
    for (const client of clients) client.socket.destroy()
    clients.clear()
  }

  return { handleUpgrade, emit, closeAll, get size() { return clients.size } }
}
