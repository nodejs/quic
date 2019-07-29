// Flags: --expose-internals
'use strict';

// Test that destroying a QuicStream immediately and synchronously
// after creation does not crash the process and closes the streams
// abruptly on both ends of the connection.

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const { internalBinding } = require('internal/test/binding');
const {
  constants: {
    NGTCP2_NO_ERROR,
    QUIC_ERROR_APPLICATION,
  }
} = internalBinding('quic');

const assert = require('assert');
const fs = require('fs');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');
const { debuglog } = require('util');
const debug = debuglog('test');

const { createSocket } = require('quic');

const kServerPort = process.env.NODE_DEBUG_KEYLOG ? 5678 : 0;
const kClientPort = process.env.NODE_DEBUG_KEYLOG ? 5679 : 0;

const kServerName = 'agent2';  // Intentionally the wrong servername
const kALPN = 'zzz';  // ALPN can be overriden to whatever we want

const server = createSocket({ port: kServerPort });

server.listen({ key, cert, ca, alpn: kALPN });

server.on('session', common.mustCall((session) => {
  debug('QuicServerSession Created');

  if (process.env.NODE_DEBUG_KEYLOG) {
    const kl = fs.createWriteStream(process.env.NODE_DEBUG_KEYLOG);
    session.on('keylog', kl.write.bind(kl));
  }

  session.on('close', common.mustCall());
  session.on('stream', common.mustNotCall());
  session.destroy();

}));

server.on('ready', common.mustCall(() => {
  debug('Server is listening on port %d', server.address.port);

  const client = createSocket({
    port: kClientPort,
    client: { key, cert, ca, alpn: kALPN }
  });

  client.on('close', common.mustCall(() => {
    debug('Client closing. Duration', client.duration);
  }));

  const req = client.connect({
    address: 'localhost',
    port: server.address.port,
    servername: kServerName,
  });

  req.on('secure', common.mustNotCall());
  req.on('close', common.mustCall());
}));

server.on('listening', common.mustCall());
