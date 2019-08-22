// Flags: --expose-internals
'use strict';

// Tests QUIC server busy support

const common = require('../common');
if (!common.hasQuic)
  common.skip('missing quic');

// TODO(@jasnell): Marking a server as busy will cause all new
// connection attempts to fail with a SERVER_BUSY CONNECTION_CLOSE.
// Unfortunately, however, ngtcp2 does not yet support writing a
// CONNECTION_CLOSE in an initial packet as required by the
// specification so we can't enable this yet. The basic mechanism
// has been implemented but we can't expose it yet.

common.skip('setServerBusy is not yet fully implemented.');

const assert = require('assert');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');

const { debuglog } = require('util');
const debug = debuglog('test');

const { createSocket } = require('quic');

const kServerPort = process.env.NODE_DEBUG_KEYLOG ? 5678 : 0;
const kClientPort = process.env.NODE_DEBUG_KEYLOG ? 5679 : 0;
const kALPN = 'zzz';  // ALPN can be overriden to whatever we want

// TODO(@jasnell): Implementation of this test is not yet complete.
// Once the feature is fully implemented, this test will need to be
// revisited.

let client;
const server = createSocket({
  port: kServerPort,
  server: { key, cert, ca, alpn: kALPN }
});

server.on('busy', common.mustCall((busy) => {
  assert.strictEqual(busy, true);
}));

server.setServerBusy();
server.listen();

server.on('session', common.mustNotCall());

server.on('ready', common.mustCall(() => {
  debug('Server is listening on port %d', server.address.port);
  client = createSocket({
    port: kClientPort,
    client: { key, cert, ca, alpn: kALPN }
  });

  client.connect({
    address: 'localhost',
    port: server.address.port,
  });

}));

server.on('listening', common.mustCall());

server.on('close', () => {
  debug('Server closing. Duration', server.duration);
  debug('  Bound duration:',
        server.boundDuration);
  debug('  Listen duration:',
        server.listenDuration);
  debug('  Bytes Sent/Received: %d/%d',
        server.bytesSent,
        server.bytesReceived);
  debug('  Packets Sent/Received: %d/%d',
        server.packetsSent,
        server.packetsReceived);
  debug('  Sessions:', server.serverSessions);
});
