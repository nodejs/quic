'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const fs = require('fs');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent8-key.pem', 'binary');
const cert = fixtures.readKey('agent8-cert.pem', 'binary');

const { createSocket } = require('quic');

const socket = createSocket({ type: 'udp4', port: 1234 });

socket.listen({ key, cert });

socket.on('session', common.mustCall((session) => {

  session.on('secure', (servername, alpn, cipher) => {
    assert.strictEqual(session.servername, servername);
    assert.strictEqual(session.alpnProtocol, alpn);
    // We can only open a unidirectional stream after the handshake has
    // completed.
    // TODO(@jasnell): This will change once we get 0RTT working
    const uni = session.openStream({ halfOpen: true });
    uni.end('I wonder if it worked.');
    // uni.end('test');
  });

  session.on('stream', common.mustCall((stream) => {
    const file = fs.createReadStream(__filename);
    file.pipe(stream);

    stream.setEncoding('utf8');
    stream.resume();
    stream.on('end', () => console.log('stream ended'));
  }));

  session.on('close', () => console.log('session closed'));
}));

socket.on('ready', common.mustCall(() => {
  console.log(socket.address);
}));

socket.on('listening', common.mustCall());
