// Flags: --expose-internals
'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const Countdown = require('../common/countdown');
const assert = require('assert');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');
const { debuglog } = require('util');
const debug = debuglog('test');

const { createSocket } = require('quic');

let client;
const server = createSocket({ port: 0 });

const kServerName = 'agent1';
const kALPN = 'zzz';

const countdown = new Countdown(2, () => {
  debug('Countdown expired. Destroying sockets');
  server.close();
  client.close();
});

server.listen({
  key,
  cert,
  ca,
  alpn: kALPN,
});
server.on('session', common.mustCall((session) => {
  debug('QuicServerSession Created');

  session.on('secure', common.mustCall((servername, alpn, cipher) => {
    const uni = session.openStream({ halfOpen: true });
    uni.write('hi');
    uni.close(3);

    uni.on('abort', common.mustCall((code, finalSize) => {
      assert.strictEqual(code, 3);
      assert.strictEqual(finalSize, 2);
    }));

    uni.on('data', common.mustNotCall());
    uni.on('end', common.mustCall());
    uni.on('finish', common.mustCall());
    uni.on('close', common.mustCall());

    debug('Unidirectional, Server-initiated stream %d opened', uni.id);
  }));

  session.on('stream', common.mustCall((stream) => {
    debug('Bidirectional, Client-initiated stream %d received', stream.id);
    stream.write('hello there');
    stream.on('end', common.mustNotCall());
    stream.on('finish', common.mustNotCall());
    stream.on('close', common.mustCall());
  }));

  session.on('close', common.mustCall());
}));

server.on('ready', common.mustCall(() => {
  debug('Server is listening on port %d', server.address.port);
  client = createSocket({
    port: 0,
    client: {
      key,
      cert,
      ca,
      alpn: kALPN,
    }
  });

  const req = client.connect({
    address: 'localhost',
    port: server.address.port,
    servername: kServerName,
  });

  req.on('secure', common.mustCall((servername, alpn, cipher) => {
    debug('QuicClientSession TLS Handshake Complete');

    const stream = req.openStream();

    stream.write('hello');
    stream.close(1);

    // The abort event should emit because the stream closed abruptly
    // before the stream was finished.
    stream.on('abort', common.mustCall((code, finalSize) => {
      debug('Bidirectional, Client-initated stream %d aborted', stream.id);
      assert.strict(code, 1);
      assert.strict(finalSize, 11); // The server sent 'hello there'
    }));

    stream.on('finish', common.mustCall());
    stream.on('end', common.mustCall());

    stream.on('close', common.mustCall(() => {
      debug('Bidirectional, Client-initiated stream %d closed', stream.id);
      countdown.dec();
    }));

    debug('Bidirectional, Client-initiated stream %d opened', stream.id);
  }));

  req.on('stream', common.mustCall((stream) => {
    debug('Unidirectional, Server-initiated stream %d received', stream.id);
    stream.on('abort', common.mustNotCall());
    stream.on('data', common.mustCall());
    stream.on('end', common.mustCall());
    stream.on('close', common.mustCall(() => {
      debug('Unidirectional, Server-initiated stream %d closed', stream.id);
      countdown.dec();
    }));
  }));

  req.on('close', common.mustCall());
}));

server.on('listening', common.mustCall());
server.on('close', common.mustCall());
