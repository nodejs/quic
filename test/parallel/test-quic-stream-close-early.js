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
    uni.close(2);

    uni.on('abort', common.mustCall((code, finalSize) => {
      // TODO(@jasnell): Code is currently 0 for some reason..
      // need to investigate
      // assert.strictEqual(code, 2);
      assert.strictEqual(finalSize, 0);
    }));

    // End will be called because the writable side is closed before
    // close is event called. The data event will never be emitted.
    uni.on('data', common.mustNotCall());
    uni.on('end', common.mustCall());

    // Finish will not emitted because the stream is closed abruptly
    // before the stream can complete.
    uni.on('finish', common.mustNotCall());

    // The close event will always emit, however
    uni.on('close', common.mustCall());

    debug('Unidirectional, Server-initiated stream %d opened', uni.id);
  }));

  session.on('stream', common.mustCall((stream) => {
    debug('Bidirectional, Client-initiated stream %d received', stream.id);
    stream.write('hello there');

    stream.on('abort', common.mustCall((code, finalSize) => {
      debug('Bidirectional, Client-initiated stream %d aborted', stream.id);
      assert.strictEqual(code, 1);
      assert.strictEqual(finalSize, 5);  // The client sent 'hello'
    }));

    // Because the stream ended abruptly, abort is emitted but end and
    // finish are not.
    stream.on('end', common.mustNotCall());
    stream.on('finish', common.mustNotCall());

    // Close is always emitted, however.
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

    // Finish and end are not called because the stream has closed abruptly
    // before the stream was finished.
    stream.on('finish', common.mustNotCall());
    stream.on('end', common.mustNotCall());

    stream.on('close', common.mustCall(() => {
      debug('Bidirectional, Client-initiated stream %d closed', stream.id);
      countdown.dec();
    }));

    debug('Bidirectional, Client-initiated stream %d opened', stream.id);
  }));

  req.on('stream', common.mustCall((stream) => {
    debug('Unidirectional, Server-initiated stream %d received', stream.id);

    stream.on('abort', common.mustCall((code, finalSize) => {
      debug('Unidirectional, Server-initiated stream %d aborted', stream.id);
      assert.strictEqual(code, 2);
      assert.strictEqual(finalSize, 2);
    }));

    // The data event will be emitted once...
    stream.on('data', common.mustCall());

    // But because the stream has been closed abruptly, the abort event
    // will be emitted and end will never emit.
    stream.on('end', common.mustNotCall());

    // The close event will always emit.
    stream.on('close', common.mustCall(() => {
      debug('Unidirectional, Server-initiated stream %d closed', stream.id);
      countdown.dec();
    }));
  }));

  req.on('close', common.mustCall());
}));

server.on('listening', common.mustCall());
server.on('close', common.mustCall());
