// Flags: --expose-internals
'use strict';

// Tests a simple QUIC client/server round-trip

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

const { Buffer } = require('buffer');
const Countdown = require('../common/countdown');
const assert = require('assert');
const fs = require('fs');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent8-key.pem', 'binary');
const cert = fixtures.readKey('agent8-cert.pem', 'binary');
const { debuglog } = require('util');
const debug = debuglog('test');

const filedata = fs.readFileSync(__filename, { encoding: 'utf8' });

const { createSocket } = require('quic');

let client;
const server = createSocket({ type: 'udp4', port: 0 });

const unidata = ['I wonder if it worked.', 'test'];
const kServerName = 'test';
const kALPN = 'zzz';  // ALPN can be overriden to whatever we want


const kKeylogs = [
  /QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET.*/,
  /SERVER_HANDSHAKE_TRAFFIC_SECRET.*/,
  /QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET.*/,
  /CLIENT_HANDSHAKE_TRAFFIC_SECRET.*/,
  /QUIC_SERVER_TRAFFIC_SECRET_0.*/,
  /EXPORTER_SECRET.*/,
  /SERVER_TRAFFIC_SECRET_0.*/,
  /QUIC_CLIENT_TRAFFIC_SECRET_0.*/,
  /CLIENT_TRAFFIC_SECRET_0.*/,
];


const countdown = new Countdown(2, () => {
  debug('Countdown expired. Destroying sockets');
  server.close();
  client.close();
});

server.listen({ key, cert, alpn: kALPN });
server.on('session', common.mustCall((session) => {
  debug('QuicServerSession Created');

  session.on('keylog', common.mustCall((line) => {
    assert(kKeylogs.shift().test(line));
  }, kKeylogs.length));

  session.on('secure', common.mustCall((servername, alpn, cipher) => {
    debug('QuicServerSession TLS Handshake Complete');
    debug('  Server name: %s', servername);
    debug('  ALPN: %s', alpn);
    debug('  Cipher: %s, %s', cipher.name, cipher.version);
    assert.strictEqual(session.servername, servername);
    assert.strictEqual(servername, kServerName);
    assert.strictEqual(session.alpnProtocol, alpn);

    const uni = session.openStream({ halfOpen: true });
    uni.write(unidata[0]);
    uni.end(unidata[1]);
    debug('Unidirectional, Server-initiated stream %d opened', uni.id);
    uni.on('data', common.mustNotCall());
    uni.on('finish', common.mustCall());
    uni.on('close', common.mustCall());
    uni.on('end', common.mustCall());
  }));

  session.on('stream', common.mustCall((stream) => {
    debug('Bidirectional, Client-initiated stream %d received', stream.id);
    const file = fs.createReadStream(__filename);
    let data = '';
    file.pipe(stream);
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => data += chunk);
    stream.on('end', common.mustCall(() => {
      assert.strictEqual(data, filedata);
      debug('Server received expected data for stream %d', stream.id);
    }));
    stream.on('close', common.mustCall());
    stream.on('finish', common.mustCall());
  }));

  session.on('close', common.mustCall(() => {
    const {
      code,
      family
    } = session.closeCode;
    debug(`Server sesion closed with code ${code} (family: ${family})`);
    assert.strictEqual(code, NGTCP2_NO_ERROR);
    assert.strictEqual(family, QUIC_ERROR_APPLICATION);
  }));
}));

server.on('ready', common.mustCall(() => {
  debug('Server is listening on port %d', server.address.port);
  client = createSocket({ type: 'udp4', port: 0 });
  const req = client.connect({
    type: 'udp4',
    address: 'localhost',
    port: server.address.port,
    rejectUnauthorized: false,
    maxStreamsUni: 1000,
    servername: kServerName,
    minCidLen: 5,
    maxCidLen: 10,
    alpn: kALPN,
  });

  client.on('close', () => debug('Client closing'));

  assert.strictEqual(req.servername, kServerName);

  req.on('sessionTicket', common.mustCall((id, ticket, params) => {
    debug('Session ticket received');
    assert(id instanceof Buffer);
    assert(ticket instanceof Buffer);
    assert(params instanceof Buffer);
    debug('  ID: %s', id.toString('hex'));
    debug('  Ticket: %s', ticket.toString('hex'));
    debug('  Params: %s', params.toString('hex'));
  }, 2));

  req.on('secure', common.mustCall((servername, alpn, cipher) => {
    debug('QuicClientSession TLS Handshake Complete');
    debug('  Server name: %s', servername);
    debug('  ALPN: %s', alpn);
    debug('  Cipher: %s, %s', cipher.name, cipher.version);
    assert.strictEqual(servername, kServerName);
    assert.strictEqual(req.servername, kServerName);
    assert.strictEqual(alpn, kALPN);
    assert.strictEqual(req.alpnProtocol, kALPN);
    assert(req.ephemeralKeyInfo);
    assert(req.getPeerCertificate());

    const file = fs.createReadStream(__filename);
    const stream = req.openStream();
    file.pipe(stream);
    let data = '';
    stream.resume();
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => data += chunk);
    stream.on('finish', common.mustCall());
    stream.on('end', common.mustCall(() => {
      assert.strictEqual(data, filedata);
      debug('Client received expected data for stream %d', stream.id);
    }));
    stream.on('close', common.mustCall(() => {
      debug('Bidirectional, Client-initiated stream %d closed', stream.id);
      countdown.dec();
    }));
    debug('Bidirectional, Client-initiated stream %d opened', stream.id);
  }));

  req.on('stream', common.mustCall((stream) => {
    debug('Unidirectional, Server-initiated stream %d received', stream.id);
    let data = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => data += chunk);
    stream.on('end', common.mustCall(() => {
      assert.strictEqual(data, unidata.join(''));
      debug('Client received expected data for stream %d', stream.id);
    }));
    stream.on('close', common.mustCall(() => {
      debug('Unidirectional, Server-initiated stream %d closed', stream.id);
      countdown.dec();
    }));
  }));

  req.on('close', common.mustCall(() => {
    const {
      code,
      family
    } = req.closeCode;
    debug(`Client sesion closed with code ${code} (family: ${family})`);
    assert.strictEqual(code, NGTCP2_NO_ERROR);
    assert.strictEqual(family, QUIC_ERROR_APPLICATION);
  }));
}));

server.on('listening', common.mustCall());
server.on('close', () => debug('Server closing'));
