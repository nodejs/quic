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
const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');
const { debuglog } = require('util');
const debug = debuglog('test');

const filedata = fs.readFileSync(__filename, { encoding: 'utf8' });

const { createSocket } = require('quic');

let client;
const server = createSocket({ type: 'udp4', port: 0 });

// Diagnostic Packet Loss allows packets to be randomly ignored
// to simulate network packet loss conditions. This is not a
// feature that should be turned on in production unless the
// intent is to simulate loss to gather performance data or
// debug issues. The values for rx and tx must be between
// 0.0 and 1.0 (inclusive)
server.setDiagnosticPacketLoss({ rx: 0.0, tx: 0.00 });

const unidata = ['I wonder if it worked.', 'test'];
const kServerName = 'agent2';  // Intentionally the wrong servername
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

server.listen({
  key,
  cert,
  ca,
  requestCert: true,
  rejectUnauthorized: false,
  alpn: kALPN
});
server.on('session', common.mustCall((session) => {
  debug('QuicServerSession Created');

  {
    const {
      address,
      family,
      port
    } = session.remoteAddress;
    assert.strictEqual(port, client.address.port);
    assert.strictEqual(family, client.address.family);
    debug(`QuicServerSession Client ${family} address ${address}:${port}`);
  }

  session.on('clientHello', common.mustCall(
    (alpn, servername, ciphers, cb) => {
      assert.strictEqual(alpn, kALPN);
      assert.strictEqual(servername, kServerName);
      assert.strictEqual(ciphers.length, 4);
      cb();
    }));

  session.on('OCSPRequest', common.mustCall(
    (servername, context, cb) => {
      debug('QuicServerSession received a OCSP request');
      assert.strictEqual(servername, kServerName);

      // This will be a SecureContext. By default it will
      // be the SecureContext used to create the QuicSession.
      // If the user wishes to do something with it, it can,
      // but if it wishes to pass in a new SecureContext,
      // it can pass it in as the second argument to the
      // callback below.
      assert(context);
      debug('QuicServerSession Certificate: ', context.getCertificate());
      debug('QuicServerSession Issuer: ', context.getIssuer());

      // The callback can be invoked asynchronously
      // TODO(@jasnell): Using setImmediate here causes the test
      // to fail, but it shouldn't. Investigate why.
      process.nextTick(() => {
        // The first argument is a potential error,
        // in which case the session will be destroyed
        // immediately.
        // The second is an optional new SecureContext
        // The third is the ocsp response.
        // All arguments are optional
        cb(null, null, Buffer.from('hello'));
      });
    }));

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
    assert.strictEqual(session.getPeerCertificate().subject.CN, 'agent1');

    debug('QuicServerSession client is %sauthenticated',
          session.authenticated ? '' : 'not ');
    assert(session.authenticated);
    assert.strictEqual(session.authenticationError, undefined);

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
    debug(`Server session closed with code ${code} (family: ${family})`);
    assert.strictEqual(code, NGTCP2_NO_ERROR);
    assert.strictEqual(family, QUIC_ERROR_APPLICATION);
  }));
}));

server.on('ready', common.mustCall(() => {
  debug('Server is listening on port %d', server.address.port);
  client = createSocket({
    type: 'udp4',
    port: 0,
    client: {
      type: 'udp4',
      key,
      cert,
      ca,
      maxStreamsUni: 1000,
      minCidLen: 5,
      maxCidLen: 10,
      alpn: kALPN,
    }
  });

  const req = client.connect({
    address: 'localhost',
    port: server.address.port,
    servername: kServerName,
    requestOCSP: true,
  });

  client.on('close', () => {
    debug('Client closing. Duration', client.duration);
    debug('  Bound duration',
          client.boundDuration);
    debug('  Bytes Sent/Received: %d/%d',
          client.bytesSent,
          client.bytesReceived);
    debug('  Packets Sent/Received: %d/%d',
          client.packetsSent,
          client.packetsReceived);
    debug('  Sessions:', client.clientSessions);
  });

  assert.strictEqual(req.servername, kServerName);

  req.on('OCSPResponse', common.mustCall((response) => {
    debug(`QuicClientSession OCSP response: "${response.toString()}"`);
    assert.strictEqual(response.toString(), 'hello');
  }));

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

    // The server's identity won't be valid because the requested
    // SNI hostname does not match the certificate used.
    debug('QuicClientSession server is %sauthenticated',
          req.authenicated ? '' : 'not ');
    assert(!req.authenicated);
    common.expectsError(() => { throw req.authenticationError; }, {
      code: 'ERR_QUIC_VERIFY_HOSTNAME_MISMATCH',
      message: 'Hostname mismatch'
    });

    {
      const {
        address,
        family,
        port
      } = req.remoteAddress;
      assert.strictEqual(port, server.address.port);
      assert.strictEqual(family, server.address.family);
      debug(`QuicClientSession Server ${family} address ${address}:${port}`);
    }

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
    debug(`Client session closed with code ${code} (family: ${family})`);
    assert.strictEqual(code, NGTCP2_NO_ERROR);
    assert.strictEqual(family, QUIC_ERROR_APPLICATION);
  }));
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
