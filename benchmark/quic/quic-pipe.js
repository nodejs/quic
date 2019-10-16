// Test the speed of .pipe() with QUIC sockets
'use strict';

const common = require('../common.js');
const quic = require('quic');
const fixtures = require('../../test/common/fixtures');

const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');

const bench = common.createBenchmark(main, {
  dur: [5],
});

function main({ dur, len, type }) {
  const server = quic.createSocket({ port: 0, validateAddress: true });

  server.listen({
    key,
    cert,
    ca,
    rejectUnauthorized: false,
    alpn: 'meow'
  });

  server.on('session', (session) => {
    session.on('stream', (stream) => {
      stream.pipe(stream);
    });
  });

  const buffer = Buffer.alloc(102400);
  let received = 0;

  server.on('ready', () => {
    const client = quic.createSocket({
      port: 0,
      client: {
        key,
        cert,
        ca,
        alpn: 'meow'
      }
    });

    const req = client.connect({
      address: 'localhost',
      port: server.address.port
    });

    req.on('secure', () => {
      const stream = req.openStream({ halfOpen: false });
      stream.on('data', (chunk) => received += chunk.length);

      function write() {
        stream.write(buffer, write);
      }

      bench.start();
      write();

      setTimeout(() => {
        // Multiply by 2 since we're sending it first one way
        // then then back again.
        const bytes = received * 2;
        const gbits = (bytes * 8) / (1024 * 1024 * 1024);
        bench.end(gbits);
        process.exit(0);
      }, dur * 1000);
    });
  });
}
