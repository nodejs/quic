'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const fs = require('fs');
const Countdown = require('../common/countdown');
const createSocket = require('quic');

const socket = createSocket({ type: 'udp4', port: 1235 });

const countdown = new Countdown(2, () => {
  socket.destroy();
});

const client = socket.connect({
  type: 'udp4',
  address: '192.168.86.31',
  port: 1234,
  rejectUnauthorized: false,
  maxStreamsUni: 1000,
  servername: 'test'
});

assert.strictEqual(client.servername, 'test');

client.on('secure', (servername, alpn) => {
  assert.strictEqual('test', servername);
  assert.strictEqual('h3-19', alpn);
  assert.strictEqual('test', client.servername);
  assert.strictEqual('h3-19', client.alpnProtocol);
  console.log(client.ephemeralKeyInfo);
  console.log(client.getPeerCertificate());
  console.log('secure!');
  const file = fs.createReadStream(__filename);
  const stream = client.openStream();
  file.pipe(stream);

  stream.setEncoding('utf8');
  stream.on('data', console.log);
  stream.on('close', () => {
    countdown.dec();
  });
});


client.on('stream', (stream) => {
  stream.setEncoding('utf8');
  stream.on('data', console.log);
  stream.on('end', console.log);
  stream.on('close', () => {
    countdown.dec();
  });
});
