'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const fs = require('fs');
const Countdown = require('../common/countdown');
const { createSocket } = require('quic');

const socket = createSocket({ type: 'udp4', port: 1235 });
const kALPN = 'h3-20';

const countdown = new Countdown(2, () => {
  socket.close();
});

const client = socket.connect({
  type: 'udp4',
  address: 'localhost',
  port: 1234,
  rejectUnauthorized: false,
  maxStreamsUni: 1000,
  servername: 'test',
});

assert.strictEqual(client.servername, 'test');

client.on('sessionTicket', (id, ticket, params) => {
  console.log('session ID: ', id);
  console.log('session ticket: ', ticket);
  console.log('transport params: ', params);
});

client.on('secure', (servername, alpn) => {
  assert.strictEqual(servername, 'test');
  assert.strictEqual(alpn, kALPN);
  assert.strictEqual(client.servername, 'test');
  assert.strictEqual(client.alpnProtocol, kALPN);
  console.log(client.ephemeralKeyInfo);
  console.log(client.getPeerCertificate());
  console.log('secure!');
  const file = fs.createReadStream(__filename);
  const stream = client.openStream();
  file.pipe(stream);
  console.log(`client stream is ${stream.id}`);
  stream.setEncoding('utf8');
  stream.on('data', console.log);
  stream.on('close', () => {
    console.log(1, stream.id);
    countdown.dec();
  });
});


client.on('stream', (stream) => {
  console.log(`server stream is ${stream.id}`);
  stream.setEncoding('utf8');
  stream.on('data', console.log);
  stream.on('end', console.log);
  stream.on('close', () => {
    console.log(2, stream.id);
    countdown.dec();
  });
});
