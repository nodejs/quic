'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const Countdown = require('../common/countdown');
const createSocket = require('quic');

const socket = createSocket({ type: 'udp4', port: 1234 });

const countdown = new Countdown(2, () => {
  socket.destroy();
});

const client = socket.connect({
  type: 'udp4',
  address: '192.168.86.117',
  port: 1234,
  rejectUnauthorized: false,
});

client.on('secure', () => {
  console.log('secure!');
  const stream = client.openStream();
  stream.end('GET /server.cc HTTP/1.1\n\n');
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
