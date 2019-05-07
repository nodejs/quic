'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const fs = require('fs');
const Countdown = require('../common/countdown');
const createSocket = require('quic');

const socket = createSocket({ type: 'udp4', port: 1235 });
const socket2 = createSocket({ type: 'udp4', port: 1236 });

const countdown = new Countdown(2, () => {
  socket.destroy();
  socket2.destroy();
});

const client = socket.connect({
  type: 'udp4',
  address: 'localhost',
  port: 1234,
  rejectUnauthorized: false,
});

client.on('secure', (servername, alpn) => {
  setTimeout(() => {
    client.setSocket(socket2, (err) => {
      const file = fs.createReadStream(__filename);
      const stream = client.openStream();
      file.pipe(stream);

      stream.setEncoding('utf8');
      stream.on('data', console.log);
      stream.on('close', () => {
        countdown.dec();
      });
    });
  }, 1000);
});


client.on('stream', (stream) => {
  stream.setEncoding('utf8');
  stream.on('data', console.log);
  stream.on('end', console.log);
  stream.on('close', () => {
    countdown.dec();
  });
});
