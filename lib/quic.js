'use strict';

const {
  createSocket
} = require('internal/quic/core');

createSocket.createSocket = createSocket;

module.exports = createSocket;

/**

const createSocket = require('quic');

const socket = createSocket({ type: 'udp4', lookup() {...} });

const server = socket.createServer(options);
server.listen(options, (session) => {
  // Function added as an on('session') handler
  session.on('stream', (stream) => {});
  const stream = session.openStream(options);
});

const client = socket.connect(options, () => {
  // Function added as an on('ready') handler
});
client.on('stream', (stream) => {});
const stream = client.openStream(options);

 */
