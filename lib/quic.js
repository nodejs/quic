'use strict';

const {
  createSocket
} = require('internal/quic/core');

createSocket.createSocket = createSocket;

module.exports = createSocket;
