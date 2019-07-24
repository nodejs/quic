// Flags: --no-warnings
'use strict';

// Test QuicSocket constructor option errors.

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');

const { createSocket } = require('quic');

const socket = createSocket();
assert(socket);

// Before listen is called, serverSecureContext is always undefined.
assert.strictEqual(socket.serverSecureContext, undefined);

// Socket is not bound, so address should be empty
assert.deepStrictEqual(socket.address, {});

// Socket is not bound
assert(!socket.bound);

// Socket is not pending
assert(!socket.pending);

// Socket is not destroyed
assert(!socket.destroyed);

assert.strictEqual(typeof socket.duration, 'bigint');
assert.strictEqual(typeof socket.boundDuration, 'bigint');
assert.strictEqual(typeof socket.listenDuration, 'bigint');
assert.strictEqual(typeof socket.bytesReceived, 'bigint');
assert.strictEqual(socket.bytesReceived, 0n);
assert.strictEqual(socket.bytesSent, 0n);
assert.strictEqual(socket.packetsReceived, 0n);
assert.strictEqual(socket.packetsSent, 0n);
assert.strictEqual(socket.serverSessions, 0n);
assert.strictEqual(socket.clientSessions, 0n);

// Will throw because the QuicSocket is not bound
assert.throws(() => socket.setTTL(1), {
  code: 'EBADF',
  errno: -4083
});

// Will throw because the QuicSocket is not bound
assert.throws(() => socket.setMulticastTTL(1), {
  code: 'EBADF',
  errno: -4083
});

// Will throw because the QuicSocket is not bound
assert.throws(() => socket.setBroadcast(), {
  code: 'EBADF',
  errno: -4083
});

// Will throw because the QuicSocket is not bound
assert.throws(() => socket.setMulticastLoopback(), {
  code: 'EBADF',
  errno: -4083
});

// Will throw because the QuicSocket is not bound
assert.throws(() => socket.setMulticastInterface('0.0.0.0'), {
  code: 'EBADF',
  errno: -4083
});

assert.throws(() => socket.addMembership('127.0.0.1', '127.0.0.1'));
assert.throws(() => socket.dropMembership('127.0.0.1', '127.0.0.1'));

['test', null, {}, [], 1n, false].forEach((rx) => {
  assert.throws(() => socket.setDiagnosticPacketLoss({ rx }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

['test', null, {}, [], 1n, false].forEach((tx) => {
  assert.throws(() => socket.setDiagnosticPacketLoss({ tx }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

assert.throws(() => socket.setDiagnosticPacketLoss({ rx: -1 }), {
  code: 'ERR_OUT_OF_RANGE'
});

assert.throws(() => socket.setDiagnosticPacketLoss({ rx: 1.1 }), {
  code: 'ERR_OUT_OF_RANGE'
});

assert.throws(() => socket.setDiagnosticPacketLoss({ tx: -1 }), {
  code: 'ERR_OUT_OF_RANGE'
});

assert.throws(() => socket.setDiagnosticPacketLoss({ tx: 1.1 }), {
  code: 'ERR_OUT_OF_RANGE'
});

[1, 1n, false, [], {}, null].forEach((alpn) => {
  assert.throws(() => socket.listen({ alpn }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

[1, 1n, false, [], {}, null].forEach((ciphers) => {
  assert.throws(() => socket.listen({ ciphers }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

[1, 1n, false, [], {}, null].forEach((groups) => {
  assert.throws(() => socket.listen({ groups }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

socket.listen();
assert(socket.pending);

socket.on('ready', common.mustCall(() => {
  assert(socket.bound);

  // QuicSocket is already listening.
  assert.throws(() => socket.listen(), {
    code: 'ERR_QUICSOCKET_LISTENING'
  });

  assert.strictEqual(typeof socket.address.address, 'string');
  assert.strictEqual(typeof socket.address.port, 'number');
  assert.strictEqual(typeof socket.address.family, 'string');

  socket.setTTL(1);
  socket.setMulticastTTL(1);
  socket.setBroadcast();
  socket.setBroadcast(true);
  socket.setBroadcast(false);
  [1, 'test', {}, NaN, 1n, null].forEach((i) => {
    assert.throws(() => socket.setBroadcast(i), {
      code: 'ERR_INVALID_ARG_TYPE'
    });
  });

  socket.setMulticastLoopback();
  socket.setMulticastLoopback(true);
  socket.setMulticastLoopback(false);
  [1, 'test', {}, NaN, 1n, null].forEach((i) => {
    assert.throws(() => socket.setMulticastLoopback(i), {
      code: 'ERR_INVALID_ARG_TYPE'
    });
  });

  socket.setMulticastInterface('0.0.0.0');

  socket.setDiagnosticPacketLoss({ rx: 0.5, tx: 0.5 });

  socket.destroy();
  assert(socket.destroyed);
}));
