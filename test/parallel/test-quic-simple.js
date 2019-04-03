'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent8-key.pem', 'binary');
const cert = fixtures.readKey('agent8-cert.pem', 'binary');
const ca = fixtures.readKey('fake-startcom-root-cert.pem', 'binary');

const createSocket = require('quic');

const socket = createSocket({ type: 'udp4', port: 1234 });

socket.listen({ key, cert, ca });

socket.on('session', common.mustCall((session) => {

  session.on('secure', () => {
    // We can only open a unidirectional stream after the handshake has
    // completed.
    // TODO(@jasnell): This will change once we get 0RTT working
    const uni = session.openStream({ halfOpen: true });
    uni.write('I wonder if it worked.');
    uni.end('test');
  });

  session.on('stream', common.mustCall((stream) => {
    console.log(stream);
    stream.end('Hello World');

    stream.setEncoding('utf8');
    stream.resume();
    // stream.on('data', console.log);
    stream.on('end', () => console.log('stream ended'));
  }));
}));

socket.on('ready', common.mustCall(() => {
  console.log(socket.address);
}));

socket.on('listening', common.mustCall());
