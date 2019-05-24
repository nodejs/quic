# QUIC

<!--introduced_in=REPLACEME-->

> Stability: 1 - Experimental

The `quic` module provides an implementation of the QUIC protocol. To access it:

```js
const quic = require('quic');
```

## Example

```js
'use strict';

const key = getTLSKeySomehow();
const cert = getTLSCertSomehow();

const { createSocket } = require('quic');

// Create the local QUIC UDP socket...
const socket = createSocket({ type: 'udp4', port: 1234 });

// Tell the socket to operate as a server...
socket.listen({ key, cert });

socket.on('session', (session) => {
  // A new server side session has been created!

  session.on('secure', () => {
    // Once the TLS handshake is completed, we can
    // open streams...
    const uni = session.openStream({ halfOpen: true });
    uni.write('hi ');
    uni.end('from the server!');
  });

  // The peer opened a new stream!
  session.on('stream', (stream) => {
    // Let's say hello
    stream.end('Hello World');

    // Let's see what the peer has to say...
    stream.setEncoding('utf8');
    stream.on('data', console.log);
    stream.on('end', () => console.log('stream ended'));
  });
});

// The socket is ready to be used... we can create new sessions
socket.on('ready', () => {
  console.log(socket.address);
});

socket.on('listening', () => {
  // The socket is listening for sessions!
});
```

## quic.createSocket([options])
<!-- YAML
added: REPLACEME
-->

* `options` {Object}
  * `address` {string} The local address to bind to. This may be an IPv4 or IPv6
    address or a hostname. If a hostname is given, it will be resolved to an IP
    address.
  * `client` {Object} A default configuration for QUIC client sessions created
    using `quicsocket.connect()`.
  * `lookup` {Function} A custom DNS lookup function. Default `dns.lookup()`.
  * `maxConnectionsPerHost` {number} The maximum number of inbound connections
    per remote host. Default: `100`.
  * `port` {number} The local port to bind to.
  * `retryTokenTimeout` {number} The maximum number of seconds for retry token
    validation. Defaults: `10`.
  * `server` {Object} A default configuration for QUIC server sessions.
  * `type` {string} Either `'udp4'` or `'upd6'` to use either IPv4 or IPv6,
     respectively.

Creates a new `QuicSocket` instance.

## Class: QuicSession exends EventEmitter
<!-- YAML
added: REPLACEME
-->
* Extends: {EventEmitter}

The `QuicSession` is an abstract base class that defines events, methods, and
properties that are shared by both `QuicClientSession` and `QuicServerSession`.

Users will not create instances of `QuicSession` directly.

### Event: `'close'`
<!-- YAML
added: REPLACEME
-->

Emiitted after the `QuicSession` has been destroyed.

### Event: `'error'`
<!-- YAML
added: REPLACEME
-->

Emitted before the `'close'` event if the `QuicSession` was destroyed with
an error.

### Event: `'extendMaxBidiStreams'`
<!-- YAML
added: REPLACEME
-->

Emitted when the maximum number of bidirectional streams has been extended.

The callback will be invoked with a single argument:

* `maxStreams` {number} The new maximum number of bidirectional streams

### Event: `'extendMaxUniStreams'`
<!-- YAML
added: REPLACEME
-->

Emitted when the maximum number of unidirectional streams has been extended.

The callback will be invoked with a single argument:

* `maxStreams` {number} The new maximum number of unidirectional streams

### Event: `'secure'`
<!-- YAML
added: REPLACEME
-->

Emitted after the TLS handshake has been completed.

The callback will be invoked with two arguments:

* `servername` {string} The SNI servername requested by the client.
* `alpnProtocol` {string} The negotiated ALPN protocol.
* `cipher` {Object} Information about the selected cipher algorithm.
  * `name` {string} The cipher algorithm name.
  * `version` {string} The TLS version (currently always `'TLSv1.3'`).

These will also be available using the `quicsession.servername`,
`quicsession.alpnProtocol`, and `quicsession.cipher` properties.

### Event: `'stream'`
<!-- YAML
added: REPLACEME
-->

Emitted when a new `QuicStream` has been initiated by the connected peer.

### quicsession.alpnProtocol
<!-- YAML
added: REPLACEME
-->

* Type: {string}

The ALPN protocol identifier negotiated for this session.

### quicsession.cipher
<!-- YAML
added: REPLACEME
-->

* Type: {object}
  * `name` {string} The cipher algorithm name.
  * `type` {string} The TLS version (currently always `'TLSv1.3'`).

Information about the cipher algorithm selected for the session.

### quicsession.close([code[, callback]])
<!-- YAML
added: REPLACEME
-->

* `code` {number} The error code to when closing the session. Default: `0`.
* `callback` {Function} Callback invoked when the close operation is completed

Begins a graceful close of the `QuicSession`. Existing `QuicStream` instances will be
permitted to close naturally. New `QuicStream` instances will not be permitted. Once
all `QuicStream` instances have closed, the `QuicSession` instance will be destroyed.

### quicsession.closing
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

Set the `true` if the `QuicSession` is in the process of a graceful shutdown.

### quicsession.destroy([error])
<!-- YAML
added: REPLACEME
-->

* `error` {any}

Destroys the `QuicSession` immediately causing the `close` event to be emitted.
If `error` is not `undefined`, the `error` event will be emitted following the `close`
event.

Any `QuicStream` instances that are still opened will be abruptly closed.

### quicsession.destroyed
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

Set to `true` if the `QuicSession` has been destroyed.

### quicsession.getCertificate()
<!-- YAML
added: REPLACEME
-->

* Returns: {Object} A [Certificate Object][].

Returns an object representing the local certificate. The returned object has some
properties corresponding to the fields of the certificate.

If there is no local certificate, or if the `QuicSession` has been destroyed, an empty
object will be returned.

### quicsession.getPeerCertificate([detailed])
<!-- YAML
added: REPLACEME
-->

* `detailed` {boolean} Include the full certificate chain if `true`, otherwise include
  just the peer's certificate.
* Returns: {Object} A [Certificate Object][].

Returns an object representing the peer's certificate. If the peer does not provide a
certificate, or if the `QuicSession` has been destroyed, an empty object will be returned.

If the full certificate chain was requested, each certificate will include an `issuerCertificate`
property containing an object representing its issuer's certificate.

### quicsession.handshakeComplete
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

True if the TLS handshake has completed.

### quicsession.openStream([options])
<!-- YAML
added: REPLACEME
-->
* `options` {Object}
  * `halfOpen` {boolean} Set to `true` to open a unidirectional stream, `false`
    to open a bidirectional stream. Defaults to `true`.
  * `highWaterMark` {number}
* Returns: {QuicStream}

Returns a new `QuicStream`.

An error will be thrown if the `QuicSession` has been destroyed or is in the process
of a graceful shutdown.

### quicsession.servername
<!-- YAML
added: REPLACEME
-->

* Type: {string}

The SNI servername requested for this session by the client.

### quicsession.socket
<!-- YAML
added: REPLACEME
-->

* Type: {QuicSocket}

The `QuicSocket` the `QuicSession` is associated with.

## Class: QuicClientSession extends QuicSession
<!-- YAML
added: REPLACEME
-->

* Extends: {QuicSession}

The `QuicClientSession` class implements the client side of a QUIC connection.
Instances are created using the `quicsocket.connect()` method.

### Event: `'sessionTicket'`

The `'sessionTicket'` event is emitted when a new TLS session ticket has been
generated for the current `QuicClientSession`. The callback is invoked with
three arguments:

* `sessionID` {Buffer} The serialized session ticket identifier.
* `sessionTicket` {Buffer} The serialized session ticket.
* `remoteTransportParams` {Buffer} The serialized remote transport parameters
  provided by the QUIC server.

The `sessionTicket` and `remoteTransportParams` are useful when creating a new
`QuicClientSession` to more quickly resume an existing session.

### quicclientsession.ephemeralKeyInfo
<!-- YAML
added: REPLACEME
-->

* Type: {Object}

An object representing the type, name, and size of parameter of an ephemeral
key exchange in Perfect Forward Secrecy on a client connection. It is an
empty object when the key exchange is not ephemeral. The supported types are
`'DH'` and `'ECDH'`. The `name` property is available only when type is `'ECDH'`.

For example: `{ type: 'ECDH', name: 'prime256v1', size: 256 }`.

### quicclientsession.ready
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

True if the `QuicClientSession` is ready for use. False if the `QuicSocket` has not
yet been bound.

### quicclientsession.readyToMigrate
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

Once established, a `QuicClientSession` can be migrated from one `QuicSocket` instance
to another, without requiring the TLS handshake to be reestablished. Migration, however,
can only occur once the TLS handshake is complete and the underlying session has had an
opportunity to generate a pool of extra connection identifiers.

### quicclientsession.setSocket(socket, callback])
<!-- YAML
added: REPLACEME
-->

* `socket` {QuicSocket} A `QuicSocket` instance to move this session to.
* `callback` {Function} A callback function that will be invoked once the migration to
  the new `QuicSocket` is complete.

Migrates the `QuicClientSession` to the given `QuicSocket` instance. If the new `QuicSocket`
has not yet been bound to a local UDP port, it will be bound prior to attempting the
migration. If `quicclientsession.readyToMigrate` is `false`, an error will be thrown.

## Class: QuicServerSession extends QuicSession
<!-- YAML
added: REPLACEME
-->

* Extends: {QuicSession}

The `QuicServerSession` class implements the server side of a QUIC connection.
Instances are created internally and are emitted using the `QuicSocket` `'session'`
event.

## Class: QuicSocket
<!-- YAML
added: REPLACEME
-->

New instances of `QuicSocket` are created using the `quic.createSocket()` method.

Once created, a `QuicSocket` can be configured to work as both a client and a server.

### Event: `'close'`
<!-- YAML
added: REPLACEME
-->

Emitted after the `QuicSocket` has been destroyed and is no longer usable.

### Event: `'error'`
<!-- YAML
added: REPLACEME
-->

Emitted before the `'close'` event if the `QuicSocket` was destroyed with an `error`.

### Event: `'ready'`
<!-- YAML
added: REPLACEME
-->

Emitted once the `QuicSocket` has been bound to a local UDP port.

### Event: `'session'`
<!-- YAML
added: REPLACEME
-->

Emitted when a new `QuicServerSession` has been created.

### quicsocket.addMembership(address, iface)
<!-- YAML
added: REPLACEME
-->

* `address` {string}
* `iface` {string}

Tells the kernel to join a multicast group at the given `multicastAddress` and
`multicastInterface` using the `IP_ADD_MEMBERSHIP` socket option. If the
`multicastInterface` argument is not specified, the operating system will
choose one interface and will add membership to it. To add membership to every
available interface, call `quicsocket.addMembership()` multiple times, once per
interface.


### quicsocket.address
<!-- YAML
added: REPLACEME
-->

* Type: Address

An object containing the address information for a bound `QuicSocket`.

The object will contain the properties:

* `address` {string} The local IPv4 or IPv6 address to which the `QuicSocket` is bound.
* `family` {string} Either `'IPv4'` or `'IPv6'`.
* `port` {number} The local IP port to which the `QuicSocket` is bound.

If the `QuicSocket` is not bound, `quicsocket.address` is an empty object.

### quicsocket.bound
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

Will be `true` if the `QuicSocket` has been successfully bound to the local UDP
port.

### quicsocket.close([callback])
<!-- YAML
added: REPLACEME
-->

* `callback` {Function}

Gracefully closes the `QuicSocket`. Existing `QuicSession` instances will be permitted to
close naturally. New `QuicClientSession` and `QuicServerSession` instances will not be
allowed.

### quicsocket.connect([options])
<!-- YAML
added: REPLACEME
-->

* `options` {Object}
  * `address` {string} The domain name or IP address of the QUIC server
    endpoint.
  * `alpn` {string} An ALPN protocol identifier.
  * `ca` {string|string[]|Buffer|Buffer[]} Optionally override the trusted CA
    certificates. Default is to trust the well-known CAs curated by Mozilla.
    Mozilla's CAs are completely replaced when CAs are explicitly specified
    using this option. The value can be a string or `Buffer`, or an `Array` of
    strings and/or `Buffer`s. Any string or `Buffer` can contain multiple PEM
    CAs concatenated together. The peer's certificate must be chainable to a CA
    trusted by the server for the connection to be authenticated. When using
    certificates that are not chainable to a well-known CA, the certificate's CA
    must be explicitly specified as a trusted or the connection will fail to
    authenticate.
    If the peer uses a certificate that doesn't match or chain to one of the
    default CAs, use the `ca` option to provide a CA certificate that the peer's
    certificate can match or chain to.
    For self-signed certificates, the certificate is its own CA, and must be
    provided.
    For PEM encoded certificates, supported types are "TRUSTED CERTIFICATE",
    "X509 CERTIFICATE", and "CERTIFICATE".
  * `cert` {string|string[]|Buffer|Buffer[]} Cert chains in PEM format. One cert
    chain should be provided per private key. Each cert chain should consist of
    the PEM formatted certificate for a provided private `key`, followed by the
    PEM formatted intermediate certificates (if any), in order, and not
    including the root CA (the root CA must be pre-known to the peer, see `ca`).
    When providing multiple cert chains, they do not have to be in the same
    order as their private keys in `key`. If the intermediate certificates are
    not provided, the peer will not be able to validate the certificate, and the
    handshake will fail.
  * `ciphers` {string} Cipher suite specification, replacing the default. For
    more information, see [modifying the default cipher suite][]. Permitted
    ciphers can be obtained via [`tls.getCiphers()`][]. Cipher names must be
    uppercased in order for OpenSSL to accept them.
  * `clientCertEngine` {string} Name of an OpenSSL engine which can provide the
    client certificate.
  * `crl` {string|string[]|Buffer|Buffer[]} PEM formatted CRLs (Certificate
    Revocation Lists).
  * `dhparam` {string|Buffer} Diffie Hellman parameters, required for
    [Perfect Forward Secrecy][]. Use `openssl dhparam` to create the parameters.
    The key length must be greater than or equal to 1024 bits, otherwise an
    error will be thrown. It is strongly recommended to use 2048 bits or larger
    for stronger security. If omitted or invalid, the parameters are silently
    discarded and DHE ciphers will not be available.
  * `ecdhCurve` {string} A string describing a named curve or a colon separated
    list of curve NIDs or names, for example `P-521:P-384:P-256`, to use for
    ECDH key agreement. Set to `auto` to select the
    curve automatically. Use [`crypto.getCurves()`][] to obtain a list of
    available curve names. On recent releases, `openssl ecparam -list_curves`
    will also display the name and description of each available elliptic curve.
    **Default:** [`tls.DEFAULT_ECDH_CURVE`].
  * `honorCipherOrder` {boolean} Attempt to use the server's cipher suite
    preferences instead of the client's. When `true`, causes
    `SSL_OP_CIPHER_SERVER_PREFERENCE` to be set in `secureOptions`, see
    [OpenSSL Options][] for more information.
  * `idleTimeout` {number}
  * `ipv6Only` {boolean}
  * `key` {string|string[]|Buffer|Buffer[]|Object[]} Private keys in PEM format.
    PEM allows the option of private keys being encrypted. Encrypted keys will
    be decrypted with `options.passphrase`. Multiple keys using different
    algorithms can be provided either as an array of unencrypted key strings or
    buffers, or an array of objects in the form `{pem: <string|buffer>[,
    passphrase: <string>]}`. The object form can only occur in an array.
    `object.passphrase` is optional. Encrypted keys will be decrypted with
    `object.passphrase` if provided, or `options.passphrase` if it is not.
  * `maxAckDelay` {number}
  * `maxCidLen` {number}
  * `maxData` {number}
  * `maxPacketSize` {number}
  * `maxStreamDataBidiLocal` {number}
  * `maxStreamDataBidiRemote` {number}
  * `maxStreamDataUni` {number}
  * `maxStreamsBidi` {number}
  * `maxStreamsUni` {number}
  * `minCidLen` {number}
  * `passphrase` {string} Shared passphrase used for a single private key and/or
    a PFX.
  * `pfx` {string|string[]|Buffer|Buffer[]|Object[]} PFX or PKCS12 encoded
    private key and certificate chain. `pfx` is an alternative to providing
    `key` and `cert` individually. PFX is usually encrypted, if it is,
    `passphrase` will be used to decrypt it. Multiple PFX can be provided either
    as an array of unencrypted PFX buffers, or an array of objects in the form
    `{buf: <string|buffer>[, passphrase: <string>]}`. The object form can only
    occur in an array. `object.passphrase` is optional. Encrypted PFX will be
    decrypted with `object.passphrase` if provided, or `options.passphrase` if
    it is not.
  * `port` {number} The IP port of the remote QUIC server.
  * `preferredAddressPolicy` {string} `'accept'` or `'reject'`.
  * `remoteTransportParams` {Buffer|TypedArray|DataView} The serialized remote
    transport parameters from a previously established session. These would
    have been provided as part of the `'sessionTicket'` event on a previous
    `QuicClientSession` object.
  * `secureOptions` {number} Optionally affect the OpenSSL protocol behavior,
    which is not usually necessary. This should be used carefully if at all!
    Value is a numeric bitmask of the `SSL_OP_*` options from
    [OpenSSL Options][].
  * `sessionIdContext` {string} Opaque identifier used by servers to ensure
    session state is not shared between applications. Unused by clients.
  * `sessionTicket`: {Buffer|TypedArray|DataView} The serialized TLS Session
    Ticket from a previously established session. These would have been
    provided as part of the `'sessionTicket`' event on a previous
    `QuicClientSession` object.
  * `type`: {string} Identifies the type of UDP socket. The value must either
    be `'udp4'`, indicating UDP over IPv4, or `'udp6'`, indicating UDP over
    IPv6. Defaults to `'udp4'`.

Create a new `QuicClientSession`.

### quicsocket.destroy([error])
<!-- YAML
added: REPLACEME
-->

* `error` {any}

Destroys the `QuicSocket` then emits the `'close'` event when done. The `'error'`
event will be emitted after `'close'` if the `error` is not `undefined`.

### quicsocket.destroyed
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

Will be `true` if the `QuicSocket` has been destroyed.

### quicsocket.dropMembership(address, iface)
<!-- YAML
added: REPLACEME
-->

* `address` {string}
* `iface` {string}

Instructs the kernel to leave a multicast group at `multicastAddress` using the
`IP_DROP_MEMBERSHIP` socket option. This method is automatically called by the
kernel when the socket is closed or the process terminates, so most apps will
never have reason to call this.

If `multicastInterface` is not specified, the operating system will attempt to
drop membership on all valid interfaces.

### quicsocket.fd
<!-- YAML
added: REPLACEME
-->

* Type: {integer}

The system file descriptor the `QuicSocket` is bound to.

### quicsocket.listen([options][, callback])
<!-- YAML
added: REPLACEME
-->

* `options` {Object}
  * `alpn` {string} An ALPN protocol identifier.
  * `ca` {string|string[]|Buffer|Buffer[]} Optionally override the trusted CA
    certificates. Default is to trust the well-known CAs curated by Mozilla.
    Mozilla's CAs are completely replaced when CAs are explicitly specified
    using this option. The value can be a string or `Buffer`, or an `Array` of
    strings and/or `Buffer`s. Any string or `Buffer` can contain multiple PEM
    CAs concatenated together. The peer's certificate must be chainable to a CA
    trusted by the server for the connection to be authenticated. When using
    certificates that are not chainable to a well-known CA, the certificate's CA
    must be explicitly specified as a trusted or the connection will fail to
    authenticate.
    If the peer uses a certificate that doesn't match or chain to one of the
    default CAs, use the `ca` option to provide a CA certificate that the peer's
    certificate can match or chain to.
    For self-signed certificates, the certificate is its own CA, and must be
    provided.
    For PEM encoded certificates, supported types are "TRUSTED CERTIFICATE",
    "X509 CERTIFICATE", and "CERTIFICATE".
  * `cert` {string|string[]|Buffer|Buffer[]} Cert chains in PEM format. One cert
    chain should be provided per private key. Each cert chain should consist of
    the PEM formatted certificate for a provided private `key`, followed by the
    PEM formatted intermediate certificates (if any), in order, and not
    including the root CA (the root CA must be pre-known to the peer, see `ca`).
    When providing multiple cert chains, they do not have to be in the same
    order as their private keys in `key`. If the intermediate certificates are
    not provided, the peer will not be able to validate the certificate, and the
    handshake will fail.
  * `ciphers` {string} Cipher suite specification, replacing the default. For
    more information, see [modifying the default cipher suite][]. Permitted
    ciphers can be obtained via [`tls.getCiphers()`][]. Cipher names must be
    uppercased in order for OpenSSL to accept them.
  * `clientCertEngine` {string} Name of an OpenSSL engine which can provide the
    client certificate.
  * `crl` {string|string[]|Buffer|Buffer[]} PEM formatted CRLs (Certificate
    Revocation Lists).
  * `dhparam` {string|Buffer} Diffie Hellman parameters, required for
    [Perfect Forward Secrecy][]. Use `openssl dhparam` to create the parameters.
    The key length must be greater than or equal to 1024 bits, otherwise an
    error will be thrown. It is strongly recommended to use 2048 bits or larger
    for stronger security. If omitted or invalid, the parameters are silently
    discarded and DHE ciphers will not be available.
  * `ecdhCurve` {string} A string describing a named curve or a colon separated
    list of curve NIDs or names, for example `P-521:P-384:P-256`, to use for
    ECDH key agreement. Set to `auto` to select the
    curve automatically. Use [`crypto.getCurves()`][] to obtain a list of
    available curve names. On recent releases, `openssl ecparam -list_curves`
    will also display the name and description of each available elliptic curve.
    **Default:** [`tls.DEFAULT_ECDH_CURVE`].
  * `honorCipherOrder` {boolean} Attempt to use the server's cipher suite
    preferences instead of the client's. When `true`, causes
    `SSL_OP_CIPHER_SERVER_PREFERENCE` to be set in `secureOptions`, see
    [OpenSSL Options][] for more information.
  * `idleTimeout` {number}
  * `key` {string|string[]|Buffer|Buffer[]|Object[]} Private keys in PEM format.
    PEM allows the option of private keys being encrypted. Encrypted keys will
    be decrypted with `options.passphrase`. Multiple keys using different
    algorithms can be provided either as an array of unencrypted key strings or
    buffers, or an array of objects in the form `{pem: <string|buffer>[,
    passphrase: <string>]}`. The object form can only occur in an array.
    `object.passphrase` is optional. Encrypted keys will be decrypted with
    `object.passphrase` if provided, or `options.passphrase` if it is not.
  * `maxAckDelay` {number}
  * `maxCidLen` {number}
  * `maxData` {number}
  * `maxPacketSize` {number}
  * `maxStreamsBidi` {number}
  * `maxStreamsUni` {number}
  * `maxStreamDataBidiLocal` {number}
  * `maxStreamDataBidiRemote` {number}
  * `maxStreamDataUni` {number}
  * `minCidLen` {number}
  * `passphrase` {string} Shared passphrase used for a single private key and/or
    a PFX.
  * `pfx` {string|string[]|Buffer|Buffer[]|Object[]} PFX or PKCS12 encoded
    private key and certificate chain. `pfx` is an alternative to providing
    `key` and `cert` individually. PFX is usually encrypted, if it is,
    `passphrase` will be used to decrypt it. Multiple PFX can be provided either
    as an array of unencrypted PFX buffers, or an array of objects in the form
    `{buf: <string|buffer>[, passphrase: <string>]}`. The object form can only
    occur in an array. `object.passphrase` is optional. Encrypted PFX will be
    decrypted with `object.passphrase` if provided, or `options.passphrase` if
    it is not.
  * `preferredAddress` {Object}
    * `address` {string}
    * `port` {number}
    * `type` {string} `'udp4'` or `'udp6'`.
  * `secureOptions` {number} Optionally affect the OpenSSL protocol behavior,
    which is not usually necessary. This should be used carefully if at all!
    Value is a numeric bitmask of the `SSL_OP_*` options from
    [OpenSSL Options][].
  * `sessionIdContext` {string} Opaque identifier used by servers to ensure
    session state is not shared between applications. Unused by clients.

* `callback` {Function}

Listen for new peer-initiated sessions.

If a `callback` is given, it is registered as a handler for the
`'session'` event.

### quicsocket.pending
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

Will be `true` if the socket is not yet bound to the local UDP port.

### quicsocket.ref()
<!-- YAML
added: REPLACEME
-->

### quicsocket.setBroadcast([on])
<!-- YAML
added: REPLACEME
-->

* `on` {boolean}

Sets or clears the `SO_BROADCAST` socket option. When set to `true`, UDP packets may be sent
to a local interface's broadcast address.

### quicsocket.setMulticastLoopback([on])
<!-- YAML
added: REPLACEME
-->

* `on` {boolean}

Sets or clears the `IP_MULTICAST_LOOP` socket option. When set to `true`, multicast packets
will also be received on the local interface.

### quicsocket.setMulticastInterface(iface)
<!-- YAML
added: REPLACEME
-->

* `iface` {string}

All references to scope in this section are referring to IPv6 Zone Indices, which are
defined by [RFC 4007][]. In string form, an IP with a scope index is written as `'IP%scope'`
where scope is an interface name or interface number.

Sets the default outgoing multicast interface of the socket to a chosen interface or back to
system interface selection. The multicastInterface must be a valid string representation of
an IP from the socket's family.

For IPv4 sockets, this should be the IP configured for the desired physical interface. All
packets sent to multicast on the socket will be sent on the interface determined by the most
recent successful use of this call.

For IPv6 sockets, multicastInterface should include a scope to indicate the interface as in
the examples that follow. In IPv6, individual send calls can also use explicit scope in
addresses, so only packets sent to a multicast address without specifying an explicit scope
are affected by the most recent successful use of this call.

#### Examples: IPv6 Outgoing Multicast Interface
<!-- YAML
added: REPLACEME
-->
On most systems, where scope format uses the interface name:

```js
const socket = quic.createSocket({ type: 'udp6', port: 1234 });

socket.on('ready', () => {
  socket.setMulticastInterface('::%eth1');
});
```

On Windows, where scope format uses an interface number:

```js
const socket = quic.createSocket({ type: 'udp6', port: 1234 });

socket.on('ready', () => {
  socket.setMulticastInterface('::%2');
});
```

#### Example: IPv4 Outgoing Multicast Interface
<!-- YAML
added: REPLACEME
-->
All systems use an IP of the host on the desired physical interface:

```js
const socket = quic.createSocket({ type: 'udp4', port: 1234 });

socket.on('ready', () => {
  socket.setMulticastInterface('10.0.0.2');
});
```

#### Call Results#

A call on a socket that is not ready to send or no longer open may throw a Not running Error.

If multicastInterface can not be parsed into an IP then an `EINVAL` System Error is thrown.

On IPv4, if `multicastInterface` is a valid address but does not match any interface, or if
the address does not match the family then a System Error such as `EADDRNOTAVAIL` or
`EPROTONOSUP` is thrown.

On IPv6, most errors with specifying or omitting scope will result in the socket continuing
to use (or returning to) the system's default interface selection.

A socket's address family's ANY address (IPv4 `'0.0.0.0'` or IPv6 `'::'`) can be used to
return control of the sockets default outgoing interface to the system for future multicast packets.

### quicsocket.setMulticastTTL(ttl)
<!-- YAML
added: REPLACEME
-->

* `ttl` {number}

Sets the `IP_MULTICAST_TTL` socket option. While TTL generally stands for "Time to Live",
in this context it specifies the number of IP hops that a packet is allowed to travel through,
specifically for multicast traffic. Each router or gateway that forwards a packet decrements
the TTL. If the TTL is decremented to `0` by a router, it will not be forwarded.

The argument passed to `socket.setMulticastTTL()` is a number of hops between `0` and `255`.
The default on most systems is `1` but can vary.

### quicsocket.setTTL(ttl)
<!-- YAML
added: REPLACEME
-->

* `ttl` {number}

Sets the `IP_TTL` socket option. While TTL generally stands for "Time to Live", in this
context it specifies the number of IP hops that a packet is allowed to travel through. Each
router or gateway that forwards a packet decrements the TTL. If the TTL is decremented to `0`
by a router, it will not be forwarded. Changing TTL values is typically done for network
probes or when multicasting.

The argument to `socket.setTTL()` is a number of hops between `1` and `255`. The default on
most systems is `64` but can vary.

### quicsocket.unref();
<!-- YAML
added: REPLACEME
-->


## Class: QuicStream extends stream.Duplex
<!-- YAML
added: REPLACEME
-->
* Extends: {stream.Duplex}

### Event: `'close'`
<!-- YAML
added: REPLACEME
-->

### Event: `'data'`
<!-- YAML
added: REPLACEME
-->

### Event: `'error'`
<!-- YAML
added: REPLACEME
-->

### Event: `'readable'`
<!-- YAML
added: REPLACEME
-->

### quicstream.bidirectional
<!--YAML
added: REPLACEME
-->

* Type: {boolean}

True if the `QuicStream` is bidirectional.

### quicstream.clientInitiated
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

True if the `QuicStream` was initiated by a `QuicClientSession` instance.

### quicstream.id
<!-- YAML
added: REPLACEME
-->

* Type: {number}

The numeric identifier of the `QuicStream`.

### quicstream.serverInitiated
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

True if the `QuicStream` was initiated by a `QuicServerSession` instance.

### quicstream.session
<!-- YAML
added: REPLACEME
-->

* Type: {QuicSession}

The `QuicServerSession` or `QuicClientSession`.

### quicstream.unidirectional
<!-- YAML
added: REPLACEME
-->

* Type: {boolean}

True if the `QuicStream` is unidirectional.



[RFC 4007]: https://tools.ietf.org/html/rfc4007
[Certificate Object]: https://nodejs.org/dist/latest-v12.x/docs/api/tls.html#tls_certificate_object
