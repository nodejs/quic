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
const ca = getTLSCAListSomehow();

// The default export of the quic module is the
// createSocket function.
const createSocket = require('quic');

// Create the local QUIC UDP socket...
const socket = createSocket({ type: 'udp4', port: 1234 });

// Tell the socket to operate as a server...
socket.listen({ key, cert, ca });

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

### quic.createSocket([options])
<!-- YAML
added: REPLACEME
-->

* `options` {Object}
  * `address` {string} The local address to bind to.
  * `ipv6Only` {boolean}
  * `lookup` {Function}
  * `port` {number} The local port to bind to.
  * `resuseAddr` {boolean}
  * `type` {string} Either `'udp4'` or `'upd6'` to use either IPv4 or IPv6,
     respectively.

Creates a new `QuicSocket` instance.

### Class: QuicSession
<!-- YAML
added: REPLACEME
-->
* Extends: {EventEmitter}

### Event: `'close'`
<!-- YAML
added: REPLACEME
-->

Emiitted after the `QuicSession` has been destroyed.

### Event: `'error'`
<!-- YAML
added: REPLACEME
-->

Emitted after the `'close'` event if the `QuicSession` was destroyed with
an error.

### Event: `'secure'`
<!-- YAML
added: REPLACEME
-->

Emitted after the TLS handshake has been completed.

The callback will be invoked with two arguments:

* `servername` {string} The SNI servername requested by the client.
* `alpnProtocol` {string} The negotiated ALPN protocol.

These will also be available using the `quicsession.servername` and
`quicsession.alpnProtocol` properties.

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

### quicsession.close([callback])
<!-- YAML
added: REPLACEME
-->

* `callback` {Function} Callback invoked when the close operation is completed

Closes the `QuicSession`.

### quicsession.destroy([error])
<!-- YAML
added: REPLACEME
-->

* `error` {any}

Destroys the `QuicSession` causing the `close` event to be emitted. If `error`
is not `undefined`, the `error` event will be emitted following the `close`
event.

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

### quicsession.getPeerCertificate([detailed])
<!-- YAML
added: REPLACEME
-->

* `detailed` {boolean} Defaults to `false`

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

### Class: QuicClientSession
<!-- YAML
added: REPLACEME
-->

* Extends: {QuicSession}

TBD

#### quicclientsession.ephemeralKeyInfo
<!-- YAML
added: REPLACEME
-->

### Class: QuicServerSession
<!-- YAML
added: REPLACEME
-->

* Extends: {QuicSession}

TBD

### Class: QuicSocket
<!-- YAML
added: REPLACEME
-->

### Event: `'close'`
<!-- YAML
added: REPLACEME
-->

### Event: `'error'`
<!-- YAML
added: REPLACEME
-->

### Event: `'ready'`
<!-- YAML
added: REPLACEME
-->

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

### quicsocket.address
<!-- YAML
added: REPLACEME
-->

* Type: Address

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

Closes the `QuicSocket`.

### quicsocket.connect([options])
<!-- YAML
added: REPLACEME
-->

* `options` {Object}
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
  * `key` {string|string[]|Buffer|Buffer[]|Object[]} Private keys in PEM format.
    PEM allows the option of private keys being encrypted. Encrypted keys will
    be decrypted with `options.passphrase`. Multiple keys using different
    algorithms can be provided either as an array of unencrypted key strings or
    buffers, or an array of objects in the form `{pem: <string|buffer>[,
    passphrase: <string>]}`. The object form can only occur in an array.
    `object.passphrase` is optional. Encrypted keys will be decrypted with
    `object.passphrase` if provided, or `options.passphrase` if it is not.
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
  * `secureOptions` {number} Optionally affect the OpenSSL protocol behavior,
    which is not usually necessary. This should be used carefully if at all!
    Value is a numeric bitmask of the `SSL_OP_*` options from
    [OpenSSL Options][].
  * `sessionIdContext` {string} Opaque identifier used by servers to ensure
    session state is not shared between applications. Unused by clients.

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
  * `key` {string|string[]|Buffer|Buffer[]|Object[]} Private keys in PEM format.
    PEM allows the option of private keys being encrypted. Encrypted keys will
    be decrypted with `options.passphrase`. Multiple keys using different
    algorithms can be provided either as an array of unencrypted key strings or
    buffers, or an array of objects in the form `{pem: <string|buffer>[,
    passphrase: <string>]}`. The object form can only occur in an array.
    `object.passphrase` is optional. Encrypted keys will be decrypted with
    `object.passphrase` if provided, or `options.passphrase` if it is not.
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

### quicsocket.setMulticastLoopback([on])
<!-- YAML
added: REPLACEME
-->

* `on` {boolean}

### quicsocket.setMulticastInterface(iface)
<!-- YAML
added: REPLACEME
-->

* `iface` {string}

### quicsocket.setMulticastTTL(ttl)
<!-- YAML
added: REPLACEME
-->

* `ttl` {number}

### quicsocket.setTTL(ttl)
<!-- YAML
added: REPLACEME
-->

* `ttl` {number}

### quicsocket.unref();
<!-- YAML
added: REPLACEME
-->


### Class: QuicStream
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

### quicstream.id
<!-- YAML
added: REPLACEME
-->

* Type: {number}

### quicstream.session
<!-- YAML
added: REPLACEME
-->

* Type: {QuicSession}
