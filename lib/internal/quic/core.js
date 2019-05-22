'use strict';

/* eslint-disable no-use-before-define */

const {
  assertCrypto,
  customInspectSymbol: kInspect,
} = require('internal/util');

assertCrypto();

const {
  getAllowUnauthorized,
  getSocketType,
  lookup4,
  lookup6,
  validateTransportParams,
  validateQuicClientSessionOptions,
  validateQuicSocketOptions,
} = require('internal/quic/util');
const util = require('util');
const assert = require('internal/assert');
const EventEmitter = require('events');
const { Duplex } = require('stream');
const {
  createSecureContext: _createSecureContext
} = require('tls');
const {
  translatePeerCertificate
} = require('_tls_common');
const {
  defaultTriggerAsyncIdScope, // eslint-disable-line no-unused-vars
  symbols: {
    async_id_symbol,
    owner_symbol,
  },
} = require('internal/async_hooks');

const {
  writeGeneric,
  writevGeneric,
  onStreamRead,
  kAfterAsyncWrite,
  kMaybeDestroy,
  kUpdateTimer,
  kHandle,
  setStreamTimeout // eslint-disable-line no-unused-vars
} = require('internal/stream_base_commons');

const {
  ShutdownWrap,
  kReadBytesOrError, // eslint-disable-line no-unused-vars
  streamBaseState // eslint-disable-line no-unused-vars
} = internalBinding('stream_wrap');

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_CALLBACK,
    ERR_QUICSESSION_DESTROYED,
    ERR_QUICSOCKET_CLOSING,
    ERR_QUICSOCKET_DESTROYED,
    ERR_QUICSOCKET_LISTENING,
    ERR_QUICCLIENTSESSION_FAILED,
    ERR_QUICCLIENTSESSION_FAILED_SETSOCKET,
    ERR_QUICSESSION_UNABLE_TO_MIGRATE,
    ERR_TLS_DH_PARAM_SIZE,
  },
  errnoException,
  exceptionWithHostPort
} = require('internal/errors');

const {
  QuicSocket: QuicSocketHandle,
  initSecureContext,
  initSecureContextClient,
  createClientSession: _createClientSession,
  openBidirectionalStream: _openBidirectionalStream,
  openUnidirectionalStream: _openUnidirectionalStream,
  sessionConfig,
  setCallbacks,
  constants: {
    AF_INET,
    AF_INET6,
    UV_EBADF,
    UV_UDP_IPV6ONLY,
    UV_UDP_REUSEADDR,
    NGTCP2_MAX_CIDLEN,
    NGTCP2_MIN_CIDLEN,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI,
    IDX_QUIC_SESSION_MAX_DATA,
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI,
    IDX_QUIC_SESSION_MAX_STREAMS_UNI,
    IDX_QUIC_SESSION_IDLE_TIMEOUT,
    IDX_QUIC_SESSION_MAX_PACKET_SIZE,
    IDX_QUIC_SESSION_MAX_CID_LEN,
    IDX_QUIC_SESSION_MIN_CID_LEN,
    IDX_QUIC_SESSION_CONFIG_COUNT,
    IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT,
    IDX_QUIC_SESSION_MAX_ACK_DELAY,
    IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT,
    IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED,
    ERR_INVALID_REMOTE_TRANSPORT_PARAMS,
    ERR_INVALID_TLS_SESSION_TICKET,
    NGTCP2_PATH_VALIDATION_RESULT_FAILURE,
  }
} = internalBinding('quic');

const DEFAULT_QUIC_CIPHERS = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:' +
                             'TLS_CHACHA20_POLY1305_SHA256';
const DEFAULT_GROUPS = 'P-256:X25519:P-384:P-521';

const emit = EventEmitter.prototype.emit;

const kAddSession = Symbol('kAddSession');
const kAddStream = Symbol('kAddStream');
const kContinueBind = Symbol('kContinueBind');
const kContinueConnect = Symbol('kContinueConnect');
const kContinueListen = Symbol('kContinueListen');
const kExtend = Symbol('kExtend');
const kHandshake = Symbol('kHandshake');
const kHandshakePost = Symbol('kHandshakePost');
const kInit = Symbol('kInit');
const kMaybeBind = Symbol('kMaybeBind');
const kMaybeReady = Symbol('kMaybeReady');
const kReady = Symbol('kReady');
const kReceiveStart = Symbol('kReceiveStart');
const kReceiveStop = Symbol('kReceiveStop');
const kRemoveSession = Symbol('kRemove');
const kRemoveStream = Symbol('kRemoveStream');
const kReset = Symbol('kReset');
const kSetSocket = Symbol('kSetSocket');
const kTrackWriteState = Symbol('kTrackWriteState');
const kWriteGeneric = Symbol('kWriteGeneric');

const kSocketUnbound = 0;
const kSocketPending = 1;
const kSocketBound = 2;
const kSocketClosing = 3;
const kSocketDestroyed = 4;

function setConfigField(val, index) {
  if (typeof val === 'number') {
    sessionConfig[index] = val;
    return 1 << index;
  }
  return 0;
}

function setTransportParams(config) {
  const {
    maxStreamDataBidiLocal,
    maxStreamDataBidiRemote,
    maxStreamDataUni,
    maxData,
    maxStreamsBidi,
    maxStreamsUni,
    idleTimeout,
    maxPacketSize,
    maxAckDelay,
    maxCidLen,
    minCidLen,
  } = { ...config };
  const flags = setConfigField(maxStreamDataBidiLocal,
                               IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL) |
                setConfigField(maxStreamDataBidiRemote,
                               IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE) |
                setConfigField(maxStreamDataUni,
                               IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI) |
                setConfigField(maxData, IDX_QUIC_SESSION_MAX_DATA) |
                setConfigField(maxStreamsBidi,
                               IDX_QUIC_SESSION_MAX_STREAMS_BIDI) |
                setConfigField(maxStreamsUni,
                               IDX_QUIC_SESSION_MAX_STREAMS_UNI) |
                setConfigField(idleTimeout, IDX_QUIC_SESSION_IDLE_TIMEOUT) |
                setConfigField(maxAckDelay, IDX_QUIC_SESSION_MAX_ACK_DELAY) |
                setConfigField(maxPacketSize,
                               IDX_QUIC_SESSION_MAX_PACKET_SIZE) |
                setConfigField(maxCidLen, IDX_QUIC_SESSION_MAX_CID_LEN) |
                setConfigField(minCidLen, IDX_QUIC_SESSION_MIN_CID_LEN);

  sessionConfig[IDX_QUIC_SESSION_CONFIG_COUNT] = flags;
}

// Called when the socket has been bound and is ready for use
function onSocketReady(fd) {
  this[owner_symbol][kReady](fd);
}

// Called when the socket is closed
function onSocketClose() {
  this[owner_symbol].destroy();
}

// Called when an error occurs on the socket
function onSocketError(err) {
  this[owner_symbol].destroy(errnoException(err));
}

// Called when a new QuicSession is ready to use
function onSessionReady(sessionHandle) {
  const socket = this[owner_symbol];
  const session = new QuicServerSession(socket, sessionHandle);
  process.nextTick(emit.bind(socket, 'session', session));
}

// Called when a QuicSession is closed
function onSessionClose(code) {
  this[owner_symbol].destroy();
}

function onSessionHandshake(
  servername,
  alpn,
  cipher,
  cipherVersion,
  maxPacketLength) {
  this[owner_symbol][kHandshake](
    servername,
    alpn,
    cipher,
    cipherVersion,
    maxPacketLength);
}

function onSessionTicket(sessionID, sessionTicket, transportParams) {
  process.nextTick(
    emit.bind(
      this[owner_symbol],
      'sessionTicket',
      sessionID,
      sessionTicket,
      transportParams));
}

function onSessionPathValidation(res, local, remote) {
  const session = this[owner_symbol];
  process.nextTick(
    emit.bind(
      session,
      'pathValidation',
      res === NGTCP2_PATH_VALIDATION_RESULT_FAILURE ? 'failure' : 'success',
      local,
      remote));
}

// Called when an error occurs in a QuicSession
function onSessionError(error) {
  this[owner_symbol].destroy(error);
}

function onSessionExtend(bidi, maxStreams) {
  this[owner_symbol][kExtend](bidi, maxStreams);
}

function onSessionKeylog(line) {
  this[owner_symbol].emit('keylog', line);
//  process.nextTick(emit.bind(this[owner_symbol], 'keylog', line));
}

// Called when a new QuicStream is ready to use
function onStreamReady(streamHandle, id) {
  const session = this[owner_symbol];

  // onStreamReady should never be called if the stream is in a closing
  // state because new streams should not have been accepted at the C++
  // level.
  assert(!session.closing);

  // TODO(@jasnell): Get default options from session
  const uni = id & 0b10;
  const stream = new QuicStream({ writable: !uni }, session, id, streamHandle);
  if (uni)
    stream.end();
  session[kAddStream](id, stream);
  process.nextTick(emit.bind(session, 'stream', stream));
}

// Called when a stream is closed on the C++ side and
// needs to be destroyed on the JavaScript side.
function onStreamClose() {
  this[owner_symbol].destroy();
}

// Called when a stream reset is received
function onStreamReset(finalSize, appErrorCode) {
  this[owner_symbol][kReset](finalSize, appErrorCode);
}

// Called when an error occurs in a QuicStream
function onStreamError(streamHandle, error) {
  streamHandle[owner_symbol].destroy(error);
}

// Register the callbacks with the QUIC internal binding.
setCallbacks({
  onSocketReady,
  onSocketClose,
  onSocketError,
  onSessionReady,
  onSessionClose,
  onSessionError,
  onSessionExtend,
  onSessionHandshake,
  onSessionKeylog,
  onSessionTicket,
  onStreamReady,
  onStreamClose,
  onStreamError,
  onStreamReset,
  onSessionPathValidation,
});

function afterLookup(callback, err, ip) {
  if (err) {
    this.destroy(err);
    return;
  }
  this[kContinueBind](ip, callback);
}

function connectAfterLookup(type, err, ip) {
  if (err) {
    this.destroy(err);
    return;
  }
  this[kContinueConnect](type, ip);
}

function afterPreferredAddressLookup(
  transportParams,
  port,
  type,
  err,
  address) {
  if (err) {
    this.destroy(err);
    return;
  }
  this[kContinueListen](transportParams, { address, port, type });
}

function continueListen(transportParams, lookup) {
  const { preferredAddress } = transportParams;

  if (preferredAddress && typeof preferredAddress === 'object') {
    const {
      address,
      port,
      type = 'udp4',
    } = { ...preferredAddress };
    const typeVal = getSocketType(type);
    // If preferred address is set, we need to perform a lookup on it
    // to get the IP address. Only after that lookup completes can we
    // continue with the listen operation, passing in the resolved
    // preferred address.
    lookup(
      address || (typeVal === AF_INET6 ? '::' : '0.0.0.0'),
      afterPreferredAddressLookup.bind(this, transportParams, port, typeVal));
    return;
  }
  // If preferred address is not set, we can skip directly to the listen
  this[kContinueListen](transportParams);
}

function connectAfterBind(session, lookup, address, type) {
  lookup(
    address || (type === AF_INET6 ? '::' : '0.0.0.0'),
    connectAfterLookup.bind(session, type));
}

function createSecureContext(options, init_cb) {
  const {
    ca,
    cert,
    ciphers = DEFAULT_QUIC_CIPHERS,
    clientCertEngine,
    crl,
    dhparam,
    ecdhCurve,
    groups = DEFAULT_GROUPS,
    honorCipherOrder,
    key,
    passphrase,
    pfx,
    sessionIdContext,
    secureProtocol
  } = { ...options };

  if (typeof ciphers !== 'string')
    throw new ERR_INVALID_ARG_TYPE('option.ciphers', 'string', ciphers);
  if (typeof groups !== 'string')
    throw new ERR_INVALID_ARG_TYPE('option.groups', 'string', groups);

  const sc = _createSecureContext({
    secureProtocol,
    ca,
    cert,
    ciphers: ciphers || DEFAULT_QUIC_CIPHERS,
    clientCertEngine,
    crl,
    dhparam,
    ecdhCurve,
    honorCipherOrder,
    key,
    passphrase,
    pfx,
    sessionIdContext
  });
  // Perform additional QUIC specific initialization on the SecureContext
  init_cb(sc.context, groups || DEFAULT_GROUPS);
  return sc;
}

function onNewKeylogListener(event) {
  if (event !== 'keylog' ||
      this[kHandle] === undefined ||
      this.listenerCount('keylog') !== 0) {
    return;
  }
  this[kHandle].state[IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED] = 1;
}

function onRemoveKeylogListener(event) {
  if (event !== 'keylog' ||
      this[kHandle] === undefined ||
      this.listenerCount('keylog') !== 0) {
    return;
  }
  this[kHandle].state[IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED] = 0;
}

// QuicSocket wraps a UDP socket plus the associated TLS context and QUIC
// Protocol state. There may be *multiple* QUIC connections (QuicSession)
// associated with a single QuicSocket.
class QuicSocket extends EventEmitter {
  #address = undefined;
  #client = undefined;
  #fd = UV_EBADF;
  #ipv6Only = undefined;
  #lookup = undefined;
  #port = undefined;
  #reuseAddr = undefined;
  #server = undefined;
  #serverListening = false;
  #serverSecureContext = undefined;
  #sessions = new Set();
  #state = kSocketUnbound;
  #type = undefined;
  #alpn = undefined;

  constructor(options) {
    const {
      address,               // The local IP address or hostname to bind to
      client,                // Default configuration for QuicClientSessions
      ipv6Only,              // True if only IPv6 should be used
      lookup,                // A custom function used to resolve hostname to IP
      maxConnectionsPerHost, // The maximum number of connections per host
      port,                  // The local IP port to bind to
      reuseAddr,             //
      retryTokenTimeout,     // The maximum number of seconds for retry token
      server,                // Default configuration for QuicServerSessions
      type,                  // 'udp4' or 'udp6'
      validateAddress,       // True if address verification should be used.
    } = validateQuicSocketOptions(options || {});
    super();
    const handle =
      new QuicSocketHandle(
        validateAddress,
        retryTokenTimeout,
        maxConnectionsPerHost);
    handle[owner_symbol] = this;
    this[async_id_symbol] = handle.getAsyncId();
    this[kHandle] = handle;
    this.#address = address || (type === AF_INET6 ? '::' : '0.0.0.0');
    this.#client = client;
    this.#ipv6Only = !!ipv6Only;
    this.#lookup = lookup || (type === AF_INET6 ? lookup6 : lookup4);
    this.#port = port || 0;
    this.#reuseAddr = reuseAddr;
    this.#server = server;
    this.#type = type;
  }

  [kInspect]() {
    const obj = {
      address: this.address,
      fd: this.#fd,
      sessions: this.#sessions,
      type: this.#type
    };
    return `QuicSocket ${util.format(obj)}`;
  }

  [kAddSession](session) {
    this.#sessions.add(session);
  }

  [kRemoveSession](session) {
    this.#sessions.delete(session);
  }

  // Bind the UDP socket on demand, only if it hasn't already been bound.
  // Function is a non-op if the socket is already bound
  [kMaybeBind](callback = () => {}) {
    // This socket will be in a pending state until it is bound. Once bound,
    // the this[kReady]() method will be called, switching the state to
    // kSocketBound and notifying the associated sessions
    if (this.#state !== kSocketUnbound)
      return;
    this.#state = kSocketPending;
    this.#lookup(this.#address, afterLookup.bind(this, callback));
  }

  // Called by the afterLookup callback to continue the binding operation
  // after the DNS lookup of the address has been completed.
  [kContinueBind](ip, callback) {
    const flags =
      (this.#reuseAddr ? UV_UDP_REUSEADDR : 0) ||
      (this.#ipv6Only ? UV_UDP_IPV6ONLY : 0);
    const ret = this[kHandle].bind(this.#type, ip, this.#port || 0, flags);
    if (ret) {
      this.destroy(exceptionWithHostPort(ret, 'bind', ip, this.#port || 0));
      return;
    }

    if (typeof callback === 'function')
      callback();
  }

  // The kReady function is called after the socket has been bound to the
  // local port. It signals when the various sessions may begin
  // doing their various things they do.
  [kReady](fd) {
    this.#state = kSocketBound;
    this.#fd = fd;
    for (const session of this.#sessions)
      session[kReady]();
    process.nextTick(emit.bind(this, 'ready'));
  }

  // A socket should only be put into the receiving state if there is a
  // listening server or an active client. This will be called on demand
  // when needed.
  [kReceiveStart]() {
    this[kHandle].receiveStart();
  }

  // The socket should be moved to a not receiving state if there is no
  // listening server and no active sessions. This will be called on demand
  // when needed.
  [kReceiveStop]() {
    this[kHandle].receiveStop();
  }

  [kContinueListen](transportParams, preferredAddress) {
    const {
      address,
      port,
      type = AF_INET,
    } = { ...preferredAddress };
    setTransportParams(transportParams);
    this[kHandle].listen(
      this.#serverSecureContext.context,
      address,
      type,
      port,
      this.#alpn);
    process.nextTick(emit.bind(this, 'listening'));
  }


  // Begin listening for server connections
  listen(options, callback) {
    if (this.#serverListening)
      throw new ERR_QUICSOCKET_LISTENING();

    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('listen');

    if (this.#state === kSocketClosing)
      throw new ERR_QUICSOCKET_CLOSING('listen');

    this[kMaybeBind]();

    if (typeof options === 'function') {
      callback = options;
      options = {};
    }

    options = {
      secureProtocol: 'TLSv1_3_server_method',
      ...this.#server,
      ...options
    };

    const { alpn } = options;
    if (alpn !== undefined && typeof alpn !== 'string')
      throw new ERR_INVALID_ARG_TYPE('options.alpn', 'string', alpn);

    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('session', callback);
    }

    // Store the secure context so that it is not garbage collected
    // while we still need to make use of it.
    // TODO(@jasnell): We could store a reference at the C++ level instead
    // since we do not need to access this anywhere else.
    this.#serverSecureContext = createSecureContext(options, initSecureContext);
    this.#serverListening = true;
    this.#alpn = alpn;

    const doListen =
      continueListen.bind(
        this,
        validateTransportParams(options, NGTCP2_MAX_CIDLEN, NGTCP2_MIN_CIDLEN),
        this.#lookup);

    // If the QuicSocket is already bound, we'll begin listening
    // immediately. If we're still pending, however, wait until
    // the 'ready' event is emitted, then carry on.
    if (this.#state === kSocketPending) {
      this.on('ready', doListen);
      return;
    }
    doListen();
  }

  connect(options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }

    options = {
      ...this.#client,
      ...options
    };

    const {
      type = 'udp4',
      address,
    } = options;

    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('connect');

    if (this.#state === kSocketClosing)
      throw new ERR_QUICSOCKET_CLOSING('connect');

    const session = new QuicClientSession(this, options);

    if (typeof callback === 'function')
      session.on('ready', callback);

    this[kMaybeBind](
      connectAfterBind.bind(
        this,
        session,
        this.#lookup,
        address,
        getSocketType(type)));

    return session;
  }

  // kMaybeDestroy is called one or more times after the close() method
  // is called. The QuicSocket will be destroyed if there are no remaining
  // open sessions.
  [kMaybeDestroy]() {
    if (this.#sessions.size === 0) {
      // Destroying requires that we first close the UDP
      // handle, then destroy the actual handle..
      // TODO(@jasnell): eliminate the need to destroy separately
      this[kHandle].close((err) => this.destroy(err));
    }
  }

  // Closing the QuicSocket allows any existing QuicSessions to be
  // closed gracefully. Subsequent calls to connect will fail. If
  // the socket is listening, new sessions will be rejected. Once
  // there are no more QuicSessions, the QuicSocket will be destroyed.
  close(callback) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('close');

    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      if (this.#state === kSocketUnbound) {
        callback();
        return;
      }
      this.on('close', callback);
    }

    // If we are already closing, do othing else and wait
    // for the close event to be invoked.
    if (this.#state === kSocketClosing)
      return;
    this.#state = kSocketClosing;

    // Otherwise, gracefully close each QuicSession, with
    // [kMaybeDestroy]() being called after each closes.
    const maybeDestroy = this[kMaybeDestroy].bind(this);

    // If there are no sessions, call [kMaybeDestroy]()
    // immediately to destroy the QuicSocket
    if (this.#sessions.size === 0) {
      this[kMaybeDestroy]();
      maybeDestroy();
      return;
    }

    for (const session of this.#sessions)
      session.close(maybeDestroy);
  }

  // Destroy the QuicSocket immediately. If there are remaining
  // sessions, those will be destroyed.
  destroy(error) {
    if (this.#state === kSocketDestroyed)
      return;
    this.#state = kSocketDestroyed;

    for (const session of this.#sessions)
      session.destroy(error);

    const handle = this[kHandle];
    if (handle !== undefined) {
      this[kHandle] = undefined;
      handle[owner_symbol] = undefined;
      handle.close();
    }

    if (error) process.nextTick(emit.bind(this, 'error', error));
    process.nextTick(emit.bind(this, 'close'));
  }

  ref() {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('ref');
    this[kHandle].ref();
    return this;
  }

  unref() {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('unref');
    this[kHandle].unref();
    return this;
  }

  get address() {
    const out = {};
    if (this.#state !== kSocketDestroyed) {
      const err = this[kHandle].getsockname(out);
      if (err)
        throw errnoException(err, 'address');
    }
    return out;
  }

  get bound() {
    return this.#state === kSocketBound;
  }

  get pending() {
    return this.#state === kSocketPending;
  }

  get destroyed() {
    return this.#state === kSocketDestroyed;
  }

  get fd() {
    return this.#fd;
  }

  setTTL(ttl) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setTTL');
    if (typeof ttl !== 'number')
      throw new ERR_INVALID_ARG_TYPE('ttl', 'number', ttl);
    if (ttl < 1 || ttl > 255)
      throw new ERR_INVALID_ARG_VALUE('ttl', ttl);
    const err = this[kHandle].setTTL(ttl);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }

  setMulticastTTL(ttl) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastTTL');
    if (typeof ttl !== 'number')
      throw new ERR_INVALID_ARG_TYPE('ttl', 'number', ttl);
    if (ttl < 1 || ttl > 255)
      throw new ERR_INVALID_ARG_VALUE('ttl', ttl);
    const err = this[kHandle].setMulticastTTL(ttl);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }

  setBroadcast(on = true) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setBroadcast');
    if (typeof on !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('on', 'boolean', on);
    const err = this[kHandle].setBroadcast(on);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }

  setMulticastLoopback(on = true) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastLoopback');
    if (typeof on !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('on', 'boolean', on);
    const err = this[kHandle].setMulticastLoopback(on);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }

  setMulticastInterface(iface) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastInterface');
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].setMulticastInterface(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }

  addMembership(address, iface) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('addMembership');
    if (typeof address !== 'string')
      throw new ERR_INVALID_ARG_TYPE('address', 'string', address);
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].addMembership(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }

  dropMembership(address, iface) {
    if (this.#state === kSocketDestroyed)
      throw new ERR_QUICSOCKET_DESTROYED('dropMembership');
    if (typeof address !== 'string')
      throw new ERR_INVALID_ARG_TYPE('address', 'string', address);
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].dropMembership(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
    return this;
  }
}

class QuicSession extends EventEmitter {
  #alpn = undefined;
  #cipher = undefined;
  #cipherVersion = undefined;
  #closeCode = 0;
  #closing = false;
  #destroyed = false;
  #handshakeComplete = false;
  #maxBidiStreams = 10;  // TODO(@jasnell): Set to the actual initial value
  #maxPacketLength = IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT;
  #maxUniStreams = 10;   // TODO(@jasnell): Set to the actual initial value
  #servername = undefined;
  #socket = undefined;
  #streams = new Map();

  constructor(socket, servername) {
    super();
    this.on('newListener', onNewKeylogListener);
    this.on('removeListener', onRemoveKeylogListener);
    this.#socket = socket;
    socket[kAddSession](this);
    this.#servername = servername;
  }

  [kInspect]() {
    const obj = {
      alpn: this.#alpn,
      cipher: this.cipher,
      closing: this.closing,
      destroyed: this.destroyed,
      servername: this.servername,
      streams: this.#streams.size,
    };
    return `${this.constructor.name} ${util.format(obj)}`;
  }

  [kSetSocket](socket) {
    this.#socket = socket;
  }

  [kHandshake](servername, alpn, cipher, cipherVersion, maxPacketLength) {
    this.#handshakeComplete = true;
    this.#servername = servername;
    this.#alpn = alpn;
    this.#cipher = cipher;
    this.#cipherVersion = cipherVersion;
    this.#maxPacketLength = maxPacketLength;

    if (!this[kHandshakePost]())
      return;

    process.nextTick(
      emit.bind(this, 'secure', servername, alpn, this.cipher));
  }

  [kHandshakePost]() {
    // Non-op for the default case. QuicClientSession
    // overrides this with some client-side specific
    // checks
    return true;
  }

  [kExtend](bidi, maxStreams) {
    let event;
    if (bidi) {
      event = 'extendMaxBidiStreams';
      this.#maxBidiStreams = maxStreams;
    } else {
      event = 'extendMaxUniStreams';
      this.#maxUniStreams = maxStreams;
    }
    process.nextTick(emit.bind(this, event, maxStreams));
  }

  [kRemoveStream](stream) {
    this.#streams.delete(stream.id);
  }

  [kAddStream](id, stream) {
    stream.on('close', this[kMaybeDestroy].bind(this));
    if (stream.serverInitiated && stream.unidirectional)
      stream.end();
    this.#streams.set(id, stream);
  }

  // The QuicSession will be destroyed if closing has been
  // called and there are no remaining streams
  [kMaybeDestroy]() {
    if (this.#closing && this.#streams.size === 0)
      this.destroy();
  }

  // Closing allows any existing QuicStream's to complete
  // normally but disallows any new QuicStreams from being
  // opened. Calls to openStream() will fail, and new streams
  // from the peer will be rejected/ignored. Once all existing
  // streams have completed, the QuicSession will be destroyed,
  // causing the handle to be freed and the close event to be
  // emitted.
  //
  // It is important to note that using close, it may take some
  // time for the QuicSession to be destroyed and all timeouts
  // will still be active.
  close(code, callback) {
    if (this.#destroyed)
      throw new ERR_QUICSESSION_DESTROYED('close');

    if (typeof code === 'function') {
      callback = code;
      code = 0;
    }

    if (code !== undefined && typeof code !== 'number')
      throw new ERR_INVALID_ARG_TYPE('code', 'number', code);

    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }

    // If we're already closing, do nothing else.
    // Callback will be invoked once the session
    // has been destroyed
    if (this.#closing)
      return;

    // We have to let both the JavaScript and C++ sides know that
    // the session is closing. On the JavaScript side, the flag is
    // used to prevent new streams from being opened. On the C++
    // side, it is used to prevent acceptance of new Streams.
    this.#closing = true;
    this.#closeCode = code;
    this[kHandle].close(code);

    // Try destroying immediately
    this[kMaybeDestroy]();
  }

  // Destroying synchronously shuts down and frees the
  // QuicSession immediately, even if there are still open
  // streams.
  //
  // A CONNECTION_CLOSE packet is sent to the
  // connected peer and the session is immediately
  // destroyed.
  //
  // If destroy is called with an error argument, the
  // 'error' event is emitted on next tick.
  //
  // Once destroyed, and after the 'error' event (if any),
  // the close event is emitted on next tick.
  destroy(error) {
    // Destroy can only be called once. Multiple calls will be ignored
    if (this.#destroyed)
      return;
    this.#destroyed = true;
    this.#closing = false;

    // Destroy any remaining streams immediately
    for (const stream of this.#streams.values())
      stream.destroy(error);

    this.removeListener('newListener', onNewKeylogListener);
    this.removeListener('removeListener', onRemoveKeylogListener);

    const handle = this[kHandle];
    if (handle !== undefined) {
      handle[owner_symbol] = undefined;
      this[kHandle] = undefined;
      // Calling destroy will cause a CONNECTION_CLOSE to be
      // sent to the peer and will destroy the QuicSession
      // handler immediately.
      handle.destroy();
    }

    // Remove the QuicSession JavaScript object from the
    // associated QuicSocket.
    this.#socket[kRemoveSession](this);
    this.#socket = undefined;

    if (error) process.nextTick(emit.bind(this, 'error', error));
    process.nextTick(emit.bind(this, 'close'));
  }

  get handshakeComplete() {
    return this.#handshakeComplete;
  }

  get alpnProtocol() {
    return this.#alpn;
  }

  get cipher() {
    const name = this.#cipher;
    const version = this.#cipherVersion;
    return this.handshakeComplete ? { name, version } : {};
  }

  getCertificate() {
    return this[kHandle] ?
      translatePeerCertificate(this[kHandle].getCertificate() || {}) : {};
  }

  getPeerCertificate(detailed = false) {
    return this[kHandle] ?
      translatePeerCertificate(
        this[kHandle].getPeerCertificate(detailed) || {}) : {};
  }

  get servername() {
    return this.#servername;
  }

  get destroyed() {
    return this.#destroyed;
  }

  get closing() {
    return this.#closing;
  }

  get socket() {
    return this.#socket;
  }

  openStream(options) {
    if (this.#destroyed || this.#closing)
      throw new ERR_QUICSESSION_DESTROYED('openStream');
    const {
      halfOpen = false,
      highWaterMark,
    } = { ...options };
    if (halfOpen !== undefined && typeof halfOpen !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('options.halfOpen', 'boolean', halfOpen);

    const handle =
      halfOpen ?
        _openUnidirectionalStream(this[kHandle]) :
        _openBidirectionalStream(this[kHandle]);
    if (typeof handle === 'number') {
      // eslint-disable-next-line no-restricted-syntax
      throw new Error();
    }
    const id = handle.id();
    const stream = new QuicStream(
      {
        highWaterMark,
        readable: !halfOpen
      },
      this,
      id,
      handle);
    if (halfOpen) {
      stream.push(null);
      stream.read();
    }
    this.#streams.set(id, stream);
    return stream;
  }
}

class QuicServerSession extends QuicSession {
  constructor(socket, handle) {
    super(socket);
    this[kHandle] = handle;
    handle[owner_symbol] = this;
  }

  [kReady]() {
    process.nextTick(emit.bind(this, 'ready'));
  }
}

function setSocketAfterBind(socket, callback) {
  if (!this.readyToMigrate) {
    callback(new ERR_QUICSESSION_UNABLE_TO_MIGRATE());
    return;
  }

  if (socket.destroyed) {
    callback(new ERR_QUICSOCKET_DESTROYED('setSocket'));
    return;
  }

  const err = this[kHandle].setSocket(socket[kHandle]);
  if (err !== 0) {
    callback(new ERR_QUICCLIENTSESSION_FAILED_SETSOCKET(err));
    return;
  }

  if (this.socket) {
    this.socket[kRemoveSession](this);
    this[kSetSocket](undefined);
  }
  socket[kAddSession](this);
  this[kSetSocket](socket);

  callback();
}

class QuicClientSession extends QuicSession {
  #alpn = undefined;
  #handleReady = false;
  #ipv6Only = undefined;
  #minDHSize = undefined;
  #port = undefined;
  #secureContext = undefined;
  #socketReady = false;
  #transportParams = undefined;
  #sessionTicket = undefined;
  #remoteTransportParams = undefined;
  #dcid = undefined;
  #preferredAddressPolicy;

  constructor(socket, options) {
    const sc_options = {
      secureProtocol: 'TLSv1_3_client_method',
      rejectUnauthorized: !getAllowUnauthorized(),
      ...options
    };

    const {
      alpn,
      dcid,
      ipv6Only,
      maxCidLen,
      minCidLen,
      minDHSize,
      port,
      preferredAddressPolicy,
      remoteTransportParams,
      servername,
      sessionTicket,
    } = validateQuicClientSessionOptions(options);

    super(socket, servername);
    this.#alpn = alpn;
    this.#transportParams =
      validateTransportParams(
        options,
        maxCidLen,
        minCidLen);
    this.#ipv6Only = ipv6Only;
    this.#minDHSize = minDHSize;
    this.#port = port || 0;
    this.#secureContext = createSecureContext(sc_options,
                                              initSecureContextClient);
    this.#sessionTicket = sessionTicket;
    this.#remoteTransportParams = remoteTransportParams;
    this.#dcid = dcid;
    this.#preferredAddressPolicy = preferredAddressPolicy;
  }

  [kHandshakePost]() {
    const { type, size } = this.ephemeralKeyInfo;
    if (type === 'DH' && size < this.#minDHSize) {
      this.destroy(new ERR_TLS_DH_PARAM_SIZE(size));
      return false;
    }
    return true;
  }

  [kContinueConnect](type, ip) {
    const flags = this.#ipv6Only ? UV_UDP_IPV6ONLY : 0;
    setTransportParams(this.#transportParams);
    const handle =
      _createClientSession(
        this.socket[kHandle],
        type,
        ip,
        this.#port,
        flags,
        this.#secureContext.context,
        this.servername || ip,
        this.#remoteTransportParams,
        this.#sessionTicket,
        this.#dcid,
        this.#preferredAddressPolicy,
        this.#alpn);
    // We no longer need these, unset them so
    // memory can be garbage collected.
    this.#remoteTransportParams = undefined;
    this.#sessionTicket = undefined;
    this.#dcid = undefined;
    if (typeof handle === 'number') {
      let reason;
      switch (handle) {
        case ERR_INVALID_REMOTE_TRANSPORT_PARAMS:
          reason = 'Invalid Remote Transport Params';
          break;
        case ERR_INVALID_TLS_SESSION_TICKET:
          reason = 'Invalid TLS Session Ticket';
          break;
        default:
          reason = `${handle}`;
      }
      this.destroy(new ERR_QUICCLIENTSESSION_FAILED(reason));
      return;
    }
    this[kInit](handle);
  }

  [kInit](handle) {
    this[kHandle] = handle;
    handle[owner_symbol] = this;
    this.#handleReady = true;
    this[kMaybeReady]();
  }

  [kReady]() {
    this.#socketReady = true;
    this[kMaybeReady]();
  }

  [kMaybeReady]() {
    if (this.#socketReady && this.#handleReady)
      process.nextTick(emit.bind(this, 'ready'));
  }

  get ready() {
    return this.#handleReady && this.#socketReady;
  }

  get ephemeralKeyInfo() {
    return this[kHandle] !== undefined ?
      this[kHandle].getEphemeralKeyInfo() :
      undefined;
  }

  get readyToMigrate() {
    // A new QuicSession cannot be migrated until ngtcp2 has created a pool
    // of available connection IDs, which is done immediately after handshake.
    // Unfortunately, there's no signal provided by ngtcp2 that it is done
    // creating these so we have to keep track of how many connection IDs
    // have been generated. If there is more than one, then we can support
    // migrating to a new connection ID.
    if (!this.ready || this.destroyed || this.closing)
      return false;
    const { state } = this[kHandle];
    return state[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] > 0;
  }

  setSocket(socket, callback) {
    if (!(socket instanceof QuicSocket))
      throw new ERR_INVALID_ARG_TYPE('socket', 'QuicSocket', socket);

    if (typeof callback !== 'function')
      throw new ERR_INVALID_CALLBACK();

    socket[kMaybeBind](setSocketAfterBind.bind(this, socket, callback));
  }
}

function afterShutdown() {
  this.callback();
  const stream = this.handle[owner_symbol];
  if (stream)
    stream[kMaybeDestroy]();
}

class QuicStream extends Duplex {
  #didRead = false;
  #id = undefined;
  #session = undefined;

  constructor(options, session, id, handle) {
    super({
      ...options,
      allowHalfOpen: true,
      decodeStrings: true,
      emitClose: true,
      autoDestroy: true,
    });
    handle.onread = onStreamRead;
    handle[owner_symbol] = this;
    this[async_id_symbol] = handle.getAsyncId();
    this[kHandle] = handle;
    this.#id = id;
    this.#session = session;
  }

  get serverInitiated() {
    return this.#id & 0b01;
  }

  get clientInitiated() {
    return !this.serverInitiated;
  }

  get unidirectional() {
    return this.#id & 0b10;
  }

  get bidirectional() {
    return !this.unidirectional;
  }

  [kReset](finalSize, appErrorCode) {
    // End both the writable and readable sides of the duplex.
    // TODO(@jasnell): we should also cancel any buffered data
    // remaining within the duplex writable side queue.
    this.end();
    this.push(null);
    process.nextTick(emit.bind(this, 'reset', finalSize, appErrorCode));
    // TODO(@jasnell): Should we destroy here? It's not yet clear
    // what else should be done
  }

  [kAfterAsyncWrite]({ bytes }) {
    // TODO(@jasnell): Implement this
  }

  [kInspect]() {
    const direction = this.bidirectional ? 'bidirectional' : 'unidirectional';
    const initiated = this.serverInitiated ? 'server' : 'client';
    const obj = {
      id: this.#id,
      direction,
      initiated,
      writableState: this._writableState,
      readableState: this._readableState,
    };
    return `QuicStream ${util.format(obj)}`;
  }

  [kMaybeDestroy](code) {
    // TODO(@jasnell): Implement this
  }

  [kTrackWriteState](stream, bytes) {
    // TODO(@jasnell): Not yet sure what we want to do with these
    // this.#writeQueueSize += bytes;
    // this.#writeQueueSize += bytes;
    // this[kHandle].chunksSentSinceLastWrite = 0;
  }

  [kWriteGeneric](writev, data, encoding, cb) {
    if (this.destroyed)
      return;

    this[kUpdateTimer]();
    const req = (writev) ?
      writevGeneric(this, data, cb) :
      writeGeneric(this, data, encoding, cb);

    this[kTrackWriteState](this, req.bytes);
  }

  _write(data, encoding, cb) {
    this[kWriteGeneric](false, data, encoding, cb);
  }

  _writev(data, encoding, cb) {
    this[kWriteGeneric](true, data, '', cb);
  }

  _final(cb) {
    const handle = this[kHandle];
    if (handle === undefined) {
      cb();
      return;
    }

    const req = new ShutdownWrap();
    req.oncomplete = afterShutdown;
    req.callback = cb;
    req.handle = handle;
    const err = handle.shutdown(req);
    if (err === 1)
      return afterShutdown.call(req, 0);
  }

  _read(nread) {
    if (this.destroyed) {
      this.push(null);
      return;
    }
    if (!this.#didRead) {
      this._readableState.readingMore = false;
      this.#didRead = true;
    }
    this[kHandle].readStart();
  }

  get bufferSize() {
    // TODO(@jasnell): Implement this
    return undefined;
  }

  get id() {
    return this.#id;
  }

  get session() {
    return this.#session;
  }

  _destroy(error, callback) {
    this.#session[kRemoveStream](this);
    const handle = this[kHandle];
    if (handle !== undefined) {
      this[kHandle] = undefined;
      handle.destroy();
      handle[owner_symbol] = undefined;
    }
    callback(error);
  }

  _onTimeout() {
    // TODO(@jasnell): Implement this
  }

  [kUpdateTimer]() {
    // TODO(@jasnell): Implement this later
  }
}

function createSocket(options = {}) {
  if (options == null || typeof options !== 'object')
    throw new ERR_INVALID_ARG_TYPE('options', 'Object', options);
  return new QuicSocket(options);
}

module.exports = {
  createSocket
};

/* eslint-enable no-use-before-define */

// A single QuicSocket may act as both a Server and a Client.
// There are two kinds of sessions:
//   * QuicServerSession
//   * QuicClientSession
//
// It is important to understand that QUIC sessions are
// independent of the QuicSocket. A default configuration
// for QuicServerSession and QuicClientSessions may be
// set when the QuicSocket is created, but the actual
// configuration for a particular QuicSession instance is
// not set until the session itself is created.
//
// QuicSockets and QuicSession instances have distinct
// configuration options that apply independently:
//
// QuicSocket Options:
//   * `lookup` {Function} A function used to resolve DNS names.
//   * `type` {string} Either `'udp4'` or `'udp6'`, defaults to
//     `'udp4'`.
//   * `port` {number} The local IP port the QuicSocket will
//     bind to.
//   * `address` {string} The local IP address or hostname that
//     the QuicSocket will bind to. If a hostname is given, the
//     `lookup` function will be invoked to resolve an IP address.
//   * `ipv6Only`
//   * `reuseAddr`
//
// Keep in mind that while all QUIC network traffic is encrypted
// using TLS 1.3, every QuicSession maintains it's own SecureContext
// that is completely independent of the QuicSocket. Every
// QuicServerSession and QuicClientSession could, in theory,
// use a completely different TLS 1.3 configuration. To keep it
// simple, however, we use the same SecureContext for all QuicServerSession
// instances, but that may be something we want to revisit later.
//
// Every QuicSession has two sets of configuration parameters:
//   * Options
//   * Transport Parameters
//
// Options establish implementation specific operation parameters,
// such as the default highwatermark for new QuicStreams. Transport
// Parameters are QUIC specific and are passed to the peer as part
// of the TLS handshake.
//
// Every QuicSession may have separate options and transport
// parameters, even within the same QuicSocket, so the configuration
// must be established when the session is created.
//
// When creating a QuicSocket, it is possible to set a default
// configuration for both QuicServerSession and QuicClientSession
// options.
//
// const soc = createSocket({
//   type: 'udp4',
//   port: 0,
//   server: {
//     // QuicServerSession configuration defaults
//   },
//   client: {
//     // QuicClientSession configuration defaults
//   }
// });
//
// When calling listen() on the created QuicSocket, the server
// specific configuration that will be used for all new
// QuicServerSession instances will be given, with the values
// provided to createSocket() using the server option used
// as a default.
//
// When calling connect(), the client specific configuration
// will be given, with the values provided to the createSocket()
// using the client option used as a default.


// Some lifecycle documentation for the various objects:
//
// QuicSocket
//   Close
//     * Close all existing Sessions
//     * Do not allow any new Sessions (inbound or outbound)
//     * Destroy once there are no more sessions

//   Destroy
//     * Destroy all remaining sessions
//     * Destroy and free the QuicSocket handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicClientSession
//   Close
//     * Allow existing Streams to complete normally
//     * Do not allow any new Streams (inbound or outbound)
//     * Destroy once there are no more streams

//   Destroy
//     * Send CONNECTION_CLOSE
//     * Destroy all remaining Streams
//     * Remove Session from Parent Socket
//     * Destroy and free the QuicSession handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicServerSession
//   Close
//     * Allow existing Streams to complete normally
//     * Do not allow any new Streams (inbound or outbound)
//     * Destroy once there are no more streams
//   Destroy
//     * Send CONNECTION_CLOSE
//     * Destroy all remaining Streams
//     * Remove Session from Parent Socket
//     * Destroy and free the QuicSession handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicStream
//   Destroy
//     * Remove Stream From Parent Session
//     * Destroy and free the QuicStream handle immediately
//     * If Error, emit Error event
//     * Emit Close event
