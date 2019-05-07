'use strict';

/* eslint-disable no-use-before-define */

const {
  assertCrypto,
  customInspectSymbol: kInspect,
} = require('internal/util');

assertCrypto();

const util = require('util');
const { debuglog } = util;
const debug = debuglog('quic');
const assert = require('internal/assert');
const EventEmitter = require('events');
const { Duplex } = require('stream');
const { isArrayBufferView } = require('internal/util/types');
const {
  isIP,
  isLegalPort,
} = require('internal/net');
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
  kSession,
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
    ERR_OUT_OF_RANGE,
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
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI,
    IDX_QUIC_SESSION_MAX_DATA,
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI,
    IDX_QUIC_SESSION_MAX_STREAMS_UNI,
    IDX_QUIC_SESSION_IDLE_TIMEOUT,
    IDX_QUIC_SESSION_MAX_PACKET_SIZE,
    IDX_QUIC_SESSION_CONFIG_COUNT,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI_DEFAULT,
    IDX_QUIC_SESSION_MAX_DATA_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAMS_UNI_DEFAULT,
    IDX_QUIC_SESSION_IDLE_TIMEOUT_DEFAULT,
    IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT,
    IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT,
    ERR_INVALID_REMOTE_TRANSPORT_PARAMS,
    ERR_INVALID_TLS_SESSION_TICKET,
  }
} = internalBinding('quic');

const DEFAULT_QUIC_CIPHERS = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:' +
                             'TLS_CHACHA20_POLY1305_SHA256';
const DEFAULT_GROUPS = 'P-256:X25519:P-384:P-521';

const emit = EventEmitter.prototype.emit;

// Lazy load dns
let dns;

const kAddSession = Symbol('kAddSession');
const kID = Symbol('kID');
const kInit = Symbol('kInit');
const kMaybeBind = Symbol('kMaybeBind');
const kMaybeClose = Symbol('kMaybeClose');
const kMaybeReady = Symbol('kMaybeReady');
const kReady = Symbol('kReady');
const kReceiveStart = Symbol('kReceiveStart');
const kReceiveStop = Symbol('kReceiveStop');
const kRemoveSession = Symbol('kRemove');
const kState = Symbol('kState');
const kWriteGeneric = Symbol('kWriteGeneric');

const kSocketUnbound = 0;
const kSocketPending = 1;
const kSocketBound = 2;
const kSocketClosing = 3;
const kSocketDestroyed = 4;

function lazyDNS() {
  if (!dns)
    dns = require('dns');
  return dns;
}

function validateNumberInRange(val, name, range) {
  if (typeof val !== 'number')
    throw new ERR_INVALID_ARG_TYPE(name, 'number', val);
  if (val < 0)
    throw new ERR_OUT_OF_RANGE(name, range, val);
}

function validateSessionConfig(config = {}) {
  const {
    maxStreamDataBidiLocal =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL_DEFAULT,
    maxStreamDataBidiRemote =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE_DEFAULT,
    maxStreamDataUni =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI_DEFAULT,
    maxData =
    IDX_QUIC_SESSION_MAX_DATA_DEFAULT,
    maxStreamsBidi =
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI_DEFAULT,
    maxStreamsUni =
    IDX_QUIC_SESSION_MAX_STREAMS_UNI_DEFAULT,
    idleTimeout =
    IDX_QUIC_SESSION_IDLE_TIMEOUT_DEFAULT,
    maxPacketSize =
    IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT,
  } = { ...config };
  validateNumberInRange(
    maxStreamDataBidiLocal,
    'options.maxStreamDataBidiLocal',
    '>=0');
  validateNumberInRange(
    maxStreamDataBidiRemote,
    'options.maxStreamDataBidiRemote',
    '>=0');
  validateNumberInRange(
    maxStreamDataUni,
    'options.maxStreamDataUni',
    '>=0');
  validateNumberInRange(
    maxData,
    'options.maxData',
    '>=0');
  validateNumberInRange(
    maxStreamsBidi,
    'options.maxStreamdsBidi',
    '>=0');
  validateNumberInRange(
    maxStreamsUni,
    'options.maxStreamsUni',
    '>=0');
  validateNumberInRange(
    idleTimeout,
    'options.idleTimeout',
    '>=0');
  validateNumberInRange(
    maxPacketSize,
    'options.maxPacketSize',
    '>=0');
}

function setConfigField(val, index) {
  if (typeof val === 'number') {
    sessionConfig[index] = val;
    return 1 << index;
  }
  return 0;
}

function setSessionConfig(config = {}) {
  const {
    maxStreamDataBidiLocal =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL_DEFAULT,
    maxStreamDataBidiRemote =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE_DEFAULT,
    maxStreamDataUni =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI_DEFAULT,
    maxData =
    IDX_QUIC_SESSION_MAX_DATA_DEFAULT,
    maxStreamsBidi =
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI_DEFAULT,
    maxStreamsUni =
    IDX_QUIC_SESSION_MAX_STREAMS_UNI_DEFAULT,
    idleTimeout =
    IDX_QUIC_SESSION_IDLE_TIMEOUT_DEFAULT,
    maxPacketSize =
    IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT
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
                setConfigField(maxPacketSize, IDX_QUIC_SESSION_MAX_PACKET_SIZE);

  sessionConfig[IDX_QUIC_SESSION_CONFIG_COUNT] = flags;
}

// Called when the socket has been bound and is ready for use
function onSocketReady(fd) {
  const socket = this[owner_symbol];
  socket[kReady](fd);
}

// Called when the socket is closed
function onSocketClose() {
  const socket = this[owner_symbol];
  // Destroy the socket without any error to shut it down
  socket.destroy();
}

// Called when an error occurs on the socket
function onSocketError(err) {
  const socket = this[owner_symbol];
  socket.destroy(errnoException(err));
}

// Called when a new QuicSession is ready to use
function onSessionReady(sessionHandle) {
  debug('A new QUIC server session has been created');
  const socket = this[owner_symbol];
  const session = new QuicServerSession(socket, sessionHandle);
  process.nextTick(emit.bind(socket, 'session', session));
}

// Called when a QuicSession is closed
function onSessionClose(code) {
  debug('A QUIC session is being destroyed');
  const session = this[owner_symbol];
  session.destroy();
}

function onSessionHandshake(servername, alpn, cipher, cipherVersion) {
  debug('The session handshake is completed. ' +
        `Servername: ${servername}, ALPN Protocol: ${alpn}`);
  const session = this[owner_symbol];
  session[kState].handshakeComplete = true;
  session[kState].servername = servername;
  session[kState].alpn = alpn;
  session[kState].cipher = cipher;
  session[kState].cipherVersion = cipherVersion;

  const { minDHSize } = session[kState];
  if (session instanceof QuicClientSession && typeof minDHSize === 'number') {
    const ekeyinfo = session.ephemeralKeyInfo;
    if (ekeyinfo.type === 'DH' && ekeyinfo.size < minDHSize) {
      session.destroy(new ERR_TLS_DH_PARAM_SIZE(ekeyinfo.size));
      return;
    }
  }

  process.nextTick(emit.bind(session, 'secure',
                             servername, alpn,
                             session.cipher));
}

function onSessionTicket(sessionID, sessionTicket, transportParams) {
  const session = this[owner_symbol];
  process.nextTick(
    emit.bind(
      session,
      'sessionTicket',
      sessionID,
      sessionTicket,
      transportParams));
}

// Called when an error occurs in a QuicSession
function onSessionError(error) {
  const session = this[owner_symbol];
  session.destroy(error);
}

function onSessionExtend(bidi, maxStreams) {
  const session = this[owner_symbol];
  if (bidi) {
    session[kState].maxBidiStreams = maxStreams;
  } else {
    session[kState].maxUniStreams = maxStreams;
  }
  process.nextTick(emit.bind(session, 'extendMaxStreams'));
}

// Called when a new QuicStream is ready to use
function onStreamReady(streamHandle, id) {
  debug('A QUIC Server stream has been created');
  const session = this[owner_symbol];
  // TODO(@jasnell): Get default options from session
  const stream = new QuicStream({ /* options */ }, session, id, streamHandle);
  if (stream.serverInitiated && stream.unidirectional)
    stream.end();
  session[kState].streams.set(id, stream);
  process.nextTick(emit.bind(session, 'stream', stream));
}

// Called when a stream is closed
function onStreamClose() {
  const stream = this[owner_symbol];
  debug(`Closing QUIC Stream ${stream.id}`);
  stream.destroy();
}

// Called when an error occurs in a QuicStream
function onStreamError(streamHandle, error) {
  const stream = streamHandle[owner_symbol];
  stream.destroy(error);
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
  onSessionTicket,
  onStreamReady,
  onStreamClose,
  onStreamError,
});

function getSocketType(type) {
  switch (type) {
    case 'udp4': return AF_INET;
    case 'udp6': return AF_INET6;
  }
  throw new ERR_INVALID_ARG_VALUE('options.type', type);
}

function validateBindOptions(port, address) {
  if (port != null && typeof port !== 'number')
    throw new ERR_INVALID_ARG_TYPE('options.port', 'number', port);
  if (address != null && typeof address !== 'string')
    throw new ERR_INVALID_ARG_TYPE('options.address', 'string', address);
}

function lookup4(address, callback) {
  const { lookup } = lazyDNS();
  debug(`QuicSocket::bind::lookup4[${address}]`);
  lookup(address || '127.0.0.1', 4, callback);
}

function lookup6(address, callback) {
  const { lookup } = lazyDNS();
  debug(`QuicSocket::bind::lookup6[${address}]`);
  lookup(address || '::1', 6, callback);
}

// The fourth argument is err here because we are calling a bound
// copy of afterLookup where the type and port arguments
// are pre-set.
function afterLookup(type, port, callback, err, ip) {
  debug(`QuicSocket::bind::afterLookup[${port}, ${ip}]`);
  if (err) {
    this.destroy(err);
    return;
  }
  // TODO(@jasnell): Check if the handle is still valid. Socket destroyed?
  // or Closing?
  let flags = 0;
  if (this[kState].reuseAddr)
    flags |= UV_UDP_REUSEADDR;
  if (this[kState].ipv6Only)
    flags |= UV_UDP_IPV6ONLY;

  const ret = this[kHandle].bind(type, ip, port || 0, flags);
  // TODO(@jasnell): QUIC specific error below
  if (ret) {
    debug(`QuicSocket::bind::afterLookup[error: ${ret}]`);
    this.destroy(exceptionWithHostPort(ret, 'bind', ip, port || 0));
  }

  if (typeof callback === 'function')
    callback();
}

function connectAfterLookup(
  session,
  type,
  port,
  ipv6Only,
  remoteTransportParams,
  sessionTicket,
  err, ip) {
  debug(`QuicSocket::bind::connectAfterLookup[${port}, ${ip}]`);
  if (err) {
    session.destroy(err);
    return;
  }

  const {
    clientSecureContext,
    servername
  } = session[kState];

  let flags = 0;
  if (ipv6Only)
    flags |= UV_UDP_IPV6ONLY;
  setSessionConfig(session[kState].sessionConfig);
  const handle =
    _createClientSession(
      this,
      type,
      ip,
      port || 0,
      flags,
      clientSecureContext.context,
      servername || ip,
      remoteTransportParams,
      sessionTicket);
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
    session.destroy(new ERR_QUICCLIENTSESSION_FAILED(reason));
    return;
  }
  session[kInit](handle);
}

// QuicSocket wraps a UDP socket plus the associated TLS context and QUIC
// Protocol state. There may be *multiple* QUIC connections (QuicSession)
// associated with a single QuicSocket.
class QuicSocket extends EventEmitter {

  // Events:
  // * session -- emitted when a new server session is established
  // * ready -- emitted when the socket is ready for use
  // * close -- emitted when the socket is closed (after any associated sessions
  //            are closed)
  // * error -- emitted when an error occurs

  constructor(options = {}) {
    const {
      lookup,
      type = 'udp4',
      port = 0,
      address,
      ipv6Only = false,
      reuseAddr = false
    } = options || {};
    if (typeof type !== 'string')
      throw new ERR_INVALID_ARG_TYPE('options.type', 'string', type);
    if (lookup && typeof lookup !== 'function')
      throw new ERR_INVALID_ARG_TYPE('options.lookup', 'Function', lookup);
    validateBindOptions(port, address);
    debug(`QuicSocket::constructor[${type} ${port} ${address}]`);
    super();
    const typeVal = getSocketType(type);
    const handle = this[kHandle] = new QuicSocketHandle({ type: typeVal });
    handle[owner_symbol] = this;
    this[async_id_symbol] = handle.getAsyncId();
    this[kState] = {
      fd: UV_EBADF,
      port,
      address: address || (typeVal === AF_INET6 ? '::' : '0.0.0.0'),
      reuseAddr: !!reuseAddr,
      ipv6Only: !!ipv6Only,
      destroyed: false,
      state: kSocketUnbound,
      type: typeVal,
      lookup: lookup || (typeVal === AF_INET6 ? lookup6 : lookup4),
      serverListening: false,
      serverSecureContext: undefined,
      sessionConfig: undefined,
      sessions: new Set()
    };
  }

  [kAddSession](session) {
    this[kState].sessions.add(session);
    session[kState].socket = this;
  }

  [kRemoveSession](session) {
    this[kState].sessions.delete(session);
    session[kState].socket = undefined;
  }

  // Bind the UDP socket on demand, only if it hasn't already been bound.
  // Function is a non-op if the socket is already bound
  [kMaybeBind](callback = () => {}) {
    const {
      state,
      type = 'udp4',
      lookup,
      port = 0,
      address,
    } = this[kState];
    debug(`QuicSocket::kMaybeBind[${state}]`);
    if (state !== kSocketUnbound)
      return;

    // This socket will be in a pending state until it is bound. Once bound,
    // the this[kReady]() method will be called, switching the state to
    // kSocketBound and notifying the associated sessions
    this[kState].state = kSocketPending;
    const doAfterLookup = afterLookup.bind(this, type, port, callback);
    lookup(address, doAfterLookup);
  }

  // Close is a graceful shutdown...a QuicSocket should only close if all
  // of it's sessions have closed. When those close, they will
  // remove themselves from the sockets list.
  [kMaybeClose]() {
    const { state, sessions } = this[kState];
    debug(`Maybe close socket? size: ${sessions.size}, state: ${state}`);
    if (sessions.size === 0) {
      const doClose = () => {
        debug('Closing QuicSocket');
        this[kReceiveStop]();
        this[kHandle].close();
        this[kState].state = kSocketUnbound;
      };
      if (state === kSocketPending) {
        // TODO(jasnell): Decide if we really want to wait or interrupt
        debug('Deferring close until socket is ready');
        this.on('ready', doClose);
        return;
      }
      doClose();
    }
  }

  // The kReady function is called after the socket has been bound to the
  // local port. It signals when the various sessions may begin
  // doing their various things they do.
  [kReady](fd) {
    const { sessions } = this[kState];
    this[kState].state = kSocketBound;
    this[kState].fd = fd;
    for (const session of sessions)
      session[kReady]();
    debug(`QuicSocket is bound to FD ${fd} and ready for use`);
    process.nextTick(emit.bind(this, 'ready'));
  }

  // A socket should only be put into the receiving state if there is a
  // listening server or an active client. This will be called on demand
  // when needed.
  [kReceiveStart]() {
    // TODO(jasnell): Proper error handling here
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('kReceiveStart');
    this[kHandle].receiveStart();
  }

  // The socket should be moved to a not receiving state if there is no
  // listening server and no active sessions. This will be called on demand
  // when needed.
  [kReceiveStop]() {
    // TODO(jasnell): Proper error handling here
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('kReceiveStop');
    this[kHandle].receiveStop();
  }

  listen(options = {}, callback) {
    if (this[kState].serverListening)
      throw new ERR_QUICSOCKET_LISTENING();
    switch (this[kState].state) {
      case kSocketDestroyed:
        throw new ERR_QUICSOCKET_DESTROYED('createServer');
      case kSocketClosing:
        throw new ERR_QUICSOCKET_CLOSING('createServer');
      default:
        // Fall-through
    }

    this[kMaybeBind]();

    options = {
      secureProtocol: 'TLSv1_3_server_method',
      ...options
    };

    // Store the secure context on the state object so
    // that it is not garbage collected while we still
    // need to make use of it.
    const sc =
      this[kState].serverSecureContext =
        createSecureContext(options, initSecureContext);

    const {
      maxStreamDataBidiLocal,
      maxStreamDataBidiRemote,
      maxStreamDataUni,
      maxData,
      maxStreamsBidi,
      maxStreamsUni,
      idleTimeout,
      maxPacketSize,
      preferredAddress
    } = options;
    this[kState].sessionConfig = {
      maxStreamDataBidiLocal,
      maxStreamDataBidiRemote,
      maxStreamDataUni,
      maxData,
      maxStreamsBidi,
      maxStreamsUni,
      idleTimeout,
      maxPacketSize,
      preferredAddress
    };
    validateSessionConfig(this[kState].sessionConfig);

    this[kState].serverListening = true;
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('session', callback);
    }

    const doListen = () => {
      const {
        preferredAddress
      } = this[kState].sessionConfig;

      const doFinalListen = (preferredAddress = {}) => {
        const {
          address,
          port,
          type = 'udp4'
        } = preferredAddress;
        setSessionConfig(this[kState].sessionConfig);
        this[kHandle].listen(sc.context, address, type, port);
        process.nextTick(emit.bind(this, 'listening'));
      };

      if (preferredAddress && typeof preferredAddress === 'object') {
        // If preferred address is set, we need to perform a lookup on it
        // to get the IP address. Only after that lookup completes can we
        // continue with the listen operation, passing in the resolved
        // preferred address.
        const { address, port, type = 'udp4' } = preferredAddress;
        const { lookup } = this[kState];
        const typeVal = getSocketType(type);
        lookup(
          address || (typeVal === AF_INET6 ? '::' : '0.0.0.0'),
          (err, address) => {
            if (err) {
              // TODO(@jasnell): More descriptive error
              this.destroy(err);
              return;
            }
            doFinalListen({ address, port, type: typeVal });
          });
      } else {
        // If preferred address is not set, we can skip directly
        // to the listen
        doFinalListen();
      }
    };

    if (this[kState].state === kSocketPending) {
      this.on('ready', doListen);
      return;
    }
    doListen();
  }

  connect(options, callback) {
    const {
      state,
      lookup,
    } = this[kState];

    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    options = { ...options };

    const {
      type = 'udp4',
      address,
      port = 0,
      ipv6Only = false,
      // Passed only if the user is resuming an existing session
      remoteTransportParams,
      sessionTicket,
    } = options;

    if (!isLegalPort(port)) {
      throw new ERR_INVALID_ARG_VALUE(
        'options.port', port,
        'is not a valid IP port');
    }
    // Set the sername to the address if servername is
    // not already explicitly set.
    options.servername = options.servername || address;

    const typeVal = getSocketType(type);

    switch (state) {
      case kSocketDestroyed:
        throw new ERR_QUICSOCKET_DESTROYED('connect');
      case kSocketClosing:
        throw new ERR_QUICSOCKET_CLOSING('connect');
      default:
        // Fall-through
    }

    if (remoteTransportParams && !isArrayBufferView(remoteTransportParams)) {
      throw new ERR_INVALID_ARG_TYPE(
        'options.remoteTransportParams',
        ['Buffer', 'TypedArray', 'DataView'],
        remoteTransportParams);
    }
    if (sessionTicket && !isArrayBufferView(sessionTicket)) {
      throw new ERR_INVALID_ARG_TYPE(
        'options.sessionTicket',
        ['Buffer', 'TypedArray', 'DataView'],
        sessionTicket);
    }

    const session = new QuicClientSession(this, options);
    this[kAddSession](session);

    if (typeof callback === 'function')
      session.on('ready', callback);

    this[kMaybeBind](() => {
      const doAfterLookup =
        connectAfterLookup.bind(
          this[kHandle],
          session,
          typeVal,
          port,
          ipv6Only,
          remoteTransportParams,
          sessionTicket);
      lookup(address ||
             (typeVal === AF_INET6 ? '::' : '0.0.0.0'), doAfterLookup);
    });

    return session;
  }

  close(callback) {
    switch (this[kState].state) {
      case kSocketUnbound:
      case kSocketDestroyed:
      case kSocketClosing:
        return;
      default:
        // Fall-through
    }

    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }

    this[kState].state = kSocketClosing;
    const { sessions } = this[kState];

    if (sessions.size === 0) {
      this[kMaybeClose]();
      return;
    }

    const maybeClose = this[kMaybeClose].bind(this);
    for (const session of sessions)
      session.close(maybeClose);
  }

  destroy(error) {
    if (this.destroyed)
      return;
    debug(`QuicSocket::destroy[${error}]`);
    this.close(() => {
      const { sessions } = this[kState];
      for (const session of sessions)
        session.destroy(error);

      const handle = this[kHandle];
      this[kHandle] = undefined;
      this[kState].state = kSocketDestroyed;
      handle[owner_symbol] = undefined;
      handle.destroy();

      if (error) process.nextTick(emit.bind(this, 'error', error));
      process.nextTick(emit.bind(this, 'close'));
    });
  }

  ref() {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('ref');
    this[kHandle].ref();
    return this;
  }

  unref() {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('unref');
    this[kHandle].unref();
    return this;
  }

  get address() {
    if (this.destroyed)
      return undefined;
    const out = {};
    const err = this[kHandle].getsockname(out);
    if (err)
      throw errnoException(err, 'address');
    return out;
  }

  get bound() {
    return this[kState].state === kSocketBound;
  }

  get pending() {
    return this[kState].state === kSocketPending;
  }

  get destroyed() {
    return this[kState].state === kSocketDestroyed;
  }

  get fd() {
    return this[kState].fd;
  }

  setTTL(ttl) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setTTL');
    if (typeof ttl !== 'number')
      throw new ERR_INVALID_ARG_TYPE('ttl', 'number', ttl);
    if (ttl < 1 || ttl > 255)
      throw new ERR_INVALID_ARG_VALUE('ttl', ttl);
    const err = this[kHandle].setTTL(ttl);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setMulticastTTL(ttl) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastTTL');
    if (typeof ttl !== 'number')
      throw new ERR_INVALID_ARG_TYPE('ttl', 'number', ttl);
    if (ttl < 1 || ttl > 255)
      throw new ERR_INVALID_ARG_VALUE('ttl', ttl);
    const err = this[kHandle].setMulticastTTL(ttl);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setBroadcast(on = true) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setBroadcast');
    if (typeof on !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('on', 'boolean', on);
    const err = this[kHandle].setBroadcast(on);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setMulticastLoopback(on = true) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastLoopback');
    if (typeof on !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('on', 'boolean', on);
    const err = this[kHandle].setMulticastLoopback(on);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setMulticastInterface(iface) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastInterface');
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].setMulticastInterface(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  addMembership(address, iface) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('addMembership');
    if (typeof address !== 'string')
      throw new ERR_INVALID_ARG_TYPE('address', 'string', address);
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].addMembership(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  dropMembership(address, iface) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('dropMembership');
    if (typeof address !== 'string')
      throw new ERR_INVALID_ARG_TYPE('address', 'string', address);
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].dropMembership(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
  }
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
  } = options;

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

class QuicSession extends EventEmitter {
  // Events:
  // * stream -- New Stream was Created
  // * error -- Error occurred
  // * ready -- Session is ready for use
  // * close -- Server is closed
  constructor(socket, initialState = {}) {
    super();
    this[kState] = {
      socket,
      destroyed: false,
      maxBidiStreams: 10,  // TODO(@jasnell): Set to the actual initial value
      maxUniStreams: 10,   // TODO(@jasnell): Set to the actual initial value
      streams: new Map(),
      handshakeComplete: false,
      alpn: undefined,
      servername: undefined,
      cipher: undefined,
      cipherVersion: undefined,
      ...initialState
    };
  }

  close(callback) {
    if (this[kState].destroyed)
      throw new ERR_QUICSESSION_DESTROYED('close');
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }
    // TODO(@jasnell): Implement proper graceful shutdown
    this.destroy();
  }

  destroy(error) {
    if (this[kState].destroyed)
      return;
    this[kState].destroyed = true;

    debug('Destroying streams...');
    for (const stream of this[kState].streams.values())
      stream.destroy();

    const handle = this[kHandle];
    if (handle !== undefined) {
      handle[owner_symbol] = undefined;
      this[kHandle] = undefined;
      handle.destroy();
    }

    this[kState].socket[kRemoveSession](this);

    if (error) process.nextTick(emit.bind(this, 'error', error));
    process.nextTick(emit.bind(this, 'close'));
  }

  get handshakeComplete() {
    return this[kState].handshakeComplete;
  }

  get alpnProtocol() {
    return this[kState].alpn;
  }

  get cipher() {
    const name = this[kState].cipher;
    const version = this[kState].cipherVersion;
    return { name, version };
  }

  getCertificate() {
    if (this[kHandle] !== undefined) {
      return translatePeerCertificate(
        this[kHandle].getCertificate() || {});
    }
  }

  getPeerCertificate(detailed = false) {
    if (this[kHandle] !== undefined) {
      return translatePeerCertificate(
        this[kHandle].getPeerCertificate(detailed) || {});
    }
  }

  get servername() {
    return this[kState].servername;
  }

  get destroyed() {
    return this[kState].destroyed;
  }

  get socket() {
    return this[kState].socket;
  }

  openStream(options = {}) {
    const {
      destroyed,
      streams
    } = this[kState];
    if (destroyed)
      throw new ERR_QUICSESSION_DESTROYED('close');
    const {
      halfOpen = false,
      highWaterMark,
    } = options || {};
    if (halfOpen !== undefined && typeof halfOpen !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('options.halfOpen', 'boolean', halfOpen);

    const handle = halfOpen ? _openUnidirectionalStream(this[kHandle]) :
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
    streams.set(id, stream);
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

let warnOnAllowUnauthorized = true;

class QuicClientSession extends QuicSession {
  constructor(socket, options) {
    const allowUnauthorized = process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0';

    if (allowUnauthorized && warnOnAllowUnauthorized) {
      warnOnAllowUnauthorized = false;
      process.emitWarning(
        'Setting the NODE_TLS_REJECT_UNAUTHORIZED ' +
        'environment variable to \'0\' makes TLS connections ' +
        'and HTTPS requests insecure by disabling ' +
        'certificate verification.');
    }

    const sc_options = {
      secureProtocol: 'TLSv1_3_client_method',
      rejectUnauthorized: !allowUnauthorized,
      ...options
    };

    const {
      maxStreamDataBidiLocal,
      maxStreamDataBidiRemote,
      maxStreamDataUni,
      maxData,
      maxStreamsBidi,
      maxStreamsUni,
      idleTimeout,
      maxPacketSize,
      servername,
      minDHSize = 1024
    } = options;
    const sessionConfig = {
      maxStreamDataBidiLocal,
      maxStreamDataBidiRemote,
      maxStreamDataUni,
      maxData,
      maxStreamsBidi,
      maxStreamsUni,
      idleTimeout,
      maxPacketSize,
    };
    validateSessionConfig(sessionConfig);
    if (servername && typeof servername !== 'string') {
      throw new ERR_INVALID_ARG_TYPE(
        'options.servername', 'string', servername);
    }
    if (isIP(servername)) {
      throw new ERR_INVALID_ARG_VALUE(
        'options.servername', servername, 'cannot be an IP address');
    }

    super(socket, {
      clientSecureContext:
        createSecureContext(sc_options, initSecureContextClient),
      handleReady: false,
      minDHSize,
      socketReady: false,
      servername,
      sessionConfig,
    });
  }

  [kInit](handle) {
    this[kHandle] = handle;
    handle[owner_symbol] = this;
    this[kState].handleReady = true;
    this[kMaybeReady]();
  }

  [kReady]() {
    this[kState].socketReady = true;
    this[kMaybeReady]();
  }

  [kMaybeReady]() {
    if (this[kState].socketReady && this[kState].handleReady)
      process.nextTick(emit.bind(this, 'ready'));
  }

  get ready() {
    const {
      handleReady,
      socketReady
    } = this[kState];
    return handleReady && socketReady;
  }

  get ephemeralKeyInfo() {
    return this[kHandle] !== undefined ?
      this[kHandle].getEphemeralKeyInfo() :
      undefined;
  }

  get readyToMigrate() {
    if (!this.ready || this.destroyed)
      return false;
    const { state } = this[kHandle];
    return state[IDX_QUIC_SESSION_STATE_CONNECTION_ID_COUNT] > 0;
  }

  setSocket(socket, callback) {
    if (!(socket instanceof QuicSocket))
      throw new ERR_INVALID_ARG_TYPE('socket', 'QuicSocket', socket);
    if (typeof callback !== 'function')
      throw new ERR_INVALID_CALLBACK();

    if (!this.readyToMigrate)
      throw new ERR_QUICSESSION_UNABLE_TO_MIGRATE();

    if (socket.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setSocket');

    socket[kMaybeBind](() => {
      // We have to check the error conditiions again
      if (this.destroyed) {
        callback(new ERR_QUICSESSION_DESTROYED('setSocket'));
        return;
      }
      if (socket.destroyed) {
        callback(new ERR_QUICSOCKET_DESTROYED('setSocket'));
        return;
      }
      if (!this.readyToMigrate) {
        throw new ERR_QUICSESSION_UNABLE_TO_MIGRATE();
      }
      if (this[kState].socket)
        this[kState].socket[kRemoveSession](this);
      socket[kAddSession](this);

      const err = this[kHandle].setSocket(socket[kHandle]);
      if (err !== 0) {
        callback(new ERR_QUICCLIENTSESSION_FAILED_SETSOCKET(err));
        return;
      }

      callback();
    });
  }
}

function afterShutdown() {
  this.callback();
  const stream = this.handle[owner_symbol];
  if (stream)
    stream[kMaybeDestroy]();
}

function trackWriteState(stream, bytes) {
  // TODO(@jasnell): Not yet sure what we want to do with these
  // const session = stream[kSession];
  // stream[kState].writeQueueSize += bytes;
  // session[kState].writeQueueSize += bytes;
  // session[kHandle].chunksSentSinceLastWrite = 0;
}

class QuicStream extends Duplex {
  constructor(options, session, id, handle) {
    assert(options !== undefined);
    assert(session !== undefined);
    assert(id !== undefined);
    assert(handle !== undefined);
    options.allowHalfOpen = true;
    options.decodeStrings = false;
    options.emitClose = true;
    super(options);
    handle.onread = onStreamRead;
    this[async_id_symbol] = handle.getAsyncId();
    this[kHandle] = handle;
    this[kID] = id;
    this[kSession] = session;
    handle[owner_symbol] = this;
    this._readableState.readingMore = true;
    this[kState] = {};
  }

  get serverInitiated() {
    return this[kID] & 0b01;
  }

  get clientInitiated() {
    return !this.serverInitiated;
  }

  get unidirectional() {
    return this[kID] & 0b10;
  }

  get bidirectional() {
    return !this.unidirectional();
  }

  [kAfterAsyncWrite]({ bytes }) {
    // TODO(@jasnell): Implement this
  }

  [kInspect]() {
    const obj = {
      id: this[kID]
    };
    return `QuicStream ${util.format(obj)}`;
  }

  [kMaybeDestroy](code) {
    // TODO(@jasnell): Implement this
  }

  [kWriteGeneric](writev, data, encoding, cb) {
    if (this.destroyed)
      return;

    this[kUpdateTimer]();
    const req = (writev) ?
      writevGeneric(this, data, cb) :
      writeGeneric(this, data, encoding, cb);

    trackWriteState(this, req.bytes);
  }

  _write(data, encoding, cb) {
    this[kWriteGeneric](false, data, encoding, cb);
  }

  _writev(data, encoding, cb) {
    this[kWriteGeneric](true, data, '', cb);
  }

  _final(cb) {
    debug(`QuicStream ${this[kID]} _final shutting down`);
    const handle = this[kHandle];
    if (handle !== undefined) {
      const req = new ShutdownWrap();
      req.oncomplete = afterShutdown;
      req.callback = cb;
      req.handle = handle;
      const err = handle.shutdown(req);
      if (err === 1)
        return afterShutdown.call(req, 0);
    } else {
      cb();
    }
  }

  _read(nread) {
    if (this.destroyed) {
      this.push(null);
      return;
    }
    if (!this[kState].didRead) {
      this._readableState.readingMore = false;
      this[kState].didRead = true;
    }
    this[kHandle].readStart();
  }

  get bufferSize() {
    // TODO(@jasnell): Implement this
    return undefined;
  }

  get id() {
    return this[kID];
  }

  get session() {
    return this[kSession];
  }

  _onTimeout() {
    // TODO(@jasnell): Implement this
  }

  _destroy(error, callback) {
    debug(`Destroying stream ${this[kID]}`);
    this[kSession][kState].streams.delete(this[kID]);
    const handle = this[kHandle];
    this[kHandle] = undefined;
    handle.destroy();
    handle[owner_symbol] = undefined;
    callback(error);
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
