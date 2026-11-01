// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.netstack.TcpSegment.ACK;
import static com.skanavi.javaguard.netstack.TcpSegment.FIN;
import static com.skanavi.javaguard.netstack.TcpSegment.PSH;
import static com.skanavi.javaguard.netstack.TcpSegment.RST;
import static com.skanavi.javaguard.netstack.TcpSegment.SYN;
import static com.skanavi.javaguard.netstack.TcpSegment.le;
import static com.skanavi.javaguard.netstack.TcpSegment.lt;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * One TCP connection (RFC 9293): the state machine, send and receive buffers, retransmission with
 * RFC 6298 timers, NewReno congestion control (RFC 5681, RFC 6582), window scaling (RFC 7323),
 * zero-window probing, and RFC 5961 protection against blind RST and SYN injection.
 *
 * <p>Inbound segments, application calls and timers all run under one lock; outgoing packets are
 * only queued while it is held. Delayed ACKs, SACK, timestamps and keepalives are not implemented.
 */
final class TcpConnection {
  enum State {
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED
  }

  static final int BUFFER_SIZE = 256 * 1024;
  private static final int WINDOW_SCALE = 3; // 256 KiB >> 3 fits the 16-bit window field
  private static final int SYN_RETRIES = 6;
  private static final int DATA_RETRIES = 15;
  private static final long INITIAL_RTO = TimeUnit.SECONDS.toNanos(1);
  private static final long MAX_RTO = TimeUnit.SECONDS.toNanos(60);
  private static final long FIN_WAIT_2_TIMEOUT = TimeUnit.SECONDS.toNanos(60);
  private static final int MAX_OUT_OF_ORDER_SEGMENTS = 512;
  private static final int MAX_CWND = 64 * 1024 * 1024;

  private record Pending(int seq, byte[] data) {}

  final Netstack stack;
  final TcpKey key;
  private final byte[] localIp;
  private final byte[] remoteIp;
  private final TcpListener listener;
  private final ReentrantLock lock = new ReentrantLock();
  private final Condition changed = lock.newCondition();

  private State state;
  private IOException error;
  private boolean peerOfferedWindowScale;

  // Send side.
  private final ByteRing sendBuffer = new ByteRing(BUFFER_SIZE);
  private final int iss;
  private int sndUna;
  private int sndNxt;
  private int sndMax; // highest sequence number sent so far; sndNxt rewinds below it on timeout
  private int sndWnd;
  private int sndWl1;
  private int sndWl2;
  private int sndWindowScale;
  private int sndMss;
  private final int ourMss;
  private boolean finPending;
  private boolean finSent;
  private int finSeq;
  private boolean outputShutdown;

  // Congestion control.
  private int cwnd;
  private int ssthresh = Integer.MAX_VALUE;
  private int dupAcks;
  private boolean inRecovery;
  private int recover;

  // Round-trip estimation.
  private long srtt = -1;
  private long rttvar;
  private long rto = INITIAL_RTO;
  private boolean rttTiming;
  private int rttSeq;
  private long rttStart;
  private int retries;
  private long persistBackoff;

  // Receive side.
  private final ByteRing receiveBuffer = new ByteRing(BUFFER_SIZE);
  private int rcvNxt;
  private int rcvWindowScale;
  private int lastAdvertised;
  private final List<Pending> outOfOrder = new ArrayList<>();
  private boolean pendingFin;
  private int pendingFinSeq;
  private boolean eof;
  private boolean inputClosed;

  private final TcpTimer retransmitTimer;
  private final TcpTimer persistTimer;
  private final TcpTimer lingerTimer;

  /** Creates an actively opening connection; call {@link #connect(long)}. */
  TcpConnection(Netstack stack, TcpKey key) {
    this(stack, key, null, State.SYN_SENT);
  }

  /** Creates a passively opened connection answering {@code syn}; sends the SYN-ACK. */
  static TcpConnection accept(Netstack stack, TcpKey key, TcpListener listener, TcpSegment syn) {
    TcpConnection c = new TcpConnection(stack, key, listener, State.SYN_RECEIVED);
    c.lock.lock();
    try {
      c.rcvNxt = syn.seq() + 1;
      c.sndWnd = syn.window();
      c.negotiate(syn);
      c.transmit(c.iss, SYN | ACK, null, 0, 0);
      c.retransmitTimer.start(c.rto);
    } finally {
      c.lock.unlock();
    }
    return c;
  }

  private TcpConnection(Netstack stack, TcpKey key, TcpListener listener, State initial) {
    this.stack = stack;
    this.key = key;
    this.localIp = key.localAddress().getAddress();
    this.remoteIp = key.remoteAddress().getAddress();
    this.listener = listener;
    this.state = initial;
    this.iss = stack.randomInt();
    this.sndUna = iss;
    this.sndNxt = iss + 1;
    this.sndMax = sndNxt;
    this.ourMss =
        stack.mtu() - IpPacket.headerLength(localIp.length == 4 ? 4 : 6) - TcpSegment.HEADER;
    this.sndMss = localIp.length == 4 ? 536 : 1220; // RFC 9293 default until the peer says more
    this.cwnd = 10 * sndMss;
    this.retransmitTimer = new TcpTimer(stack.scheduler(), this::onRetransmitTimeout);
    this.persistTimer = new TcpTimer(stack.scheduler(), this::onPersistTimeout);
    this.lingerTimer = new TcpTimer(stack.scheduler(), this::onLingerTimeout);
  }

  // ---------------------------------------------------------------- application side

  /** Sends the SYN and waits for the handshake. */
  void connect(long timeoutNanos) throws IOException {
    lock.lock();
    try {
      transmit(iss, SYN, null, 0, 0);
      retransmitTimer.start(rto);
      long left = timeoutNanos;
      while (state == State.SYN_SENT && error == null) {
        if (left <= 0) {
          enterClosed(new SocketTimeoutException("connect timed out"));
          break;
        }
        left = changed.awaitNanos(left);
      }
      if (error != null) {
        throw error;
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      enterClosed(new SocketException("connect interrupted"));
      throw error;
    } finally {
      lock.unlock();
    }
  }

  /** Reads into {@code b}; -1 at end of stream; throws on reset or timeout. */
  int read(byte[] b, int off, int len, long timeoutNanos) throws IOException {
    if (len == 0) {
      return 0;
    }
    lock.lock();
    try {
      long left = timeoutNanos;
      while (receiveBuffer.size() == 0 && !eof && error == null && !inputClosed) {
        if (timeoutNanos > 0) {
          if (left <= 0) {
            throw new SocketTimeoutException("read timed out");
          }
          left = changed.awaitNanos(left);
        } else {
          changed.await();
        }
      }
      if (inputClosed) {
        throw new SocketException("socket closed");
      }
      if (receiveBuffer.size() == 0) {
        if (error != null) {
          throw error;
        }
        return -1;
      }
      int n = receiveBuffer.read(b, off, len);
      maybeSendWindowUpdate();
      return n;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SocketException("read interrupted");
    } finally {
      lock.unlock();
    }
  }

  /** Bytes readable without blocking. */
  int available() {
    lock.lock();
    try {
      return receiveBuffer.size();
    } finally {
      lock.unlock();
    }
  }

  /** Queues all of {@code b[off..off+len)} for sending, blocking while the send buffer is full. */
  void write(byte[] b, int off, int len) throws IOException {
    lock.lock();
    try {
      while (len > 0) {
        checkWritable();
        int n = sendBuffer.write(b, off, len);
        if (n == 0) {
          changed.await();
          continue;
        }
        off += n;
        len -= n;
        output();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SocketException("write interrupted");
    } finally {
      lock.unlock();
    }
  }

  private void checkWritable() throws IOException {
    if (error != null) {
      throw error;
    }
    if (outputShutdown) {
      throw new SocketException("output is shut down");
    }
    if (state != State.ESTABLISHED && state != State.CLOSE_WAIT) {
      throw new SocketException("connection is " + state);
    }
  }

  /** Sends FIN once queued data is out. Further writes fail. */
  void shutdownOutput() {
    lock.lock();
    try {
      if (!outputShutdown) {
        outputShutdown = true;
        finPending = true;
        output();
        changed.signalAll();
      }
    } finally {
      lock.unlock();
    }
  }

  /**
   * Closes both directions. Unread received data turns this into an abort (RST), as in common
   * stacks; otherwise the connection finishes gracefully in the background.
   */
  void close() {
    lock.lock();
    try {
      if (inputClosed) {
        return;
      }
      inputClosed = true;
      if (receiveBuffer.size() > 0 || state == State.SYN_SENT || state == State.SYN_RECEIVED) {
        abortLocked(new SocketException("socket closed"));
        return;
      }
      shutdownOutput();
      if (state == State.FIN_WAIT_2) {
        lingerTimer.start(FIN_WAIT_2_TIMEOUT);
      }
      changed.signalAll();
    } finally {
      lock.unlock();
    }
  }

  /** Resets the connection immediately. */
  void abort() {
    lock.lock();
    try {
      inputClosed = true;
      abortLocked(new SocketException("connection aborted"));
    } finally {
      lock.unlock();
    }
  }

  private void abortLocked(IOException reason) {
    if (state != State.CLOSED && state != State.TIME_WAIT && state != State.SYN_SENT) {
      transmit(sndNxt, RST | ACK, null, 0, 0);
    }
    enterClosed(reason);
  }

  /** A snapshot of the connection's variables, for diagnostics. */
  @Override
  public String toString() {
    if (!lock.tryLock()) {
      return "TcpConnection[" + key + ", locked]";
    }
    try {
      return "TcpConnection["
          + key.localPort()
          + "->"
          + key.remotePort()
          + " "
          + state
          + " una="
          + (sndUna - iss)
          + " nxt="
          + (sndNxt - iss)
          + " max="
          + (sndMax - iss)
          + " sndBuf="
          + sendBuffer.size()
          + " wnd="
          + sndWnd
          + " cwnd="
          + cwnd
          + " ssthresh="
          + ssthresh
          + " rto="
          + rto / 1_000_000
          + "ms retries="
          + retries
          + " recovery="
          + inRecovery
          + " rtx="
          + retransmitTimer.isPending()
          + " persist="
          + persistTimer.isPending()
          + " rcvBuf="
          + receiveBuffer.size()
          + " ooo="
          + outOfOrder.size()
          + " eof="
          + eof
          + " fin="
          + finPending
          + "/"
          + finSent
          + " err="
          + error
          + "]";
    } finally {
      lock.unlock();
    }
  }

  State state() {
    lock.lock();
    try {
      return state;
    } finally {
      lock.unlock();
    }
  }

  // ---------------------------------------------------------------- inbound segments

  void onSegment(TcpSegment seg) {
    lock.lock();
    try {
      switch (state) {
        case CLOSED -> {}
        case SYN_SENT -> synSent(seg);
        default -> synchronizedState(seg);
      }
    } finally {
      lock.unlock();
    }
  }

  private void synSent(TcpSegment seg) {
    if (seg.has(ACK) && (le(seg.ack(), iss) || lt(sndNxt, seg.ack()))) {
      if (!seg.has(RST)) {
        transmit(seg.ack(), RST, null, 0, 0);
      }
      return;
    }
    if (seg.has(RST)) {
      if (seg.has(ACK)) {
        enterClosed(new ConnectException("connection refused"));
      }
      return;
    }
    if (!seg.has(SYN)) {
      return;
    }
    rcvNxt = seg.seq() + 1;
    negotiate(seg);
    if (seg.has(ACK)) {
      sndUna = seg.ack();
      updateWindow(seg, false);
      retransmitTimer.stop();
      retries = 0;
      state = State.ESTABLISHED;
      sendAck();
      changed.signalAll();
      output();
    } else {
      state = State.SYN_RECEIVED; // simultaneous open
      transmit(iss, SYN | ACK, null, 0, 0);
    }
  }

  private void negotiate(TcpSegment syn) {
    if (syn.mss() > 0) {
      sndMss = Math.min(syn.mss(), ourMss);
    } else {
      sndMss = Math.min(sndMss, ourMss);
    }
    cwnd = 10 * sndMss;
    peerOfferedWindowScale = syn.windowScale() >= 0;
    if (peerOfferedWindowScale) {
      sndWindowScale = syn.windowScale();
      rcvWindowScale = WINDOW_SCALE;
    }
    sndWl1 = syn.seq();
    sndWl2 = syn.ack();
  }

  private void synchronizedState(TcpSegment seg) {
    int segLen = seg.sequenceLength();
    if (state == State.TIME_WAIT) {
      if (seg.has(RST)) {
        return;
      }
      if (seg.has(FIN)) {
        lingerTimer.start(stack.timeWaitNanos());
      }
      sendAck();
      return;
    }
    // 1. Acceptability (RFC 9293 3.10.7.4).
    if (!acceptable(seg.seq(), segLen)) {
      if (state == State.SYN_RECEIVED && seg.has(SYN) && !seg.has(ACK) && seg.seq() == rcvNxt - 1) {
        transmit(iss, SYN | ACK, null, 0, 0); // retransmitted SYN: resend our SYN-ACK
      } else if (!seg.has(RST)) {
        sendAck();
      }
      return;
    }
    // 2. RST, accepted only at exactly rcvNxt (RFC 5961 section 3).
    if (seg.has(RST)) {
      if (seg.seq() == rcvNxt) {
        enterClosed(new SocketException("connection reset by peer"));
      } else {
        sendAck(); // challenge ACK
      }
      return;
    }
    // 3. SYN in a synchronized state: challenge ACK (RFC 5961 section 4).
    if (seg.has(SYN)) {
      sendAck();
      return;
    }
    // 4/5. ACK processing.
    if (!seg.has(ACK)) {
      return;
    }
    if (state == State.SYN_RECEIVED) {
      if (lt(sndUna, seg.ack()) && le(seg.ack(), sndNxt)) {
        sndUna = seg.ack();
        retransmitTimer.stop();
        retries = 0;
        updateWindow(seg, true);
        state = State.ESTABLISHED;
        changed.signalAll();
        if (listener != null && !listener.established(this)) {
          abortLocked(new SocketException("listener closed or backlog full"));
          return;
        }
      } else {
        transmit(seg.ack(), RST, null, 0, 0);
        return;
      }
    }
    if (!processAck(seg)) {
      return;
    }
    // 6/7. Data and FIN.
    if (seg.dataLength() > 0 || seg.has(FIN)) {
      if (state == State.ESTABLISHED || state == State.FIN_WAIT_1 || state == State.FIN_WAIT_2) {
        if (inputClosed && seg.dataLength() > 0) {
          abortLocked(new SocketException("data received after close"));
          return;
        }
        receive(seg);
      } else if (seg.has(FIN) || seg.dataLength() > 0) {
        sendAck(); // already past the peer's FIN: re-acknowledge
      }
    }
    if (state != State.CLOSED) {
      output();
    }
  }

  private boolean acceptable(int seq, int segLen) {
    int window = receiveBuffer.free();
    if (segLen == 0) {
      return window == 0 ? seq == rcvNxt : inWindow(seq, window);
    }
    if (window == 0) {
      return false;
    }
    return inWindow(seq, window) || inWindow(seq + segLen - 1, window);
  }

  private boolean inWindow(int seq, int window) {
    return le(rcvNxt, seq) && lt(seq, rcvNxt + window);
  }

  /** Handles the ACK field; returns false if processing of the segment must stop. */
  private boolean processAck(TcpSegment seg) {
    int ack = seg.ack();
    if (lt(sndMax, ack)) {
      sendAck(); // acknowledges something we never sent
      return false;
    }
    int previousWindow = sndWnd;
    if (lt(sndUna, ack)) {
      int acked = ack - sndUna;
      onNewAck(ack, acked);
    } else if (ack == sndUna
        && seg.dataLength() == 0
        && !seg.has(FIN)
        && (seg.window() << sndWindowScale) == previousWindow
        && sndMax != sndUna) {
      onDuplicateAck();
    }
    updateWindow(seg, false);
    boolean finAcked = finSent && lt(finSeq, sndUna);
    switch (state) {
      case FIN_WAIT_1 -> {
        if (finAcked) {
          state = State.FIN_WAIT_2;
          if (inputClosed) {
            lingerTimer.start(FIN_WAIT_2_TIMEOUT);
          }
        }
      }
      case CLOSING -> {
        if (finAcked) {
          enterTimeWait();
          return false;
        }
      }
      case LAST_ACK -> {
        if (finAcked) {
          enterClosed(null);
          return false;
        }
      }
      default -> {}
    }
    return true;
  }

  private void onNewAck(int ack, int acked) {
    long now = System.nanoTime();
    if (rttTiming && lt(rttSeq, ack)) {
      updateRto(now - rttStart);
      rttTiming = false;
    }
    int dataAcked = Math.min(acked, sendBuffer.size());
    sendBuffer.skip(dataAcked);
    sndUna = ack;
    if (lt(sndNxt, ack)) {
      sndNxt = ack; // after a go-back, the peer had more than we resent
    }
    retries = 0;
    if (inRecovery) {
      if (!lt(ack, recover)) {
        cwnd = Math.max(ssthresh, sndMss); // full acknowledgment: leave fast recovery
        inRecovery = false;
        dupAcks = 0;
      } else {
        retransmitFirst(); // partial acknowledgment (RFC 6582)
        cwnd = Math.max(cwnd - acked + sndMss, sndMss);
      }
    } else {
      dupAcks = 0;
      if (cwnd < ssthresh) {
        cwnd += Math.min(acked, sndMss);
      } else {
        cwnd += Math.max(1, (int) ((long) sndMss * sndMss / cwnd));
      }
      cwnd = Math.min(cwnd, MAX_CWND);
    }
    if (sndUna == sndMax) {
      retransmitTimer.stop();
    } else {
      retransmitTimer.start(rto);
    }
    changed.signalAll(); // send buffer space
  }

  private void onDuplicateAck() {
    dupAcks++;
    if (inRecovery) {
      cwnd = Math.min(cwnd + sndMss, MAX_CWND);
    } else if (dupAcks == 3) {
      ssthresh = Math.max((sndMax - sndUna) / 2, 2 * sndMss);
      recover = sndMax;
      inRecovery = true;
      rttTiming = false;
      retransmitFirst();
      cwnd = ssthresh + 3 * sndMss;
    }
  }

  private void updateWindow(TcpSegment seg, boolean force) {
    if (force || lt(sndWl1, seg.seq()) || (sndWl1 == seg.seq() && le(sndWl2, seg.ack()))) {
      sndWnd = seg.has(SYN) ? seg.window() : seg.window() << sndWindowScale;
      sndWl1 = seg.seq();
      sndWl2 = seg.ack();
      if (sndWnd > 0) {
        persistTimer.stop();
        persistBackoff = 0;
      }
    }
  }

  private void receive(TcpSegment seg) {
    byte[] data = seg.data();
    int off = seg.dataOffset();
    int len = seg.dataLength();
    int seq = seg.seq();
    boolean fin = seg.has(FIN);
    int skip = rcvNxt - seq;
    if (skip > 0) {
      if (skip > len) {
        sendAck(); // entirely old (FIN included)
        return;
      }
      off += skip;
      len -= skip;
      seq = rcvNxt;
    }
    int window = receiveBuffer.free();
    if (seq == rcvNxt) {
      int n = Math.min(len, window);
      receiveBuffer.write(data, off, n);
      rcvNxt += n;
      if (n < len) {
        fin = false; // FIN lies beyond what we accepted
      }
      drainOutOfOrder();
      if (fin) {
        finReceived();
      } else if (pendingFin && pendingFinSeq == rcvNxt) {
        finReceived();
      }
      if (n > 0) {
        changed.signalAll();
      }
    } else {
      int rel = seq - rcvNxt;
      if (rel < window && outOfOrder.size() < MAX_OUT_OF_ORDER_SEGMENTS) {
        int n = Math.min(len, window - rel);
        byte[] copy = new byte[n];
        System.arraycopy(data, off, copy, 0, n);
        outOfOrder.add(new Pending(seq, copy));
        if (fin && n == len) {
          pendingFin = true;
          pendingFinSeq = seq + n;
        }
      }
    }
    sendAck();
  }

  private void drainOutOfOrder() {
    boolean progress = true;
    while (progress && !outOfOrder.isEmpty()) {
      progress = false;
      for (int i = 0; i < outOfOrder.size(); i++) {
        Pending p = outOfOrder.get(i);
        int end = p.seq() + p.data().length;
        if (le(end, rcvNxt)) {
          outOfOrder.remove(i--); // fully duplicate
          continue;
        }
        if (le(p.seq(), rcvNxt)) {
          int skip = rcvNxt - p.seq();
          int n = Math.min(p.data().length - skip, receiveBuffer.free());
          receiveBuffer.write(p.data(), skip, n);
          rcvNxt += n;
          outOfOrder.remove(i--);
          progress = true;
        }
      }
    }
  }

  private void finReceived() {
    rcvNxt += 1;
    eof = true;
    pendingFin = false;
    outOfOrder.clear();
    changed.signalAll();
    switch (state) {
      case ESTABLISHED -> state = State.CLOSE_WAIT;
      case FIN_WAIT_1 -> {
        if (finSent && lt(finSeq, sndUna)) {
          sendAck();
          enterTimeWait();
          return;
        }
        state = State.CLOSING;
      }
      case FIN_WAIT_2 -> {
        sendAck();
        enterTimeWait();
        return;
      }
      default -> {}
    }
  }

  // ---------------------------------------------------------------- output

  private int flightSize() {
    return sndNxt - sndUna;
  }

  /** Sends whatever the windows allow, then a FIN if one is due. */
  private void output() {
    if (state != State.ESTABLISHED
        && state != State.CLOSE_WAIT
        && state != State.FIN_WAIT_1
        && state != State.CLOSING
        && state != State.LAST_ACK) {
      return;
    }
    while (true) {
      int sentData = Math.min(flightSize(), sendBuffer.size());
      int unsent = sendBuffer.size() - sentData;
      if (unsent > 0) {
        int usable = Math.min(cwnd, sndWnd) - flightSize();
        if (usable <= 0) {
          if (sndWnd == 0 && flightSize() == 0) {
            persistTimer.startIfIdle(rto);
          }
          return;
        }
        int n = Math.min(Math.min(unsent, usable), sndMss);
        byte[] chunk = new byte[n];
        sendBuffer.peek(sentData, chunk, 0, n);
        transmit(sndNxt, ACK | (n == unsent ? PSH : 0), chunk, 0, n);
        if (!rttTiming) {
          rttTiming = true;
          rttSeq = sndNxt;
          rttStart = System.nanoTime();
        }
        sndNxt += n;
        if (lt(sndMax, sndNxt)) {
          sndMax = sndNxt;
        }
        retransmitTimer.startIfIdle(rto);
        continue;
      }
      // All data is out: send the FIN, or resend it after a go-back reached it again.
      if (finPending && (!finSent || sndNxt == finSeq)) {
        boolean first = !finSent;
        finSeq = sndNxt;
        transmit(sndNxt, FIN | ACK, null, 0, 0);
        sndNxt += 1;
        if (lt(sndMax, sndNxt)) {
          sndMax = sndNxt;
        }
        finSent = true;
        retransmitTimer.startIfIdle(rto);
        if (first && state == State.ESTABLISHED) {
          state = State.FIN_WAIT_1;
        } else if (first && state == State.CLOSE_WAIT) {
          state = State.LAST_ACK;
        }
      }
      return;
    }
  }

  /** Retransmits the first unacknowledged segment without moving sndNxt. */
  private void retransmitFirst() {
    int dataInFlight = Math.min(sndMax - sndUna, sendBuffer.size());
    int n = Math.min(dataInFlight, sndMss);
    if (n > 0) {
      byte[] chunk = new byte[n];
      sendBuffer.peek(0, chunk, 0, n);
      transmit(sndUna, ACK | PSH, chunk, 0, n);
    } else if (finSent && finSeq == sndUna) {
      transmit(finSeq, FIN | ACK, null, 0, 0);
    }
  }

  private void sendAck() {
    // Pure ACKs carry sndMax, not a rewound sndNxt: a sequence number below what the peer already
    // received would make it discard the segment, ACK field included (BSD tcp_output does this).
    transmit(sndMax, ACK, null, 0, 0);
  }

  private void maybeSendWindowUpdate() {
    int window = receiveBuffer.free();
    if (window - lastAdvertised >= Math.min(sndMss * 2, BUFFER_SIZE / 2)
        && (state == State.ESTABLISHED || state == State.FIN_WAIT_1 || state == State.FIN_WAIT_2)) {
      sendAck();
    }
  }

  private void transmit(int seq, int flags, byte[] data, int off, int len) {
    boolean syn = (flags & SYN) != 0;
    int free = receiveBuffer.free();
    int window = syn ? Math.min(free, 65535) : Math.min(free >> rcvWindowScale, 65535);
    lastAdvertised = syn ? window : window << rcvWindowScale;
    int mss = syn ? ourMss : -1;
    int windowScale =
        syn && (state == State.SYN_SENT || peerOfferedWindowScale) ? WINDOW_SCALE : -1;
    int ack = (flags & ACK) != 0 ? rcvNxt : 0;
    stack.sendTcp(
        localIp,
        remoteIp,
        key.localPort(),
        key.remotePort(),
        seq,
        ack,
        flags,
        window,
        mss,
        windowScale,
        data,
        off,
        len);
  }

  // ---------------------------------------------------------------- timers

  private void updateRto(long sample) {
    if (srtt < 0) {
      srtt = sample;
      rttvar = sample / 2;
    } else {
      rttvar = (3 * rttvar + Math.abs(srtt - sample)) / 4;
      srtt = (7 * srtt + sample) / 8;
    }
    long granularity = TimeUnit.MILLISECONDS.toNanos(1);
    rto =
        Math.min(MAX_RTO, Math.max(stack.minRtoNanos(), srtt + Math.max(granularity, 4 * rttvar)));
  }

  private void onRetransmitTimeout() {
    lock.lock();
    try {
      switch (state) {
        case SYN_SENT, SYN_RECEIVED -> {
          if (++retries > SYN_RETRIES) {
            enterClosed(new SocketTimeoutException("connect timed out"));
            return;
          }
          rto = Math.min(rto * 2, MAX_RTO);
          transmit(iss, state == State.SYN_SENT ? SYN : SYN | ACK, null, 0, 0);
          retransmitTimer.start(rto);
        }
        case CLOSED, TIME_WAIT -> {}
        default -> {
          if (sndUna == sndMax) {
            return;
          }
          if (++retries > DATA_RETRIES) {
            abortLocked(new SocketTimeoutException("connection timed out"));
            return;
          }
          ssthresh = Math.max((sndMax - sndUna) / 2, 2 * sndMss);
          cwnd = sndMss;
          inRecovery = false;
          dupAcks = 0;
          rttTiming = false;
          rto = Math.min(rto * 2, MAX_RTO);
          sndNxt = sndUna; // go back and resend from the first unacknowledged byte
          output();
          retransmitTimer.startIfIdle(rto);
        }
      }
    } finally {
      lock.unlock();
    }
  }

  private void onPersistTimeout() {
    lock.lock();
    try {
      if (state == State.CLOSED || sndWnd != 0) {
        return;
      }
      transmit(sndUna - 1, ACK, null, 0, 0); // zero-window probe: elicits an ACK with the window
      persistBackoff = persistBackoff == 0 ? rto : Math.min(persistBackoff * 2, MAX_RTO);
      persistTimer.start(persistBackoff);
    } finally {
      lock.unlock();
    }
  }

  private void onLingerTimeout() {
    lock.lock();
    try {
      if (state == State.TIME_WAIT || state == State.FIN_WAIT_2) {
        enterClosed(null);
      }
    } finally {
      lock.unlock();
    }
  }

  private void enterTimeWait() {
    state = State.TIME_WAIT;
    retransmitTimer.stop();
    persistTimer.stop();
    lingerTimer.start(stack.timeWaitNanos());
    changed.signalAll();
  }

  private void enterClosed(IOException reason) {
    boolean halfOpen = state == State.SYN_RECEIVED;
    state = State.CLOSED;
    if (reason != null && error == null) {
      error = reason;
    }
    retransmitTimer.stop();
    persistTimer.stop();
    lingerTimer.stop();
    stack.removeTcp(key, this);
    if (listener != null && halfOpen) {
      listener.halfOpenClosed();
    }
    changed.signalAll();
  }
}
