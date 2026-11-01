// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.LockSupport;

/**
 * Runs packet crypto in parallel while keeping order: {@link #submit} hands the work to a shared
 * worker pool and queues the completion step, which one consumer thread runs strictly in submission
 * order once each job's work is done. Order is global, which implies per-peer order.
 */
final class CryptoPipeline implements AutoCloseable {
  private static final System.Logger LOG = System.getLogger(CryptoPipeline.class.getName());

  /** One packet's work and its in-order completion. */
  private static final class Job {
    final Runnable work;
    final Runnable complete;
    volatile boolean done;
    volatile Thread waiter;

    Job(Runnable work, Runnable complete) {
      this.work = work;
      this.complete = complete;
    }
  }

  private static final Job STOP = new Job(() -> {}, () -> {});

  private final ExecutorService workers;
  private final BlockingQueue<Job> order;
  private final Thread consumer;

  CryptoPipeline(ExecutorService workers, int capacity, String name) {
    this.workers = workers;
    this.order = new ArrayBlockingQueue<>(capacity);
    this.consumer = new Thread(this::consume, name);
    consumer.setDaemon(true);
    consumer.start();
  }

  /**
   * Queues {@code work} to run on a worker and {@code complete} to run on the consumer afterwards,
   * in submission order. Blocks while the pipeline is full (backpressure).
   */
  void submit(Runnable work, Runnable complete) {
    Job job = new Job(work, complete);
    try {
      order.put(job);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return;
    }
    workers.execute(
        () -> {
          try {
            job.work.run();
          } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "packet crypto failed", e);
          } finally {
            job.done = true;
            Thread w = job.waiter;
            if (w != null) {
              LockSupport.unpark(w);
            }
          }
        });
  }

  private void consume() {
    Thread self = Thread.currentThread();
    try {
      while (true) {
        Job job = order.take();
        if (job == STOP) {
          return;
        }
        job.waiter = self;
        while (!job.done) {
          LockSupport.park(job);
          if (self.isInterrupted()) {
            return;
          }
        }
        try {
          job.complete.run();
        } catch (RuntimeException e) {
          LOG.log(System.Logger.Level.WARNING, "packet completion failed", e);
        }
      }
    } catch (InterruptedException e) {
      // closing
    }
  }

  @Override
  public void close() {
    order.clear();
    order.offer(STOP);
    consumer.interrupt();
  }
}
