// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <sodium.h>

typedef struct DThreadConnectionCrypto {
  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
} DThreadConnectionCrypto;

/**
 * A connection to a single dthread server
 * 
 * has pointer
 */
typedef struct DThreadConnection {
  int fd;
  DThreadConnectionCrypto *crypto;
} DThreadConnection;

/**
 * A pool of connections to zero or more dthread servers
 */
typedef struct DThreadPool {
  size_t connectionsSize;
  size_t connectionsCapacity;
  DThreadConnection **connections;
} DThreadPool;

/**
 * A job running on some server from some pool
 */
typedef struct DThreadJob {
  DThreadPool *pool;
  DThreadConnection *connection;
} DThreadJob;

/**
 * Initializes an empty pool
 *
 * this also spins off a local thread to handle networking
 *
 * @param pool pool to initialize
 */
int dthreadPoolInit(DThreadPool *pool);

/**
 * Adds a server to some pool
 *
 * @param pool pool to add server to
 * @param host web addess of host to connect to
 * @param port port number to connect to
 * @param password password to use to communicate to the server
 */
int dthreadConnect(DThreadPool *pool, char const *host, unsigned short port, char const *password);

/**
 * Adds a job to some pool
 *
 * @param job job struct to initialize
 * @param pool pool to assign job to
 * @param routineDesc routine number to run
 * @param arg data to pass to routine
 */
int dthreadCreate(DThreadJob *job, DThreadPool *pool, int routineDesc,
                  void *arg);

/**
 * Detaches a job from the current thread
 */
int dthreadDetach(DThreadJob *job);

/**
 * Waits for a job to finish
 */
int dthreadJoin(DThreadJob *job);