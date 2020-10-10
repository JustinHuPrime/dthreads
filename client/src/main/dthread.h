// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <pthread.h>
#include <sodium.h>

typedef enum {
  DTHREAD_CONNECT = 1,
  DTHREAD_IO,
  DTHREAD_AUTH,
  DTHREAD_MEM,
} DThreadError;

/**
 * a connection to a dthread server
 */
typedef struct DThreadConnection {
  int fd;
  uint32_t utilization;
  uint32_t bandwidth;

  unsigned char salt[crypto_pwhash_SALTBYTES];
  crypto_secretstream_xchacha20poly1305_state *writeState;
  crypto_secretstream_xchacha20poly1305_state *readState;

  struct DThreadConnection *next;
  struct DThreadConnection *prev;
} DThreadConnection;

/**
 * a circular doubly-linked list w/ sentinel node of connections
 */
typedef struct {
  DThreadConnection *connections;

  uint32_t nextFileNo;
  uint32_t nextJobNo;

  pthread_mutex_t mutex;
} DThreadPool;

/**
 * initializes a pool connections
 *
 * @param pool pool to initialize
 *
 * @returns negative integer error code or 0 on success
 */
int dthreadPoolInit(DThreadPool *pool);

/**
 * adds a connection to the pool
 *
 * blocking, thread-safe
 *
 * @param pool pool to add to
 * @param host host to connect to
 * @param port port to connect to
 * @param password password to use
 * @param connOut nullable output pointer - stores address of created connection
 *
 * @returns negative integer error code or 0 on success
 */
int dthreadConnect(DThreadPool *pool, char const *host, uint16_t port,
                   char const *password, DThreadConnection **connOut);

/**
 * uploads a file to the server
 *
 * @param pool pool to upload to
 * @param file file to upload
 * @param fileLen length of file
 *
 * @returns positive integer file id or negative integer error code
 */
int dthreadLoad(DThreadPool *pool, void *file, uint32_t fileLen);

/**
 * removes a connection from the pool
 *
 * blocking, thread safe
 *
 * @param pool pool to remove connection from
 * @param connection connection to remove - must be in the pool and have no jobs
 * @returns negative integer error code or 0 on success - currently doesn't fail
 */
int dthreadClose(DThreadPool *pool, DThreadConnection *connection);

/**
 * closes all connections and deinitializes the pool
 *
 * @param pool pool to deinit
 * @returns negative integer error code or 0 on success - currently doesn't fail
 */
int dthreadPoolUninit(DThreadPool *pool);

typedef struct {
  DThreadConnection *connection;
  uint32_t jobid;
} DThreadJob;