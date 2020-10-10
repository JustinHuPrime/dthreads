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
  DTHREAD_BUSY,
} DThreadError;

struct DThreadConnection;
/**
 * a job record
 */
typedef struct DThreadJob {
  enum {
    /** job sent to server, but no reply yet */
    DTHREAD_SENT,
    /** job recieved reply from server */
    DTHREAD_DONE,
    /** job marked as detached, but no reply yet */
    DTHREAD_DETACHED,
  } status;

  uint32_t returnLen;
  void *returnData;

  struct DThreadConnection *conn;
  uint32_t jobId;

  struct DThreadJob *next;
  struct DThreadJob *prev;
} DThreadJob;

/**
 * a connection to a dthread server
 */
typedef struct DThreadConnection {
  int fd;
  uint32_t utilization;
  uint32_t bandwidth;
  uint32_t nextJobId;

  unsigned char salt[crypto_pwhash_SALTBYTES];
  crypto_secretstream_xchacha20poly1305_state *writeState;
  crypto_secretstream_xchacha20poly1305_state *readState;

  /** circular doubly-linked list w/ sentinel */
  DThreadJob *jobs;

  struct DThreadConnection *next;
  struct DThreadConnection *prev;
} DThreadConnection;

/**
 * A connection pool
 */
typedef struct {
  /** circular doubly-linked list w/ sentinel */
  DThreadConnection *connections;
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
 * @param fileId file id to send
 *
 * @returns zero or negative integer error code
 */
int dthreadLoad(DThreadPool *pool, void *file, uint32_t fileLen,
                uint32_t fileId);

/**
 * queues a job on an appropriate server
 *
 * @param pool pool to start job in
 * @param fileId file id to run
 * @param data data to give to job
 * @param dataLen length of data
 * @param jobOut output pointer, job for later waiting
 *
 * @returns zero or negative integer error code
 */
int dthreadStart(DThreadPool *pool, uint32_t fileId, void *data,
                 uint32_t dataLen, DThreadJob **jobOut);

/**
 * marks a job as detached
 *
 * @param job job to mark as detached
 *
 * @returns zero or negative integer error code (currently doesn't fail)
 */
int dthreadDetach(DThreadJob *job);

/**
 * removes a connection from the pool
 *
 * note that the connection should not be deleted while a job assigned to this
 * connection is being joined
 *
 * @param pool pool to remove connection from
 * @param connection connection to remove - must be in the pool and have no jobs
 *
 * @returns negative integer error code or 0 on success - currently doesn't fail
 */
int dthreadClose(DThreadPool *pool, DThreadConnection *connection);

/**
 * closes all connections and deinitializes the pool
 *
 * @param pool pool to deinit
 *
 * @returns negative integer error code or 0 on success - currently doesn't fail
 */
int dthreadPoolUninit(DThreadPool *pool);