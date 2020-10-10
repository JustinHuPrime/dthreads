// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "dthread.h"

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int writeAll(int fd, void *data, size_t len) {
  size_t start = 0;
  while (start != len) {
    ssize_t writeLen = write(fd, (char *)data + start, len - start);
    if (writeLen == -1) {
      if (errno == EINTR)
        continue;
      else
        return -1;
    }
    start += (size_t)writeLen;
  }

  return 0;
}

static int readAll(int fd, void *buf, size_t len) {
  size_t start = 0;
  while (start != len) {
    ssize_t readLen = read(fd, (char *)buf + start, len - start);
    if (readLen == -1) {
      if (errno == EINTR)
        continue;
      else
        return -1;
    }
    start += (size_t)readLen;
  }

  return 0;
}

int dthreadPoolInit(DThreadPool *pool) {
  pool->connections = malloc(sizeof(DThreadConnection));
  pool->connections->prev = pool->connections->next = pool->connections;

  return 0;
}

int dthreadConnect(DThreadPool *pool, char const *host, uint16_t port,
                   char const *password, DThreadConnection **connOut) {
  // resolve and connect to given host and port
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char portString[6];
  sprintf(portString, "%hu", port);

  struct addrinfo *results;
  if (getaddrinfo(host, portString, &hints, &results) != 0)
    return -DTHREAD_CONNECT;

  int fd = -1;
  for (struct addrinfo *curr = results; curr != NULL; curr = curr->ai_next) {
    fd = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol);
    if (fd == -1) continue;

    if (connect(fd, curr->ai_addr, curr->ai_addrlen) == 0) break;

    close(fd);
    fd = -1;
  }

  freeaddrinfo(results);

  if (fd == -1) return -DTHREAD_CONNECT;

  // generate and send salt

  DThreadConnection *conn = malloc(sizeof(DThreadConnection));
  conn->fd = fd;
  conn->utilization = 0;
  conn->nextJobId = 1;

  randombytes_buf(conn->salt, crypto_pwhash_SALTBYTES);
  if (writeAll(fd, conn->salt, crypto_pwhash_SALTBYTES) == -1) {
    free(conn);
    return -DTHREAD_IO;
  }

  // establish encrypted connection
  unsigned char *key =
      sodium_malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);
  if (crypto_pwhash(
          key, crypto_secretstream_xchacha20poly1305_KEYBYTES, password,
          strlen(password), conn->salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
    sodium_free(key);
    free(conn);
    return -DTHREAD_MEM;
  }

  conn->writeState =
      sodium_malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(conn->writeState, header,
                                                  key);

  if (writeAll(fd, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES) !=
      0) {
    sodium_free(conn->writeState);
    sodium_free(key);
    free(conn);
    return -DTHREAD_IO;
  }

  if (readAll(fd, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES) !=
      0) {
    sodium_free(conn->writeState);
    sodium_free(key);
    free(conn);
    return -DTHREAD_IO;
  }

  conn->readState =
      sodium_malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));
  if (crypto_secretstream_xchacha20poly1305_init_pull(conn->readState, header,
                                                      key) != 0) {
    sodium_free(conn->writeState);
    sodium_free(conn->readState);
    sodium_free(key);
    free(conn);
    return -DTHREAD_AUTH;
  }

  sodium_free(key);

  // get capabilities message
  unsigned char serverCapMsgCT[sizeof(uint32_t) +
                               crypto_secretstream_xchacha20poly1305_ABYTES];
  if (readAll(fd, serverCapMsgCT,
              sizeof(uint32_t) +
                  crypto_secretstream_xchacha20poly1305_ABYTES) != 0) {
    sodium_free(conn->writeState);
    sodium_free(conn->readState);
    free(conn);
    return -DTHREAD_IO;
  }

  unsigned char serverCapMsg[sizeof(uint32_t)];
  if (crypto_secretstream_xchacha20poly1305_pull(
          conn->readState, serverCapMsg, NULL, NULL, serverCapMsgCT,
          sizeof(uint32_t) + crypto_secretstream_xchacha20poly1305_ABYTES, NULL,
          0) != 0) {
    sodium_free(conn->writeState);
    sodium_free(conn->readState);
    free(conn);
    return -DTHREAD_AUTH;
  }

  conn->bandwidth =
      ntohl((uint32_t)serverCapMsg[0] << 24 | (uint32_t)serverCapMsg[1] << 16 |
            (uint32_t)serverCapMsg[2] << 8 | (uint32_t)serverCapMsg[3] << 0);

  conn->jobs = malloc(sizeof(DThreadJob));
  conn->jobs->prev = conn->jobs->next = conn->jobs;

  conn->prev = pool->connections->prev;
  conn->next = pool->connections;
  conn->prev->next = conn;
  conn->next->prev = conn;

  if (connOut != NULL) *connOut = conn;

  return 0;
}

int dthreadLoad(DThreadPool *pool, void *file, uint32_t fileLen,
                uint32_t fileId) {
  int retval = 0;

  // construct common header
  unsigned char header[16];
  memset(header, 0, 16);
  header[0] = 'f';
  uint32_t netFileLen = htonl(fileLen);
  memcpy(header + 4, &netFileLen, 4);
  uint32_t netFileId = htonl(fileId);
  memcpy(header + 8, &netFileId, 4);

  for (DThreadConnection *conn = pool->connections->next;
       conn != pool->connections; conn = conn->next) {
    // encrypt and send header
    unsigned char headerCT[16 + crypto_secretstream_xchacha20poly1305_ABYTES];
    crypto_secretstream_xchacha20poly1305_push(conn->writeState, headerCT, NULL,
                                               header, 16, NULL, 0, 0);
    if (writeAll(conn->fd, headerCT,
                 16 + crypto_secretstream_xchacha20poly1305_ABYTES) != 0) {
      retval = -DTHREAD_IO;
      break;
    }

    // encrypt and send file
    unsigned char *fileCT =
        malloc(fileLen + crypto_secretstream_xchacha20poly1305_ABYTES);
    crypto_secretstream_xchacha20poly1305_push(conn->writeState, fileCT, NULL,
                                               file, fileLen, NULL, 0, 0);
    if (writeAll(conn->fd, headerCT,
                 fileLen + crypto_secretstream_xchacha20poly1305_ABYTES) != 0) {
      retval = -DTHREAD_IO;
      free(fileCT);
      break;
    }

    free(fileCT);
  }

  return retval;
}

int dthreadStart(DThreadPool *pool, uint32_t fileId, void *data,
                 uint32_t dataLen, DThreadJob **jobOut) {
  // traverse pool to find connection with most free bandwidth
  DThreadConnection *conn = NULL;
  uint32_t mostFree = 0;
  for (DThreadConnection *curr = pool->connections->next;
       curr != pool->connections; curr = curr->next) {
    if (curr->bandwidth - curr->utilization > mostFree) {
      mostFree = curr->bandwidth - curr->utilization;
      conn = curr;
    }
  }

  if (conn == NULL) return -DTHREAD_BUSY;

  // send header
  unsigned char header[16];
  header[0] = 'j';
  uint32_t netFileId = htonl(fileId);
  memcpy(header + 4, &netFileId, 4);
  uint32_t netJobId = htonl(conn->nextJobId);
  memcpy(header + 8, &netJobId, 4);
  uint32_t netDataLen = htonl(dataLen);
  memcpy(header + 12, &netDataLen, 4);

  unsigned char headerCT[16 + crypto_secretstream_xchacha20poly1305_ABYTES];
  crypto_secretstream_xchacha20poly1305_push(conn->writeState, headerCT, NULL,
                                             header, 16, NULL, 0, 0);
  if (writeAll(conn->fd, headerCT,
               16 + crypto_secretstream_xchacha20poly1305_ABYTES) != 0)
    return -DTHREAD_IO;

  // send data
  unsigned char *dataCT =
      malloc(dataLen + crypto_secretstream_xchacha20poly1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(conn->writeState, dataCT, NULL,
                                             data, dataLen, NULL, 0, 0);
  if (writeAll(conn->fd, headerCT,
               dataLen + crypto_secretstream_xchacha20poly1305_ABYTES) != 0) {
    free(dataCT);
    return -DTHREAD_IO;
  }

  // construct job entry
  DThreadJob *job = malloc(sizeof(DThreadJob));
  job->status = DTHREAD_SENT;
  job->conn = conn;
  job->jobId = conn->nextJobId;
  job->prev = conn->jobs->prev;
  job->next = conn->jobs;
  job->prev->next = job;
  job->next->prev = job;

  conn->utilization++;
  conn->nextJobId++;

  return 0;
}

int dthreadDetach(DThreadJob *job) {
  switch (job->status) {
    case DTHREAD_SENT: {
      job->status = DTHREAD_DETACHED;
      break;
    }
    case DTHREAD_DONE: {
      free(job->returnData);
      job->prev->next = job->next;
      job->next->prev = job->prev;
      free(job);
      break;
    }
    case DTHREAD_DETACHED: {
      // do nothing
      break;
    }
  }
}

int dthreadClose(DThreadPool *pool, DThreadConnection *conn) {
  conn->prev->next = conn->next;
  conn->next->prev = conn->prev;

  close(conn->fd);
  sodium_free(conn->readState);
  sodium_free(conn->writeState);
  free(conn);

  return 0;
}

int dthreadPoolUninit(DThreadPool *pool) {
  int retval = 0;

  while (pool->connections->next != pool->connections) {
    int additional = dthreadClose(pool, pool->connections->next);
    if (retval == 0) retval = additional;
  }

  free(pool->connections);

  return retval;
}