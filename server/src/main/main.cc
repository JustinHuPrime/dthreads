// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sodium.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "jobFile.h"
#include "sodiumAllocator.h"
#include "uniqueFD.h"

namespace {
using namespace dthreadd;

int writeAll(int fd, void *data, size_t len) {
  size_t start = 0;
  while (start != len) {
    ssize_t writeLen =
        write(fd, static_cast<char *>(data) + start, len - start);
    if (writeLen == -1) {
      if (errno == EINTR)
        continue;
      else
        return -1;
    }
    start += static_cast<size_t>(writeLen);
  }

  return 0;
}

int readAll(int fd, void *buf, size_t len) {
  size_t start = 0;
  while (start != len) {
    ssize_t readLen = read(fd, static_cast<char *>(buf) + start, len - start);
    if (readLen == -1) {
      if (errno == EINTR)
        continue;
      else
        return -1;
    }
    start += static_cast<size_t>(readLen);
  }

  return 0;
}
}  // namespace

int main() {
  std::cout << "dthreadd v0.1.0\n";

  if (sodium_init() == -1) {
    std::cerr << "Could not initialize libsodium!\n";
    return EXIT_FAILURE;
  }

  std::cout << "Password: ";

  struct termios tty;
  tcgetattr(STDIN_FILENO, &tty);
  tcflag_t original = tty.c_lflag;
  tty.c_lflag &= ~ECHO;
  tty.c_lflag |= ECHONL;
  tcsetattr(STDIN_FILENO, TCSANOW, &tty);

  std::basic_string<char, std::char_traits<char>, SodiumAllocator<char>>
      password;
  std::getline(std::cin, password);

  tty.c_lflag = original;
  tcsetattr(STDIN_FILENO, TCSANOW, &tty);

  std::cout << "Job limit: ";
  uint32_t bandwidth;
  std::cin >> bandwidth;

  std::cout << "Port: ";
  uint16_t port;
  std::cin >> port;

  // bind to a socket
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo *resultRaw;
  if (getaddrinfo(nullptr, std::to_string(static_cast<int>(port)).c_str(),
                  &hints, &resultRaw) != 0) {
    std::cerr << "Could not bind to socket (getaddrinfo failed)!\n";
    return EXIT_FAILURE;
  }

  std::unique_ptr<struct addrinfo, void (*)(struct addrinfo *)> result(
      resultRaw, freeaddrinfo);
  UniqueFD listening;
  for (struct addrinfo *curr = result.get(); curr != nullptr;
       curr = curr->ai_next) {
    listening =
        UniqueFD(socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol));
    if (listening.get() == -1) continue;

    if (bind(listening.get(), curr->ai_addr, curr->ai_addrlen) == 0) break;

    listening.reset();
  }

  if (listening.get() == -1) {
    std::cerr << "Could not bind to socket (bind failed)!\n";
    return EXIT_FAILURE;
  }

  struct sigaction action;
  action.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &action, nullptr);
  if (listen(listening.get(), 1) != 0) {
    std::cerr << "Could not listen on socket!\n";
    return EXIT_FAILURE;
  }

  for (unsigned long clientId = 1; true; clientId++) {
    std::cout << "Waiting for client...\n";
    UniqueFD fd(accept(listening.get(), nullptr, nullptr));

    std::thread clientHandler(
        [bandwidth, clientId, &password](UniqueFD fd) {
          std::cout << "Connecting...\n";
          std::mutex loopMutex;
          std::condition_variable threadDone;
          unsigned long runningThreads = 0;

          // read salt
          std::array<unsigned char, crypto_pwhash_SALTBYTES> salt;
          if (readAll(fd.get(), salt.data(), salt.size()) == -1) {
            std::cerr << "Connection failed (IO error)\n";
            std::unique_lock loopLock(loopMutex);
            while (runningThreads > 0) threadDone.wait(loopLock);
            return;
          }

          // establish encrypted communications
          std::unique_ptr<
              std::array<unsigned char,
                         crypto_secretstream_xchacha20poly1305_KEYBYTES>,
              void (*)(void *)>
              key(new (sodium_malloc(
                      sizeof(std::array<
                             unsigned char,
                             crypto_secretstream_xchacha20poly1305_KEYBYTES>)))(
                      std::array<
                          unsigned char,
                          crypto_secretstream_xchacha20poly1305_KEYBYTES>),
                  sodium_free);
          if (crypto_pwhash(key->data(),
                            crypto_secretstream_xchacha20poly1305_KEYBYTES,
                            password.c_str(), password.length(), salt.data(),
                            crypto_pwhash_OPSLIMIT_INTERACTIVE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_DEFAULT) != 0) {
            std::cerr << "Connection failed (hashing error)\n";
            std::unique_lock loopLock(loopMutex);
            while (runningThreads > 0) threadDone.wait(loopLock);
            return;
          }

          std::unique_ptr<crypto_secretstream_xchacha20poly1305_state,
                          void (*)(void *)>
              writeState(new (sodium_malloc(sizeof(
                             crypto_secretstream_xchacha20poly1305_state)))(
                             crypto_secretstream_xchacha20poly1305_state),
                         sodium_free);
          std::array<unsigned char,
                     crypto_secretstream_xchacha20poly1305_HEADERBYTES>
              handshake;
          crypto_secretstream_xchacha20poly1305_init_push(
              writeState.get(), handshake.data(), key->data());
          if (writeAll(fd.get(), handshake.data(), handshake.size()) != 0) {
            std::cerr << "Connection failed (IO error)\n";
            std::unique_lock loopLock(loopMutex);
            while (runningThreads > 0) threadDone.wait(loopLock);
            return;
          }
          if (readAll(fd.get(), handshake.data(), handshake.size()) != 0) {
            std::cerr << "Connection failed (IO error)\n";
            std::unique_lock loopLock(loopMutex);
            while (runningThreads > 0) threadDone.wait(loopLock);
            return;
          }
          std::unique_ptr<crypto_secretstream_xchacha20poly1305_state,
                          void (*)(void *)>
              readState(new (sodium_malloc(sizeof(
                            crypto_secretstream_xchacha20poly1305_state)))(
                            crypto_secretstream_xchacha20poly1305_state),
                        sodium_free);
          if (crypto_secretstream_xchacha20poly1305_init_pull(
                  readState.get(), handshake.data(), key->data()) != 0) {
            std::cerr << "Connection failed (authentication error)\n";
            std::unique_lock loopLock(loopMutex);
            while (runningThreads > 0) threadDone.wait(loopLock);
            return;
          }

          key.reset();

          // send capabilities message
          std::cout << "Connected, sending capabilities message...\n";

          std::array<unsigned char, 4> serverCapMsg;
          uint32_t netBandwidth = htonl(bandwidth);
          memcpy(serverCapMsg.data(), &netBandwidth, 4);
          std::array<unsigned char,
                     4 + crypto_secretstream_xchacha20poly1305_ABYTES>
              serverCapMsgCT;
          crypto_secretstream_xchacha20poly1305_push(
              writeState.get(), serverCapMsgCT.data(), nullptr,
              serverCapMsg.data(), serverCapMsg.size(), nullptr, 0, 0);
          if (writeAll(fd.get(), serverCapMsgCT.data(),
                       serverCapMsgCT.size()) != 0) {
            std::cerr << "Connection failed (IO error)\n";
            std::unique_lock loopLock(loopMutex);
            while (runningThreads > 0) threadDone.wait(loopLock);
            return;
          }

          std::unordered_map<uint32_t, JobFile> files;

          while (true) {
            // wait for client messages
            std::cout << "Waiting for message...\n";

            std::array<unsigned char,
                       16 + crypto_secretstream_xchacha20poly1305_ABYTES>
                headerCT;
            if (readAll(fd.get(), headerCT.data(), headerCT.size()) != 0) {
              std::cerr << "Connection failed (IO error)\n";
              std::unique_lock loopLock(loopMutex);
              while (runningThreads > 0) threadDone.wait(loopLock);
              return;
            }
            std::array<unsigned char, 16> header;
            if (crypto_secretstream_xchacha20poly1305_pull(
                    readState.get(), header.data(), nullptr, nullptr,
                    headerCT.data(), headerCT.size(), nullptr, 0) != 0) {
              std::cerr << "Connection failed (authentication error)\n";
              std::unique_lock loopLock(loopMutex);
              while (runningThreads > 0) threadDone.wait(loopLock);
              return;
            }

            switch (header[0]) {
              case 'f': {
                // download file
                std::cout << "Reading file sent by client...\n";

                uint32_t fileLen = static_cast<uint32_t>(header[4]) << 24 |
                                   static_cast<uint32_t>(header[5]) << 16 |
                                   static_cast<uint32_t>(header[6]) << 8 |
                                   static_cast<uint32_t>(header[7]) << 0;
                uint32_t fileId = static_cast<uint32_t>(header[8]) << 24 |
                                  static_cast<uint32_t>(header[9]) << 16 |
                                  static_cast<uint32_t>(header[10]) << 8 |
                                  static_cast<uint32_t>(header[11]) << 0;

                std::vector<unsigned char> bufferCT(
                    fileLen + crypto_secretstream_xchacha20poly1305_ABYTES);
                if (readAll(fd.get(), bufferCT.data(), bufferCT.size()) != 0) {
                  std::cerr << "Connection failed (IO error)\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                std::vector<unsigned char> buffer(fileLen);
                if (crypto_secretstream_xchacha20poly1305_pull(
                        readState.get(), buffer.data(), nullptr, nullptr,
                        bufferCT.data(), bufferCT.size(), nullptr, 0) != 0) {
                  std::cerr << "Connection failed (authentication error)\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }

                std::string soname =
                    "./temp" + std::to_string(clientId) + ".so";
                UniqueFD dlfd(creat(soname.c_str(), S_IRWXU));
                if (dlfd.get() == -1) {
                  std::cerr << "Could not open temp file\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                if (writeAll(dlfd.get(), buffer.data(), fileLen) != 0) {
                  std::cerr << "Could not write to temp file\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                dlfd.reset();

                void *handle = dlopen(soname.c_str(), RTLD_NOW | RTLD_LOCAL);
                unlink(soname.c_str());
                if (handle == nullptr) {
                  std::cerr << "Could not load temp file\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                if (dlsym(handle, "jobInLen") == nullptr) {
                  std::cerr << "Missing jobInLen from sent file\n";
                  dlclose(handle);
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                if (dlsym(handle, "jobOutLen") == nullptr) {
                  std::cerr << "Missing jobOutLen from sent file\n";
                  dlclose(handle);
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                if (dlsym(handle, "job") == nullptr) {
                  std::cerr << "Missing job from sent file\n";
                  dlclose(handle);
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }

                // can't overwrite anything while someone might be using it
                if (files.find(fileId) != files.end()) {
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                }
                files[fileId] = JobFile(handle);

                std::cout << "File loaded!\n";

                break;
              }
              case 'j': {
                // start a job
                std::cout << "Starting job for client...\n";

                uint32_t fileId = static_cast<uint32_t>(header[4]) << 24 |
                                  static_cast<uint32_t>(header[5]) << 16 |
                                  static_cast<uint32_t>(header[6]) << 8 |
                                  static_cast<uint32_t>(header[7]) << 0;
                uint32_t jobId = static_cast<uint32_t>(header[8]) << 24 |
                                 static_cast<uint32_t>(header[9]) << 16 |
                                 static_cast<uint32_t>(header[10]) << 8 |
                                 static_cast<uint32_t>(header[11]) << 0;

                JobFile &file = files[fileId];
                if (file.get() == nullptr) {
                  std::cerr << "Connection failed (client named bad fileId)\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }

                uint32_t inLen = *reinterpret_cast<uint32_t *>(
                    dlsym(file.get(), "jobInLen"));
                uint32_t outLen = *reinterpret_cast<uint32_t *>(
                    dlsym(file.get(), "jobOutLen"));
                void (*function)(void *, void *) =
                    reinterpret_cast<void (*)(void *, void *)>(
                        dlsym(file.get(), "job"));

                std::vector<unsigned char> inBufferCT(
                    inLen + crypto_secretstream_xchacha20poly1305_ABYTES);
                if (readAll(fd.get(), inBufferCT.data(), inBufferCT.size()) !=
                    0) {
                  std::cerr << "Connection failed (IO error)\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }
                std::vector<unsigned char> inBuffer(inLen);
                if (crypto_secretstream_xchacha20poly1305_pull(
                        readState.get(), inBuffer.data(), nullptr, nullptr,
                        inBufferCT.data(), inBufferCT.size(), nullptr,
                        0) != 0) {
                  std::cout << std::dec << "\n";
                  std::cerr << "Connection failed (authentication error)\n";
                  std::unique_lock loopLock(loopMutex);
                  while (runningThreads > 0) threadDone.wait(loopLock);
                  return;
                }

                {
                  std::scoped_lock scopedLoopLock(loopMutex);
                  runningThreads++;
                }
                std::thread jobRunner(
                    [jobId, outLen, function, &fd, &writeState, &loopMutex,
                     &runningThreads,
                     &threadDone](std::vector<unsigned char> inBuffer) {
                      std::vector<unsigned char> outBuffer(outLen);
                      function(inBuffer.data(), outBuffer.data());

                      std::array<unsigned char, 16> header;
                      header[0] = 'f';
                      uint32_t netJobId = htonl(jobId);
                      memcpy(header.data() + 4, &netJobId, 4);
                      uint32_t netOutLen = htonl(outLen);
                      memcpy(header.data() + 8, &netOutLen, 4);

                      {
                        std::scoped_lock scopedLoopLock(loopMutex);

                        std::array<
                            unsigned char,
                            16 + crypto_secretstream_xchacha20poly1305_ABYTES>
                            headerCT;
                        crypto_secretstream_xchacha20poly1305_push(
                            writeState.get(), headerCT.data(), nullptr,
                            header.data(), header.size(), nullptr, 0, 0);
                        if (writeAll(fd.get(), headerCT.data(),
                                     headerCT.size()) != 0) {
                          runningThreads--;
                          threadDone.notify_one();
                          return;
                        }

                        std::vector<unsigned char> outBufferCT(
                            outLen +
                            crypto_secretstream_xchacha20poly1305_ABYTES);
                        crypto_secretstream_xchacha20poly1305_push(
                            writeState.get(), outBufferCT.data(), nullptr,
                            outBuffer.data(), outBuffer.size(), nullptr, 0, 0);
                        if (writeAll(fd.get(), outBufferCT.data(),
                                     outBufferCT.size()) != 0) {
                          runningThreads--;
                          threadDone.notify_one();
                          return;
                        }

                        runningThreads--;
                        threadDone.notify_one();
                      }
                    },
                    inBuffer);
                jobRunner.detach();

                std::cout << "Job started!\n";

                break;
              }
              case 'b': {
                // client says bye
                std::cout << "Client disconnected!\n";
                std::unique_lock loopLock(loopMutex);
                while (runningThreads > 0) threadDone.wait(loopLock);
                return;
              }
              default: {
                // bad client!
                std::cerr << "Connection failed (protocol error)\n";
                std::unique_lock loopLock(loopMutex);
                while (runningThreads > 0) threadDone.wait(loopLock);
                return;
              }
            }
          }
        },
        std::move(fd));
    clientHandler.detach();
  }

  return EXIT_SUCCESS;
}