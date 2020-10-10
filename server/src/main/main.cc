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

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
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
  std::cout << "Password: ";

  struct termios termStdIn;
  tcgetattr(0, &termStdIn);
  tcflag_t original = termStdIn.c_iflag;
  termStdIn.c_iflag &= ~ECHO;
  termStdIn.c_iflag |= ECHONL;
  tcsetattr(0, TCSANOW, &termStdIn);

  std::basic_string<char, std::char_traits<char>, SodiumAllocator<char>>
      password;
  std::getline(std::cin, password);

  termStdIn.c_iflag = original;
  tcsetattr(0, TCSANOW, &termStdIn);

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

  while (true) {
    UniqueFD fd(accept(listening.get(), nullptr, nullptr));
    std::cout << "Connecting...\n";

    // read salt
    std::array<unsigned char, crypto_pwhash_SALTBYTES> salt;
    if (readAll(fd.get(), salt.data(), salt.size()) == -1) {
      std::cout << "Connection failed (IO error)\n";
      continue;
    }

    // establish encrypted communications
    std::unique_ptr<std::array<unsigned char,
                               crypto_secretstream_xchacha20poly1305_KEYBYTES>,
                    void (*)(void *)>
        key(new (sodium_malloc(sizeof(
                std::array<unsigned char,
                           crypto_secretstream_xchacha20poly1305_KEYBYTES>)))(
                std::array<unsigned char,
                           crypto_secretstream_xchacha20poly1305_KEYBYTES>),
            sodium_free);
    if (crypto_pwhash(key->data(),
                      crypto_secretstream_xchacha20poly1305_KEYBYTES,
                      password.c_str(), password.length(), salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
      std::cout << "Connection failed (hashing error)\n";
      continue;
    }

    std::unique_ptr<crypto_secretstream_xchacha20poly1305_state,
                    void (*)(void *)>
        writeState(new (sodium_malloc(
                       sizeof(crypto_secretstream_xchacha20poly1305_state)))(
                       crypto_secretstream_xchacha20poly1305_state),
                   sodium_free);
    std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>
        handshake;
    crypto_secretstream_xchacha20poly1305_init_push(
        writeState.get(), handshake.data(), key->data());
    if (writeAll(fd.get(), handshake.data(), handshake.size()) != 0) {
      std::cout << "Connection failed (IO error)\n";
      continue;
    }
    if (readAll(fd.get(), handshake.data(), handshake.size()) != 0) {
      std::cout << "Connection failed (IO error)\n";
      continue;
    }
    std::unique_ptr<crypto_secretstream_xchacha20poly1305_state,
                    void (*)(void *)>
        readState(new (sodium_malloc(
                      sizeof(crypto_secretstream_xchacha20poly1305_state)))(
                      crypto_secretstream_xchacha20poly1305_state),
                  sodium_free);
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            readState.get(), handshake.data(), key->data()) != 0) {
      std::cout << "Connection failed (authentication error)\n";
      continue;
    }

    key.reset();

    // send capabilities message
    std::array<unsigned char, 4> serverCapMsg;
    uint32_t netBandwidth = htonl(bandwidth);
    memcpy(serverCapMsg.data(), &netBandwidth, 4);
    std::array<unsigned char, 4 + crypto_secretstream_xchacha20poly1305_ABYTES>
        serverCapMsgCT;
    crypto_secretstream_xchacha20poly1305_push(
        writeState.get(), serverCapMsgCT.data(), nullptr, serverCapMsg.data(),
        serverCapMsg.size(), nullptr, 0, 0);
    if (writeAll(fd.get(), serverCapMsgCT.data(), serverCapMsgCT.size()) != 0) {
      std::cout << "Connection failed (IO error)\n";
      continue;
    }

    std::unordered_map<uint32_t, JobFile> files;

    while (true) {
      // wait for client messages
      std::array<unsigned char,
                 16 + crypto_secretstream_xchacha20poly1305_ABYTES>
          headerCT;
      if (readAll(fd.get(), headerCT.data(), headerCT.size()) != 0) {
        std::cout << "Connection failed (IO error)\n";
        goto outer_continue;
      }
      std::array<unsigned char, 16> header;
      if (crypto_secretstream_xchacha20poly1305_pull(
              readState.get(), header.data(), nullptr, nullptr, headerCT.data(),
              headerCT.size(), nullptr, 0) != 0) {
        std::cout << "Connection failed (authentication error)\n";
        goto outer_continue;
      }

      switch (header[0]) {
        case 'f': {
          // download file
          uint32_t fileLen = ntohl(static_cast<uint32_t>(header[4]) << 24 |
                                   static_cast<uint32_t>(header[5]) << 16 |
                                   static_cast<uint32_t>(header[6]) << 8 |
                                   static_cast<uint32_t>(header[7]) << 0);
          uint32_t fileId = ntohl(static_cast<uint32_t>(header[8]) << 24 |
                                  static_cast<uint32_t>(header[9]) << 16 |
                                  static_cast<uint32_t>(header[10]) << 8 |
                                  static_cast<uint32_t>(header[11]) << 0);

          std::vector<unsigned char> bufferCT(
              fileLen + crypto_secretstream_xchacha20poly1305_ABYTES);
          if (readAll(fd.get(), bufferCT.data(), bufferCT.size()) != 0) {
            std::cout << "Connection failed (IO error)\n";
            goto outer_continue;
          }
          std::vector<unsigned char> buffer(fileLen);
          if (crypto_secretstream_xchacha20poly1305_pull(
                  readState.get(), buffer.data(), nullptr, nullptr,
                  bufferCT.data(), bufferCT.size(), nullptr, 0) != 0) {
            std::cout << "Connection failed (authentication error)\n";
            goto outer_continue;
          }

          UniqueFD dlfd(creat("temp.so", S_IRWXU));
          if (dlfd.get() == -1) {
            std::cout << "Could not open temp file\n";
            goto outer_continue;
          }
          if (writeAll(dlfd.get(), buffer.data(), fileLen) != 0) {
            std::cout << "Could not write to temp file\n";
            goto outer_continue;
          }
          dlfd.reset();

          void *handle = dlopen("./temp.so", RTLD_NOW | RTLD_LOCAL);
          if (handle == nullptr) {
            std::cout << "Could not load temp file\n";
            goto outer_continue;
          }
          if (dlsym(handle, "jobInLen") == nullptr) {
            std::cout << "Missing jobInLen from sent file\n";
            dlclose(handle);
            goto outer_continue;
          }
          if (dlsym(handle, "jobOutLen") == nullptr) {
            std::cout << "Missing jobOutLen from sent file\n";
            dlclose(handle);
            goto outer_continue;
          }
          if (dlsym(handle, "job") == nullptr) {
            std::cout << "Missing job from sent file\n";
            dlclose(handle);
            goto outer_continue;
          }
          files[fileId] = JobFile(handle);

          break;
        }
        case 'j': {
          // start a job
          uint32_t fileId = ntohl(static_cast<uint32_t>(header[4]) << 24 |
                                  static_cast<uint32_t>(header[5]) << 16 |
                                  static_cast<uint32_t>(header[6]) << 8 |
                                  static_cast<uint32_t>(header[7]) << 0);
          uint32_t jobId = ntohl(static_cast<uint32_t>(header[8]) << 24 |
                                 static_cast<uint32_t>(header[9]) << 16 |
                                 static_cast<uint32_t>(header[10]) << 8 |
                                 static_cast<uint32_t>(header[11]) << 0);

          JobFile &file = files[fileId];
          if (file.get() == nullptr) {
            std::cout << "Connection failed (client named bad fileId)\n";
            goto outer_continue;
          }

          uint32_t inLen =
              *reinterpret_cast<uint32_t *>(dlsym(file.get(), "jobInLen"));
          uint32_t outLen =
              *reinterpret_cast<uint32_t *>(dlsym(file.get(), "jobOutLen"));
          void (*function)(void *, void *) =
              reinterpret_cast<void (*)(void *, void *)>(
                  dlsym(file.get(), "job"));

          std::vector<unsigned char> inBufferCT(
              inLen + crypto_secretstream_xchacha20poly1305_ABYTES);
          if (readAll(fd.get(), inBufferCT.data(), inBufferCT.size()) != 0) {
            std::cout << "Connection failed (IO error)\n";
            goto outer_continue;
          }
          std::vector<unsigned char> inBuffer(inLen);
          if (crypto_secretstream_xchacha20poly1305_pull(
                  readState.get(), inBuffer.data(), nullptr, nullptr,
                  inBufferCT.data(), inBufferCT.size(), nullptr, 0) != 0) {
            std::cout << "Connection failed (authentication error)\n";
            goto outer_continue;
          }

          std::thread jobRunner(
              [jobId, outLen, function, &fd,
               &writeState](std::vector<unsigned char> inBuffer) {
                std::vector<unsigned char> outBuffer(outLen);
                function(inBuffer.data(), outBuffer.data());

                std::array<unsigned char, 16> header;
                header[0] = 'f';
                uint32_t netJobId = htonl(jobId);
                memcpy(header.data() + 4, &netJobId, 4);
                uint32_t netOutLen = htonl(outLen);
                memcpy(header.data() + 8, &netOutLen, 4);

                std::array<unsigned char,
                           16 + crypto_secretstream_xchacha20poly1305_ABYTES>
                    headerCT;
                crypto_secretstream_xchacha20poly1305_push(
                    writeState.get(), headerCT.data(), nullptr, header.data(),
                    header.size(), nullptr, 0, 0);
                if (writeAll(fd.get(), headerCT.data(), headerCT.size()) != 0)
                  return;

                std::vector<unsigned char> outBufferCT(
                    outLen + crypto_secretstream_xchacha20poly1305_ABYTES);
                crypto_secretstream_xchacha20poly1305_push(
                    writeState.get(), outBufferCT.data(), nullptr,
                    outBuffer.data(), outBuffer.size(), nullptr, 0, 0);
                if (writeAll(fd.get(), outBufferCT.data(),
                             outBufferCT.size()) != 0)
                  return;
              },
              inBuffer);
          jobRunner.detach();

          break;
        }
        default: {
          // bad client!
          std::cout << "Connection failed (protocol error)\n";
          goto outer_continue;
        }
      }
    }
  outer_continue:;
  }

  return EXIT_SUCCESS;
}