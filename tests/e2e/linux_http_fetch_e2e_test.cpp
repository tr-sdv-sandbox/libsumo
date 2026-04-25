/**
 * @file linux_http_fetch_e2e_test.cpp
 * @brief T1.5 — libcurl-backed HTTP fetch in platform_linux.
 *
 * Spins up a tiny in-process HTTP/1.0 server bound to 127.0.0.1 on an
 * ephemeral port, serves a fixture envelope's ciphertext under a known
 * path, and runs sumo_process_image with `http://...` in the manifest.
 * The orchestrator drives plat_fetch → libcurl → server, decrypts the
 * payload, and writes it to a staging file we can compare against the
 * plaintext.
 *
 * Coexists with T1.4 file:// tests — same backend, different URI scheme.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" {
#include "sumo/orchestrator.h"
#include "sumo/platform_linux.h"
#include "sumo/validator.h"
}

#include "e2e_test_helpers.h"

namespace {

class TmpDir {
public:
    TmpDir() {
        char tmpl[] = "/tmp/sumo_t15_XXXXXX";
        char *p = mkdtemp(tmpl);
        if (!p) std::abort();
        path_ = p;
    }
    ~TmpDir() {
        std::string cmd = "rm -rf " + path_;
        int rc = system(cmd.c_str());
        (void)rc;
    }
    const std::string &path() const { return path_; }
private:
    std::string path_;
};

/* Minimal HTTP/1.0 server: accepts one connection, reads (and discards)
 * the request up through "\r\n\r\n", writes a response with the supplied
 * body, then closes. Returns 0 on success. */
class OneShotHttpServer {
public:
    OneShotHttpServer(std::vector<uint8_t> body)
        : body_(std::move(body)) {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) std::abort();
        int reuse = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR,
                     &reuse, sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  /* ephemeral */
        if (::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr),
                   sizeof(addr)) < 0) std::abort();
        if (::listen(listen_fd_, 1) < 0) std::abort();

        sockaddr_in bound{};
        socklen_t blen = sizeof(bound);
        ::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&bound), &blen);
        port_ = ntohs(bound.sin_port);

        thread_ = std::thread([this] { Run(); });
    }

    ~OneShotHttpServer() {
        Shutdown();
    }

    void Shutdown() {
        if (listen_fd_ >= 0) { ::close(listen_fd_); listen_fd_ = -1; }
        if (thread_.joinable()) thread_.join();
    }

    int port() const { return port_; }

private:
    void Run() {
        int conn = ::accept(listen_fd_, nullptr, nullptr);
        if (conn < 0) return;

        /* Drain request headers. */
        char buf[2048];
        std::string req;
        while (req.find("\r\n\r\n") == std::string::npos) {
            ssize_t n = ::read(conn, buf, sizeof(buf));
            if (n <= 0) break;
            req.append(buf, n);
            if (req.size() > 8192) break;  /* paranoia */
        }

        char hdr[160];
        int hlen = std::snprintf(hdr, sizeof(hdr),
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            body_.size());
        (void)::write(conn, hdr, hlen);
        (void)::write(conn, body_.data(), body_.size());
        ::close(conn);
    }

    std::vector<uint8_t> body_;
    std::thread thread_;
    int listen_fd_ = -1;
    int port_      = 0;
};

}  // namespace

TEST(LinuxHttpFetch, ProcessImageOverHttp) {
    /* 16 KB plaintext for variety. */
    std::vector<uint8_t> firmware(16 * 1024);
    for (size_t i = 0; i < firmware.size(); i++)
        firmware[i] = static_cast<uint8_t>((i * 7) ^ 0xC3);

    /* Build the encrypted bits up front so we know the ciphertext. */
    sumo::CoseKey enc_key = sumo::CoseKey::FromCoseKeyBytes(
        {kA128kwCoseKey, sizeof(kA128kwCoseKey)});
    std::vector<sumo::Recipient> rcpts;
    rcpts.push_back({std::move(enc_key), {}});
    auto enc = sumo::EncryptFirmware(firmware, rcpts);

    /* Serve the ciphertext on 127.0.0.1:<ephemeral>/fw.enc */
    OneShotHttpServer server(enc.ciphertext);

    char uri[64];
    std::snprintf(uri, sizeof(uri), "http://127.0.0.1:%d/fw.enc",
                  server.port());

    /* Build the manifest pointing at the live URL. */
    auto digest = sumo::Sha256(firmware);
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});
    auto envelope = sumo::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(42)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri(uri)
        .SetEncryptionInfo(enc.encryption_info)
        .Build(signing_key);

    /* Wire up: validator + Linux platform_ops rooted in tmpdir. */
    TmpDir d;
    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    ASSERT_EQ(sumo_validate_envelope(v, envelope.data(), envelope.size(),
                                     0, &m),
              SUMO_OK);

    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    EXPECT_EQ(sumo_process_image(v, m, ops), SUMO_OK);

    /* Find the staging file and confirm content matches plaintext. */
    std::string staging = d.path() + "/staging";
    DIR *dir = opendir(staging.c_str());
    ASSERT_NE(dir, nullptr);
    struct dirent *de;
    std::string staging_file;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        staging_file = staging + "/" + de->d_name;
        break;
    }
    closedir(dir);
    ASSERT_FALSE(staging_file.empty());

    std::ifstream f(staging_file, std::ios::binary);
    std::istreambuf_iterator<char> begin(f), end;
    std::vector<uint8_t> on_disk(begin, end);
    EXPECT_EQ(on_disk, firmware);

    sumo_linux_platform_ops_free(ops);
    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST(LinuxHttpFetch, FetchFailsWhenServerUnreachable) {
    /* Pick a port no one listens on (assumes high port is free). */
    TmpDir d;
    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    const char *uri = "http://127.0.0.1:1/never";  /* port 1 is privileged + closed */
    uint8_t buf[64];
    size_t got = 0;
    EXPECT_NE(ops->fetch(uri, std::strlen(uri),
                         buf, sizeof(buf), &got, ops->user_ctx),
              0);

    sumo_linux_platform_ops_free(ops);
}

TEST(LinuxHttpFetch, FetchFailsOnHttp404) {
    /* Server that always returns 404 — libcurl with FAILONERROR maps
     * that to an error. */
    auto ServerThread = [](int listen_fd) {
        int conn = ::accept(listen_fd, nullptr, nullptr);
        if (conn < 0) return;
        char buf[2048];
        std::string req;
        while (req.find("\r\n\r\n") == std::string::npos) {
            ssize_t n = ::read(conn, buf, sizeof(buf));
            if (n <= 0) break;
            req.append(buf, n);
        }
        const char *resp =
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        (void)::write(conn, resp, std::strlen(resp));
        ::close(conn);
    };

    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listen_fd, 0);
    int reuse = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listen_fd, reinterpret_cast<sockaddr *>(&addr),
                     sizeof(addr)), 0);
    ASSERT_EQ(::listen(listen_fd, 1), 0);

    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    ::getsockname(listen_fd, reinterpret_cast<sockaddr *>(&bound), &blen);
    int port = ntohs(bound.sin_port);

    std::thread srv(ServerThread, listen_fd);

    TmpDir d;
    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    char uri[64];
    std::snprintf(uri, sizeof(uri), "http://127.0.0.1:%d/missing", port);
    uint8_t buf[64];
    size_t got = 0;
    EXPECT_NE(ops->fetch(uri, std::strlen(uri),
                         buf, sizeof(buf), &got, ops->user_ctx),
              0);

    sumo_linux_platform_ops_free(ops);
    ::close(listen_fd);
    srv.join();
}
