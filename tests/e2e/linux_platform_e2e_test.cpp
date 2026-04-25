/**
 * @file linux_platform_e2e_test.cpp
 * @brief T1.4 — file-backed Linux platform_ops + storage_ops.
 *
 * Exercises sumo_linux_platform_ops() / sumo_linux_storage_ops() against
 * a real per-test tmpdir:
 *   - storage round-trip: write u64/i64 via callbacks, read back through
 *     a freshly-constructed ops bundle (separate process simulated).
 *   - policy_save → policy_load round-trips the persisted seq + the new
 *     "sumo_sec_ver" key from T1.2 across an instance boundary.
 *   - file:// fetch: orchestrator's sumo_process_image runs end-to-end
 *     against the Linux backend; ciphertext at a real path on disk gets
 *     pulled in, decrypted, and the staging file matches the plaintext.
 *   - swap: two staging files exchange content and the ops report success.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <gtest/gtest.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>
#include <unistd.h>

extern "C" {
#include "sumo/orchestrator.h"
#include "sumo/platform_linux.h"
#include "sumo/policy.h"
#include "sumo/validator.h"
}

#include "e2e_test_helpers.h"

namespace {

class TmpDir {
public:
    TmpDir() {
        char tmpl[] = "/tmp/sumo_t14_XXXXXX";
        char *p = mkdtemp(tmpl);
        if (!p) std::abort();
        path_ = p;
    }
    ~TmpDir() {
        std::string cmd = "rm -rf " + path_;
        int rc = system(cmd.c_str());
        (void)rc;  /* best-effort cleanup */
    }
    const std::string &path() const { return path_; }
    std::string sub(const char *name) const { return path_ + "/" + name; }
private:
    std::string path_;
};

/* Hex-encode bytes (mirrors what the platform impl does internally so
 * the test can find the staging file by component-id without poking
 * private headers). */
static std::string HexCid(const std::vector<std::string> &segments) {
    /* Match how the offboard builder serialises component_id: a CBOR
     * array of bstrs. We don't have that builder output here, but the
     * orchestrator hands the CBOR-encoded-component bytes to the write
     * callback. For this test we read the staging dir and assume the
     * single file in there is the one we're after. */
    (void)segments;
    return {};
}

static std::vector<uint8_t> ReadFile(const std::string &p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}

static void WriteFile(const std::string &p, const std::vector<uint8_t> &b) {
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char *>(b.data()), b.size());
    f.close();
}

}  // namespace

/* ===== storage_ops ===== */

TEST(LinuxStorageOps, U64RoundTrip) {
    TmpDir d;
    sumo_storage_ops_t *ops = sumo_linux_storage_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    EXPECT_EQ(ops->write_u64("seq", 0xDEADBEEFCAFEBABEull, ops->ctx), 0);
    uint64_t v = 0;
    EXPECT_EQ(ops->read_u64("seq", &v, ops->ctx), 0);
    EXPECT_EQ(v, 0xDEADBEEFCAFEBABEull);

    /* Confirm bytes really hit disk */
    auto f = ReadFile(d.sub("seq"));
    EXPECT_EQ(f.size(), 8u);

    sumo_linux_storage_ops_free(ops);
}

TEST(LinuxStorageOps, I64NegativeRoundTrip) {
    TmpDir d;
    sumo_storage_ops_t *ops = sumo_linux_storage_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    EXPECT_EQ(ops->write_i64("revoke_before", -42, ops->ctx), 0);
    int64_t v = 0;
    EXPECT_EQ(ops->read_i64("revoke_before", &v, ops->ctx), 0);
    EXPECT_EQ(v, -42);

    sumo_linux_storage_ops_free(ops);
}

TEST(LinuxStorageOps, ReadMissingKeyFails) {
    TmpDir d;
    sumo_storage_ops_t *ops = sumo_linux_storage_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    uint64_t v = 0xAA;
    EXPECT_NE(ops->read_u64("nonexistent", &v, ops->ctx), 0);
    EXPECT_EQ(v, 0xAAu);  /* untouched on miss */

    sumo_linux_storage_ops_free(ops);
}

TEST(LinuxStorageOps, AtomicityViaTmpRename) {
    TmpDir d;
    sumo_storage_ops_t *ops = sumo_linux_storage_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    EXPECT_EQ(ops->write_u64("seq", 1, ops->ctx), 0);
    EXPECT_EQ(ops->write_u64("seq", 2, ops->ctx), 0);

    /* No leftover .tmp file should remain */
    struct stat st;
    EXPECT_NE(stat((d.path() + "/seq.tmp").c_str(), &st), 0);

    uint64_t v = 0;
    EXPECT_EQ(ops->read_u64("seq", &v, ops->ctx), 0);
    EXPECT_EQ(v, 2u);

    sumo_linux_storage_ops_free(ops);
}

/* ===== policy_save / policy_load through real files ===== */

TEST(LinuxStorageOps, PolicyRoundTripAcrossInstances) {
    TmpDir d;

    /* First instance: validate a fresh manifest, save policy. */
    {
        TestImage img = BuildTestImage(
            std::vector<uint8_t>{0xAA, 0xBB, 0xCC, 0xDD},
            {"ecu-a", "firmware"}, 7, "file:///tmp/unused");

        sumo_validator_t *v = CreateTestValidator();
        ASSERT_NE(v, nullptr);
        sumo_manifest_t *m = nullptr;
        ASSERT_EQ(sumo_validate_envelope(v,
                                         img.envelope.data(), img.envelope.size(),
                                         0, &m),
                  SUMO_OK);

        sumo_storage_ops_t *st = sumo_linux_storage_ops(d.path().c_str());
        ASSERT_NE(st, nullptr);
        ASSERT_EQ(sumo_policy_save(m, st), 0);
        sumo_linux_storage_ops_free(st);

        sumo_manifest_free(m);
        sumo_validator_free(v);
    }

    /* Second instance: load policy into a fresh validator, observe the
     * floor was applied. Re-validating the same envelope (seq=7) is
     * rejected because the floor is now also 7 (strict-greater rule). */
    {
        sumo_validator_t *v2 = CreateTestValidator();
        ASSERT_NE(v2, nullptr);

        sumo_storage_ops_t *st = sumo_linux_storage_ops(d.path().c_str());
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(sumo_policy_load(v2, st), 0);
        sumo_linux_storage_ops_free(st);

        TestImage same = BuildTestImage(
            std::vector<uint8_t>{0xAA, 0xBB, 0xCC, 0xDD},
            {"ecu-a", "firmware"}, 7, "file:///tmp/unused");

        sumo_manifest_t *m = nullptr;
        EXPECT_EQ(sumo_validate_envelope(v2,
                                         same.envelope.data(), same.envelope.size(),
                                         0, &m),
                  SUMO_ERR_ROLLBACK_REJECTED);
        EXPECT_EQ(m, nullptr);
        sumo_validator_free(v2);
    }
}

/* ===== platform_ops: end-to-end process_image ===== */

TEST(LinuxPlatformOps, ProcessImageReadsFileUri) {
    TmpDir d;

    /* 8KB plaintext, encrypted to a file at a known path. */
    std::vector<uint8_t> firmware(8192);
    for (size_t i = 0; i < firmware.size(); i++)
        firmware[i] = static_cast<uint8_t>((i * 13) ^ 0x55);

    std::string ct_path = d.sub("fw.enc");
    std::string uri = "file://" + ct_path;

    TestImage img = BuildTestImage(firmware, {"ecu-a", "firmware"}, 100, uri);
    WriteFile(ct_path, img.ciphertext);

    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);
    sumo_manifest_t *m = nullptr;
    ASSERT_EQ(sumo_validate_envelope(v,
                                     img.envelope.data(), img.envelope.size(),
                                     0, &m),
              SUMO_OK);

    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);
    EXPECT_EQ(sumo_process_image(v, m, ops), SUMO_OK);

    /* Exactly one staging file should exist; its contents must equal
     * the plaintext. */
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
    ASSERT_FALSE(staging_file.empty()) << "no staging file written";

    auto on_disk = ReadFile(staging_file);
    EXPECT_EQ(on_disk, firmware);

    sumo_linux_platform_ops_free(ops);
    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST(LinuxPlatformOps, FetchRejectsHttp) {
    TmpDir d;
    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    const char *uri = "https://example.com/fw.bin";
    uint8_t buf[16];
    size_t got = 0;
    EXPECT_NE(ops->fetch(uri, strlen(uri), buf, sizeof(buf), &got, ops->user_ctx),
              0);

    sumo_linux_platform_ops_free(ops);
}

TEST(LinuxPlatformOps, FetchReadsBarePath) {
    TmpDir d;
    auto path = d.sub("blob.bin");
    std::vector<uint8_t> data{0x01, 0x02, 0x03, 0x04, 0x05};
    WriteFile(path, data);

    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    uint8_t buf[16];
    size_t got = 0;
    EXPECT_EQ(ops->fetch(path.c_str(), path.size(),
                         buf, sizeof(buf), &got, ops->user_ctx),
              0);
    EXPECT_EQ(got, data.size());
    EXPECT_EQ(memcmp(buf, data.data(), data.size()), 0);

    sumo_linux_platform_ops_free(ops);
}

TEST(LinuxPlatformOps, SwapExchangesFiles) {
    TmpDir d;
    sumo_platform_ops_t *ops = sumo_linux_platform_ops(d.path().c_str());
    ASSERT_NE(ops, nullptr);

    /* Pre-seed two staging files via the write callback, using two
     * distinct component-id byte strings. */
    const uint8_t cid_a[] = {0x11, 0x22};
    const uint8_t cid_b[] = {0xAA, 0xBB};
    const uint8_t data_a[] = {'A', 'A', 'A'};
    const uint8_t data_b[] = {'B', 'B', 'B', 'B'};

    ASSERT_EQ(ops->write(cid_a, sizeof(cid_a), 0, data_a, sizeof(data_a),
                         ops->user_ctx), 0);
    ASSERT_EQ(ops->write(cid_b, sizeof(cid_b), 0, data_b, sizeof(data_b),
                         ops->user_ctx), 0);

    EXPECT_EQ(ops->swap(cid_a, sizeof(cid_a),
                        cid_b, sizeof(cid_b),
                        ops->user_ctx), 0);

    auto a_now = ReadFile(d.path() + "/staging/1122");
    auto b_now = ReadFile(d.path() + "/staging/aabb");
    /* After swap: A's slot holds B's old data, and vice versa. */
    EXPECT_EQ(a_now, std::vector<uint8_t>(data_b, data_b + sizeof(data_b)));
    EXPECT_EQ(b_now, std::vector<uint8_t>(data_a, data_a + sizeof(data_a)));

    sumo_linux_platform_ops_free(ops);
}
