#pragma once

#include "mock_unikem.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace smsim {

enum class MockRkemMode {
    Nonupdated,
    Updated,
    Ct0Only,
};

struct MockRkemEncapsulationKey {
    std::uint64_t id = 0;
    MockRkemMode mode = MockRkemMode::Nonupdated;

    auto operator<=>(const MockRkemEncapsulationKey&) const = default;
};

struct MockRkemDecapsulationKey {
    std::uint64_t id = 0;
    MockRkemMode mode = MockRkemMode::Nonupdated;

    auto operator<=>(const MockRkemDecapsulationKey&) const = default;
};

struct MockRkemCiphertext {
    std::uint64_t id = 0;

    auto operator<=>(const MockRkemCiphertext&) const = default;
};

struct MockRkemSharedSecret {
    std::uint64_t ct_id = 0;
    std::uint64_t key_id = 0;
    MockRkemMode mode_used = MockRkemMode::Nonupdated;

    auto operator<=>(const MockRkemSharedSecret&) const = default;
};

struct MockRkemKeyPair {
    MockRkemEncapsulationKey ek;
    MockRkemDecapsulationKey dk;
};

struct MockRkemEncapsulationResult {
    MockRkemCiphertext ct;
    MockRkemSharedSecret secret;
    MockRkemDecapsulationKey updated_dk;
};

struct MockRkemDecapsulationResult {
    MockRkemSharedSecret secret;
    MockRkemEncapsulationKey updated_ek;
};

inline std::vector<std::uint8_t> encode_mock_rkem_key(MockRkemEncapsulationKey ek) {
    auto bytes = encode_u64(ek.id);
    bytes.push_back(static_cast<std::uint8_t>(ek.mode));
    return bytes;
}

inline MockRkemEncapsulationKey decode_mock_rkem_key(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != 9) {
        throw std::runtime_error("bad mock RKEM EK encoding");
    }
    std::vector<std::uint8_t> id_bytes(bytes.begin(), bytes.begin() + 8);
    auto mode = static_cast<MockRkemMode>(bytes[8]);
    return {decode_u64(id_bytes), mode};
}

inline std::vector<std::uint8_t> encode_mock_rkem_ciphertext(MockRkemCiphertext ct) {
    return encode_u64(ct.id);
}

inline MockRkemCiphertext decode_mock_rkem_ciphertext(const std::vector<std::uint8_t>& bytes) {
    return {decode_u64(bytes)};
}

class MockRkem {
public:
    static MockRkemKeyPair initial_updated_keypair() {
        return {{0, MockRkemMode::Updated}, {0, MockRkemMode::Updated}};
    }

    MockRkemKeyPair keygen(MockRkemMode mode) {
        auto id = next_key_id_++;
        return {{id, mode}, {id, mode}};
    }

    MockRkemEncapsulationResult encaps(MockRkemEncapsulationKey ek,
                                       MockRkemDecapsulationKey dk_to_update) {
        auto ct = MockRkemCiphertext{next_ct_id_++};
        auto mode_used = ek.mode == MockRkemMode::Updated ? MockRkemMode::Updated
                                                          : MockRkemMode::Nonupdated;
        return {
            ct,
            {ct.id, ek.id, mode_used},
            {dk_to_update.id, MockRkemMode::Updated},
        };
    }

    MockRkemDecapsulationResult decaps(MockRkemDecapsulationKey dk, MockRkemCiphertext ct,
                                       MockRkemEncapsulationKey ek_to_update) const {
        auto mode_used = dk.mode == MockRkemMode::Updated ? MockRkemMode::Updated
                                                          : MockRkemMode::Nonupdated;
        return {
            {ct.id, dk.id, mode_used},
            {ek_to_update.id, MockRkemMode::Updated},
        };
    }

private:
    std::uint64_t next_key_id_ = 1;
    std::uint64_t next_ct_id_ = 1;
};

} // namespace smsim
