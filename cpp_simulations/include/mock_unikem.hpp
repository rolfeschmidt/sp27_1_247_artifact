#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace smsim {

inline std::vector<std::uint8_t> encode_u64(std::uint64_t value) {
    std::vector<std::uint8_t> out(8);
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(7 - i)] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
    }
    return out;
}

inline std::uint64_t decode_u64(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != 8) {
        throw std::runtime_error("bad mock integer encoding");
    }
    std::uint64_t value = 0;
    for (auto byte : bytes) {
        value = (value << 8) | byte;
    }
    return value;
}

struct MockEncapsulationKey {
    std::uint64_t id = 0;

    auto operator<=>(const MockEncapsulationKey&) const = default;
};

struct MockSecret {
    std::uint64_t id = 0;

    auto operator<=>(const MockSecret&) const = default;
};

struct MockSharedSecret {
    std::uint64_t ek_id = 0;
    std::uint64_t ct0_id = 0;

    auto operator<=>(const MockSharedSecret&) const = default;
};

struct MockKeyPair {
    MockEncapsulationKey ek;
    MockSecret dk;
};

struct MockEncapsResult {
    std::vector<std::uint8_t> ct1;
    MockSharedSecret secret;
};

class MockUniKem {
public:
    MockKeyPair keygen() {
        auto id = next_id_++;
        return {{id}, {id}};
    }

    std::pair<MockSecret, std::vector<std::uint8_t>> enc_pk() {
        auto id = next_id_++;
        return {{id}, encode_u64(id)};
    }

    MockEncapsResult enc_ct(MockEncapsulationKey ek, MockSecret es) {
        auto ct1 = encode_u64((ek.id << 32) ^ es.id);
        return {ct1, {ek.id, es.id}};
    }

    MockSharedSecret decaps(MockSecret dk, const std::vector<std::uint8_t>& ct0,
                            const std::vector<std::uint8_t>& ct1) const {
        auto ct0_id = decode_u64(ct0);
        auto packed = decode_u64(ct1);
        auto ek_id = packed >> 32;
        auto ct1_id = packed & 0xffffffff;
        if (dk.id != ek_id || ct0_id != ct1_id) {
            throw std::runtime_error("mock decapsulation mismatch");
        }
        return {ek_id, ct0_id};
    }

private:
    std::uint64_t next_id_ = 1;
};

} // namespace smsim
