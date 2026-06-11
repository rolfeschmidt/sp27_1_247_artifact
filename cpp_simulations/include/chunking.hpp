#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <vector>

namespace smsim {

struct Chunk {
    std::uint64_t stream_id = 0;
    std::uint64_t index = 0;
    std::vector<std::uint8_t> bytes;

    auto operator<=>(const Chunk&) const = default;
};

class Encoder {
public:
    Encoder() = default;

    Encoder(std::uint64_t stream_id, std::vector<std::uint8_t> bytes)
        : stream_id_(stream_id), bytes_(std::move(bytes)) {}

    Chunk next_chunk() {
        return Chunk{stream_id_, emitted_++, bytes_};
    }

    std::uint64_t emitted() const {
        return emitted_;
    }

private:
    std::uint64_t stream_id_ = 0;
    std::uint64_t emitted_ = 0;
    std::vector<std::uint8_t> bytes_;
};

class Decoder {
public:
    explicit Decoder(std::uint64_t chunks_needed)
        : chunks_needed_(chunks_needed) {}

    void add(const Chunk& chunk) {
        if (!stream_id_) {
            stream_id_ = chunk.stream_id;
            bytes_ = chunk.bytes;
        }
        if (*stream_id_ != chunk.stream_id) {
            return;
        }
        seen_.insert(chunk.index);
    }

    std::optional<std::vector<std::uint8_t>> message() const {
        if (seen_.size() >= chunks_needed_) {
            return bytes_;
        }
        return std::nullopt;
    }

private:
    std::uint64_t chunks_needed_ = 1;
    std::optional<std::uint64_t> stream_id_;
    std::set<std::uint64_t> seen_;
    std::vector<std::uint8_t> bytes_;
};

} // namespace smsim
