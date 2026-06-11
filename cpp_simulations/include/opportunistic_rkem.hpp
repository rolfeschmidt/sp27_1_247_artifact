#pragma once

#include "chunking.hpp"
#include "ids.hpp"
#include "mock_rkem.hpp"
#include "secure_messaging.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace smsim {

struct OppRkemMessage {
    enum class ChunkType {
        Ek,
        Ct,
    };

    std::optional<ChunkType> chunk_type;
    std::optional<Chunk> chunk;
    Epoch ct_send_epoch = 0;
    Epoch ek_send_epoch = 0;
    Epoch ct_recv_epoch = 0;
    Epoch ek_recv_epoch = 0;
    std::uint64_t ct_chunks_received = 0;
    std::uint64_t ek_chunks_received = 0;
    Epoch using_epoch = 0;

    auto operator<=>(const OppRkemMessage&) const = default;
};

class OppRkem {
public:
    using OutputKey = MockRkemSharedSecret;
    using Message = OppRkemMessage;
    using SendResult = SparseSendResult<OutputKey, Message>;
    using ReceiveResult = SparseReceiveResult<OutputKey>;

    enum class InvalidEventPolicy {
        Ignore,
        Throw,
    };

    static OppRkem init_alice(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        auto initial = MockRkem::initial_updated_keypair();
        RequestorState req;
        req.receiving_epoch = 2;
        req.sending_epoch = 2;
        req.ct_in = Decoder(kCtChunks);

        ResponderState rsp;
        rsp.sending_epoch = 1;
        rsp.receiving_epoch = 3;
        rsp.ek_in = Decoder(kEkChunks);
        rsp.eks[3] = initial.ek;

        AckSet acks;
        acks.insert_default_rsp_done(1);
        acks.insert_default_req_done(2);
        acks.set_ek_received(3, infinite_chunks());

        return OppRkem(std::move(req), std::move(rsp), std::move(acks), policy);
    }

    static OppRkem init_bob(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        auto initial = MockRkem::initial_updated_keypair();
        RequestorState req;
        req.receiving_epoch = 1;
        req.sending_epoch = 3;
        req.ct_in = Decoder(kCtChunks);
        req.dks[3] = initial.dk;

        ResponderState rsp;
        rsp.sending_epoch = 2;
        rsp.receiving_epoch = 2;
        rsp.ek_in = Decoder(kEkChunks);

        AckSet acks;
        acks.insert_default_rsp_done(2);
        acks.insert_default_req_done(1);
        acks.set_ek_received(3, infinite_chunks());

        return OppRkem(std::move(req), std::move(rsp), std::move(acks), policy);
    }

    static SckaOutputId initial_epoch() {
        return message_output(0);
    }

    SendResult send() {
        if (should_sample_keypair() && !req_.ek_out) {
            sample_keypair();
        }

        std::optional<std::pair<SckaOutputId, OutputKey>> output_key;
        if (should_sample_ct() && !rsp_.ct_out) {
            output_key = sample_ciphertext();
        }

        auto maybe_chunk = next_chunk();
        if (maybe_chunk) {
            if (maybe_chunk->first == Message::ChunkType::Ek) {
                acks_.increment_ek_sent(req_.sending_epoch);
            } else {
                acks_.increment_ct_sent(rsp_.sending_epoch);
            }
        }

        mutual_send_epoch_ = acks_.latest_mutual_epoch();
        Message message;
        if (maybe_chunk) {
            message.chunk_type = maybe_chunk->first;
            message.chunk = maybe_chunk->second;
        }
        message.ct_send_epoch = rsp_.sending_epoch;
        message.ek_send_epoch = req_.sending_epoch;
        message.ct_recv_epoch = reported_ct_receive_epoch();
        message.ek_recv_epoch = reported_ek_receive_epoch();
        message.ct_chunks_received = acks_.ct_received_count(message.ct_recv_epoch);
        message.ek_chunks_received = acks_.ek_received_count(message.ek_recv_epoch);
        message.using_epoch = mutual_send_epoch_;

        // Rust RkemMessagingScka queues outputs until the mutual epoch catches up.
        // This framework keeps message-epoch selection in SecureMessaging via
        // sending_output / receiving_output, so OppRkem emits derived keys immediately.
        return {output_key, current_message_output(), message};
    }

    ReceiveResult receive(const Message& message, SckaOutputId encrypted_output) {
        acks_.set_ek_received(message.ek_recv_epoch, message.ek_chunks_received);
        acks_.set_ct_received(message.ct_recv_epoch, message.ct_chunks_received);
        skip_completed_receive_epochs();

        auto output_key = process_chunk(message);

        if (acks_.ct_received(rsp_.sending_epoch)) {
            rsp_.ct_out = std::nullopt;
        }
        if (acks_.ek_received(req_.sending_epoch)) {
            req_.ek_out = std::nullopt;
        }

        mutual_send_epoch_ = std::max(mutual_send_epoch_, message.using_epoch);
        mutual_receive_epoch_ = std::max(mutual_receive_epoch_, message.using_epoch);
        return {output_key, encrypted_output};
    }

    std::vector<ProtocolSecretPattern> compromised_secret_patterns() const {
        std::vector<ProtocolSecretPattern> patterns;
        auto add = [&](Epoch epoch) {
            patterns.push_back(scka_secret(OppUniKemOutputPattern{epoch}));
        };

        for (const auto& [epoch, dk] : req_.dks) {
            add(epoch);
            if (dk.mode == MockRkemMode::Nonupdated && epoch > 0) {
                add(epoch - 1);
            }
        }
        std::sort(patterns.begin(), patterns.end());
        patterns.erase(std::unique(patterns.begin(), patterns.end()), patterns.end());
        return patterns;
    }

    std::optional<MessageEpoch> last_emitted_epoch_id() const {
        return last_emitted_id_;
    }

    const std::vector<MessageEpoch>& emitted_epoch_ids() const {
        return emitted_ids_;
    }

    std::string_view role_state_name() const {
        if (req_.ek_out && rsp_.ct_out) {
            return "SendEkSendCt";
        }
        if (req_.ek_out) {
            return "SendEk";
        }
        if (rsp_.ct_out) {
            return "SendCt";
        }
        return "Idle";
    }

private:
    static constexpr std::uint64_t kEkChunks = 39;
    static constexpr std::uint64_t kCtChunks = 3;

    struct RequestorState {
        Epoch receiving_epoch = 0;
        Epoch sending_epoch = 0;
        std::map<Epoch, MockRkemDecapsulationKey> dks;
        Decoder ct_in{1};
        std::optional<Encoder> ek_out;
    };

    struct ResponderState {
        Epoch sending_epoch = 0;
        Epoch receiving_epoch = 0;
        std::map<Epoch, MockRkemEncapsulationKey> eks;
        Decoder ek_in{1};
        std::optional<Encoder> ct_out;
    };

    struct Ack {
        std::uint64_t ct_sent = 0;
        std::uint64_t ek_received = 0;
        std::uint64_t ek_sent = 0;
        std::uint64_t ct_received = 0;
    };

    class AckSet {
    public:
        void insert_default_req_done(Epoch epoch) {
            acks_[epoch] = {infinite_chunks(), infinite_chunks(), infinite_chunks(), infinite_chunks()};
        }

        void insert_default_rsp_done(Epoch epoch) {
            acks_[epoch] = {infinite_chunks(), infinite_chunks(), infinite_chunks(), infinite_chunks()};
        }

        bool ek_received(Epoch epoch) const {
            auto it = acks_.find(epoch);
            return it != acks_.end() && it->second.ek_received >= kEkChunks;
        }

        bool ct_received(Epoch epoch) const {
            auto it = acks_.find(epoch);
            return it != acks_.end() && it->second.ct_received >= kCtChunks;
        }

        Epoch latest_mutual_epoch() const {
            if (acks_.empty()) {
                return 0;
            }
            auto last = acks_.rbegin()->first;
            for (Epoch epoch = last; epoch > 0; --epoch) {
                auto prev = acks_.find(epoch - 1);
                auto curr = acks_.find(epoch);
                if (prev != acks_.end() && curr != acks_.end()
                    && prev->second.ct_received >= kCtChunks
                    && curr->second.ct_received >= kCtChunks) {
                    return epoch;
                }
            }
            return 0;
        }

        std::uint64_t ct_received_count(Epoch epoch) const {
            auto it = acks_.find(epoch);
            return it == acks_.end() ? 0 : it->second.ct_received;
        }

        std::uint64_t ek_received_count(Epoch epoch) const {
            auto it = acks_.find(epoch);
            return it == acks_.end() ? 0 : it->second.ek_received;
        }

        void set_ek_received(Epoch epoch, std::uint64_t count) {
            auto& ack = acks_[epoch];
            ack.ek_received = std::max(ack.ek_received, count);
        }

        void set_ct_received(Epoch epoch, std::uint64_t count) {
            auto& ack = acks_[epoch];
            ack.ct_received = std::max(ack.ct_received, count);
        }

        void increment_ek_sent(Epoch epoch) {
            auto& ack = acks_[epoch];
            if (ack.ek_sent < infinite_chunks()) {
                ++ack.ek_sent;
            }
        }

        void increment_ct_sent(Epoch epoch) {
            auto& ack = acks_[epoch];
            if (ack.ct_sent < infinite_chunks()) {
                ++ack.ct_sent;
            }
        }

        void increment_ek_received(Epoch epoch) {
            auto& ack = acks_[epoch];
            if (ack.ek_received < infinite_chunks()) {
                ++ack.ek_received;
            }
        }

        void increment_ct_received(Epoch epoch) {
            auto& ack = acks_[epoch];
            if (ack.ct_received < infinite_chunks()) {
                ++ack.ct_received;
            }
        }

    private:
        std::map<Epoch, Ack> acks_;
    };

    explicit OppRkem(RequestorState req, ResponderState rsp, AckSet acks,
                     InvalidEventPolicy policy)
        : req_(std::move(req)),
          rsp_(std::move(rsp)),
          acks_(std::move(acks)),
          invalid_event_policy_(policy) {}

    static constexpr std::uint64_t infinite_chunks() {
        return std::numeric_limits<std::uint64_t>::max();
    }

    bool should_sample_keypair() const {
        return acks_.ct_received(rsp_.sending_epoch)
            && acks_.ek_received(req_.sending_epoch)
            && req_.sending_epoch > 0
            && acks_.ct_received(req_.sending_epoch - 1);
    }

    bool can_sample_ct(Epoch epoch) const {
        return epoch > 0 && acks_.ct_received(epoch - 1) && acks_.ek_received(epoch);
    }

    bool should_sample_ct() const {
        return can_sample_ct(rsp_.sending_epoch + 2)
            && acks_.ek_received(rsp_.sending_epoch + 3);
    }

    void skip_completed_receive_epochs() {
        while (acks_.ct_received(req_.receiving_epoch)) {
            req_.receiving_epoch += 2;
            req_.ct_in = Decoder(kCtChunks);
        }
        while (acks_.ek_received(rsp_.receiving_epoch)) {
            rsp_.receiving_epoch += 2;
            rsp_.ek_in = Decoder(kEkChunks);
        }
    }

    Epoch reported_ct_receive_epoch() const {
        if (acks_.ct_received(req_.receiving_epoch)) {
            return req_.receiving_epoch;
        }
        if (req_.receiving_epoch >= 2 && acks_.ct_received(req_.receiving_epoch - 2)) {
            return req_.receiving_epoch - 2;
        }
        return req_.receiving_epoch;
    }

    Epoch reported_ek_receive_epoch() const {
        if (acks_.ek_received(rsp_.receiving_epoch)) {
            return rsp_.receiving_epoch;
        }
        if (rsp_.receiving_epoch >= 2 && acks_.ek_received(rsp_.receiving_epoch - 2)) {
            return rsp_.receiving_epoch - 2;
        }
        return rsp_.receiving_epoch;
    }

    void sample_keypair() {
        req_.sending_epoch += 2;
        auto kp = kem_.keygen(MockRkemMode::Nonupdated);
        req_.ek_out = Encoder(stream_id(), encode_mock_rkem_key(kp.ek));
        req_.dks[req_.sending_epoch] = kp.dk;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> sample_ciphertext() {
        auto dk_it = req_.dks.find(rsp_.sending_epoch + 3);
        if (dk_it == req_.dks.end()) {
            invalid_event("missing DK to update when sampling CT");
            return std::nullopt;
        }
        auto ek_it = rsp_.eks.find(rsp_.sending_epoch + 2);
        if (ek_it == rsp_.eks.end()) {
            invalid_event("missing EK when sampling CT");
            return std::nullopt;
        }

        rsp_.sending_epoch += 2;
        auto result = kem_.encaps(ek_it->second, dk_it->second);
        rsp_.eks.erase(ek_it);
        req_.dks[rsp_.sending_epoch + 1] = result.updated_dk;
        rsp_.ct_out = Encoder(stream_id(), encode_mock_rkem_ciphertext(result.ct));
        return record_output(rsp_.sending_epoch, result.secret, false);
    }

    std::optional<std::pair<Message::ChunkType, Chunk>> next_chunk() {
        if (req_.ek_out) {
            return std::pair{Message::ChunkType::Ek, req_.ek_out->next_chunk()};
        }
        if (rsp_.ct_out) {
            return std::pair{Message::ChunkType::Ct, rsp_.ct_out->next_chunk()};
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> process_chunk(const Message& message) {
        if (!message.chunk_type || !message.chunk) {
            return std::nullopt;
        }
        if (*message.chunk_type == Message::ChunkType::Ek) {
            if (message.ek_send_epoch != rsp_.receiving_epoch) {
                return std::nullopt;
            }
            acks_.increment_ek_received(rsp_.receiving_epoch);
            rsp_.ek_in.add(*message.chunk);
            if (auto ek = rsp_.ek_in.message()) {
                rsp_.eks[rsp_.receiving_epoch] = decode_mock_rkem_key(*ek);
                rsp_.receiving_epoch += 2;
                rsp_.ek_in = Decoder(kEkChunks);
            }
            return std::nullopt;
        }

        if (message.ct_send_epoch != req_.receiving_epoch) {
            return std::nullopt;
        }
        acks_.increment_ct_received(req_.receiving_epoch);
        req_.ct_in.add(*message.chunk);
        if (auto ct = req_.ct_in.message()) {
            auto output = decapsulate(decode_mock_rkem_ciphertext(*ct));
            if (output) {
                req_.receiving_epoch += 2;
                req_.ct_in = Decoder(kCtChunks);
            }
            return output;
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> decapsulate(MockRkemCiphertext ct) {
        auto dk_it = req_.dks.find(req_.receiving_epoch);
        if (dk_it == req_.dks.end()) {
            invalid_event("missing DK when receiving CT");
            return std::nullopt;
        }
        auto ek_it = rsp_.eks.find(req_.receiving_epoch + 1);
        if (ek_it == rsp_.eks.end()) {
            return std::nullopt;
        }
        auto result = kem_.decaps(dk_it->second, ct, ek_it->second);
        req_.dks.erase(dk_it);
        rsp_.eks.erase(ek_it);
        rsp_.eks[req_.receiving_epoch + 1] = result.updated_ek;
        return record_output(req_.receiving_epoch, result.secret, true);
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> record_output(Epoch epoch,
                                                                    OutputKey secret,
                                                                    bool usable_for_sending) {
        auto id = MessageEpoch{epoch};
        last_emitted_id_ = id;
        emitted_ids_.push_back(id);
        output_records_.push_back({epoch, usable_for_sending});
        return std::pair{message_output(epoch), secret};
    }

    SckaOutputId current_message_output() const {
        std::optional<Epoch> usable;
        for (const auto& output : output_records_) {
            if ((output.usable_for_sending || acks_.ct_received(output.epoch))
                && (!usable || output.epoch > *usable)) {
                usable = output.epoch;
            }
        }
        if (usable) {
            return message_output(*usable);
        }
        return initial_epoch();
    }

    void invalid_event(std::string_view what) const {
        if (invalid_event_policy_ == InvalidEventPolicy::Throw) {
            throw std::runtime_error(std::string("invalid Opp-RKEM event: ") + std::string(what));
        }
    }

    std::uint64_t stream_id() {
        return next_stream_id_++;
    }

    RequestorState req_;
    ResponderState rsp_;
    AckSet acks_;
    InvalidEventPolicy invalid_event_policy_ = InvalidEventPolicy::Ignore;
    MockRkem kem_;
    Epoch mutual_send_epoch_ = 0;
    Epoch mutual_receive_epoch_ = 0;
    std::uint64_t next_stream_id_ = 1;
    std::optional<MessageEpoch> last_emitted_id_;
    std::vector<MessageEpoch> emitted_ids_;
    struct OutputRecord {
        Epoch epoch = 0;
        bool usable_for_sending = false;
    };
    std::vector<OutputRecord> output_records_;
};

} // namespace smsim
