#pragma once

#include "chunking.hpp"
#include "ids.hpp"
#include "mock_rkem.hpp"
#include "secure_messaging.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace smsim {

struct AggRukemMessage {
    enum class ChunkType {
        Ek,
        Ct,
    };

    std::optional<ChunkType> chunk_type;
    std::optional<Chunk> chunk;
    Epoch epoch = 1;
    Epoch sender_key_epoch = 1;
    Epoch receiver_key_epoch = 1;
    bool ack_receiver_ek = false;
    bool permit_receiver_ct = false;

    auto operator<=>(const AggRukemMessage&) const = default;
};

struct AggRkemParams {
    static constexpr std::uint64_t kCtChunks = 3;
    static constexpr std::uint64_t kMaxUpdates = 1;
    static constexpr bool kUpdatesPeerKey = false;
};

struct AggRukemParams {
    static constexpr std::uint64_t kCtChunks = 3;
    static constexpr std::uint64_t kMaxUpdates = 7;
    static constexpr bool kUpdatesPeerKey = true;
};

template <typename Params>
class AggRkemFamily {
public:
    using OutputKey = MockRkemSharedSecret;
    using Message = AggRukemMessage;
    using SendResult = SparseSendResult<OutputKey, Message>;
    using ReceiveResult = SparseReceiveResult<OutputKey>;

    enum class InvalidEventPolicy {
        Ignore,
        Throw,
    };

    static constexpr std::uint64_t kCtChunks = Params::kCtChunks;
    static constexpr std::uint64_t kMaxUpdates = Params::kMaxUpdates;
    static constexpr bool kUpdatesPeerKey = Params::kUpdatesPeerKey;

    static AggRkemFamily init_alice(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return AggRkemFamily(Party::Alice, policy);
    }

    static AggRkemFamily init_bob(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return AggRkemFamily(Party::Bob, policy);
    }

    static SckaOutputId initial_epoch() {
        return message_output(0);
    }

    SendResult send() {
        if (can_sample_keypair()) {
            sample_keypair();
        }

        std::optional<std::pair<SckaOutputId, OutputKey>> output_key;
        std::optional<std::pair<Message::ChunkType, Chunk>> maybe_chunk;
        if (own_ek_out_ && !ack_own_ek_) {
            maybe_chunk = std::pair{Message::ChunkType::Ek, own_ek_out_->next_chunk()};
        } else if (own_ek_out_ && send_own_ct_) {
            if (!own_ct_out_) {
                output_key = sample_ciphertext();
            }
            if (own_ct_out_) {
                maybe_chunk = std::pair{Message::ChunkType::Ct, own_ct_out_->next_chunk()};
            }
        }

        Message message;
        message.epoch = epoch_;
        message.sender_key_epoch = own_key_epoch_;
        message.receiver_key_epoch = peer_key_epoch_;
        message.ack_receiver_ek = ack_peer_ek_;
        message.permit_receiver_ct = should_permit_peer_ct(maybe_chunk);
        if (maybe_chunk) {
            message.chunk_type = maybe_chunk->first;
            message.chunk = maybe_chunk->second;
        }
        return {output_key, current_message_output(), message};
    }

    ReceiveResult receive(const Message& message, SckaOutputId encrypted_output) {
        if (message.receiver_key_epoch > own_key_epoch_) {
            advance_own_key_epoch(message.receiver_key_epoch);
        }

        std::optional<std::pair<SckaOutputId, OutputKey>> output_key;
        if (message.sender_key_epoch == peer_key_epoch_) {
            output_key = process_chunk(message);
        }

        if (message.receiver_key_epoch == own_key_epoch_) {
            if (message.ack_receiver_ek) {
                ack_own_ek_ = true;
            }
            if (message.permit_receiver_ct) {
                send_own_ct_ = true;
            }
        }

        return {output_key, encrypted_output};
    }

    std::vector<ProtocolSecretPattern> compromised_secret_patterns() const {
        std::vector<ProtocolSecretPattern> patterns;
        patterns.push_back(scka_secret(AggRukemOutputPattern{own_old_ref_}));
        if (own_new_dk_) {
            patterns.push_back(scka_secret(AggRukemOutputPattern{own_new_ref_}));
        }
        std::sort(patterns.begin(), patterns.end());
        patterns.erase(std::unique(patterns.begin(), patterns.end()), patterns.end());
        return patterns;
    }

    std::optional<MessageEpoch> last_emitted_epoch_id() const {
        return last_emitted_id_;
    }

    std::vector<MessageEpoch> emitted_epoch_ids() const {
        std::vector<MessageEpoch> outputs;
        outputs.reserve(output_records_.size());
        for (const auto& output : output_records_) {
            outputs.push_back(output.record.output);
        }
        std::sort(outputs.begin(), outputs.end());
        outputs.erase(std::unique(outputs.begin(), outputs.end()), outputs.end());
        return outputs;
    }

    const std::vector<AggRukemOutputRecord>& emitted_output_records() const {
        return output_records_plain_;
    }

    std::string_view role_state_name() const {
        if (own_ct_out_) {
            return "SendCt";
        }
        if (own_ek_out_ && send_own_ct_) {
            return "ReadyToSendCt";
        }
        if (own_ek_out_ && ack_own_ek_) {
            return "EkAckedAwaitCtPermission";
        }
        if (own_ek_out_) {
            return "SendEk";
        }
        return "Idle";
    }

private:
    static constexpr std::uint64_t kEkChunks = 39;

    struct OutputRecord {
        AggRukemOutputRecord record;
        bool usable_for_sending = false;
        bool acknowledged = false;
    };

    explicit AggRkemFamily(Party party, InvalidEventPolicy policy)
        : party_(party),
          invalid_event_policy_(policy),
          own_old_ref_{party, 0, 1},
          peer_old_ref_{other(party), 0, 1} {
        auto initial = MockRkem::initial_updated_keypair();
        own_old_dk_ = initial.dk;
        peer_old_ek_ = initial.ek;
    }

    bool can_sample_keypair() const {
        return !ack_own_ek_ && !own_ek_out_
            && (!kUpdatesPeerKey || peer_old_rkem_updates_ < kMaxUpdates);
    }

    void sample_keypair() {
        auto kp = kem_.keygen(MockRkemMode::Nonupdated);
        own_new_dk_ = kp.dk;
        own_new_ref_ = {party_, own_key_epoch_, 0};
        own_ek_out_ = Encoder(stream_id(), encode_mock_rkem_key(kp.ek));
    }

    bool should_permit_peer_ct(
        const std::optional<std::pair<Message::ChunkType, Chunk>>& maybe_chunk) const {
        if (!ack_peer_ek_ || send_own_ct_) {
            return false;
        }
        auto sent_ek_chunks = own_ek_out_ ? own_ek_out_->emitted() : 0;
        if (maybe_chunk && maybe_chunk->first == Message::ChunkType::Ek) {
            sent_ek_chunks = std::max(sent_ek_chunks, maybe_chunk->second.index + 1);
        }
        return sent_ek_chunks < kEkChunks || tie_breaks_to_peer();
    }

    bool tie_breaks_to_peer() const {
        if (party_ == Party::Alice) {
            return epoch_ % 2 == 0;
        }
        return epoch_ % 2 == 1;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> sample_ciphertext() {
        if (!own_new_dk_) {
            invalid_event("missing new DK when sampling CT");
            return std::nullopt;
        }

        auto result = kem_.encaps(peer_old_ek_, *own_new_dk_);
        AggRukemOutputRecord record{
            MessageEpoch{epoch_},
            own_new_ref_,
            peer_old_ref_,
        };
        own_old_dk_ = result.updated_dk;
        own_old_ref_ = {party_, own_new_ref_.key_epoch, own_new_ref_.update + 1};
        if constexpr (kUpdatesPeerKey) {
            peer_old_ek_ = {peer_old_ek_.id, MockRkemMode::Updated};
            ++peer_old_rkem_updates_;
            ++peer_old_ref_.update;
        }
        own_new_dk_ = std::nullopt;
        own_ct_out_ = Encoder(stream_id(), encode_mock_rkem_ciphertext(result.ct));
        return record_output(record, result.secret, false);
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> process_chunk(const Message& message) {
        if (!message.chunk_type || !message.chunk) {
            return std::nullopt;
        }

        if (*message.chunk_type == Message::ChunkType::Ek) {
            if (ack_peer_ek_) {
                return std::nullopt;
            }
            peer_ek_in_.add(*message.chunk);
            if (auto ek = peer_ek_in_.message()) {
                peer_new_ek_ = decode_mock_rkem_key(*ek);
                peer_new_ref_ = {other(party_), peer_key_epoch_, 0};
                ack_peer_ek_ = true;
                peer_ek_in_ = Decoder(kEkChunks);
            }
            return std::nullopt;
        }

        if (!ack_peer_ek_ || !peer_new_ek_) {
            invalid_event("received CT before peer EK");
            return std::nullopt;
        }
        peer_ct_in_.add(*message.chunk);
        if (auto ct_bytes = peer_ct_in_.message()) {
            auto ct = decode_mock_rkem_ciphertext(*ct_bytes);
            auto result = kem_.decaps(own_old_dk_, ct, *peer_new_ek_);
            AggRukemOutputRecord record{
                MessageEpoch{epoch_},
                peer_new_ref_,
                own_old_ref_,
            };
            if constexpr (kUpdatesPeerKey) {
                own_old_dk_ = {own_old_dk_.id, MockRkemMode::Updated};
                ++own_old_ref_.update;
            }
            peer_old_ek_ = result.updated_ek;
            peer_old_ref_ = {other(party_), peer_new_ref_.key_epoch, peer_new_ref_.update + 1};
            peer_old_rkem_updates_ = 0;
            peer_new_ek_ = std::nullopt;
            ack_peer_ek_ = false;
            peer_ct_in_ = Decoder(kCtChunks);
            ++peer_key_epoch_;
            ++epoch_;
            return record_output(record, result.secret, true);
        }
        return std::nullopt;
    }

    void advance_own_key_epoch(Epoch new_epoch) {
        if (new_epoch <= own_key_epoch_) {
            return;
        }
        epoch_ += new_epoch - own_key_epoch_;
        for (auto& output : output_records_) {
            if (output.record.sender_key.party == party_
                && output.record.sender_key.key_epoch < new_epoch) {
                output.acknowledged = true;
            }
        }
        own_key_epoch_ = new_epoch;
        ack_own_ek_ = false;
        send_own_ct_ = false;
        own_ek_out_ = std::nullopt;
        own_ct_out_ = std::nullopt;
        own_new_dk_ = std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> record_output(AggRukemOutputRecord record,
                                                                    OutputKey secret,
                                                                    bool usable_for_sending) {
        last_emitted_id_ = record.output;
        output_records_plain_.push_back(record);
        output_records_.push_back({record, usable_for_sending, false});
        return std::pair{message_output(record.output.value), secret};
    }

    SckaOutputId current_message_output() const {
        std::optional<Epoch> usable;
        for (const auto& output : output_records_) {
            if ((output.usable_for_sending || output.acknowledged)
                && (!usable || output.record.output.value > *usable)) {
                usable = output.record.output.value;
            }
        }
        if (usable) {
            return message_output(*usable);
        }
        return initial_epoch();
    }

    void invalid_event(std::string_view what) const {
        if (invalid_event_policy_ == InvalidEventPolicy::Throw) {
            throw std::runtime_error(std::string("invalid Agg-RUKEM event: ") + std::string(what));
        }
    }

    std::uint64_t stream_id() {
        return next_stream_id_++;
    }

    Party party_ = Party::Alice;
    InvalidEventPolicy invalid_event_policy_ = InvalidEventPolicy::Ignore;
    MockRkem kem_;
    Epoch epoch_ = 1;
    Epoch own_key_epoch_ = 1;
    Epoch peer_key_epoch_ = 1;
    MockRkemDecapsulationKey own_old_dk_;
    MockRkemEncapsulationKey peer_old_ek_;
    AggRukemKeyRef own_old_ref_;
    AggRukemKeyRef peer_old_ref_;
    std::uint64_t peer_old_rkem_updates_ = 0;
    std::optional<MockRkemDecapsulationKey> own_new_dk_;
    AggRukemKeyRef own_new_ref_;
    std::optional<MockRkemEncapsulationKey> peer_new_ek_;
    AggRukemKeyRef peer_new_ref_;
    Decoder peer_ek_in_{kEkChunks};
    Decoder peer_ct_in_{kCtChunks};
    std::optional<Encoder> own_ek_out_;
    std::optional<Encoder> own_ct_out_;
    bool ack_own_ek_ = false;
    bool ack_peer_ek_ = false;
    bool send_own_ct_ = false;
    std::uint64_t next_stream_id_ = 1;
    std::optional<MessageEpoch> last_emitted_id_;
    std::vector<OutputRecord> output_records_;
    std::vector<AggRukemOutputRecord> output_records_plain_;
};

using AggRkem = AggRkemFamily<AggRkemParams>;
using AggRukem = AggRkemFamily<AggRukemParams>;

} // namespace smsim
