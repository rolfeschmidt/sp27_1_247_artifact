#pragma once

#include "chunking.hpp"
#include "ids.hpp"
#include "mock_unikem.hpp"
#include "secure_messaging.hpp"

#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace smsim {

struct OppUniKemMessage {
    enum class ChunkType {
        Ek,
        Ct,
    };

    Epoch epoch = 0;
    ChunkType chunk_type = ChunkType::Ek;
    bool ek_received = false;
    std::optional<Chunk> chunk;

    auto operator<=>(const OppUniKemMessage&) const = default;
};

class OppUniKem {
public:
    using OutputKey = MockSharedSecret;
    using Message = OppUniKemMessage;
    using SendResult = SparseSendResult<OutputKey, Message>;
    using ReceiveResult = SparseReceiveResult<OutputKey>;

    enum class InvalidEventPolicy {
        Ignore,
        Throw,
    };

    static OppUniKem init_alice(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return OppUniKem(EkRole{SampleEk{}}, policy);
    }

    static OppUniKem init_bob(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return OppUniKem(CtRole{RecvEk{Decoder(kEkChunks)}}, policy);
    }

    static SckaOutputId initial_epoch() {
        return message_output(0);
    }

    SendResult send() {
        auto sending_output = sending_protocol_epoch();
        if (auto* role = std::get_if<EkRole>(&role_)) {
            return {std::nullopt, sending_output, send_ek_role(*role)};
        }
        auto [output, message] = send_ct_role(std::get<CtRole>(role_));
        return {output, sending_output, message};
    }

    ReceiveResult receive(const Message& message, SckaOutputId encrypted_output) {
        if (message.epoch != receiving_epoch()) {
            if (auto* role = std::get_if<CtRole>(&role_);
                role && std::holds_alternative<SendCt2>(role->state) && message.epoch == epoch_ + 1) {
                advance_ct_role();
            } else {
                return {std::nullopt, encrypted_output};
            }
        }

        if (auto* role = std::get_if<EkRole>(&role_)) {
            return {receive_ek_role(*role, message), encrypted_output};
        }
        return {receive_ct_role(std::get<CtRole>(role_), message), encrypted_output};
    }

    std::vector<ProtocolSecretPattern> compromised_secret_patterns() const {
        std::vector<ProtocolSecretPattern> patterns;
        auto add_epoch = [&](Epoch epoch) {
            patterns.push_back(scka_secret(OppUniKemOutputPattern{epoch}));
        };
        if (const auto* role = std::get_if<EkRole>(&role_)) {
            std::visit(
                [&](const auto& state) {
                    using T = std::decay_t<decltype(state)>;
                    if constexpr (std::is_same_v<T, SendEkRecvCt1> || std::is_same_v<T, SendBehindEk>
                                  || std::is_same_v<T, RecvCt2>) {
                        add_epoch(epoch_);
                    }
                },
                role->state);
            return patterns;
        }

        const auto& role = std::get<CtRole>(role_);
        std::visit(
            [&](const auto& state) {
                using T = std::decay_t<decltype(state)>;
                if constexpr (std::is_same_v<T, SendCt1RecvEk> || std::is_same_v<T, SendBehindCt1>
                              || std::is_same_v<T, RecvAhead> || std::is_same_v<T, SampleCt2>) {
                    add_epoch(epoch_);
                }
            },
            role.state);
        return patterns;
    }

    std::optional<MessageEpoch> last_emitted_epoch_id() const {
        return last_emitted_id_;
    }

    const std::vector<MessageEpoch>& emitted_epoch_ids() const {
        return emitted_ids_;
    }

    std::string_view role_state_name() const {
        if (const auto* role = std::get_if<EkRole>(&role_)) {
            return std::visit([](const auto& state) { return state.name; }, role->state);
        }
        return std::visit([](const auto& state) { return state.name; }, std::get<CtRole>(role_).state);
    }

private:
    static constexpr std::uint64_t kEkChunks = 36;
    static constexpr std::uint64_t kCt1Chunks = 30;
    static constexpr std::uint64_t kCt2Chunks = 4;

    struct SampleEk {
        static constexpr std::string_view name = "SampleEk";
    };
    struct SendEkRecvCt1 {
        static constexpr std::string_view name = "SendEkRecvCt1";
        MockSecret dk;
        Encoder ek_enc;
        Decoder ct1_dec;
    };
    struct SendBehindEk {
        static constexpr std::string_view name = "SendBehindEk";
        MockSecret dk;
        Encoder ek_enc;
        std::vector<std::uint8_t> ct1;
    };
    struct RecvCt2 {
        static constexpr std::string_view name = "RecvCt2";
        MockSecret dk;
        std::vector<std::uint8_t> ct1;
        Decoder ct2_dec;
    };
    using EkRoleState = std::variant<SampleEk, SendEkRecvCt1, SendBehindEk, RecvCt2>;

    struct RecvEk {
        static constexpr std::string_view name = "RecvEk";
        Decoder ek_dec;
    };
    struct SendCt1RecvEk {
        static constexpr std::string_view name = "SendCt1RecvEk";
        MockSecret es;
        Encoder ct1_enc;
        Decoder ek_dec;
        std::vector<std::uint8_t> ct1;
    };
    struct SampleBehind {
        static constexpr std::string_view name = "SampleBehind";
        MockEncapsulationKey ek;
    };
    struct SendBehindCt1 {
        static constexpr std::string_view name = "SendBehindCt1";
        MockSecret es;
        Encoder ct1_enc;
        MockEncapsulationKey ek;
    };
    struct RecvAhead {
        static constexpr std::string_view name = "RecvAhead";
        MockSecret es;
        Decoder ek_dec;
    };
    struct SampleCt2 {
        static constexpr std::string_view name = "SampleCt2";
        MockSecret es;
        MockEncapsulationKey ek;
    };
    struct SendCt2 {
        static constexpr std::string_view name = "SendCt2";
        Encoder ct2_enc;
    };
    using CtRoleState = std::variant<RecvEk, SendCt1RecvEk, SampleBehind, SendBehindCt1,
                                     RecvAhead, SampleCt2, SendCt2>;

    struct EkRole {
        EkRoleState state;
    };
    struct CtRole {
        CtRoleState state;
    };
    using Role = std::variant<EkRole, CtRole>;

    explicit OppUniKem(Role role, InvalidEventPolicy policy)
        : role_(std::move(role)),
          invalid_event_policy_(policy) {}

    SckaOutputId sending_protocol_epoch() const {
        if (peer_known_id_) {
            return message_output(peer_known_id_->value);
        }
        return initial_epoch();
    }

    Epoch receiving_epoch() const {
        return epoch_;
    }

    void invalid_event(std::string_view what) const {
        if (invalid_event_policy_ == InvalidEventPolicy::Throw) {
            throw std::runtime_error(std::string("invalid Opp-UniKEM event: ") + std::string(what));
        }
    }

    Message send_ek_role(EkRole& role) {
        if (std::holds_alternative<SampleEk>(role.state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            role.state = SendEkRecvCt1{kp.dk, enc, Decoder(kCt1Chunks)};
            return {epoch_, Message::ChunkType::Ek, false, chunk};
        }
        if (auto* state = std::get_if<SendEkRecvCt1>(&role.state)) {
            return {epoch_, Message::ChunkType::Ek, false, state->ek_enc.next_chunk()};
        }
        if (auto* state = std::get_if<SendBehindEk>(&role.state)) {
            return {epoch_, Message::ChunkType::Ek, true, state->ek_enc.next_chunk()};
        }
        return {epoch_, Message::ChunkType::Ek, true, std::nullopt};
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ek_role(EkRole& role,
                                                                      const Message& message) {
        if (std::holds_alternative<SampleEk>(role.state)) {
            return std::nullopt;
        }
        if (auto* state = std::get_if<SendEkRecvCt1>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                invalid_event("EK role expected CT1 chunk");
                return std::nullopt;
            }
            state->ct1_dec.add(*message.chunk);
            if (auto ct1 = state->ct1_dec.message()) {
                role.state = SendBehindEk{state->dk, state->ek_enc, *ct1};
            }
            return std::nullopt;
        }
        if (auto* state = std::get_if<SendBehindEk>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ct || !message.chunk) {
                return std::nullopt;
            }
            Decoder dec(kCt2Chunks);
            dec.add(*message.chunk);
            role.state = RecvCt2{state->dk, state->ct1, dec};
            return maybe_finish_ct2(role);
        }
        if (auto* state = std::get_if<RecvCt2>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ct || !message.chunk) {
                return std::nullopt;
            }
            state->ct2_dec.add(*message.chunk);
            return maybe_finish_ct2(role);
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> maybe_finish_ct2(EkRole& role) {
        auto* state = std::get_if<RecvCt2>(&role.state);
        if (!state) {
            return std::nullopt;
        }
        auto ct2 = state->ct2_dec.message();
        if (!ct2) {
            return std::nullopt;
        }
        auto es_id = decode_u64(state->ct1);
        auto ek_id = decode_u64(*ct2);
        if (state->dk.id != ek_id) {
            invalid_event("CT2 does not match DK");
            return std::nullopt;
        }
        auto id = MessageEpoch{epoch_};
        auto secret = MockSharedSecret{ek_id, es_id};
        last_emitted_id_ = id;
        emitted_ids_.push_back(id);
        peer_known_id_ = id;
        ++epoch_;
        role_ = CtRole{RecvEk{Decoder(kEkChunks)}};
        return std::pair{message_output(id.value), secret};
    }

    std::pair<std::optional<std::pair<SckaOutputId, OutputKey>>, Message> send_ct_role(CtRole& role) {
        if (auto* state = std::get_if<RecvEk>(&role.state)) {
            auto [es, ct1] = kem_.enc_pk();
            Encoder enc(stream_id(), ct1);
            auto chunk = enc.next_chunk();
            role.state = SendCt1RecvEk{es, enc, std::move(state->ek_dec), ct1};
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, chunk}};
        }
        if (auto* state = std::get_if<SendCt1RecvEk>(&role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, state->ct1_enc.next_chunk()}};
        }
        if (auto* state = std::get_if<SampleBehind>(&role.state)) {
            auto [es, ct1] = kem_.enc_pk();
            Encoder enc(stream_id(), ct1);
            auto chunk = enc.next_chunk();
            auto output = commit_ct_epoch(es, state->ek);
            role.state = SendBehindCt1{es, enc, state->ek};
            return {output, {epoch_, Message::ChunkType::Ek, true, chunk}};
        }
        if (auto* state = std::get_if<SendBehindCt1>(&role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, true, state->ct1_enc.next_chunk()}};
        }
        if (std::holds_alternative<RecvAhead>(role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, std::nullopt}};
        }
        if (auto* state = std::get_if<SampleCt2>(&role.state)) {
            Encoder enc(stream_id(), encode_u64(state->ek.id));
            auto chunk = enc.next_chunk();
            role.state = SendCt2{enc};
            return {std::nullopt, {epoch_, Message::ChunkType::Ct, true, chunk}};
        }
        auto& state = std::get<SendCt2>(role.state);
        return {std::nullopt, {epoch_, Message::ChunkType::Ct, true, state.ct2_enc.next_chunk()}};
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ct_role(CtRole& role,
                                                                      const Message& message) {
        if (auto* state = std::get_if<RecvEk>(&role.state)) {
            return receive_initial_ek(role, *state, message);
        }
        if (auto* state = std::get_if<SendCt1RecvEk>(&role.state)) {
            if (message.ek_received) {
                auto next = RecvAhead{state->es, std::move(state->ek_dec)};
                role.state = next;
                return receive_ct_role(role, message);
            }
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                return std::nullopt;
            }
            state->ek_dec.add(*message.chunk);
            if (auto ek = state->ek_dec.message()) {
                auto decoded = MockEncapsulationKey{decode_u64(*ek)};
                auto output = commit_ct_epoch(state->es, decoded);
                role.state = SendBehindCt1{state->es, state->ct1_enc, decoded};
                return output;
            }
            return std::nullopt;
        }
        if (std::holds_alternative<SampleBehind>(role.state)) {
            return std::nullopt;
        }
        if (auto* state = std::get_if<SendBehindCt1>(&role.state)) {
            if (message.ek_received) {
                role.state = SampleCt2{state->es, state->ek};
            }
            return std::nullopt;
        }
        if (auto* state = std::get_if<RecvAhead>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                return std::nullopt;
            }
            state->ek_dec.add(*message.chunk);
            if (auto ek = state->ek_dec.message()) {
                auto decoded = MockEncapsulationKey{decode_u64(*ek)};
                auto output = commit_ct_epoch(state->es, decoded);
                role.state = SampleCt2{state->es, decoded};
                return output;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>>
    receive_initial_ek(CtRole& role, RecvEk& state, const Message& message) {
        if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
            invalid_event("CT role expected EK chunk");
            return std::nullopt;
        }
        state.ek_dec.add(*message.chunk);
        if (auto ek = state.ek_dec.message()) {
            role.state = SampleBehind{MockEncapsulationKey{decode_u64(*ek)}};
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> commit_ct_epoch(MockSecret es,
                                                                      MockEncapsulationKey ek) {
        auto id = MessageEpoch{epoch_};
        auto secret = MockSharedSecret{ek.id, es.id};
        last_emitted_id_ = id;
        emitted_ids_.push_back(id);
        return std::pair{message_output(id.value), secret};
    }

    void advance_ct_role() {
        ++epoch_;
        peer_known_id_ = last_emitted_id_;
        role_ = EkRole{SampleEk{}};
    }

    std::uint64_t stream_id() {
        return next_stream_id_++;
    }

    Role role_;
    InvalidEventPolicy invalid_event_policy_ = InvalidEventPolicy::Ignore;
    Epoch epoch_ = 1;
    MockUniKem kem_;
    std::uint64_t next_stream_id_ = 1;
    std::optional<MessageEpoch> last_emitted_id_;
    std::vector<MessageEpoch> emitted_ids_;
    std::optional<MessageEpoch> peer_known_id_;
};

} // namespace smsim
