#pragma once

#include "chunking.hpp"
#include "ids.hpp"
#include "mock_unikem.hpp"
#include "secure_messaging.hpp"

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace smsim {

struct OppUniKemUsenixMessage {
    enum class ChunkType {
        Ek,
        Ct,
    };

    Epoch epoch = 0;
    ChunkType chunk_type = ChunkType::Ek;
    bool ek_received = false;
    std::optional<Chunk> chunk;

    auto operator<=>(const OppUniKemUsenixMessage&) const = default;
};

class OppUniKemUsenix {
public:
    using OutputKey = MockSharedSecret;
    using Message = OppUniKemUsenixMessage;
    using SendResult = SparseSendResult<OutputKey, Message>;
    using ReceiveResult = SparseReceiveResult<OutputKey>;

    enum class InvalidEventPolicy {
        Ignore,
        Throw,
    };

    static OppUniKemUsenix init_alice(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return OppUniKemUsenix(EkRole{EkRecvEk{Decoder(kEkChunks)}}, policy);
    }

    static OppUniKemUsenix init_bob(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return OppUniKemUsenix(CtRole{CtRecvEk{Decoder(kEkChunks)}}, policy);
    }

    static SckaOutputId initial_epoch() {
        return message_output(0);
    }

    SendResult send() {
        std::optional<std::pair<SckaOutputId, OutputKey>> output;
        Message message;
        if (auto* role = std::get_if<EkRole>(&role_)) {
            std::tie(output, message) = send_ek_role(*role);
        } else {
            std::tie(output, message) = send_ct_role(std::get<CtRole>(role_));
        }
        if (output) {
            current_output_ = output->first;
        }
        return {output, current_output_, message};
    }

    ReceiveResult receive(const Message& message, SckaOutputId encrypted_output) {
        if (message.epoch < epoch()) {
            return {std::nullopt, encrypted_output};
        }
        if (message.epoch > epoch() && !can_receive_next_epoch_ack(message)) {
            invalid_event("received future Opp-UniKEM-USENIX message");
            return {std::nullopt, encrypted_output};
        }

        std::optional<std::pair<SckaOutputId, OutputKey>> output;
        if (auto* role = std::get_if<EkRole>(&role_)) {
            output = receive_ek_role(*role, message);
        } else {
            output = receive_ct_role(std::get<CtRole>(role_), message);
        }
        if (output) {
            current_output_ = output->first;
        }
        return {output, encrypted_output};
    }

    std::vector<ProtocolSecretPattern> compromised_secret_patterns() const {
        return {scka_secret(OppUniKemOutputPattern{epoch_})};
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
    static constexpr std::uint64_t kCt0Chunks = 30;
    static constexpr std::uint64_t kCtChunks = 4;

    struct EkRecvEk {
        static constexpr std::string_view name = "RecvEk";
        Decoder ct0_dec;
    };
    struct EkSendEkRecvEk {
        static constexpr std::string_view name = "SendEkRecvEk";
        MockSecret dk;
        Encoder ek_enc;
        Decoder ct0_dec;
    };
    struct EkSampleBehind {
        static constexpr std::string_view name = "SampleBehind";
        MockEncapsulationKey ct0;
    };
    struct EkSendBehind {
        static constexpr std::string_view name = "SendBehind";
        MockSecret dk;
        Encoder ek_enc;
        MockEncapsulationKey ct0;
    };
    struct EkRecvCt {
        static constexpr std::string_view name = "RecvCt";
        MockSecret dk;
        MockEncapsulationKey ct0;
        Decoder ct_dec;
    };
    struct EkKeyReady {
        static constexpr std::string_view name = "KeyReady";
        OutputKey secret;
    };
    using EkRoleState = std::variant<EkRecvEk, EkSendEkRecvEk, EkSampleBehind, EkSendBehind,
                                     EkRecvCt, EkKeyReady>;

    struct CtRecvEk {
        static constexpr std::string_view name = "RecvEk";
        Decoder ek_dec;
    };
    struct CtSendEkRecvEk {
        static constexpr std::string_view name = "SendEkRecvEk";
        MockSecret dk;
        Encoder ct0_enc;
        Decoder ek_dec;
    };
    struct CtSampleBehind {
        static constexpr std::string_view name = "SampleBehind";
        MockEncapsulationKey ek;
    };
    struct CtSendBehind {
        static constexpr std::string_view name = "SendBehind";
        MockSecret dk;
        Encoder ct0_enc;
        MockEncapsulationKey ek;
    };
    struct CtRecvAhead {
        static constexpr std::string_view name = "RecvAhead";
        MockSecret dk;
        Decoder ek_dec;
    };
    struct CtSampleCt {
        static constexpr std::string_view name = "SampleCt";
        MockSecret dk;
        MockEncapsulationKey ek;
    };
    struct CtSendCt {
        static constexpr std::string_view name = "SendCt";
        OutputKey secret;
        Encoder ct_enc;
    };
    using CtRoleState = std::variant<CtRecvEk, CtSendEkRecvEk, CtSampleBehind, CtSendBehind,
                                     CtRecvAhead, CtSampleCt, CtSendCt>;

    struct EkRole {
        EkRoleState state;
    };
    struct CtRole {
        CtRoleState state;
    };
    using Role = std::variant<EkRole, CtRole>;

    explicit OppUniKemUsenix(Role role, InvalidEventPolicy policy)
        : role_(std::move(role)),
          invalid_event_policy_(policy) {}

    Epoch epoch() const {
        return epoch_;
    }

    bool can_receive_next_epoch_ack(const Message& message) const {
        const auto* role = std::get_if<CtRole>(&role_);
        return role && std::holds_alternative<CtSendCt>(role->state) && message.epoch == epoch_ + 1;
    }

    void invalid_event(std::string_view what) const {
        if (invalid_event_policy_ == InvalidEventPolicy::Throw) {
            throw std::runtime_error(std::string("invalid Opp-UniKEM-USENIX event: ") + std::string(what));
        }
    }

    std::pair<std::optional<std::pair<SckaOutputId, OutputKey>>, Message>
    send_ek_role(EkRole& role) {
        if (auto* state = std::get_if<EkRecvEk>(&role.state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            role.state = EkSendEkRecvEk{kp.dk, enc, std::move(state->ct0_dec)};
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, chunk}};
        }
        if (auto* state = std::get_if<EkSendEkRecvEk>(&role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, state->ek_enc.next_chunk()}};
        }
        if (auto* state = std::get_if<EkSampleBehind>(&role.state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            role.state = EkSendBehind{kp.dk, enc, state->ct0};
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, true, chunk}};
        }
        if (auto* state = std::get_if<EkSendBehind>(&role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, true, state->ek_enc.next_chunk()}};
        }
        if (std::holds_alternative<EkRecvCt>(role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, true, std::nullopt}};
        }

        auto state = std::get<EkKeyReady>(role.state);
        ++epoch_;
        role.state = EkRecvEk{Decoder(kEkChunks)};
        auto [ignored, message] = send_ek_role(role);
        (void)ignored;
        return {record_output(epoch_ - 1, state.secret), message};
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ek_role(EkRole& role,
                                                                      const Message& message) {
        if (auto* state = std::get_if<EkRecvEk>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                return std::nullopt;
            }
            state->ct0_dec.add(*message.chunk);
            if (auto ct0 = state->ct0_dec.message()) {
                role.state = EkSampleBehind{MockEncapsulationKey{decode_u64(*ct0)}};
            }
            return std::nullopt;
        }
        if (auto* state = std::get_if<EkSendEkRecvEk>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                return std::nullopt;
            }
            state->ct0_dec.add(*message.chunk);
            if (auto ct0 = state->ct0_dec.message()) {
                role.state = EkSendBehind{state->dk, state->ek_enc,
                                          MockEncapsulationKey{decode_u64(*ct0)}};
            }
            return std::nullopt;
        }
        if (std::holds_alternative<EkSampleBehind>(role.state)) {
            return std::nullopt;
        }
        if (auto* state = std::get_if<EkSendBehind>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ct || !message.chunk) {
                return std::nullopt;
            }
            Decoder dec(kCtChunks);
            dec.add(*message.chunk);
            role.state = EkRecvCt{state->dk, state->ct0, dec};
            return maybe_finish_ek_ct(role);
        }
        if (auto* state = std::get_if<EkRecvCt>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ct || !message.chunk) {
                return std::nullopt;
            }
            state->ct_dec.add(*message.chunk);
            return maybe_finish_ek_ct(role);
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> maybe_finish_ek_ct(EkRole& role) {
        auto* state = std::get_if<EkRecvCt>(&role.state);
        if (!state) {
            return std::nullopt;
        }
        auto ct = state->ct_dec.message();
        if (!ct) {
            return std::nullopt;
        }
        auto secret = kem_.decaps(state->dk, encode_u64(state->ct0.id), *ct);
        role.state = EkKeyReady{secret};
        return std::nullopt;
    }

    std::pair<std::optional<std::pair<SckaOutputId, OutputKey>>, Message>
    send_ct_role(CtRole& role) {
        if (auto* state = std::get_if<CtRecvEk>(&role.state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            role.state = CtSendEkRecvEk{kp.dk, enc, std::move(state->ek_dec)};
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, chunk}};
        }
        if (auto* state = std::get_if<CtSendEkRecvEk>(&role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, state->ct0_enc.next_chunk()}};
        }
        if (auto* state = std::get_if<CtSampleBehind>(&role.state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            role.state = CtSendBehind{kp.dk, enc, state->ek};
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, true, chunk}};
        }
        if (auto* state = std::get_if<CtSendBehind>(&role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, true, state->ct0_enc.next_chunk()}};
        }
        if (std::holds_alternative<CtRecvAhead>(role.state)) {
            return {std::nullopt, {epoch_, Message::ChunkType::Ek, false, std::nullopt}};
        }
        if (auto* state = std::get_if<CtSampleCt>(&role.state)) {
            auto encap = kem_.enc_ct(state->ek, state->dk);
            Encoder enc(stream_id(), encap.ct1);
            auto chunk = enc.next_chunk();
            role.state = CtSendCt{encap.secret, enc};
            return {std::nullopt, {epoch_, Message::ChunkType::Ct, true, chunk}};
        }

        auto& state = std::get<CtSendCt>(role.state);
        return {std::nullopt, {epoch_, Message::ChunkType::Ct, true, state.ct_enc.next_chunk()}};
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ct_role(CtRole& role,
                                                                      const Message& message) {
        if (auto* state = std::get_if<CtRecvEk>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                return std::nullopt;
            }
            state->ek_dec.add(*message.chunk);
            if (auto ek = state->ek_dec.message()) {
                role.state = CtSampleBehind{MockEncapsulationKey{decode_u64(*ek)}};
            }
            return std::nullopt;
        }
        if (auto* state = std::get_if<CtSendEkRecvEk>(&role.state)) {
            if (message.chunk) {
                state->ek_dec.add(*message.chunk);
            }
            if (message.ek_received) {
                auto next = CtRecvAhead{state->dk, std::move(state->ek_dec)};
                role.state = next;
                return receive_ct_role(role, message);
            }
            if (auto ek = state->ek_dec.message()) {
                role.state = CtSendBehind{state->dk, state->ct0_enc,
                                          MockEncapsulationKey{decode_u64(*ek)}};
            }
            return std::nullopt;
        }
        if (std::holds_alternative<CtSampleBehind>(role.state)) {
            return std::nullopt;
        }
        if (auto* state = std::get_if<CtSendBehind>(&role.state)) {
            if (message.ek_received) {
                role.state = CtSampleCt{state->dk, state->ek};
            }
            return std::nullopt;
        }
        if (auto* state = std::get_if<CtRecvAhead>(&role.state)) {
            if (message.chunk_type != Message::ChunkType::Ek || !message.chunk) {
                return std::nullopt;
            }
            state->ek_dec.add(*message.chunk);
            if (auto ek = state->ek_dec.message()) {
                role.state = CtSampleCt{state->dk, MockEncapsulationKey{decode_u64(*ek)}};
            }
            return std::nullopt;
        }
        if (std::holds_alternative<CtSampleCt>(role.state)) {
            return std::nullopt;
        }

        auto state = std::get<CtSendCt>(role.state);
        if (message.epoch == epoch_ + 1) {
            ++epoch_;
            role.state = CtRecvEk{Decoder(kEkChunks)};
            auto output = record_output(epoch_ - 1, state.secret);
            (void)receive_ct_role(role, message);
            return output;
        }
        role.state = state;
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> record_output(Epoch epoch, OutputKey secret) {
        auto id = MessageEpoch{epoch};
        last_emitted_id_ = id;
        emitted_ids_.push_back(id);
        return std::pair{message_output(id.value), secret};
    }

    std::uint64_t stream_id() {
        return next_stream_id_++;
    }

    Role role_;
    InvalidEventPolicy invalid_event_policy_ = InvalidEventPolicy::Ignore;
    Epoch epoch_ = 1;
    MockUniKem kem_;
    std::uint64_t next_stream_id_ = 1;
    SckaOutputId current_output_ = initial_epoch();
    std::optional<MessageEpoch> last_emitted_id_;
    std::vector<MessageEpoch> emitted_ids_;
};

} // namespace smsim
