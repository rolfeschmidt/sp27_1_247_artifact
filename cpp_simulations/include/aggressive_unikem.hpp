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

struct AggUniKemMessage {
    enum class Type {
        None,
        Ek,
        Ct0,
        EkAck,
        Ct0Ack,
        Ct1Commit,
        Ct1,
    };

    Epoch epoch = 0;
    Type type = Type::None;
    std::uint64_t i = 0;
    std::uint64_t j = 0;
    std::optional<std::uint64_t> ek_ack;
    std::optional<std::uint64_t> ct0_ack;
    std::optional<Chunk> chunk;

    auto operator<=>(const AggUniKemMessage&) const = default;
};

class AggUniKem {
public:
    using OutputKey = MockSharedSecret;
    using Message = AggUniKemMessage;
    using SendResult = SparseSendResult<OutputKey, Message>;
    using ReceiveResult = SparseReceiveResult<OutputKey>;

    enum class InvalidEventPolicy {
        Ignore,
        Throw,
    };

    static AggUniKem init_alice(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return AggUniKem(EkRole{EkInit{Decoder(kCt0Chunks)}}, policy);
    }

    static AggUniKem init_bob(InvalidEventPolicy policy = InvalidEventPolicy::Ignore) {
        return AggUniKem(CtRole{CtInit{Decoder(kEkChunks)}}, policy);
    }

    static SckaOutputId initial_epoch() {
        return message_output(0);
    }

    SendResult send() {
        auto sending_output = sending_protocol_epoch();
        if (auto* role = std::get_if<EkRole>(&role_)) {
            return {std::nullopt, sending_output, send_ek_role(*role)};
        }
        auto [output_key, message] = send_ct_role(std::get<CtRole>(role_));
        return {output_key, sending_output, message};
    }

    ReceiveResult receive(const Message& message, SckaOutputId encrypted_output) {
        if (auto* role = std::get_if<CtRole>(&role_);
            role && std::holds_alternative<CtSendCt1>(role->state) && message.epoch == epoch_ + 1) {
            advance_ct_role();
        }
        if (message.epoch != epoch_) {
            return {std::nullopt, encrypted_output};
        }
        if (auto* role = std::get_if<EkRole>(&role_)) {
            return {receive_ek_role(*role, message), encrypted_output};
        }
        return {receive_ct_role(std::get<CtRole>(role_), message), encrypted_output};
    }

    std::vector<ProtocolSecretPattern> compromised_secret_patterns() const {
        if (const auto* role = std::get_if<EkRole>(&role_)) {
            return compromised_ek_role_patterns(*role);
        }
        return compromised_ct_role_patterns(std::get<CtRole>(role_));
    }

    std::optional<AggUniKemOutputId> last_emitted_epoch_id() const {
        return last_emitted_id_;
    }

    const std::vector<AggUniKemOutputId>& emitted_epoch_ids() const {
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
    static constexpr std::uint64_t kCt1Chunks = 4;

    struct EkInit {
        static constexpr std::string_view name = "Init";
        Decoder ct0_dec;
    };
    struct SendFirstEkRecvFirstCt0 {
        static constexpr std::string_view name = "SendFirstEkRecvFirstCt0";
        MockSecret dk;
        Encoder ek_enc;
        Decoder ct0_dec;
    };
    struct EkInitFrozenCtAwait {
        static constexpr std::string_view name = "EkInitFrozenCtAwait";
        std::uint64_t ct0_j = 0;
        std::vector<std::uint8_t> ct0;
        std::optional<std::uint64_t> pending_ct0_ack;
    };
    struct EkSampleRecvFirstCt0 {
        static constexpr std::string_view name = "EkSampleRecvFirstCt0";
        std::uint64_t acked_i = 0;
        MockSecret acked_dk;
        Decoder ct0_dec;
    };
    struct EkSendWhileRecvCt0 {
        static constexpr std::string_view name = "EkSendWhileRecvCt0";
        std::uint64_t acked_i = 0;
        MockSecret acked_dk;
        std::uint64_t current_i = 0;
        MockSecret current_dk;
        Encoder ek_enc;
        Decoder ct0_dec;
    };
    struct FrozenEk {
        std::uint64_t i = 0;
        MockSecret dk;
        Encoder enc;
        bool acked = false;
    };
    struct CachedCt0 {
        std::uint64_t j = 0;
        std::vector<std::uint8_t> ct0;
    };
    struct EkFrozenCtAwait {
        static constexpr std::string_view name = "EkFrozenCtAwait";
        FrozenEk ek;
        std::uint64_t ct0_j = 0;
        std::vector<std::uint8_t> ct0;
        std::optional<std::uint64_t> pending_ct0_ack;
        std::optional<CachedCt0> previous_ct0;
    };
    struct EkFrozenAfterAggressiveCtAwait {
        static constexpr std::string_view name = "EkFrozenAfterAggressiveCtAwait";
        std::uint64_t acked_i = 0;
        MockSecret acked_dk;
        std::optional<FrozenEk> current_ek;
        std::uint64_t ct0_j = 0;
        std::vector<std::uint8_t> ct0;
        std::optional<std::uint64_t> pending_ct0_ack;
    };
    struct EkFrozenRecvCt0 {
        static constexpr std::string_view name = "EkFrozenRecvCt0";
        FrozenEk ek;
        std::uint64_t cached_ct0_j = 0;
        std::vector<std::uint8_t> cached_ct0;
        std::uint64_t recv_ct0_j = 0;
        Decoder ct0_dec;
        std::optional<std::uint64_t> pending_ct0_ack;
        std::optional<CachedCt0> previous_ct0;
    };
    struct RecvCt1 {
        static constexpr std::string_view name = "RecvCt1";
        std::uint64_t i = 0;
        std::uint64_t j = 0;
        MockSecret dk;
        std::vector<std::uint8_t> ct0;
        Decoder ct1_dec;
    };
    using EkRoleState = std::variant<EkInit, SendFirstEkRecvFirstCt0, EkInitFrozenCtAwait,
                                     EkSampleRecvFirstCt0, EkSendWhileRecvCt0, EkFrozenCtAwait,
                                     EkFrozenAfterAggressiveCtAwait, EkFrozenRecvCt0, RecvCt1>;

    struct CtInit {
        static constexpr std::string_view name = "Init";
        Decoder ek_dec;
    };
    struct SendFirstCt0RecvFirstEk {
        static constexpr std::string_view name = "SendFirstCt0RecvFirstEk";
        MockSecret es;
        Encoder ct0_enc;
        Decoder ek_dec;
    };
    struct Ct0InitFrozenEkAwait {
        static constexpr std::string_view name = "Ct0InitFrozenEkAwait";
        std::uint64_t ek_i = 0;
        MockEncapsulationKey ek;
        std::optional<std::uint64_t> pending_ek_ack;
    };
    struct Ct0SampleRecvFirstEk {
        static constexpr std::string_view name = "Ct0SampleRecvFirstEk";
        std::uint64_t acked_j = 0;
        MockSecret acked_es;
        Decoder ek_dec;
    };
    struct Ct0SendWhileRecvEk {
        static constexpr std::string_view name = "Ct0SendWhileRecvEk";
        std::uint64_t acked_j = 0;
        MockSecret acked_es;
        std::uint64_t current_j = 0;
        MockSecret current_es;
        Encoder ct0_enc;
        Decoder ek_dec;
    };
    struct FrozenCt0 {
        std::uint64_t j = 0;
        MockSecret es;
        Encoder enc;
    };
    struct Ct0FrozenEkAwait {
        static constexpr std::string_view name = "Ct0FrozenEkAwait";
        FrozenCt0 ct0;
        std::uint64_t ek_i = 0;
        MockEncapsulationKey ek;
        std::optional<std::uint64_t> pending_ek_ack;
    };
    struct Ct0FrozenRecvEk {
        static constexpr std::string_view name = "Ct0FrozenRecvEk";
        FrozenCt0 ct0;
        std::uint64_t cached_ek_i = 0;
        MockEncapsulationKey cached_ek;
        std::uint64_t recv_ek_i = 0;
        Decoder ek_dec;
        std::optional<std::uint64_t> pending_ek_ack;
    };
    struct CtSendCt1 {
        static constexpr std::string_view name = "SendCt1";
        AggUniKemOutputId id;
        Encoder enc;
        bool first = true;
    };
    using CtRoleState = std::variant<CtInit, SendFirstCt0RecvFirstEk, Ct0InitFrozenEkAwait,
                                     Ct0SampleRecvFirstEk, Ct0SendWhileRecvEk, Ct0FrozenEkAwait,
                                     Ct0FrozenRecvEk, CtSendCt1>;

    struct EkRole {
        EkRoleState state;
    };
    struct CtRole {
        CtRoleState state;
    };
    using Role = std::variant<EkRole, CtRole>;

    explicit AggUniKem(Role role, InvalidEventPolicy policy)
        : role_(std::move(role)),
          invalid_event_policy_(policy) {}

    SckaOutputId sending_protocol_epoch() const {
        if (peer_known_id_) {
            return agg_uni_kem_output(*peer_known_id_);
        }
        return initial_epoch();
    }

    void invalid_event(std::string_view what) const {
        if (invalid_event_policy_ == InvalidEventPolicy::Throw) {
            throw std::runtime_error(std::string("invalid Agg-UniKEM event: ") + std::string(what));
        }
    }

    Message send_ek_role(EkRole& role) {
        auto message = send_ek_state(role.state);
        attach_pending_ct0_ack(role.state, message);
        return message;
    }

    Message send_ek_state(EkRoleState& state) {
        if (auto* init = std::get_if<EkInit>(&state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            state = SendFirstEkRecvFirstCt0{kp.dk, enc, std::move(init->ct0_dec)};
            return {epoch_, Message::Type::Ek, 0, 0, std::nullopt, std::nullopt, chunk};
        }
        if (auto* send = std::get_if<SendFirstEkRecvFirstCt0>(&state)) {
            return {epoch_, Message::Type::Ek, 0, 0, std::nullopt, std::nullopt, send->ek_enc.next_chunk()};
        }
        if (auto* frozen = std::get_if<EkInitFrozenCtAwait>(&state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            auto ct0_j = frozen->ct0_j;
            auto ct0 = std::move(frozen->ct0);
            auto pending = frozen->pending_ct0_ack;
            state = EkFrozenCtAwait{FrozenEk{0, kp.dk, enc, false}, ct0_j, std::move(ct0),
                                    pending, std::nullopt};
            return {epoch_, Message::Type::Ek, 0, 0, std::nullopt, std::nullopt, chunk};
        }
        if (auto* sample = std::get_if<EkSampleRecvFirstCt0>(&state)) {
            auto kp = kem_.keygen();
            Encoder enc(stream_id(), encode_u64(kp.ek.id));
            auto chunk = enc.next_chunk();
            auto current_i = sample->acked_i + 1;
            state = EkSendWhileRecvCt0{sample->acked_i, sample->acked_dk, current_i, kp.dk, enc,
                                       std::move(sample->ct0_dec)};
            return {epoch_, Message::Type::Ek, current_i, 0, std::nullopt, std::nullopt, chunk};
        }
        if (auto* send = std::get_if<EkSendWhileRecvCt0>(&state)) {
            return {epoch_, Message::Type::Ek, send->current_i, 0, std::nullopt, std::nullopt,
                    send->ek_enc.next_chunk()};
        }
        if (auto* frozen = std::get_if<EkFrozenCtAwait>(&state)) {
            if (frozen->ek.acked) {
                return {epoch_, Message::Type::None};
            }
            return {epoch_, Message::Type::Ek, frozen->ek.i, 0, std::nullopt, std::nullopt,
                    frozen->ek.enc.next_chunk()};
        }
        if (auto* frozen = std::get_if<EkFrozenAfterAggressiveCtAwait>(&state)) {
            if (!frozen->current_ek || frozen->current_ek->acked) {
                return {epoch_, Message::Type::None};
            }
            return {epoch_, Message::Type::Ek, frozen->current_ek->i, 0, std::nullopt, std::nullopt,
                    frozen->current_ek->enc.next_chunk()};
        }
        if (auto* rcv = std::get_if<EkFrozenRecvCt0>(&state)) {
            if (rcv->ek.acked) {
                return {epoch_, Message::Type::None};
            }
            return {epoch_, Message::Type::Ek, rcv->ek.i, 0, std::nullopt, std::nullopt,
                    rcv->ek.enc.next_chunk()};
        }
        return {epoch_, Message::Type::None};
    }

    void attach_pending_ct0_ack(EkRoleState& state, Message& message) {
        auto* pending = pending_ct0_ack(state);
        if (!pending || !*pending) {
            return;
        }
        if (message.type == Message::Type::None) {
            message.type = Message::Type::Ct0Ack;
            message.j = **pending;
        } else {
            message.ct0_ack = **pending;
        }
    }

    std::optional<std::uint64_t>* pending_ct0_ack(EkRoleState& state) {
        if (auto* s = std::get_if<EkInitFrozenCtAwait>(&state)) return &s->pending_ct0_ack;
        if (auto* s = std::get_if<EkFrozenCtAwait>(&state)) return &s->pending_ct0_ack;
        if (auto* s = std::get_if<EkFrozenAfterAggressiveCtAwait>(&state)) return &s->pending_ct0_ack;
        if (auto* s = std::get_if<EkFrozenRecvCt0>(&state)) return &s->pending_ct0_ack;
        return nullptr;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ek_role(EkRole& role,
                                                                      const Message& message) {
        if (message.type == Message::Type::Ct1Commit || message.type == Message::Type::Ct1) {
            return receive_ct1(role, message);
        }
        auto ack = ek_ack_from(message);
        if (message.type == Message::Type::Ct0 && message.chunk) {
            receive_ct0_for_ek_role(role.state, message, ack);
            return std::nullopt;
        }
        if (ack) {
            receive_ek_ack(role.state, *ack);
        } else if (message.type != Message::Type::None) {
            invalid_event("EK role unexpected message");
        }
        return std::nullopt;
    }

    std::optional<std::uint64_t> ek_ack_from(const Message& message) const {
        if (message.ek_ack) {
            return *message.ek_ack;
        }
        if (message.type == Message::Type::EkAck) {
            return message.i;
        }
        return std::nullopt;
    }

    void receive_ct0_for_ek_role(EkRoleState& state, const Message& message,
                                 std::optional<std::uint64_t> ack) {
        if (auto* init = std::get_if<EkInit>(&state); init && message.j == 0) {
            init->ct0_dec.add(*message.chunk);
            if (auto ct0 = init->ct0_dec.message()) {
                state = EkInitFrozenCtAwait{0, *ct0, 0};
            }
            return;
        }
        if (auto* send = std::get_if<SendFirstEkRecvFirstCt0>(&state); send && message.j == 0) {
            send->ct0_dec.add(*message.chunk);
            if (auto ct0 = send->ct0_dec.message()) {
                FrozenEk ek{0, send->dk, send->ek_enc, ack == 0};
                state = EkFrozenCtAwait{ek, 0, *ct0, 0, std::nullopt};
                return;
            }
            if (ack == 0) {
                state = EkSampleRecvFirstCt0{0, send->dk, std::move(send->ct0_dec)};
            }
            return;
        }
        if (auto* sample = std::get_if<EkSampleRecvFirstCt0>(&state); sample && message.j == 0) {
            sample->ct0_dec.add(*message.chunk);
            if (auto ct0 = sample->ct0_dec.message()) {
                state = EkFrozenAfterAggressiveCtAwait{sample->acked_i, sample->acked_dk,
                                                       std::nullopt, 0, *ct0, 0};
            }
            return;
        }
        if (auto* send = std::get_if<EkSendWhileRecvCt0>(&state); send && message.j == 0) {
            send->ct0_dec.add(*message.chunk);
            if (auto ct0 = send->ct0_dec.message()) {
                auto acked_i = send->acked_i;
                auto acked_dk = send->acked_dk;
                auto current = FrozenEk{send->current_i, send->current_dk, send->ek_enc, false};
                if (ack == send->current_i) {
                    acked_i = send->current_i;
                    acked_dk = send->current_dk;
                    current.acked = true;
                }
                state = EkFrozenAfterAggressiveCtAwait{acked_i, acked_dk, current, 0, *ct0, 0};
                return;
            }
            if (ack == send->current_i) {
                state = EkSampleRecvFirstCt0{send->current_i, send->current_dk, std::move(send->ct0_dec)};
            }
            return;
        }
        if (auto* await = std::get_if<EkFrozenCtAwait>(&state); await && message.j == await->ct0_j + 1) {
            receive_ek_ack(state, ack.value_or(static_cast<std::uint64_t>(-1)));
            Decoder dec(kCt0Chunks);
            dec.add(*message.chunk);
            state = EkFrozenRecvCt0{await->ek, await->ct0_j, await->ct0, message.j, dec,
                                    await->pending_ct0_ack, await->previous_ct0};
            return;
        }
        if (auto* rcv = std::get_if<EkFrozenRecvCt0>(&state); rcv && message.j == rcv->recv_ct0_j) {
            receive_ek_ack(state, ack.value_or(static_cast<std::uint64_t>(-1)));
            rcv->ct0_dec.add(*message.chunk);
            if (auto ct0 = rcv->ct0_dec.message()) {
                state = EkFrozenCtAwait{rcv->ek, rcv->recv_ct0_j, *ct0, rcv->recv_ct0_j,
                                        CachedCt0{rcv->cached_ct0_j, rcv->cached_ct0}};
            }
            return;
        }
        if (ack) {
            receive_ek_ack(state, *ack);
            return;
        }
        invalid_event("EK role unexpected CT0 chunk");
    }

    void receive_ek_ack(EkRoleState& state, std::uint64_t ack) {
        if (auto* send = std::get_if<SendFirstEkRecvFirstCt0>(&state); send && ack == 0) {
            state = EkSampleRecvFirstCt0{0, send->dk, std::move(send->ct0_dec)};
            return;
        }
        if (auto* send = std::get_if<EkSendWhileRecvCt0>(&state); send && ack == send->current_i) {
            state = EkSampleRecvFirstCt0{send->current_i, send->current_dk, std::move(send->ct0_dec)};
            return;
        }
        if (auto* frozen = std::get_if<EkFrozenCtAwait>(&state); frozen && ack == frozen->ek.i) {
            frozen->ek.acked = true;
            return;
        }
        if (auto* rcv = std::get_if<EkFrozenRecvCt0>(&state); rcv && ack == rcv->ek.i) {
            rcv->ek.acked = true;
            return;
        }
        if (auto* frozen = std::get_if<EkFrozenAfterAggressiveCtAwait>(&state)) {
            if (frozen->current_ek && ack == frozen->current_ek->i) {
                frozen->acked_i = frozen->current_ek->i;
                frozen->acked_dk = frozen->current_ek->dk;
                frozen->current_ek->acked = true;
            }
            return;
        }
    }

    std::optional<MockSecret> dk_for_commit(const EkRoleState& state, std::uint64_t i) const {
        if (const auto* send = std::get_if<SendFirstEkRecvFirstCt0>(&state); send && i == 0) return send->dk;
        if (const auto* sample = std::get_if<EkSampleRecvFirstCt0>(&state); sample && i == sample->acked_i) {
            return sample->acked_dk;
        }
        if (const auto* send = std::get_if<EkSendWhileRecvCt0>(&state)) {
            if (i == send->acked_i) return send->acked_dk;
            if (i == send->current_i) return send->current_dk;
        }
        if (const auto* frozen = std::get_if<EkFrozenCtAwait>(&state); frozen && i == frozen->ek.i) {
            return frozen->ek.dk;
        }
        if (const auto* rcv = std::get_if<EkFrozenRecvCt0>(&state); rcv && i == rcv->ek.i) return rcv->ek.dk;
        if (const auto* frozen = std::get_if<EkFrozenAfterAggressiveCtAwait>(&state)) {
            if (i == frozen->acked_i) return frozen->acked_dk;
            if (frozen->current_ek && i == frozen->current_ek->i) return frozen->current_ek->dk;
        }
        if (const auto* rcv = std::get_if<RecvCt1>(&state); rcv && i == rcv->i) return rcv->dk;
        return std::nullopt;
    }

    std::optional<std::vector<std::uint8_t>> ct0_for_commit(const EkRoleState& state,
                                                            std::uint64_t j) const {
        if (const auto* frozen = std::get_if<EkInitFrozenCtAwait>(&state); frozen && j == frozen->ct0_j) {
            return frozen->ct0;
        }
        if (const auto* frozen = std::get_if<EkFrozenCtAwait>(&state); frozen && j == frozen->ct0_j) {
            return frozen->ct0;
        }
        if (const auto* frozen = std::get_if<EkFrozenCtAwait>(&state);
            frozen && frozen->previous_ct0 && j == frozen->previous_ct0->j) {
            return frozen->previous_ct0->ct0;
        }
        if (const auto* frozen = std::get_if<EkFrozenAfterAggressiveCtAwait>(&state); frozen && j == frozen->ct0_j) {
            return frozen->ct0;
        }
        if (const auto* rcv = std::get_if<EkFrozenRecvCt0>(&state); rcv && j == rcv->cached_ct0_j) {
            return rcv->cached_ct0;
        }
        if (const auto* rcv = std::get_if<EkFrozenRecvCt0>(&state);
            rcv && rcv->previous_ct0 && j == rcv->previous_ct0->j) {
            return rcv->previous_ct0->ct0;
        }
        if (const auto* rcv = std::get_if<RecvCt1>(&state); rcv && j == rcv->j) return rcv->ct0;
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ct1(EkRole& role,
                                                                  const Message& message) {
        if (!message.chunk) {
            invalid_event("CT1 without chunk");
            return std::nullopt;
        }
        receive_ek_ack(role.state, message.i);
        if (!std::holds_alternative<RecvCt1>(role.state)) {
            auto dk = dk_for_commit(role.state, message.i);
            auto ct0 = ct0_for_commit(role.state, message.j);
            if (!dk || !ct0) {
                invalid_event("CT1 names unavailable commit pair");
                return std::nullopt;
            }
            Decoder dec(kCt1Chunks);
            dec.add(*message.chunk);
            role.state = RecvCt1{message.i, message.j, *dk, *ct0, dec};
        } else {
            auto& rcv = std::get<RecvCt1>(role.state);
            if (rcv.i != message.i || rcv.j != message.j) {
                invalid_event("CT1 commit indices changed");
                return std::nullopt;
            }
            rcv.ct1_dec.add(*message.chunk);
        }
        return maybe_finish_ct1(role);
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> maybe_finish_ct1(EkRole& role) {
        auto* rcv = std::get_if<RecvCt1>(&role.state);
        if (!rcv) return std::nullopt;
        auto ct1 = rcv->ct1_dec.message();
        if (!ct1) return std::nullopt;
        auto id = AggUniKemOutputId{epoch_, rcv->i, rcv->j};
        auto secret = kem_.decaps(rcv->dk, rcv->ct0, *ct1);
        last_emitted_id_ = id;
        emitted_ids_.push_back(id);
        peer_known_id_ = id;
        advance_ek_role();
        return std::pair{agg_uni_kem_output(id), secret};
    }

    void advance_ek_role() {
        ++epoch_;
        role_ = CtRole{CtInit{Decoder(kEkChunks)}};
    }

    std::pair<std::optional<std::pair<SckaOutputId, OutputKey>>, Message> send_ct_role(CtRole& role) {
        auto [output_key, message] = send_ct_state(role.state);
        attach_pending_ek_ack(role.state, message);
        return {output_key, message};
    }

    std::pair<std::optional<std::pair<SckaOutputId, OutputKey>>, Message> send_ct_state(CtRoleState& state) {
        if (auto* init = std::get_if<CtInit>(&state)) {
            auto [es, ct0] = kem_.enc_pk();
            Encoder enc(stream_id(), ct0);
            auto chunk = enc.next_chunk();
            state = SendFirstCt0RecvFirstEk{es, enc, std::move(init->ek_dec)};
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, 0, std::nullopt, std::nullopt, chunk}};
        }
        if (auto* send = std::get_if<SendFirstCt0RecvFirstEk>(&state)) {
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, 0, std::nullopt, std::nullopt,
                                   send->ct0_enc.next_chunk()}};
        }
        if (auto* frozen = std::get_if<Ct0InitFrozenEkAwait>(&state)) {
            auto [es, ct0] = kem_.enc_pk();
            Encoder enc(stream_id(), ct0);
            auto chunk = enc.next_chunk();
            auto ek_i = frozen->ek_i;
            auto ek = frozen->ek;
            auto pending = frozen->pending_ek_ack;
            state = Ct0FrozenEkAwait{FrozenCt0{0, es, enc}, ek_i, ek, pending};
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, 0, std::nullopt, std::nullopt, chunk}};
        }
        if (auto* sample = std::get_if<Ct0SampleRecvFirstEk>(&state)) {
            auto [es, ct0] = kem_.enc_pk();
            Encoder enc(stream_id(), ct0);
            auto chunk = enc.next_chunk();
            auto current_j = sample->acked_j + 1;
            state = Ct0SendWhileRecvEk{sample->acked_j, sample->acked_es, current_j, es, enc,
                                       std::move(sample->ek_dec)};
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, current_j, std::nullopt, std::nullopt,
                                   chunk}};
        }
        if (auto* send = std::get_if<Ct0SendWhileRecvEk>(&state)) {
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, send->current_j, std::nullopt,
                                   std::nullopt, send->ct0_enc.next_chunk()}};
        }
        if (auto* frozen = std::get_if<Ct0FrozenEkAwait>(&state)) {
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, frozen->ct0.j, std::nullopt,
                                   std::nullopt, frozen->ct0.enc.next_chunk()}};
        }
        if (auto* rcv = std::get_if<Ct0FrozenRecvEk>(&state)) {
            return {std::nullopt, {epoch_, Message::Type::Ct0, 0, rcv->ct0.j, std::nullopt,
                                   std::nullopt, rcv->ct0.enc.next_chunk()}};
        }
        auto& ct1 = std::get<CtSendCt1>(state);
        auto chunk = ct1.enc.next_chunk();
        Message message{epoch_, ct1.first ? Message::Type::Ct1Commit : Message::Type::Ct1,
                        ct1.id.ek_subepoch, ct1.id.ct0_subepoch, std::nullopt, std::nullopt, chunk};
        ct1.first = false;
        return {std::nullopt, message};
    }

    void attach_pending_ek_ack(CtRoleState& state, Message& message) {
        auto* pending = pending_ek_ack(state);
        if (!pending || !*pending) {
            return;
        }
        if (message.type == Message::Type::None) {
            message.type = Message::Type::EkAck;
            message.i = **pending;
        } else {
            message.ek_ack = **pending;
        }
    }

    std::optional<std::uint64_t>* pending_ek_ack(CtRoleState& state) {
        if (auto* s = std::get_if<Ct0InitFrozenEkAwait>(&state)) return &s->pending_ek_ack;
        if (auto* s = std::get_if<Ct0FrozenEkAwait>(&state)) return &s->pending_ek_ack;
        if (auto* s = std::get_if<Ct0FrozenRecvEk>(&state)) return &s->pending_ek_ack;
        return nullptr;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ct_role(CtRole& role,
                                                                      const Message& message) {
        auto ack = ct0_ack_from(message);
        if (message.type == Message::Type::Ek && message.chunk) {
            return receive_ek_for_ct_role(role.state, message, ack);
        }
        if (ack) {
            return receive_ct0_ack(role.state, *ack);
        }
        if (message.type != Message::Type::None) {
            invalid_event("CT role unexpected message");
        }
        return std::nullopt;
    }

    std::optional<std::uint64_t> ct0_ack_from(const Message& message) const {
        if (message.ct0_ack) {
            return *message.ct0_ack;
        }
        if (message.type == Message::Type::Ct0Ack) {
            return message.j;
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>>
    receive_ek_for_ct_role(CtRoleState& state, const Message& message, std::optional<std::uint64_t> ack) {
        if (auto* init = std::get_if<CtInit>(&state); init && message.i == 0) {
            init->ek_dec.add(*message.chunk);
            if (auto ek = init->ek_dec.message()) {
                state = Ct0InitFrozenEkAwait{0, MockEncapsulationKey{decode_u64(*ek)}, 0};
            }
            return std::nullopt;
        }
        if (auto* send = std::get_if<SendFirstCt0RecvFirstEk>(&state); send && message.i == 0) {
            send->ek_dec.add(*message.chunk);
            if (auto ek_bytes = send->ek_dec.message()) {
                auto ek = MockEncapsulationKey{decode_u64(*ek_bytes)};
                if (ack == 0) {
                    return commit_ct_sender(state, 0, 0, send->es, ek);
                }
                state = Ct0FrozenEkAwait{FrozenCt0{0, send->es, send->ct0_enc}, 0, ek, 0};
                return std::nullopt;
            }
            if (ack == 0) {
                state = Ct0SampleRecvFirstEk{0, send->es, std::move(send->ek_dec)};
            }
            return std::nullopt;
        }
        if (auto* sample = std::get_if<Ct0SampleRecvFirstEk>(&state); sample && message.i == 0) {
            sample->ek_dec.add(*message.chunk);
            if (auto ek = sample->ek_dec.message()) {
                return commit_ct_sender(state, 0, sample->acked_j, sample->acked_es,
                                        MockEncapsulationKey{decode_u64(*ek)});
            }
            return std::nullopt;
        }
        if (auto* send = std::get_if<Ct0SendWhileRecvEk>(&state); send && message.i == 0) {
            send->ek_dec.add(*message.chunk);
            if (auto ek = send->ek_dec.message()) {
                auto commit_j = send->acked_j;
                auto commit_es = send->acked_es;
                if (ack == send->current_j) {
                    commit_j = send->current_j;
                    commit_es = send->current_es;
                }
                return commit_ct_sender(state, 0, commit_j, commit_es, MockEncapsulationKey{decode_u64(*ek)});
            }
            if (ack == send->current_j) {
                state = Ct0SampleRecvFirstEk{send->current_j, send->current_es, std::move(send->ek_dec)};
            }
            return std::nullopt;
        }
        if (auto* await = std::get_if<Ct0FrozenEkAwait>(&state); await && message.i == await->ek_i + 1) {
            if (ack == await->ct0.j) {
                return commit_ct_sender(state, await->ek_i, await->ct0.j, await->ct0.es, await->ek);
            }
            Decoder dec(kEkChunks);
            dec.add(*message.chunk);
            state = Ct0FrozenRecvEk{await->ct0, await->ek_i, await->ek, message.i, dec,
                                    await->pending_ek_ack};
            return std::nullopt;
        }
        if (auto* rcv = std::get_if<Ct0FrozenRecvEk>(&state); rcv && message.i == rcv->recv_ek_i) {
            if (ack == rcv->ct0.j) {
                return commit_ct_sender(state, rcv->cached_ek_i, rcv->ct0.j, rcv->ct0.es, rcv->cached_ek);
            }
            rcv->ek_dec.add(*message.chunk);
            if (auto ek = rcv->ek_dec.message()) {
                auto i = rcv->recv_ek_i;
                state = Ct0FrozenEkAwait{rcv->ct0, i, MockEncapsulationKey{decode_u64(*ek)}, i};
            }
            return std::nullopt;
        }
        if (ack) {
            return receive_ct0_ack(state, *ack);
        }
        invalid_event("CT role unexpected EK chunk");
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>> receive_ct0_ack(CtRoleState& state,
                                                                      std::uint64_t ack) {
        if (auto* send = std::get_if<SendFirstCt0RecvFirstEk>(&state); send && ack == 0) {
            state = Ct0SampleRecvFirstEk{0, send->es, std::move(send->ek_dec)};
            return std::nullopt;
        }
        if (auto* send = std::get_if<Ct0SendWhileRecvEk>(&state); send && ack == send->current_j) {
            state = Ct0SampleRecvFirstEk{send->current_j, send->current_es, std::move(send->ek_dec)};
            return std::nullopt;
        }
        if (auto* frozen = std::get_if<Ct0FrozenEkAwait>(&state); frozen && ack == frozen->ct0.j) {
            return commit_ct_sender(state, frozen->ek_i, frozen->ct0.j, frozen->ct0.es, frozen->ek);
        }
        if (auto* rcv = std::get_if<Ct0FrozenRecvEk>(&state); rcv && ack == rcv->ct0.j) {
            return commit_ct_sender(state, rcv->cached_ek_i, rcv->ct0.j, rcv->ct0.es, rcv->cached_ek);
        }
        return std::nullopt;
    }

    std::optional<std::pair<SckaOutputId, OutputKey>>
    commit_ct_sender(CtRoleState& state, std::uint64_t i, std::uint64_t j, MockSecret es,
                     MockEncapsulationKey ek) {
        auto result = kem_.enc_ct(ek, es);
        auto id = AggUniKemOutputId{epoch_, i, j};
        state = CtSendCt1{id, Encoder(stream_id(), result.ct1), true};
        last_emitted_id_ = id;
        emitted_ids_.push_back(id);
        return std::pair{agg_uni_kem_output(id), result.secret};
    }

    void advance_ct_role() {
        ++epoch_;
        role_ = EkRole{EkInit{Decoder(kCt0Chunks)}};
        peer_known_id_ = last_emitted_id_;
    }

    std::vector<ProtocolSecretPattern> compromised_ek_role_patterns(const EkRole& role) const {
        std::vector<ProtocolSecretPattern> patterns;
        std::visit(
            [&](const auto& state) {
                using T = std::decay_t<decltype(state)>;
                if constexpr (std::is_same_v<T, SendFirstEkRecvFirstCt0>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, 0)));
                } else if constexpr (std::is_same_v<T, EkSampleRecvFirstCt0>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.acked_i)));
                } else if constexpr (std::is_same_v<T, EkSendWhileRecvCt0>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.acked_i)));
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.current_i)));
                } else if constexpr (std::is_same_v<T, EkFrozenCtAwait>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.ek.i)));
                } else if constexpr (std::is_same_v<T, EkFrozenRecvCt0>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.ek.i)));
                } else if constexpr (std::is_same_v<T, EkFrozenAfterAggressiveCtAwait>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.acked_i)));
                    if (state.current_ek) {
                        patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.current_ek->i)));
                    }
                } else if constexpr (std::is_same_v<T, RecvCt1>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ek_dk(epoch_, state.i)));
                }
            },
            role.state);
        return patterns;
    }

    std::vector<ProtocolSecretPattern> compromised_ct_role_patterns(const CtRole& role) const {
        std::vector<ProtocolSecretPattern> patterns;
        std::visit(
            [&](const auto& state) {
                using T = std::decay_t<decltype(state)>;
                if constexpr (std::is_same_v<T, SendFirstCt0RecvFirstEk>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ct0_state(epoch_, 0)));
                } else if constexpr (std::is_same_v<T, Ct0SampleRecvFirstEk>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ct0_state(epoch_, state.acked_j)));
                } else if constexpr (std::is_same_v<T, Ct0SendWhileRecvEk>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ct0_state(epoch_, state.acked_j)));
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ct0_state(epoch_, state.current_j)));
                } else if constexpr (std::is_same_v<T, Ct0FrozenEkAwait>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ct0_state(epoch_, state.ct0.j)));
                } else if constexpr (std::is_same_v<T, Ct0FrozenRecvEk>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::ct0_state(epoch_, state.ct0.j)));
                } else if constexpr (std::is_same_v<T, CtSendCt1>) {
                    patterns.push_back(scka_secret(AggUniKemOutputPattern::exact(state.id)));
                }
            },
            role.state);
        return patterns;
    }

    std::uint64_t stream_id() {
        return next_stream_id_++;
    }

    Role role_;
    InvalidEventPolicy invalid_event_policy_ = InvalidEventPolicy::Ignore;
    Epoch epoch_ = 1;
    MockUniKem kem_;
    std::uint64_t next_stream_id_ = 1;
    std::optional<AggUniKemOutputId> last_emitted_id_;
    std::vector<AggUniKemOutputId> emitted_ids_;
    std::optional<AggUniKemOutputId> peer_known_id_;
};

} // namespace smsim
