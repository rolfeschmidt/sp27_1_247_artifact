#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace smsim {

using Epoch = std::uint64_t;
using MessageId = std::uint64_t;

struct MessageEpoch {
    Epoch value = 0;

    auto operator<=>(const MessageEpoch&) const = default;
};

struct AggUniKemOutputId {
    Epoch message_epoch = 0;
    std::uint64_t ek_subepoch = 0;
    std::uint64_t ct0_subepoch = 0;

    auto operator<=>(const AggUniKemOutputId&) const = default;
};

using SckaOutputId = std::variant<MessageEpoch, AggUniKemOutputId>;

inline SckaOutputId message_output(Epoch epoch) {
    return MessageEpoch{epoch};
}

inline SckaOutputId agg_uni_kem_output(Epoch epoch, std::uint64_t ek_subepoch,
                                       std::uint64_t ct0_subepoch) {
    return AggUniKemOutputId{epoch, ek_subepoch, ct0_subepoch};
}

inline SckaOutputId agg_uni_kem_output(AggUniKemOutputId id) {
    return id;
}

inline MessageEpoch root_key_epoch_for_scka_output(const SckaOutputId& output) {
    return std::visit(
        [](const auto& concrete) -> MessageEpoch {
            using T = std::decay_t<decltype(concrete)>;
            if constexpr (std::is_same_v<T, MessageEpoch>) {
                return concrete;
            } else {
                return MessageEpoch{concrete.message_epoch};
            }
        },
        output);
}

inline MessageEpoch next_root_key_epoch_after_scka_output(const SckaOutputId& output) {
    return MessageEpoch{root_key_epoch_for_scka_output(output).value + 1};
}

inline std::string canonical_string(const MessageEpoch& epoch) {
    return "message:" + std::to_string(epoch.value);
}

inline std::string canonical_string(const AggUniKemOutputId& id) {
    std::ostringstream out;
    out << "agg-uni-kem:" << id.message_epoch << ':' << id.ek_subepoch << ':' << id.ct0_subepoch;
    return out.str();
}

inline std::string canonical_string(const SckaOutputId& output) {
    return std::visit([](const auto& concrete) { return canonical_string(concrete); }, output);
}

enum class ChainId {
    AliceSender,
    BobSender,
};

enum class Party {
    Alice,
    Bob,
};

inline Party other(Party party) {
    return party == Party::Alice ? Party::Bob : Party::Alice;
}

inline ChainId chain_from_sender(Party party) {
    return party == Party::Alice ? ChainId::AliceSender : ChainId::BobSender;
}

struct MessageSecretId {
    SckaOutputId output;
    ChainId chain_id = ChainId::AliceSender;
    std::uint64_t chain_counter = 0;

    auto operator<=>(const MessageSecretId&) const = default;
};

struct MessageRecord {
    MessageId id = 0;
    MessageSecretId secret;

    auto operator<=>(const MessageRecord&) const = default;
};

struct LegacyOutputPattern {
    Epoch epoch = 0;

    auto operator<=>(const LegacyOutputPattern&) const = default;
};

struct AggUniKemOutputPattern {
    Epoch message_epoch = 0;
    std::optional<std::uint64_t> ek_subepoch;
    std::optional<std::uint64_t> ct0_subepoch;

    static AggUniKemOutputPattern ek_dk(Epoch epoch, std::uint64_t ek_subepoch) {
        return {epoch, ek_subepoch, std::nullopt};
    }

    static AggUniKemOutputPattern ct0_state(Epoch epoch, std::uint64_t ct0_subepoch) {
        return {epoch, std::nullopt, ct0_subepoch};
    }

    static AggUniKemOutputPattern exact(AggUniKemOutputId id) {
        return {id.message_epoch, id.ek_subepoch, id.ct0_subepoch};
    }

    bool matches(AggUniKemOutputId id) const {
        return message_epoch == id.message_epoch
            && (!ek_subepoch || *ek_subepoch == id.ek_subepoch)
            && (!ct0_subepoch || *ct0_subepoch == id.ct0_subepoch);
    }

    auto operator<=>(const AggUniKemOutputPattern&) const = default;
};

struct OppUniKemOutputPattern {
    Epoch epoch = 0;

    auto operator<=>(const OppUniKemOutputPattern&) const = default;
};

struct AggRukemKeyRef {
    Party party = Party::Alice;
    Epoch key_epoch = 0;
    std::uint64_t update = 0;

    auto operator<=>(const AggRukemKeyRef&) const = default;
};

struct AggRukemOutputPattern {
    AggRukemKeyRef key;

    auto operator<=>(const AggRukemOutputPattern&) const = default;
};

struct AggRukemOutputRecord {
    MessageEpoch output;
    AggRukemKeyRef sender_key;
    AggRukemKeyRef receiver_key;

    bool matches(AggRukemOutputPattern pattern) const {
        auto key_matches = [](AggRukemKeyRef compromised, AggRukemKeyRef used) {
            return compromised.party == used.party
                && compromised.key_epoch == used.key_epoch
                && compromised.update <= used.update;
        };
        return key_matches(pattern.key, sender_key) || key_matches(pattern.key, receiver_key);
    }

    auto operator<=>(const AggRukemOutputRecord&) const = default;
};

using ProtocolSecretPattern = std::variant<LegacyOutputPattern, AggUniKemOutputPattern,
                                           OppUniKemOutputPattern, AggRukemOutputPattern>;

struct RootKeyPattern {
    MessageEpoch epoch;

    auto operator<=>(const RootKeyPattern&) const = default;
};

struct ChainKeyPattern {
    SckaOutputId output;
    ChainId chain_id = ChainId::AliceSender;
    std::uint64_t chain_counter = 0;

    auto operator<=>(const ChainKeyPattern&) const = default;
};

struct MessageKeyPattern {
    MessageSecretId id;

    auto operator<=>(const MessageKeyPattern&) const = default;
};

using SecretPattern = std::variant<RootKeyPattern, ChainKeyPattern, MessageKeyPattern>;

inline SecretPattern root_key(MessageEpoch epoch) {
    return RootKeyPattern{epoch};
}

inline SecretPattern chain_key(SckaOutputId output, ChainId chain_id, std::uint64_t counter) {
    return ChainKeyPattern{std::move(output), chain_id, counter};
}

inline SecretPattern message_key(MessageSecretId id) {
    return MessageKeyPattern{id};
}

inline ProtocolSecretPattern scka_secret(ProtocolSecretPattern pattern) {
    return pattern;
}

} // namespace smsim
