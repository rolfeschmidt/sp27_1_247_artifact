#pragma once

#include "agg_rukem_resolver.hpp"
#include "agg_unikem_resolver.hpp"
#include "aggressive_rukem.hpp"
#include "aggressive_unikem.hpp"
#include "opp_unikem_resolver.hpp"
#include "opportunistic_rkem.hpp"
#include "opportunistic_rkem_usenix.hpp"
#include "opportunistic_unikem.hpp"
#include "opportunistic_unikem_usenix.hpp"
#include "resolver.hpp"
#include "secure_messaging.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace smsim {

enum class TrafficModel {
    PingPong,
    Ratio,
};

enum class EventType {
    Send,
    Receive,
    Compromise,
};

struct AggUniKemRunnerConfig {
    TrafficModel traffic_model = TrafficModel::PingPong;
    double ratio = 1.0;
    std::uint64_t ticks = 40;
    std::uint64_t seed = 0;
    std::uint64_t run_id = 0;
};

struct CompromiseSnapshot {
    std::uint64_t sample_id = 0;
    std::uint64_t tick = 0;
    EventType event_type = EventType::Compromise;
    std::optional<MessageId> event_message_id;
    Party compromised_party = Party::Alice;
    std::vector<SecretPattern> messaging_patterns;
    std::vector<ProtocolSecretPattern> protocol_patterns;
    std::uint64_t messages_by_alice = 0;
    std::uint64_t messages_by_bob = 0;
};

struct VmsSampleRow {
    std::uint64_t sample_id = 0;
    std::uint64_t tick = 0;
    EventType event_type = EventType::Compromise;
    std::optional<MessageId> event_message_id;
    Party compromised_party = Party::Alice;
    std::uint64_t total_messages = 0;
    std::uint64_t messages_by_alice = 0;
    std::uint64_t messages_by_bob = 0;
    std::uint64_t compromised_scka_outputs_count = 0;
    std::uint64_t vms_total = 0;
    std::uint64_t vms_alice = 0;
    std::uint64_t vms_bob = 0;
};

struct HealingHistogramEntry {
    std::uint64_t num_msgs = 0;
    std::uint64_t tot_by_alice = 0;
    std::uint64_t tot_by_bob = 0;
};

struct HealingStats {
    double mean = 0.0;
    double stddev = 0.0;
    std::array<std::uint64_t, 11> deciles{};
};

struct AggUniKemRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<AggUniKemOutputId> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

struct OppUniKemRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<MessageEpoch> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

struct OppUniKemUsenixRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<MessageEpoch> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

struct OppRkemRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<MessageEpoch> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

struct OppRkemUsenixRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<MessageEpoch> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

struct AggRkemRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<AggRukemOutputRecord> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

struct AggRukemRunResult {
    AggUniKemRunnerConfig config;
    std::vector<MessageRecord> messages;
    std::map<MessageId, Party> message_senders;
    std::vector<AggRukemOutputRecord> emitted_outputs;
    std::vector<CompromiseSnapshot> snapshots;
    std::vector<VmsSampleRow> rows;
};

inline std::string to_string(Party party) {
    return party == Party::Alice ? "alice" : "bob";
}

inline std::string to_string(EventType event_type) {
    switch (event_type) {
    case EventType::Send:
        return "send";
    case EventType::Receive:
        return "receive";
    case EventType::Compromise:
        return "compromise";
    }
    throw std::runtime_error("unknown event type");
}

inline std::string to_string(TrafficModel model) {
    return model == TrafficModel::PingPong ? "ping-pong" : "ratio";
}

inline std::string to_csv_message_id(const std::optional<MessageId>& message_id) {
    return message_id ? std::to_string(*message_id) : "";
}

struct RatioTrafficProbabilities {
    double alice = 1.0;
    double bob = 1.0;
};

struct WakingParties {
    std::array<Party, 2> parties{};
    std::uint8_t count = 0;

    const Party* begin() const {
        return parties.data();
    }

    const Party* end() const {
        return parties.data() + count;
    }
};

inline WakingParties sample_waking_parties(const AggUniKemRunnerConfig& config,
                                           std::bernoulli_distribution& alice_wakes,
                                           std::bernoulli_distribution& bob_wakes,
                                           std::mt19937_64& rng) {
    const bool alice_woke = config.traffic_model == TrafficModel::PingPong || alice_wakes(rng);
    const bool bob_woke = config.traffic_model == TrafficModel::PingPong || bob_wakes(rng);

    WakingParties waking;
    if (alice_woke && bob_woke) {
        std::bernoulli_distribution alice_first(0.5);
        if (alice_first(rng)) {
            waking.parties = {Party::Alice, Party::Bob};
        } else {
            waking.parties = {Party::Bob, Party::Alice};
        }
        waking.count = 2;
    } else if (alice_woke) {
        waking.parties[0] = Party::Alice;
        waking.count = 1;
    } else if (bob_woke) {
        waking.parties[0] = Party::Bob;
        waking.count = 1;
    }
    return waking;
}

inline RatioTrafficProbabilities ratio_traffic_probabilities(double ratio) {
    if (ratio <= 0.0) {
        throw std::runtime_error("ratio must be positive");
    }
    auto denominator = ratio + 1.0;
    return {
        ratio / denominator,
        1.0 / denominator,
    };
}

inline std::string join_scka_outputs(const std::set<SckaOutputId>& outputs) {
    std::ostringstream out;
    bool first = true;
    for (const auto& output : outputs) {
        if (!first) {
            out << ';';
        }
        first = false;
        out << canonical_string(output);
    }
    return out.str();
}

inline void append_unique_outputs(std::vector<AggUniKemOutputId>& merged,
                                  const std::vector<AggUniKemOutputId>& outputs) {
    for (auto output : outputs) {
        if (std::find(merged.begin(), merged.end(), output) == merged.end()) {
            merged.push_back(output);
        }
    }
    std::sort(merged.begin(), merged.end());
}

inline void append_unique_outputs(std::vector<MessageEpoch>& merged,
                                  const std::vector<MessageEpoch>& outputs) {
    for (auto output : outputs) {
        if (std::find(merged.begin(), merged.end(), output) == merged.end()) {
            merged.push_back(output);
        }
    }
    std::sort(merged.begin(), merged.end());
}

inline void append_unique_outputs(std::vector<AggRukemOutputRecord>& merged,
                                  const std::vector<AggRukemOutputRecord>& outputs) {
    for (auto output : outputs) {
        if (std::find(merged.begin(), merged.end(), output) == merged.end()) {
            merged.push_back(output);
        }
    }
    std::sort(merged.begin(), merged.end());
}

class AggUniKemSimulation {
public:
    explicit AggUniKemSimulation(AggUniKemRunnerConfig config)
        : result_{config} {
        auto pair = SecureMessaging<AggUniKem>::create_pair();
        alice_ = std::move(pair.first);
        bob_ = std::move(pair.second);
    }

    AggUniKemRunResult run() {
        RatioTrafficProbabilities probabilities;
        if (result_.config.traffic_model == TrafficModel::Ratio) {
            probabilities = ratio_traffic_probabilities(result_.config.ratio);
        }

        std::mt19937_64 rng(result_.config.seed);
        std::bernoulli_distribution alice_sends(probabilities.alice);
        std::bernoulli_distribution bob_sends(probabilities.bob);
        for (std::uint64_t tick = 0; tick < result_.config.ticks; ++tick) {
            for (auto party : sample_waking_parties(result_.config, alice_sends, bob_sends, rng)) {
                if (party == Party::Alice) {
                    receive_all_for_alice();
                    send_from_alice(tick);
                } else {
                    receive_all_for_bob();
                    send_from_bob(tick);
                }
            }
            record_compromise_snapshots(tick);
        }

        append_unique_outputs(result_.emitted_outputs, alice_->scka().emitted_epoch_ids());
        append_unique_outputs(result_.emitted_outputs, bob_->scka().emitted_epoch_ids());
        resolve_snapshots();
        return result_;
    }

private:
    using Message = SecureMessaging<AggUniKem>::Message;

    struct QueuedMessage {
        MessageId id = 0;
        Message message;
    };

    void send_from_alice(std::uint64_t tick) {
        auto message = alice_->send();
        auto id = record_message(Party::Alice, message.message_secret);
        alice_to_bob_.push_back({id, std::move(message)});
    }

    void send_from_bob(std::uint64_t tick) {
        auto message = bob_->send();
        auto id = record_message(Party::Bob, message.message_secret);
        bob_to_alice_.push_back({id, std::move(message)});
    }

    void receive_all_for_alice() {
        if (bob_to_alice_.empty()) {
            return;
        }
        while (!bob_to_alice_.empty()) {
            auto queued = std::move(bob_to_alice_.front());
            bob_to_alice_.pop_front();
            (void)alice_->receive(queued.message);
        }
    }

    void receive_all_for_bob() {
        if (alice_to_bob_.empty()) {
            return;
        }
        while (!alice_to_bob_.empty()) {
            auto queued = std::move(alice_to_bob_.front());
            alice_to_bob_.pop_front();
            (void)bob_->receive(queued.message);
        }
    }

    MessageId record_message(Party sender, MessageSecretId secret) {
        auto id = next_message_id_++;
        result_.messages.push_back({id, std::move(secret)});
        result_.message_senders[id] = sender;
        if (sender == Party::Alice) {
            ++messages_by_alice_;
        } else {
            ++messages_by_bob_;
        }
        return id;
    }

    void record_compromise_snapshots(std::uint64_t tick) {
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Alice);
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Bob);
    }

    void record_snapshot(std::uint64_t tick, EventType event_type,
                         std::optional<MessageId> message_id, Party compromised_party) {
        const auto& party = compromised_party == Party::Alice ? *alice_ : *bob_;
        result_.snapshots.push_back({
            next_sample_id_++,
            tick,
            event_type,
            message_id,
            compromised_party,
            party.compromised_secret_patterns(),
            party.compromised_protocol_secret_patterns(),
            messages_by_alice_,
            messages_by_bob_,
        });
    }

    void resolve_snapshots() {
        VmsResolver resolver(result_.messages);
        for (const auto& snapshot : result_.snapshots) {
            auto compromised_outputs =
                resolve_agg_unikem_outputs(result_.emitted_outputs, snapshot.protocol_patterns);
            auto counts = resolver.resolve_counts(snapshot.messaging_patterns, compromised_outputs);

            VmsSampleRow row;
            row.sample_id = snapshot.sample_id;
            row.tick = snapshot.tick;
            row.event_type = snapshot.event_type;
            row.event_message_id = snapshot.event_message_id;
            row.compromised_party = snapshot.compromised_party;
            row.total_messages = snapshot.messages_by_alice + snapshot.messages_by_bob;
            row.messages_by_alice = snapshot.messages_by_alice;
            row.messages_by_bob = snapshot.messages_by_bob;
            row.compromised_scka_outputs_count = compromised_outputs.size();
            row.vms_total = counts.total;
            if (snapshot.compromised_party == Party::Alice) {
                row.vms_alice = counts.total;
            } else {
                row.vms_bob = counts.total;
            }
            result_.rows.push_back(std::move(row));
        }
    }

    AggUniKemRunResult result_;
    std::optional<SecureMessaging<AggUniKem>> alice_;
    std::optional<SecureMessaging<AggUniKem>> bob_;
    std::deque<QueuedMessage> alice_to_bob_;
    std::deque<QueuedMessage> bob_to_alice_;
    MessageId next_message_id_ = 0;
    std::uint64_t next_sample_id_ = 0;
    std::uint64_t messages_by_alice_ = 0;
    std::uint64_t messages_by_bob_ = 0;
};

inline AggUniKemRunResult run_agg_unikem_simulation(AggUniKemRunnerConfig config) {
    return AggUniKemSimulation(std::move(config)).run();
}

template <typename SckaProtocol, typename RunResult>
class AggRkemFamilySimulation {
public:
    explicit AggRkemFamilySimulation(AggUniKemRunnerConfig config)
        : result_{config} {
        auto pair = SecureMessaging<SckaProtocol>::create_pair();
        alice_ = std::move(pair.first);
        bob_ = std::move(pair.second);
    }

    RunResult run() {
        RatioTrafficProbabilities probabilities;
        if (result_.config.traffic_model == TrafficModel::Ratio) {
            probabilities = ratio_traffic_probabilities(result_.config.ratio);
        }

        std::mt19937_64 rng(result_.config.seed);
        std::bernoulli_distribution alice_sends(probabilities.alice);
        std::bernoulli_distribution bob_sends(probabilities.bob);
        for (std::uint64_t tick = 0; tick < result_.config.ticks; ++tick) {
            for (auto party : sample_waking_parties(result_.config, alice_sends, bob_sends, rng)) {
                if (party == Party::Alice) {
                    receive_all_for_alice();
                    send_from_alice(tick);
                } else {
                    receive_all_for_bob();
                    send_from_bob(tick);
                }
            }
            record_compromise_snapshots(tick);
        }

        append_unique_outputs(result_.emitted_outputs, alice_->scka().emitted_output_records());
        append_unique_outputs(result_.emitted_outputs, bob_->scka().emitted_output_records());
        resolve_snapshots();
        return result_;
    }

private:
    using Message = SecureMessaging<SckaProtocol>::Message;

    struct QueuedMessage {
        MessageId id = 0;
        Message message;
    };

    void send_from_alice(std::uint64_t tick) {
        auto message = alice_->send();
        auto id = record_message(Party::Alice, message.message_secret);
        alice_to_bob_.push_back({id, std::move(message)});
    }

    void send_from_bob(std::uint64_t tick) {
        auto message = bob_->send();
        auto id = record_message(Party::Bob, message.message_secret);
        bob_to_alice_.push_back({id, std::move(message)});
    }

    void receive_all_for_alice() {
        if (bob_to_alice_.empty()) {
            return;
        }
        while (!bob_to_alice_.empty()) {
            auto queued = std::move(bob_to_alice_.front());
            bob_to_alice_.pop_front();
            (void)alice_->receive(queued.message);
        }
    }

    void receive_all_for_bob() {
        if (alice_to_bob_.empty()) {
            return;
        }
        while (!alice_to_bob_.empty()) {
            auto queued = std::move(alice_to_bob_.front());
            alice_to_bob_.pop_front();
            (void)bob_->receive(queued.message);
        }
    }

    MessageId record_message(Party sender, MessageSecretId secret) {
        auto id = next_message_id_++;
        result_.messages.push_back({id, std::move(secret)});
        result_.message_senders[id] = sender;
        if (sender == Party::Alice) {
            ++messages_by_alice_;
        } else {
            ++messages_by_bob_;
        }
        return id;
    }

    void record_compromise_snapshots(std::uint64_t tick) {
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Alice);
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Bob);
    }

    void record_snapshot(std::uint64_t tick, EventType event_type,
                         std::optional<MessageId> message_id, Party compromised_party) {
        const auto& party = compromised_party == Party::Alice ? *alice_ : *bob_;
        result_.snapshots.push_back({
            next_sample_id_++,
            tick,
            event_type,
            message_id,
            compromised_party,
            party.compromised_secret_patterns(),
            party.compromised_protocol_secret_patterns(),
            messages_by_alice_,
            messages_by_bob_,
        });
    }

    void resolve_snapshots() {
        VmsResolver resolver(result_.messages);
        for (const auto& snapshot : result_.snapshots) {
            auto compromised_outputs =
                resolve_agg_rukem_outputs(result_.emitted_outputs, snapshot.protocol_patterns);
            auto counts = resolver.resolve_counts(snapshot.messaging_patterns, compromised_outputs);

            VmsSampleRow row;
            row.sample_id = snapshot.sample_id;
            row.tick = snapshot.tick;
            row.event_type = snapshot.event_type;
            row.event_message_id = snapshot.event_message_id;
            row.compromised_party = snapshot.compromised_party;
            row.total_messages = snapshot.messages_by_alice + snapshot.messages_by_bob;
            row.messages_by_alice = snapshot.messages_by_alice;
            row.messages_by_bob = snapshot.messages_by_bob;
            row.compromised_scka_outputs_count = compromised_outputs.size();
            row.vms_total = counts.total;
            if (snapshot.compromised_party == Party::Alice) {
                row.vms_alice = counts.total;
            } else {
                row.vms_bob = counts.total;
            }
            result_.rows.push_back(std::move(row));
        }
    }

    RunResult result_;
    std::optional<SecureMessaging<SckaProtocol>> alice_;
    std::optional<SecureMessaging<SckaProtocol>> bob_;
    std::deque<QueuedMessage> alice_to_bob_;
    std::deque<QueuedMessage> bob_to_alice_;
    MessageId next_message_id_ = 0;
    std::uint64_t next_sample_id_ = 0;
    std::uint64_t messages_by_alice_ = 0;
    std::uint64_t messages_by_bob_ = 0;
};

inline AggRkemRunResult run_agg_rkem_simulation(AggUniKemRunnerConfig config) {
    return AggRkemFamilySimulation<AggRkem, AggRkemRunResult>(std::move(config)).run();
}

inline AggRukemRunResult run_agg_rukem_simulation(AggUniKemRunnerConfig config) {
    return AggRkemFamilySimulation<AggRukem, AggRukemRunResult>(std::move(config)).run();
}

class OppUniKemSimulation {
public:
    explicit OppUniKemSimulation(AggUniKemRunnerConfig config)
        : result_{config} {
        auto pair = SecureMessaging<OppUniKem>::create_pair();
        alice_ = std::move(pair.first);
        bob_ = std::move(pair.second);
    }

    OppUniKemRunResult run() {
        RatioTrafficProbabilities probabilities;
        if (result_.config.traffic_model == TrafficModel::Ratio) {
            probabilities = ratio_traffic_probabilities(result_.config.ratio);
        }

        std::mt19937_64 rng(result_.config.seed);
        std::bernoulli_distribution alice_sends(probabilities.alice);
        std::bernoulli_distribution bob_sends(probabilities.bob);
        for (std::uint64_t tick = 0; tick < result_.config.ticks; ++tick) {
            for (auto party : sample_waking_parties(result_.config, alice_sends, bob_sends, rng)) {
                if (party == Party::Alice) {
                    receive_all_for_alice();
                    send_from_alice(tick);
                } else {
                    receive_all_for_bob();
                    send_from_bob(tick);
                }
            }
            record_compromise_snapshots(tick);
        }

        append_unique_outputs(result_.emitted_outputs, alice_->scka().emitted_epoch_ids());
        append_unique_outputs(result_.emitted_outputs, bob_->scka().emitted_epoch_ids());
        resolve_snapshots();
        return result_;
    }

private:
    using Message = SecureMessaging<OppUniKem>::Message;

    struct QueuedMessage {
        MessageId id = 0;
        Message message;
    };

    void send_from_alice(std::uint64_t tick) {
        auto message = alice_->send();
        auto id = record_message(Party::Alice, message.message_secret);
        alice_to_bob_.push_back({id, std::move(message)});
    }

    void send_from_bob(std::uint64_t tick) {
        auto message = bob_->send();
        auto id = record_message(Party::Bob, message.message_secret);
        bob_to_alice_.push_back({id, std::move(message)});
    }

    void receive_all_for_alice() {
        if (bob_to_alice_.empty()) {
            return;
        }
        while (!bob_to_alice_.empty()) {
            auto queued = std::move(bob_to_alice_.front());
            bob_to_alice_.pop_front();
            (void)alice_->receive(queued.message);
        }
    }

    void receive_all_for_bob() {
        if (alice_to_bob_.empty()) {
            return;
        }
        while (!alice_to_bob_.empty()) {
            auto queued = std::move(alice_to_bob_.front());
            alice_to_bob_.pop_front();
            (void)bob_->receive(queued.message);
        }
    }

    MessageId record_message(Party sender, MessageSecretId secret) {
        auto id = next_message_id_++;
        result_.messages.push_back({id, std::move(secret)});
        result_.message_senders[id] = sender;
        if (sender == Party::Alice) {
            ++messages_by_alice_;
        } else {
            ++messages_by_bob_;
        }
        return id;
    }

    void record_compromise_snapshots(std::uint64_t tick) {
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Alice);
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Bob);
    }

    void record_snapshot(std::uint64_t tick, EventType event_type,
                         std::optional<MessageId> message_id, Party compromised_party) {
        const auto& party = compromised_party == Party::Alice ? *alice_ : *bob_;
        result_.snapshots.push_back({
            next_sample_id_++,
            tick,
            event_type,
            message_id,
            compromised_party,
            party.compromised_secret_patterns(),
            party.compromised_protocol_secret_patterns(),
            messages_by_alice_,
            messages_by_bob_,
        });
    }

    void resolve_snapshots() {
        VmsResolver resolver(result_.messages);
        for (const auto& snapshot : result_.snapshots) {
            auto compromised_outputs =
                resolve_opp_unikem_outputs(result_.emitted_outputs, snapshot.protocol_patterns);
            auto counts = resolver.resolve_counts(snapshot.messaging_patterns, compromised_outputs);

            VmsSampleRow row;
            row.sample_id = snapshot.sample_id;
            row.tick = snapshot.tick;
            row.event_type = snapshot.event_type;
            row.event_message_id = snapshot.event_message_id;
            row.compromised_party = snapshot.compromised_party;
            row.total_messages = snapshot.messages_by_alice + snapshot.messages_by_bob;
            row.messages_by_alice = snapshot.messages_by_alice;
            row.messages_by_bob = snapshot.messages_by_bob;
            row.compromised_scka_outputs_count = compromised_outputs.size();
            row.vms_total = counts.total;
            if (snapshot.compromised_party == Party::Alice) {
                row.vms_alice = counts.total;
            } else {
                row.vms_bob = counts.total;
            }
            result_.rows.push_back(std::move(row));
        }
    }

    OppUniKemRunResult result_;
    std::optional<SecureMessaging<OppUniKem>> alice_;
    std::optional<SecureMessaging<OppUniKem>> bob_;
    std::deque<QueuedMessage> alice_to_bob_;
    std::deque<QueuedMessage> bob_to_alice_;
    MessageId next_message_id_ = 0;
    std::uint64_t next_sample_id_ = 0;
    std::uint64_t messages_by_alice_ = 0;
    std::uint64_t messages_by_bob_ = 0;
};

inline OppUniKemRunResult run_opp_unikem_simulation(AggUniKemRunnerConfig config) {
    return OppUniKemSimulation(std::move(config)).run();
}

class OppUniKemUsenixSimulation {
public:
    explicit OppUniKemUsenixSimulation(AggUniKemRunnerConfig config)
        : result_{config} {
        auto pair = SecureMessaging<OppUniKemUsenix>::create_pair();
        alice_ = std::move(pair.first);
        bob_ = std::move(pair.second);
    }

    OppUniKemUsenixRunResult run() {
        RatioTrafficProbabilities probabilities;
        if (result_.config.traffic_model == TrafficModel::Ratio) {
            probabilities = ratio_traffic_probabilities(result_.config.ratio);
        }

        std::mt19937_64 rng(result_.config.seed);
        std::bernoulli_distribution alice_sends(probabilities.alice);
        std::bernoulli_distribution bob_sends(probabilities.bob);
        for (std::uint64_t tick = 0; tick < result_.config.ticks; ++tick) {
            for (auto party : sample_waking_parties(result_.config, alice_sends, bob_sends, rng)) {
                if (party == Party::Alice) {
                    receive_all_for_alice();
                    send_from_alice(tick);
                } else {
                    receive_all_for_bob();
                    send_from_bob(tick);
                }
            }
            record_compromise_snapshots(tick);
        }

        append_unique_outputs(result_.emitted_outputs, alice_->scka().emitted_epoch_ids());
        append_unique_outputs(result_.emitted_outputs, bob_->scka().emitted_epoch_ids());
        resolve_snapshots();
        return result_;
    }

private:
    using Message = SecureMessaging<OppUniKemUsenix>::Message;

    struct QueuedMessage {
        MessageId id = 0;
        Message message;
    };

    void send_from_alice(std::uint64_t tick) {
        auto message = alice_->send();
        auto id = record_message(Party::Alice, message.message_secret);
        alice_to_bob_.push_back({id, std::move(message)});
    }

    void send_from_bob(std::uint64_t tick) {
        auto message = bob_->send();
        auto id = record_message(Party::Bob, message.message_secret);
        bob_to_alice_.push_back({id, std::move(message)});
    }

    void receive_all_for_alice() {
        if (bob_to_alice_.empty()) {
            return;
        }
        while (!bob_to_alice_.empty()) {
            auto queued = std::move(bob_to_alice_.front());
            bob_to_alice_.pop_front();
            (void)alice_->receive(queued.message);
        }
    }

    void receive_all_for_bob() {
        if (alice_to_bob_.empty()) {
            return;
        }
        while (!alice_to_bob_.empty()) {
            auto queued = std::move(alice_to_bob_.front());
            alice_to_bob_.pop_front();
            (void)bob_->receive(queued.message);
        }
    }

    MessageId record_message(Party sender, MessageSecretId secret) {
        auto id = next_message_id_++;
        result_.messages.push_back({id, std::move(secret)});
        result_.message_senders[id] = sender;
        if (sender == Party::Alice) {
            ++messages_by_alice_;
        } else {
            ++messages_by_bob_;
        }
        return id;
    }

    void record_compromise_snapshots(std::uint64_t tick) {
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Alice);
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Bob);
    }

    void record_snapshot(std::uint64_t tick, EventType event_type,
                         std::optional<MessageId> message_id, Party compromised_party) {
        const auto& party = compromised_party == Party::Alice ? *alice_ : *bob_;
        result_.snapshots.push_back({
            next_sample_id_++,
            tick,
            event_type,
            message_id,
            compromised_party,
            party.compromised_secret_patterns(),
            party.compromised_protocol_secret_patterns(),
            messages_by_alice_,
            messages_by_bob_,
        });
    }

    void resolve_snapshots() {
        VmsResolver resolver(result_.messages);
        for (const auto& snapshot : result_.snapshots) {
            auto compromised_outputs =
                resolve_opp_unikem_outputs(result_.emitted_outputs, snapshot.protocol_patterns);
            auto counts = resolver.resolve_counts(snapshot.messaging_patterns, compromised_outputs);

            VmsSampleRow row;
            row.sample_id = snapshot.sample_id;
            row.tick = snapshot.tick;
            row.event_type = snapshot.event_type;
            row.event_message_id = snapshot.event_message_id;
            row.compromised_party = snapshot.compromised_party;
            row.total_messages = snapshot.messages_by_alice + snapshot.messages_by_bob;
            row.messages_by_alice = snapshot.messages_by_alice;
            row.messages_by_bob = snapshot.messages_by_bob;
            row.compromised_scka_outputs_count = compromised_outputs.size();
            row.vms_total = counts.total;
            if (snapshot.compromised_party == Party::Alice) {
                row.vms_alice = counts.total;
            } else {
                row.vms_bob = counts.total;
            }
            result_.rows.push_back(std::move(row));
        }
    }

    OppUniKemUsenixRunResult result_;
    std::optional<SecureMessaging<OppUniKemUsenix>> alice_;
    std::optional<SecureMessaging<OppUniKemUsenix>> bob_;
    std::deque<QueuedMessage> alice_to_bob_;
    std::deque<QueuedMessage> bob_to_alice_;
    MessageId next_message_id_ = 0;
    std::uint64_t next_sample_id_ = 0;
    std::uint64_t messages_by_alice_ = 0;
    std::uint64_t messages_by_bob_ = 0;
};

inline OppUniKemUsenixRunResult run_opp_unikem_usenix_simulation(AggUniKemRunnerConfig config) {
    return OppUniKemUsenixSimulation(std::move(config)).run();
}

class OppRkemSimulation {
public:
    explicit OppRkemSimulation(AggUniKemRunnerConfig config)
        : result_{config} {
        auto pair = SecureMessaging<OppRkem>::create_pair();
        alice_ = std::move(pair.first);
        bob_ = std::move(pair.second);
    }

    OppRkemRunResult run() {
        RatioTrafficProbabilities probabilities;
        if (result_.config.traffic_model == TrafficModel::Ratio) {
            probabilities = ratio_traffic_probabilities(result_.config.ratio);
        }

        std::mt19937_64 rng(result_.config.seed);
        std::bernoulli_distribution alice_sends(probabilities.alice);
        std::bernoulli_distribution bob_sends(probabilities.bob);
        for (std::uint64_t tick = 0; tick < result_.config.ticks; ++tick) {
            for (auto party : sample_waking_parties(result_.config, alice_sends, bob_sends, rng)) {
                if (party == Party::Alice) {
                    receive_all_for_alice();
                    send_from_alice(tick);
                } else {
                    receive_all_for_bob();
                    send_from_bob(tick);
                }
            }
            record_compromise_snapshots(tick);
        }

        append_unique_outputs(result_.emitted_outputs, alice_->scka().emitted_epoch_ids());
        append_unique_outputs(result_.emitted_outputs, bob_->scka().emitted_epoch_ids());
        resolve_snapshots();
        return result_;
    }

private:
    using Message = SecureMessaging<OppRkem>::Message;

    struct QueuedMessage {
        MessageId id = 0;
        Message message;
    };

    void send_from_alice(std::uint64_t tick) {
        auto message = alice_->send();
        auto id = record_message(Party::Alice, message.message_secret);
        alice_to_bob_.push_back({id, std::move(message)});
    }

    void send_from_bob(std::uint64_t tick) {
        auto message = bob_->send();
        auto id = record_message(Party::Bob, message.message_secret);
        bob_to_alice_.push_back({id, std::move(message)});
    }

    void receive_all_for_alice() {
        if (bob_to_alice_.empty()) {
            return;
        }
        while (!bob_to_alice_.empty()) {
            auto queued = std::move(bob_to_alice_.front());
            bob_to_alice_.pop_front();
            (void)alice_->receive(queued.message);
        }
    }

    void receive_all_for_bob() {
        if (alice_to_bob_.empty()) {
            return;
        }
        while (!alice_to_bob_.empty()) {
            auto queued = std::move(alice_to_bob_.front());
            alice_to_bob_.pop_front();
            (void)bob_->receive(queued.message);
        }
    }

    MessageId record_message(Party sender, MessageSecretId secret) {
        auto id = next_message_id_++;
        result_.messages.push_back({id, std::move(secret)});
        result_.message_senders[id] = sender;
        if (sender == Party::Alice) {
            ++messages_by_alice_;
        } else {
            ++messages_by_bob_;
        }
        return id;
    }

    void record_compromise_snapshots(std::uint64_t tick) {
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Alice);
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Bob);
    }

    void record_snapshot(std::uint64_t tick, EventType event_type,
                         std::optional<MessageId> message_id, Party compromised_party) {
        const auto& party = compromised_party == Party::Alice ? *alice_ : *bob_;
        result_.snapshots.push_back({
            next_sample_id_++,
            tick,
            event_type,
            message_id,
            compromised_party,
            party.compromised_secret_patterns(),
            party.compromised_protocol_secret_patterns(),
            messages_by_alice_,
            messages_by_bob_,
        });
    }

    void resolve_snapshots() {
        VmsResolver resolver(result_.messages);
        for (const auto& snapshot : result_.snapshots) {
            auto compromised_outputs =
                resolve_opp_unikem_outputs(result_.emitted_outputs, snapshot.protocol_patterns);
            auto counts = resolver.resolve_counts(snapshot.messaging_patterns, compromised_outputs);

            VmsSampleRow row;
            row.sample_id = snapshot.sample_id;
            row.tick = snapshot.tick;
            row.event_type = snapshot.event_type;
            row.event_message_id = snapshot.event_message_id;
            row.compromised_party = snapshot.compromised_party;
            row.total_messages = snapshot.messages_by_alice + snapshot.messages_by_bob;
            row.messages_by_alice = snapshot.messages_by_alice;
            row.messages_by_bob = snapshot.messages_by_bob;
            row.compromised_scka_outputs_count = compromised_outputs.size();
            row.vms_total = counts.total;
            if (snapshot.compromised_party == Party::Alice) {
                row.vms_alice = counts.total;
            } else {
                row.vms_bob = counts.total;
            }
            result_.rows.push_back(std::move(row));
        }
    }

    OppRkemRunResult result_;
    std::optional<SecureMessaging<OppRkem>> alice_;
    std::optional<SecureMessaging<OppRkem>> bob_;
    std::deque<QueuedMessage> alice_to_bob_;
    std::deque<QueuedMessage> bob_to_alice_;
    MessageId next_message_id_ = 0;
    std::uint64_t next_sample_id_ = 0;
    std::uint64_t messages_by_alice_ = 0;
    std::uint64_t messages_by_bob_ = 0;
};

inline OppRkemRunResult run_opp_rkem_simulation(AggUniKemRunnerConfig config) {
    return OppRkemSimulation(std::move(config)).run();
}

class OppRkemUsenixSimulation {
public:
    explicit OppRkemUsenixSimulation(AggUniKemRunnerConfig config)
        : result_{config} {
        auto pair = SecureMessaging<OppRkemUsenix>::create_pair();
        alice_ = std::move(pair.first);
        bob_ = std::move(pair.second);
    }

    OppRkemUsenixRunResult run() {
        RatioTrafficProbabilities probabilities;
        if (result_.config.traffic_model == TrafficModel::Ratio) {
            probabilities = ratio_traffic_probabilities(result_.config.ratio);
        }

        std::mt19937_64 rng(result_.config.seed);
        std::bernoulli_distribution alice_sends(probabilities.alice);
        std::bernoulli_distribution bob_sends(probabilities.bob);
        for (std::uint64_t tick = 0; tick < result_.config.ticks; ++tick) {
            for (auto party : sample_waking_parties(result_.config, alice_sends, bob_sends, rng)) {
                if (party == Party::Alice) {
                    receive_all_for_alice();
                    send_from_alice(tick);
                } else {
                    receive_all_for_bob();
                    send_from_bob(tick);
                }
            }
            record_compromise_snapshots(tick);
        }

        append_unique_outputs(result_.emitted_outputs, alice_->scka().emitted_epoch_ids());
        append_unique_outputs(result_.emitted_outputs, bob_->scka().emitted_epoch_ids());
        resolve_snapshots();
        return result_;
    }

private:
    using Message = SecureMessaging<OppRkemUsenix>::Message;

    struct QueuedMessage {
        MessageId id = 0;
        Message message;
    };

    void send_from_alice(std::uint64_t tick) {
        auto message = alice_->send();
        auto id = record_message(Party::Alice, message.message_secret);
        alice_to_bob_.push_back({id, std::move(message)});
    }

    void send_from_bob(std::uint64_t tick) {
        auto message = bob_->send();
        auto id = record_message(Party::Bob, message.message_secret);
        bob_to_alice_.push_back({id, std::move(message)});
    }

    void receive_all_for_alice() {
        if (bob_to_alice_.empty()) {
            return;
        }
        while (!bob_to_alice_.empty()) {
            auto queued = std::move(bob_to_alice_.front());
            bob_to_alice_.pop_front();
            (void)alice_->receive(queued.message);
        }
    }

    void receive_all_for_bob() {
        if (alice_to_bob_.empty()) {
            return;
        }
        while (!alice_to_bob_.empty()) {
            auto queued = std::move(alice_to_bob_.front());
            alice_to_bob_.pop_front();
            (void)bob_->receive(queued.message);
        }
    }

    MessageId record_message(Party sender, MessageSecretId secret) {
        auto id = next_message_id_++;
        result_.messages.push_back({id, std::move(secret)});
        result_.message_senders[id] = sender;
        if (sender == Party::Alice) {
            ++messages_by_alice_;
        } else {
            ++messages_by_bob_;
        }
        return id;
    }

    void record_compromise_snapshots(std::uint64_t tick) {
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Alice);
        record_snapshot(tick, EventType::Compromise, std::nullopt, Party::Bob);
    }

    void record_snapshot(std::uint64_t tick, EventType event_type,
                         std::optional<MessageId> message_id, Party compromised_party) {
        const auto& party = compromised_party == Party::Alice ? *alice_ : *bob_;
        result_.snapshots.push_back({
            next_sample_id_++,
            tick,
            event_type,
            message_id,
            compromised_party,
            party.compromised_secret_patterns(),
            party.compromised_protocol_secret_patterns(),
            messages_by_alice_,
            messages_by_bob_,
        });
    }

    void resolve_snapshots() {
        VmsResolver resolver(result_.messages);
        for (const auto& snapshot : result_.snapshots) {
            auto compromised_outputs =
                resolve_opp_unikem_outputs(result_.emitted_outputs, snapshot.protocol_patterns);
            auto counts = resolver.resolve_counts(snapshot.messaging_patterns, compromised_outputs);

            VmsSampleRow row;
            row.sample_id = snapshot.sample_id;
            row.tick = snapshot.tick;
            row.event_type = snapshot.event_type;
            row.event_message_id = snapshot.event_message_id;
            row.compromised_party = snapshot.compromised_party;
            row.total_messages = snapshot.messages_by_alice + snapshot.messages_by_bob;
            row.messages_by_alice = snapshot.messages_by_alice;
            row.messages_by_bob = snapshot.messages_by_bob;
            row.compromised_scka_outputs_count = compromised_outputs.size();
            row.vms_total = counts.total;
            if (snapshot.compromised_party == Party::Alice) {
                row.vms_alice = counts.total;
            } else {
                row.vms_bob = counts.total;
            }
            result_.rows.push_back(std::move(row));
        }
    }

    OppRkemUsenixRunResult result_;
    std::optional<SecureMessaging<OppRkemUsenix>> alice_;
    std::optional<SecureMessaging<OppRkemUsenix>> bob_;
    std::deque<QueuedMessage> alice_to_bob_;
    std::deque<QueuedMessage> bob_to_alice_;
    MessageId next_message_id_ = 0;
    std::uint64_t next_sample_id_ = 0;
    std::uint64_t messages_by_alice_ = 0;
    std::uint64_t messages_by_bob_ = 0;
};

inline OppRkemUsenixRunResult run_opp_rkem_usenix_simulation(AggUniKemRunnerConfig config) {
    return OppRkemUsenixSimulation(std::move(config)).run();
}

inline void write_csv(const AggUniKemRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "agg-uni-kem,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline void write_csv(const AggRkemRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "agg-rkem,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline void write_csv(const AggRukemRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "agg-rukem,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline void write_csv(const OppUniKemRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "opp-uni-kem,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline void write_csv(const OppUniKemUsenixRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "opp-unikem-usenix,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline void write_csv(const OppRkemRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "opp-rkem,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline void write_csv(const OppRkemUsenixRunResult& result, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open output CSV");
    }

    out << "protocol,traffic_model,seed,run_id,sample_id,tick,event_type,event_message_id,"
           "compromised_party,ratio,total_messages,messages_by_alice,messages_by_bob,"
           "compromised_scka_outputs_count,vms_total,vms_alice,vms_bob\n";
    for (const auto& row : result.rows) {
        out << "opp-rkem-usenix,"
            << to_string(result.config.traffic_model) << ','
            << result.config.seed << ','
            << result.config.run_id << ','
            << row.sample_id << ','
            << row.tick << ','
            << to_string(row.event_type) << ','
            << to_csv_message_id(row.event_message_id) << ','
            << to_string(row.compromised_party) << ','
            << result.config.ratio << ','
            << row.total_messages << ','
            << row.messages_by_alice << ','
            << row.messages_by_bob << ','
            << row.compromised_scka_outputs_count << ','
            << row.vms_total << ','
            << row.vms_alice << ','
            << row.vms_bob << '\n';
    }
}

inline std::vector<HealingHistogramEntry> healing_histogram_from_rows(
    const std::vector<VmsSampleRow>& rows) {
    std::map<std::uint64_t, HealingHistogramEntry> by_vms_size;
    for (const auto& row : rows) {
        auto& entry = by_vms_size[row.vms_total];
        entry.num_msgs = row.vms_total;
        if (row.compromised_party == Party::Alice) {
            ++entry.tot_by_alice;
        } else {
            ++entry.tot_by_bob;
        }
    }

    std::vector<HealingHistogramEntry> histogram;
    histogram.reserve(by_vms_size.size());
    for (const auto& [_, entry] : by_vms_size) {
        histogram.push_back(entry);
    }
    return histogram;
}

inline std::array<HealingStats, 2> stats_from_histogram(
    const std::vector<HealingHistogramEntry>& histogram) {
    std::array<std::uint64_t, 2> count{};
    std::array<long double, 2> sum{};
    std::array<long double, 2> sum_squares{};
    std::array<std::uint64_t, 2> min{
        std::numeric_limits<std::uint64_t>::max(),
        std::numeric_limits<std::uint64_t>::max(),
    };
    std::array<std::uint64_t, 2> max{};

    for (const auto& entry : histogram) {
        const std::array<std::uint64_t, 2> frequencies{
            entry.tot_by_alice,
            entry.tot_by_bob,
        };
        for (std::size_t party = 0; party < frequencies.size(); ++party) {
            const auto frequency = frequencies[party];
            count[party] += frequency;
            sum[party] += static_cast<long double>(entry.num_msgs) * frequency;
            sum_squares[party] += static_cast<long double>(entry.num_msgs)
                * static_cast<long double>(entry.num_msgs) * frequency;
            if (frequency > 0) {
                min[party] = std::min(min[party], entry.num_msgs);
                max[party] = std::max(max[party], entry.num_msgs);
            }
        }
    }

    std::array<HealingStats, 2> stats{};
    for (std::size_t party = 0; party < stats.size(); ++party) {
        if (count[party] == 0) {
            continue;
        }
        const auto mean = sum[party] / static_cast<long double>(count[party]);
        const auto mean_square = sum_squares[party] / static_cast<long double>(count[party]);
        const auto variance = std::max<long double>(0.0L, mean_square - mean * mean);
        stats[party].mean = static_cast<double>(mean);
        stats[party].stddev = std::sqrt(static_cast<double>(variance));
        stats[party].deciles[0] = min[party];
        stats[party].deciles[10] = max[party];

        std::uint64_t cumulative = 0;
        std::size_t decile = 1;
        for (const auto& entry : histogram) {
            cumulative += party == 0 ? entry.tot_by_alice : entry.tot_by_bob;
            while (decile < 10
                   && cumulative * 10 >= count[party] * static_cast<std::uint64_t>(decile)) {
                stats[party].deciles[decile] = entry.num_msgs;
                ++decile;
            }
        }
    }
    return stats;
}

inline void write_histogram_csv(const std::vector<HealingHistogramEntry>& histogram,
                                const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open histogram CSV");
    }

    std::uint64_t total_alice = 0;
    std::uint64_t total_bob = 0;
    for (const auto& entry : histogram) {
        total_alice += entry.tot_by_alice;
        total_bob += entry.tot_by_bob;
    }

    out << "num exposed,freq exposed by a,freq exposed by b,"
           "cumulative exposed by a, cumulative exposed by b\n";
    std::uint64_t cumulative_alice = 0;
    std::uint64_t cumulative_bob = 0;
    for (const auto& entry : histogram) {
        cumulative_alice += entry.tot_by_alice;
        cumulative_bob += entry.tot_by_bob;
        const double freq_alice = total_alice == 0
            ? 0.0
            : static_cast<double>(entry.tot_by_alice) / static_cast<double>(total_alice);
        const double freq_bob = total_bob == 0
            ? 0.0
            : static_cast<double>(entry.tot_by_bob) / static_cast<double>(total_bob);
        const double cdf_alice = total_alice == 0
            ? 0.0
            : static_cast<double>(cumulative_alice) / static_cast<double>(total_alice);
        const double cdf_bob = total_bob == 0
            ? 0.0
            : static_cast<double>(cumulative_bob) / static_cast<double>(total_bob);
        out << entry.num_msgs << ','
            << freq_alice << ','
            << freq_bob << ','
            << cdf_alice << ','
            << cdf_bob << '\n';
    }
}

inline void write_stats_csv(const std::array<HealingStats, 2>& stats,
                            const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        throw std::runtime_error("could not open stats CSV");
    }

    out << "compromised party,mean, stddev, min,p10,p20,p30,p40,p50,p60,p70,p80,p90,max\n";
    const std::array<const char*, 2> names{"A", "B"};
    for (std::size_t party = 0; party < stats.size(); ++party) {
        out << names[party] << ','
            << stats[party].mean << ','
            << stats[party].stddev;
        for (auto decile : stats[party].deciles) {
            out << ',' << decile;
        }
        out << '\n';
    }
}

template <typename RunResult>
inline void write_histogram_csv(const RunResult& result, const std::string& path) {
    write_histogram_csv(healing_histogram_from_rows(result.rows), path);
}

template <typename RunResult>
inline void write_stats_csv(const RunResult& result, const std::string& path) {
    const auto histogram = healing_histogram_from_rows(result.rows);
    write_stats_csv(stats_from_histogram(histogram), path);
}

inline std::string summary(const AggUniKemRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=agg-uni-kem\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

inline std::string summary(const AggRkemRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=agg-rkem\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

inline std::string summary(const AggRukemRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=agg-rukem\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

inline std::string summary(const OppUniKemRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=opp-uni-kem\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

inline std::string summary(const OppUniKemUsenixRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=opp-unikem-usenix\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

inline std::string summary(const OppRkemRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=opp-rkem\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

inline std::string summary(const OppRkemUsenixRunResult& result) {
    std::uint64_t max_vms = 0;
    std::uint64_t total_vms = 0;
    std::uint64_t total_vms_alice = 0;
    std::uint64_t total_vms_bob = 0;
    std::uint64_t alice_compromise_samples = 0;
    std::uint64_t bob_compromise_samples = 0;
    for (const auto& row : result.rows) {
        max_vms = std::max(max_vms, row.vms_total);
        total_vms += row.vms_total;
        if (row.compromised_party == Party::Alice) {
            total_vms_alice += row.vms_alice;
            ++alice_compromise_samples;
        } else {
            total_vms_bob += row.vms_bob;
            ++bob_compromise_samples;
        }
    }
    const double mean_vms = result.rows.empty()
        ? 0.0
        : static_cast<double>(total_vms) / static_cast<double>(result.rows.size());
    const double mean_vms_alice = alice_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_alice) / static_cast<double>(alice_compromise_samples);
    const double mean_vms_bob = bob_compromise_samples == 0
        ? 0.0
        : static_cast<double>(total_vms_bob) / static_cast<double>(bob_compromise_samples);

    std::ostringstream out;
    out << "protocol=opp-rkem-usenix\n"
        << "traffic_model=" << to_string(result.config.traffic_model) << "\n"
        << "ratio=" << result.config.ratio << "\n"
        << "ticks=" << result.config.ticks << "\n"
        << "messages=" << result.messages.size() << "\n"
        << "messages_by_alice="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Alice; })
        << "\n"
        << "messages_by_bob="
        << std::count_if(result.message_senders.begin(), result.message_senders.end(),
                         [](const auto& item) { return item.second == Party::Bob; })
        << "\n"
        << "emitted_scka_outputs=" << result.emitted_outputs.size() << "\n"
        << "samples=" << result.rows.size() << "\n"
        << "vms_total_mean=" << std::fixed << std::setprecision(2) << mean_vms << "\n"
        << "vms_alice_mean=" << std::fixed << std::setprecision(2) << mean_vms_alice << "\n"
        << "vms_bob_mean=" << std::fixed << std::setprecision(2) << mean_vms_bob << "\n"
        << "vms_total_max=" << max_vms << "\n";
    return out.str();
}

} // namespace smsim
