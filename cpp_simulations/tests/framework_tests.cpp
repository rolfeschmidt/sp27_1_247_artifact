#include "aggressive_unikem.hpp"
#include "agg_unikem_resolver.hpp"
#include "mock_rkem.hpp"
#include "opportunistic_rkem.hpp"
#include "resolver.hpp"
#include "secure_messaging.hpp"
#include "simulation_runner.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

using namespace smsim;

namespace {

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void expect_in_test(bool condition, const char* test_name, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(std::string(test_name) + ": " + message);
    }
}

bool portable_percent_chance(std::mt19937& rng, std::uint32_t percent) {
    return (rng() % 100) < percent;
}

int portable_delay(std::mt19937& rng, int max_delay) {
    if (max_delay <= 0) {
        return 0;
    }
    return static_cast<int>(rng() % static_cast<std::uint32_t>(max_delay + 1));
}

bool contains_pattern(const std::vector<SecretPattern>& patterns, const SecretPattern& pattern) {
    return std::find(patterns.begin(), patterns.end(), pattern) != patterns.end();
}

bool contains_agg_output_pattern(const std::vector<ProtocolSecretPattern>& patterns,
                                 AggUniKemOutputPattern expected) {
    for (const auto& pattern : patterns) {
        const auto* agg_pattern = std::get_if<AggUniKemOutputPattern>(&pattern);
        if (agg_pattern && *agg_pattern == expected) {
            return true;
        }
    }
    return false;
}

bool contains_agg_rukem_pattern(const std::vector<ProtocolSecretPattern>& patterns,
                                AggRukemOutputPattern expected) {
    for (const auto& pattern : patterns) {
        const auto* agg_pattern = std::get_if<AggRukemOutputPattern>(&pattern);
        if (agg_pattern && *agg_pattern == expected) {
            return true;
        }
    }
    return false;
}

MessageRecord record(MessageId id, Party sender, SckaOutputId epoch, std::uint64_t counter) {
    return {id, {epoch, chain_from_sender(sender), counter}};
}

std::vector<MessageRecord> sample_records() {
    auto e5 = agg_uni_kem_output(5, 2, 1);
    auto e6 = agg_uni_kem_output(6, 3, 4);
    return {
        record(0, Party::Alice, e5, 0),
        record(1, Party::Alice, e5, 1),
        record(2, Party::Bob, e5, 0),
        record(3, Party::Alice, e6, 0),
        record(4, Party::Bob, e6, 0),
    };
}

std::vector<AggUniKemOutputId> sample_agg_outputs() {
    return {
        {5, 2, 1},
        {5, 2, 3},
        {5, 4, 1},
        {6, 3, 4},
        {7, 8, 9},
    };
}

template <typename RunResult>
void expect_runner_samples_each_party_once_per_tick(const RunResult& result, const char* test_name) {
    std::map<std::uint64_t, std::set<Party>> parties_by_tick;
    for (const auto& row : result.rows) {
        expect_in_test(row.event_type == EventType::Compromise, test_name,
                       "runner should record explicit compromise samples");
        expect_in_test(!row.event_message_id.has_value(), test_name,
                       "tick-level compromise samples should not have a triggering message");
        parties_by_tick[row.tick].insert(row.compromised_party);
    }

    expect_in_test(result.rows.size() == result.config.ticks * 2, test_name,
                   "runner should record one sample per party per tick");
    for (std::uint64_t tick = 0; tick < result.config.ticks; ++tick) {
        expect_in_test(parties_by_tick[tick].contains(Party::Alice), test_name,
                       "runner should sample Alice on every tick");
        expect_in_test(parties_by_tick[tick].contains(Party::Bob), test_name,
                       "runner should sample Bob on every tick");
    }
}

std::set<SckaOutputId> resolve_sample_agg_outputs(const std::vector<ProtocolSecretPattern>& patterns) {
    return resolve_agg_unikem_outputs(sample_agg_outputs(), patterns);
}

struct ReceiveInstallsEpochSckaMessage {
    std::uint64_t tag = 0;

    auto operator<=>(const ReceiveInstallsEpochSckaMessage&) const = default;
};

class ReceiveInstallsEpochScka {
public:
    using OutputKey = int;
    using Message = ReceiveInstallsEpochSckaMessage;
    using SendResult = SparseSendResult<OutputKey, Message>;
    using ReceiveResult = SparseReceiveResult<OutputKey>;

    static ReceiveInstallsEpochScka init_alice() {
        return {};
    }

    static ReceiveInstallsEpochScka init_bob() {
        return {};
    }

    static SckaOutputId initial_epoch() {
        return message_output(0);
    }

    SendResult send() {
        return {std::nullopt, message_output(0), {}};
    }

    ReceiveResult receive(const Message&, SckaOutputId encrypted_output) {
        return {{std::pair{encrypted_output, 7}}, encrypted_output};
    }

    std::vector<ProtocolSecretPattern> compromised_secret_patterns() const {
        return {};
    }
};

void resolver_root_alone_exposes_nothing() {
    VmsResolver resolver(sample_records());
    auto exposed = resolver.resolve({root_key(MessageEpoch{5})});
    expect(exposed.empty(), "root key alone must not expose messages");
}

void resolver_scka_output_alone_exposes_nothing() {
    VmsResolver resolver(sample_records());
    std::vector<ProtocolSecretPattern> protocol_patterns{
        scka_secret(AggUniKemOutputPattern::ek_dk(5, 2)),
    };
    auto exposed = resolver.resolve({}, resolve_sample_agg_outputs(protocol_patterns));
    expect(exposed.empty(), "SCKA output alone must not expose messages");
}

void resolver_root_plus_matching_output_exposes_epoch() {
    VmsResolver resolver(sample_records());
    std::vector<SecretPattern> patterns{
        root_key(MessageEpoch{5}),
    };
    std::vector<ProtocolSecretPattern> protocol_patterns{
        scka_secret(AggUniKemOutputPattern::exact({5, 2, 1})),
    };
    auto exposed = resolver.resolve(patterns, resolve_sample_agg_outputs(protocol_patterns));
    expect((exposed == std::set<MessageId>{0, 1, 2}),
           "root plus matching output must expose both chains in that epoch");
}

void resolver_root_iteration_exposes_later_epoch() {
    VmsResolver resolver(sample_records());
    std::vector<SecretPattern> patterns{
        root_key(MessageEpoch{5}),
    };
    std::vector<ProtocolSecretPattern> protocol_patterns{
        scka_secret(AggUniKemOutputPattern::exact({5, 2, 1})),
        scka_secret(AggUniKemOutputPattern::exact({6, 3, 4})),
    };
    auto exposed = resolver.resolve(patterns, resolve_sample_agg_outputs(protocol_patterns));
    expect((exposed == std::set<MessageId>{0, 1, 2, 3, 4}),
           "derived root key must iterate into later matching output");
}

void resolver_future_output_from_current_secret_is_counted() {
    VmsResolver resolver(sample_records());
    std::vector<SecretPattern> patterns{
        root_key(MessageEpoch{5}),
    };
    std::vector<ProtocolSecretPattern> protocol_patterns{
        scka_secret(AggUniKemOutputPattern::ct0_state(5, 1)),
    };
    auto exposed = resolver.resolve(patterns, resolve_sample_agg_outputs(protocol_patterns));
    expect((exposed == std::set<MessageId>{0, 1, 2}),
           "current CT0-side state should resolve to later output that uses it");
}

void resolver_chain_key_exposes_suffix() {
    VmsResolver resolver(sample_records());
    auto e5 = agg_uni_kem_output(5, 2, 1);
    auto exposed = resolver.resolve({
        chain_key(e5, ChainId::AliceSender, 1),
    });
    expect((exposed == std::set<MessageId>{1}),
           "chain key must expose only messages at or after the counter");
}

void resolver_message_key_exposes_exact_message() {
    auto messages = sample_records();
    VmsResolver resolver(messages);
    auto exposed = resolver.resolve({
        message_key(messages[4].secret),
    });
    expect((exposed == std::set<MessageId>{4}),
           "message key must expose exactly one message");
}

void agg_unikem_resolver_ek_pattern_matches_committed_outputs() {
    auto outputs = resolve_agg_unikem_outputs(
        sample_agg_outputs(),
        {scka_secret(AggUniKemOutputPattern::ek_dk(5, 2))});
    expect((outputs == std::set<SckaOutputId>{agg_uni_kem_output(5, 2, 1),
                                              agg_uni_kem_output(5, 2, 3)}),
           "EK DK pattern must match all committed outputs with that EK subepoch");
}

void agg_unikem_resolver_ct0_pattern_matches_committed_outputs() {
    auto outputs = resolve_agg_unikem_outputs(
        sample_agg_outputs(),
        {scka_secret(AggUniKemOutputPattern::ct0_state(5, 1))});
    expect((outputs == std::set<SckaOutputId>{agg_uni_kem_output(5, 2, 1),
                                              agg_uni_kem_output(5, 4, 1)}),
           "CT0 state pattern must match all committed outputs with that CT0 subepoch");
}

void agg_unikem_resolver_exact_pattern_matches_one_output() {
    auto outputs = resolve_agg_unikem_outputs(
        sample_agg_outputs(),
        {scka_secret(AggUniKemOutputPattern::exact({5, 2, 1}))});
    expect((outputs == std::set<SckaOutputId>{agg_uni_kem_output(5, 2, 1)}),
           "exact Agg-UniKEM output pattern must match only that output");
}

void agg_unikem_resolver_nonmatching_pattern_exposes_no_outputs() {
    auto outputs = resolve_agg_unikem_outputs(
        sample_agg_outputs(),
        {scka_secret(AggUniKemOutputPattern::ek_dk(5, 99))});
    expect(outputs.empty(), "nonmatching Agg-UniKEM pattern must expose no outputs");
}

void agg_unikem_resolver_unions_and_deduplicates_patterns() {
    auto outputs = resolve_agg_unikem_outputs(
        sample_agg_outputs(),
        {
            scka_secret(AggUniKemOutputPattern::ek_dk(5, 2)),
            scka_secret(AggUniKemOutputPattern::ct0_state(5, 1)),
            scka_secret(AggUniKemOutputPattern::exact({5, 2, 1})),
        });
    expect((outputs == std::set<SckaOutputId>{agg_uni_kem_output(5, 2, 1),
                                              agg_uni_kem_output(5, 2, 3),
                                              agg_uni_kem_output(5, 4, 1)}),
           "multiple Agg-UniKEM patterns must union and deduplicate outputs");
}

void opp_unikem_resolver_maps_epoch_patterns_to_message_outputs() {
    auto outputs = resolve_opp_unikem_outputs(
        {MessageEpoch{1}, MessageEpoch{2}, MessageEpoch{3}},
        {scka_secret(OppUniKemOutputPattern{2}), scka_secret(OppUniKemOutputPattern{99})});

    expect((outputs == std::set<SckaOutputId>{message_output(2)}),
           "Opp-UniKEM resolver should expose exactly emitted outputs named by epoch patterns");
}

void chunking_requires_threshold_chunks() {
    Encoder encoder(7, {1, 2, 3});
    Decoder decoder(2);
    decoder.add(encoder.next_chunk());
    expect(!decoder.message(), "decoder completed too early");
    decoder.add(encoder.next_chunk());
    expect(decoder.message() == std::optional<std::vector<std::uint8_t>>({1, 2, 3}),
           "decoder did not recover message after threshold");
}

void mock_unikem_agrees_and_rejects_wrong_key() {
    MockUniKem kem;
    auto kp = kem.keygen();
    auto [es, ct0] = kem.enc_pk();
    auto enc = kem.enc_ct(kp.ek, es);
    expect(kem.decaps(kp.dk, ct0, enc.ct1) == enc.secret,
           "mock UniKEM sender and receiver keys differ");

    auto wrong = kem.keygen();
    bool rejected = false;
    try {
        (void)kem.decaps(wrong.dk, ct0, enc.ct1);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    expect(rejected, "mock UniKEM accepted wrong decapsulation key");
}

void mock_rkem_agrees_across_update() {
    MockRkem rkem;
    auto initial = MockRkem::initial_updated_keypair();
    auto next = rkem.keygen(MockRkemMode::Nonupdated);

    auto enc = rkem.encaps(initial.ek, next.dk);
    auto dec = rkem.decaps(initial.dk, enc.ct, next.ek);

    expect(enc.secret == dec.secret, "mock RKEM sender and receiver keys differ");
    expect(enc.updated_dk.mode == MockRkemMode::Updated, "mock RKEM encaps should update DK");
    expect(dec.updated_ek.mode == MockRkemMode::Updated, "mock RKEM decaps should update EK");

    auto following = rkem.keygen(MockRkemMode::Nonupdated);
    auto enc2 = rkem.encaps(dec.updated_ek, following.dk);
    auto dec2 = rkem.decaps(enc.updated_dk, enc2.ct, following.ek);
    expect(enc2.secret == dec2.secret, "mock RKEM updated sender and receiver keys differ");
}

void aggressive_unikem_first_epoch_agrees() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    std::optional<std::pair<SckaOutputId, MockSharedSecret>> bob_key;
    std::optional<std::pair<SckaOutputId, MockSharedSecret>> alice_key;

    for (int round = 0; round < 300 && (!bob_key || !alice_key); ++round) {
        auto a_send = alice.send();
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key) {
            bob_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_key = a_recv.output_key;
        }
    }

    expect(bob_key.has_value(), "Bob did not emit Agg-UniKEM key");
    expect(alice_key.has_value(), "Alice did not emit Agg-UniKEM key");
    expect(bob_key->first == alice_key->first, "Agg-UniKEM output epoch mismatch");
    expect(bob_key->second == alice_key->second, "Agg-UniKEM output secret mismatch");
    expect(std::holds_alternative<AggUniKemOutputId>(bob_key->first),
           "Agg-UniKEM output must use protocol-specific epoch id");
    expect(alice.emitted_epoch_ids().size() == 1, "Alice should record emitted Agg-UniKEM output ID");
    expect(bob.emitted_epoch_ids().size() == 1, "Bob should record emitted Agg-UniKEM output ID");
    expect(agg_uni_kem_output(alice.emitted_epoch_ids().front()) == alice_key->first,
           "Alice emitted-output ledger should match returned output epoch");
    expect(agg_uni_kem_output(bob.emitted_epoch_ids().front()) == bob_key->first,
           "Bob emitted-output ledger should match returned output epoch");
}

using OutputMap = std::map<SckaOutputId, MockSharedSecret>;
using RkemOutputMap = std::map<SckaOutputId, MockRkemSharedSecret>;

void record_output(OutputMap& outputs,
                   const std::optional<std::pair<SckaOutputId, MockSharedSecret>>& output) {
    if (!output) {
        return;
    }
    auto [it, inserted] = outputs.insert(*output);
    expect(inserted || it->second == output->second, "party emitted two different keys for one epoch");
}

void expect_matching_prefix(const char* test_name, const OutputMap& alice_outputs,
                            const OutputMap& bob_outputs, std::size_t expected_count) {
    expect_in_test(alice_outputs.size() >= expected_count, test_name,
                   "Alice did not emit enough keys: expected " + std::to_string(expected_count)
                       + ", got " + std::to_string(alice_outputs.size()));
    expect_in_test(bob_outputs.size() >= expected_count, test_name,
                   "Bob did not emit enough keys: expected " + std::to_string(expected_count)
                       + ", got " + std::to_string(bob_outputs.size()));

    std::size_t checked = 0;
    for (const auto& [epoch, alice_key] : alice_outputs) {
        auto bob = bob_outputs.find(epoch);
        if (bob == bob_outputs.end()) {
            continue;
        }
        expect_in_test(alice_key == bob->second, test_name, "Alice/Bob key mismatch");
        ++checked;
    }
    if (checked >= expected_count) {
        return;
    }
    expect_in_test(false, test_name, "not enough matching emitted epochs");
}

void record_output(RkemOutputMap& outputs,
                   const std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>>& output) {
    if (!output) {
        return;
    }
    auto [it, inserted] = outputs.insert(*output);
    expect(inserted || it->second == output->second, "party emitted two different RKEM keys for one epoch");
}

void expect_matching_prefix(const char* test_name, const RkemOutputMap& alice_outputs,
                            const RkemOutputMap& bob_outputs, std::size_t expected_count) {
    expect_in_test(alice_outputs.size() >= expected_count, test_name,
                   "Alice did not emit enough RKEM keys: expected " + std::to_string(expected_count)
                       + ", got " + std::to_string(alice_outputs.size()));
    expect_in_test(bob_outputs.size() >= expected_count, test_name,
                   "Bob did not emit enough RKEM keys: expected " + std::to_string(expected_count)
                       + ", got " + std::to_string(bob_outputs.size()));

    std::size_t checked = 0;
    for (const auto& [epoch, alice_key] : alice_outputs) {
        auto bob = bob_outputs.find(epoch);
        if (bob == bob_outputs.end()) {
            continue;
        }
        expect_in_test(alice_key == bob->second, test_name, "Alice/Bob RKEM key mismatch");
        ++checked;
    }
    if (checked >= expected_count) {
        return;
    }
    expect_in_test(false, test_name, "not enough matching emitted RKEM epochs");
}

void aggressive_unikem_ping_pong_progresses_multiple_epochs() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();
    OutputMap alice_outputs;
    OutputMap bob_outputs;

    for (int round = 0; round < 1200 && (alice_outputs.size() < 4 || bob_outputs.size() < 4); ++round) {
        auto a_send = alice.send();
        record_output(bob_outputs, bob.receive(a_send.message, a_send.sending_output).output_key);

        auto b_send = bob.send();
        record_output(alice_outputs, alice.receive(b_send.message, b_send.sending_output).output_key);
    }

    expect_matching_prefix("aggressive_unikem_ping_pong_progresses_multiple_epochs",
                           alice_outputs, bob_outputs, 4);
}

void aggressive_unikem_switches_roles_after_epoch() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    std::optional<std::pair<SckaOutputId, MockSharedSecret>> bob_key;
    std::optional<std::pair<SckaOutputId, MockSharedSecret>> alice_key;

    for (int round = 0; round < 300 && (!bob_key || !alice_key); ++round) {
        auto a_send = alice.send();
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key) {
            bob_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_key = a_recv.output_key;
        }
    }

    expect(bob_key.has_value(), "Bob did not emit first Agg-UniKEM key before role switch");
    expect(alice_key.has_value(), "Alice did not emit first Agg-UniKEM key before role switch");

    auto alice_next = alice.send();
    expect(alice_next.message.type == AggUniKem::Message::Type::Ct0,
           "Alice should become the CT0 sender in the next Agg-UniKEM epoch");
    expect(contains_agg_output_pattern(alice.compromised_secret_patterns(),
                                       AggUniKemOutputPattern::ct0_state(2, 0)),
           "Alice should report CT0-side state after becoming the CT0 sender");

    (void)bob.receive(alice_next.message, alice_next.sending_output);
    auto bob_next = bob.send();
    expect(bob_next.message.type == AggUniKem::Message::Type::Ek,
           "Bob should become the EK sender in the next Agg-UniKEM epoch");
    expect(contains_agg_output_pattern(bob.compromised_secret_patterns(),
                                       AggUniKemOutputPattern::ek_dk(2, 0)),
           "Bob should report EK-side state after becoming the EK sender");
}

struct QueuedSckaMessage {
    int deliver_at = 0;
    bool to_alice = false;
    AggUniKem::Message message;
    SckaOutputId sending_output;
};

void run_random_raw_scka_delivery(const char* test_name, unsigned seed, bool allow_drops,
                                  bool allow_reordering) {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();
    OutputMap alice_outputs;
    OutputMap bob_outputs;
    std::vector<QueuedSckaMessage> queue;
    std::mt19937 rng(seed);
    const auto drop_percent = allow_drops ? 15U : 0U;
    const auto max_delay = allow_reordering ? 7 : 0;

    for (int tick = 0; tick < 10000; ++tick) {
        if (portable_percent_chance(rng, 70)) {
            auto out = alice.send();
            if (!portable_percent_chance(rng, drop_percent)) {
                queue.push_back({tick + portable_delay(rng, max_delay), false, out.message,
                                 out.sending_output});
            }
        }
        if (portable_percent_chance(rng, 70)) {
            auto out = bob.send();
            if (!portable_percent_chance(rng, drop_percent)) {
                queue.push_back({tick + portable_delay(rng, max_delay), true, out.message,
                                 out.sending_output});
            }
        }

        for (std::size_t i = 0; i < queue.size();) {
            if (queue[i].deliver_at > tick) {
                ++i;
                continue;
            }
            auto item = queue[i];
            queue.erase(queue.begin() + static_cast<std::ptrdiff_t>(i));
            if (item.to_alice) {
                record_output(alice_outputs, alice.receive(item.message, item.sending_output).output_key);
            } else {
                record_output(bob_outputs, bob.receive(item.message, item.sending_output).output_key);
            }
        }

        if (alice_outputs.size() >= 5 && bob_outputs.size() >= 5) {
            break;
        }
    }

    expect_matching_prefix(test_name, alice_outputs, bob_outputs, 5);
}

void aggressive_unikem_random_traffic_progresses_with_reordering() {
    run_random_raw_scka_delivery("aggressive_unikem_random_traffic_progresses_with_reordering",
                                 12345, false, true);
}

void aggressive_unikem_random_traffic_progresses_with_drops_and_reordering() {
    run_random_raw_scka_delivery("aggressive_unikem_random_traffic_progresses_with_drops_and_reordering",
                                 5, true, true);
}

void aggressive_unikem_reports_wildcard_secrets() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    for (int round = 0; round < 100; ++round) {
        auto a_send = alice.send();
        (void)bob.receive(a_send.message, a_send.sending_output);
        auto b_send = bob.send();
        (void)alice.receive(b_send.message, b_send.sending_output);
    }

    auto a_patterns = alice.compromised_secret_patterns();
    auto b_patterns = bob.compromised_secret_patterns();

    expect(!a_patterns.empty(), "Alice should report resident EK-side secrets");
    expect(!b_patterns.empty(), "Bob should report resident CT0-side or committed secrets");
}

void aggressive_unikem_state_names_show_protocol_progress() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    expect(alice.role_state_name() == "Init", "Alice should start in EK Init state");
    expect(bob.role_state_name() == "Init", "Bob should start in CT Init state");

    auto a0 = alice.send();
    expect(alice.role_state_name() == "SendFirstEkRecvFirstCt0", "Alice should send initial EK");
    (void)bob.receive(a0.message, a0.sending_output);

    auto b0 = bob.send();
    expect(bob.role_state_name() == "SendFirstCt0RecvFirstEk", "Bob should send initial CT0");
    (void)alice.receive(b0.message, b0.sending_output);

    for (int round = 0; round < 100 && bob.role_state_name() != "SendCt1"; ++round) {
        auto a = alice.send();
        (void)bob.receive(a.message, a.sending_output);
        auto b = bob.send();
        (void)alice.receive(b.message, b.sending_output);
    }

    expect(alice.role_state_name() != "Init", "Alice should still be in active epoch before CT1 completes");
    expect(bob.role_state_name() == "SendCt1", "Bob should commit and send CT1");
}

void aggressive_unikem_deletes_acked_ek_when_sampling_next() {
    auto alice = AggUniKem::init_alice();

    (void)alice.send();
    AggUniKem::Message ack0;
    ack0.epoch = 1;
    ack0.type = AggUniKem::Message::Type::EkAck;
    ack0.i = 0;
    (void)alice.receive(ack0, message_output(0));

    expect(alice.role_state_name() == "EkSampleRecvFirstCt0", "Alice should hold one acked EK after EK ack");
    auto patterns = alice.compromised_secret_patterns();
    expect(patterns.size() == 1, "Alice should report exactly one EK-side secret in EkSample");

    (void)alice.send();
    expect(alice.role_state_name() == "EkSendWhileRecvCt0", "Alice should sample and send the next EK");
    patterns = alice.compromised_secret_patterns();
    expect(patterns.size() == 2, "Alice should report acked and current EK secrets in EkSend");
}

void aggressive_unikem_frozen_ek_ack_does_not_introduce_new_ek_subepoch() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    auto first_ek = alice.send();
    expect(alice.role_state_name() == "SendFirstEkRecvFirstCt0", "Alice should send initial EK");
    (void)first_ek;

    AggUniKem::Message ack0;
    ack0.epoch = 1;
    ack0.type = AggUniKem::Message::Type::EkAck;
    ack0.i = 0;
    (void)alice.receive(ack0, message_output(0));
    expect(alice.role_state_name() == "EkSampleRecvFirstCt0", "Alice should hold acked EK after synthetic ack");

    (void)alice.send();
    expect(alice.role_state_name() == "EkSendWhileRecvCt0", "Alice should enter aggressive EK send state");

    for (int chunk = 0; chunk < 40; ++chunk) {
        auto b = bob.send();
        (void)alice.receive(b.message, b.sending_output);
    }

    AggUniKem::Message ack1;
    ack1.epoch = 1;
    ack1.type = AggUniKem::Message::Type::EkAck;
    ack1.i = 1;
    (void)alice.receive(ack1, message_output(0));

    expect(alice.role_state_name() == "EkFrozenAfterAggressiveCtAwait",
           "frozen EK side should not sample a new EK after later ack");
    auto patterns = alice.compromised_secret_patterns();
    expect(!contains_agg_output_pattern(patterns, AggUniKemOutputPattern::ek_dk(1, 0)),
           "frozen EK side should delete previous EK pattern after a later EK is acknowledged");
    expect(contains_agg_output_pattern(patterns, AggUniKemOutputPattern::ek_dk(1, 1)),
           "frozen EK side should retain current EK pattern");
    expect(!contains_agg_output_pattern(patterns, AggUniKemOutputPattern::ek_dk(1, 2)),
           "frozen EK side should not introduce a new EK subepoch pattern");
}

void aggressive_unikem_ct_sender_aggressive_loop_reports_acked_and_current_ct0() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    for (int chunk = 0; chunk < 40; ++chunk) {
        auto b = bob.send();
        (void)alice.receive(b.message, b.sending_output);
    }

    auto ack = alice.send();
    (void)bob.receive(ack.message, ack.sending_output);
    expect(bob.role_state_name() == "Ct0SampleRecvFirstEk", "Bob should hold one acked CT0 state after CT0 ack");

    (void)bob.send();
    expect(bob.role_state_name() == "Ct0SendWhileRecvEk", "Bob should sample and send next CT0");

    auto patterns = bob.compromised_secret_patterns();
    expect(contains_agg_output_pattern(patterns, AggUniKemOutputPattern::ct0_state(1, 0)),
           "Bob should report acked CT0 state in aggressive send loop");
    expect(contains_agg_output_pattern(patterns, AggUniKemOutputPattern::ct0_state(1, 1)),
           "Bob should report current CT0 state in aggressive send loop");
}

void aggressive_unikem_send_ct1_reports_exact_committed_output() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();
    std::optional<std::pair<SckaOutputId, MockSharedSecret>> output;

    for (int chunk = 0; chunk < 40; ++chunk) {
        auto b = bob.send();
        (void)alice.receive(b.message, b.sending_output);
    }

    auto first_ek = alice.send();
    (void)bob.receive(first_ek.message, first_ek.sending_output);
    (void)bob.send();

    for (int chunk = 0; chunk < 50 && !output; ++chunk) {
        auto a = alice.send();
        auto received = bob.receive(a.message, a.sending_output);
        if (received.output_key) {
            output = received.output_key;
        }
    }

    expect(output.has_value(), "Bob should emit an Agg-UniKEM output after receiving full EK");
    expect(bob.role_state_name() == "SendCt1", "Bob should enter CT1 sending state after commit");
    expect(bob.last_emitted_epoch_id().has_value(), "Bob should remember the committed output ID");

    auto patterns = bob.compromised_secret_patterns();
    expect(contains_agg_output_pattern(patterns, AggUniKemOutputPattern::exact(*bob.last_emitted_epoch_id())),
           "CT1 sender should report exact committed output while output key is resident");
}

void aggressive_unikem_ek_ack_ct0_completion_race_chooses_frozen_path() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    (void)alice.send();
    for (int chunk = 0; chunk < 29; ++chunk) {
        auto b = bob.send();
        (void)alice.receive(b.message, b.sending_output);
    }

    auto final_ct0 = bob.send();
    final_ct0.message.ek_ack = 0;
    (void)alice.receive(final_ct0.message, final_ct0.sending_output);

    expect(alice.role_state_name() == "EkFrozenCtAwait",
           "AckEK plus CT0 completion should choose the non-aggressive frozen EK path");
}

void aggressive_unikem_ct0_ack_ek_completion_race_commits() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();

    (void)bob.send();
    for (int chunk = 0; chunk < 36; ++chunk) {
        auto a = alice.send();
        (void)bob.receive(a.message, a.sending_output);
    }

    auto final_ek = alice.send();
    final_ek.message.ct0_ack = 0;
    auto received = bob.receive(final_ek.message, final_ek.sending_output);

    expect(received.output_key.has_value(),
           "AckCT0 plus EK completion gives CT sender enough information to commit");
    expect(bob.role_state_name() == "SendCt1", "CT sender should enter SendCt1 after the commit race");
}

void aggressive_unikem_invalid_event_policy_can_throw() {
    auto alice = AggUniKem::init_alice(AggUniKem::InvalidEventPolicy::Throw);
    AggUniKem::Message stale_shape;
    stale_shape.epoch = 1;
    stale_shape.type = AggUniKem::Message::Type::Ct0;
    stale_shape.j = 99;
    stale_shape.chunk = Chunk{1, 0, encode_u64(99)};

    bool threw = false;
    try {
        (void)alice.receive(stale_shape, message_output(0));
    } catch (const std::runtime_error&) {
        threw = true;
    }

    expect(threw, "invalid-event Throw policy should report impossible role transitions");

    auto tolerant = AggUniKem::init_alice();
    (void)tolerant.receive(stale_shape, message_output(0));
}

void aggressive_unikem_every_ct1_chunk_carries_commit_indices() {
    auto alice = AggUniKem::init_alice();
    auto bob = AggUniKem::init_bob();
    std::optional<AggUniKemOutputId> committed;

    for (int chunk = 0; chunk < 40; ++chunk) {
        auto b = bob.send();
        (void)alice.receive(b.message, b.sending_output);
    }

    for (int chunk = 0; chunk < 50 && !committed; ++chunk) {
        auto a = alice.send();
        auto received = bob.receive(a.message, a.sending_output);
        if (received.output_key) {
            committed = *bob.last_emitted_epoch_id();
        }
    }

    expect(committed.has_value(), "Bob should commit before CT1 index checks");
    auto first = bob.send().message;
    auto second = bob.send().message;

    expect(first.type == AggUniKem::Message::Type::Ct1Commit, "first CT1 chunk should be a commit chunk");
    expect(second.type == AggUniKem::Message::Type::Ct1, "later CT1 chunk should use the CT1 tag");
    expect(first.i == committed->ek_subepoch && first.j == committed->ct0_subepoch,
           "CT1Commit should carry commit indices");
    expect(second.i == committed->ek_subepoch && second.j == committed->ct0_subepoch,
           "later CT1 chunks should also carry commit indices");
}

void opportunistic_unikem_first_epoch_agrees() {
    auto alice = OppUniKem::init_alice();
    auto bob = OppUniKem::init_bob();

    std::optional<std::pair<SckaOutputId, MockSharedSecret>> bob_key;
    std::optional<std::pair<SckaOutputId, MockSharedSecret>> alice_key;

    for (int round = 0; round < 300 && (!bob_key || !alice_key); ++round) {
        auto a_send = alice.send();
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key) {
            bob_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_key = a_recv.output_key;
        }
    }

    expect(bob_key.has_value(), "Bob did not emit Opp-UniKEM key");
    expect(alice_key.has_value(), "Alice did not emit Opp-UniKEM key");
    expect(bob_key->first == alice_key->first, "Opp-UniKEM output epoch mismatch");
    expect(bob_key->second == alice_key->second, "Opp-UniKEM output secret mismatch");
    expect(bob_key->first == message_output(1), "Opp-UniKEM first output should be message epoch 1");
}

void opportunistic_unikem_ping_pong_progresses_multiple_epochs() {
    auto alice = OppUniKem::init_alice();
    auto bob = OppUniKem::init_bob();
    OutputMap alice_outputs;
    OutputMap bob_outputs;

    for (int round = 0; round < 1500 && (alice_outputs.size() < 4 || bob_outputs.size() < 4); ++round) {
        auto a_send = alice.send();
        record_output(bob_outputs, bob.receive(a_send.message, a_send.sending_output).output_key);

        auto b_send = bob.send();
        record_output(alice_outputs, alice.receive(b_send.message, b_send.sending_output).output_key);
    }

    expect_matching_prefix("opportunistic_unikem_ping_pong_progresses_multiple_epochs",
                           alice_outputs, bob_outputs, 4);
}

void opportunistic_unikem_switches_roles_after_epoch() {
    auto alice = OppUniKem::init_alice();
    auto bob = OppUniKem::init_bob();

    std::optional<std::pair<SckaOutputId, MockSharedSecret>> bob_key;
    std::optional<std::pair<SckaOutputId, MockSharedSecret>> alice_key;

    for (int round = 0; round < 300 && (!bob_key || !alice_key); ++round) {
        auto a_send = alice.send();
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key) {
            bob_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_key = a_recv.output_key;
        }
    }

    expect(bob_key.has_value(), "Bob did not emit first Opp-UniKEM key before role switch");
    expect(alice_key.has_value(), "Alice did not emit first Opp-UniKEM key before role switch");
    expect(alice.role_state_name() == "RecvEk",
           "Alice should become the CT sender in the next Opp-UniKEM epoch");
    expect(bob.role_state_name() == "SendCt2",
           "Bob should keep sending CT2 until he sees the next Opp-UniKEM epoch");

    auto alice_next = alice.send();
    expect(alice.role_state_name() == "SendCt1RecvEk",
           "Alice should send CT1 while receiving EK in the next Opp-UniKEM epoch");
    (void)bob.receive(alice_next.message, alice_next.sending_output);
    expect(bob.role_state_name() == "SampleEk",
           "Bob should become the EK sender after seeing the next Opp-UniKEM epoch");
}

void opportunistic_unikem_state_names_show_protocol_progress() {
    auto alice = OppUniKem::init_alice();
    auto bob = OppUniKem::init_bob();

    expect(alice.role_state_name() == "SampleEk", "Alice should start ready to sample EK");
    expect(bob.role_state_name() == "RecvEk", "Bob should start receiving EK");

    auto a = alice.send();
    expect(alice.role_state_name() == "SendEkRecvCt1", "Alice should send EK while receiving CT1");
    (void)bob.receive(a.message, a.sending_output);

    auto b = bob.send();
    expect(bob.role_state_name() == "SendCt1RecvEk", "Bob should send CT1 while receiving EK");
    (void)alice.receive(b.message, b.sending_output);

    for (int round = 0; round < 120 && bob.role_state_name() != "SendCt2"; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice.message, from_alice.sending_output);
        auto from_bob = bob.send();
        (void)alice.receive(from_bob.message, from_bob.sending_output);
    }

    expect(bob.role_state_name() == "SendCt2", "Bob should send CT2 after receiving EK");
}

void opportunistic_unikem_reports_epoch_patterns() {
    auto alice = OppUniKem::init_alice();

    (void)alice.send();
    auto patterns = alice.compromised_secret_patterns();

    expect(patterns.size() == 1, "Alice should report one Opp-UniKEM epoch secret after sending EK");
    const auto* opp_pattern = std::get_if<OppUniKemOutputPattern>(&patterns.front());
    expect(opp_pattern && opp_pattern->epoch == 1,
           "Opp-UniKEM resident secret pattern should name the message epoch");
}

void opportunistic_unikem_usenix_first_epoch_agrees() {
    auto alice = OppUniKemUsenix::init_alice();
    auto bob = OppUniKemUsenix::init_bob();

    std::optional<std::pair<SckaOutputId, MockSharedSecret>> bob_key;
    std::optional<std::pair<SckaOutputId, MockSharedSecret>> alice_key;

    for (int round = 0; round < 300 && (!bob_key || !alice_key); ++round) {
        auto a_send = alice.send();
        if (a_send.output_key) {
            alice_key = a_send.output_key;
        }
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key) {
            bob_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        if (b_send.output_key) {
            bob_key = b_send.output_key;
        }
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_key = a_recv.output_key;
        }
    }

    expect(bob_key.has_value(), "Bob did not emit Opp-UniKEM-USENIX key");
    expect(alice_key.has_value(), "Alice did not emit Opp-UniKEM-USENIX key");
    expect(bob_key->first == alice_key->first, "Opp-UniKEM-USENIX output epoch mismatch");
    expect(bob_key->second == alice_key->second, "Opp-UniKEM-USENIX output secret mismatch");
    expect(bob_key->first == message_output(1),
           "Opp-UniKEM-USENIX first output should be message epoch 1");
}

void opportunistic_unikem_usenix_ping_pong_progresses_multiple_epochs() {
    auto alice = OppUniKemUsenix::init_alice();
    auto bob = OppUniKemUsenix::init_bob();
    OutputMap alice_outputs;
    OutputMap bob_outputs;

    for (int round = 0; round < 1600 && alice_outputs.size() < 4; ++round) {
        auto a_send = alice.send();
        record_output(alice_outputs, a_send.output_key);
        record_output(bob_outputs, bob.receive(a_send.message, a_send.sending_output).output_key);

        auto b_send = bob.send();
        record_output(bob_outputs, b_send.output_key);
        record_output(alice_outputs, alice.receive(b_send.message, b_send.sending_output).output_key);
    }

    expect_matching_prefix("opportunistic_unikem_usenix_ping_pong_progresses_multiple_epochs",
                           alice_outputs, bob_outputs, 4);
}

void opportunistic_unikem_usenix_state_names_show_old_protocol_progress() {
    auto alice = OppUniKemUsenix::init_alice();
    auto bob = OppUniKemUsenix::init_bob();

    expect(alice.role_state_name() == "RecvEk", "Alice should start in old RecvEk state");
    expect(bob.role_state_name() == "RecvEk", "Bob should start in old RecvEk state");

    bool saw_key_ready = false;
    bool saw_send_ct = false;
    for (int round = 0; round < 500 && (!saw_key_ready || !saw_send_ct); ++round) {
        auto a_send = alice.send();
        (void)bob.receive(a_send.message, a_send.sending_output);
        saw_key_ready = saw_key_ready || alice.role_state_name() == "KeyReady";
        saw_send_ct = saw_send_ct || bob.role_state_name() == "SendCt";

        auto b_send = bob.send();
        (void)alice.receive(b_send.message, b_send.sending_output);
        saw_key_ready = saw_key_ready || alice.role_state_name() == "KeyReady";
        saw_send_ct = saw_send_ct || bob.role_state_name() == "SendCt";
    }

    expect(saw_key_ready, "Opp-UniKEM-USENIX EK sender should hold a KeyReady secret");
    expect(saw_send_ct, "Opp-UniKEM-USENIX CT sender should hold a SendCt secret");
}

void opportunistic_unikem_usenix_reports_held_secret_epoch_patterns() {
    auto alice = OppUniKemUsenix::init_alice();
    auto bob = OppUniKemUsenix::init_bob();

    bool saw_key_ready_pattern = false;
    bool saw_send_ct_pattern = false;
    for (int round = 0; round < 500 && (!saw_key_ready_pattern || !saw_send_ct_pattern); ++round) {
        auto a_send = alice.send();
        (void)bob.receive(a_send.message, a_send.sending_output);
        saw_key_ready_pattern = saw_key_ready_pattern
            || (alice.role_state_name() == "KeyReady" && !alice.compromised_secret_patterns().empty());
        saw_send_ct_pattern = saw_send_ct_pattern
            || (bob.role_state_name() == "SendCt" && !bob.compromised_secret_patterns().empty());

        auto b_send = bob.send();
        (void)alice.receive(b_send.message, b_send.sending_output);
        saw_key_ready_pattern = saw_key_ready_pattern
            || (alice.role_state_name() == "KeyReady" && !alice.compromised_secret_patterns().empty());
        saw_send_ct_pattern = saw_send_ct_pattern
            || (bob.role_state_name() == "SendCt" && !bob.compromised_secret_patterns().empty());
    }

    expect(saw_key_ready_pattern, "KeyReady should report a resident Opp-UniKEM-USENIX epoch");
    expect(saw_send_ct_pattern, "SendCt should report a resident Opp-UniKEM-USENIX epoch");
}

void opportunistic_rkem_first_epoch_agrees() {
    auto alice = OppRkem::init_alice();
    auto bob = OppRkem::init_bob();

    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> alice_send_key;
    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_recv_key;
    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_send_key;
    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> alice_recv_key;

    for (int round = 0; round < 300
         && (!alice_send_key || !bob_recv_key || !bob_send_key || !alice_recv_key); ++round) {
        auto a_send = alice.send();
        if (a_send.output_key && !alice_send_key) {
            alice_send_key = a_send.output_key;
        }
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key && !bob_recv_key) {
            bob_recv_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        if (b_send.output_key && !bob_send_key) {
            bob_send_key = b_send.output_key;
        }
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key && !alice_recv_key) {
            alice_recv_key = a_recv.output_key;
        }
    }

    expect(alice_send_key.has_value(), "Alice did not emit send-side Opp-RKEM key");
    expect(bob_recv_key.has_value(), "Bob did not emit receive-side Opp-RKEM key");
    expect(bob_send_key.has_value(), "Bob did not emit send-side Opp-RKEM key");
    expect(alice_recv_key.has_value(), "Alice did not emit receive-side Opp-RKEM key");
    expect(alice_send_key->first == bob_recv_key->first, "Alice-send/Bob-receive Opp-RKEM epoch mismatch");
    expect(alice_send_key->second == bob_recv_key->second, "Alice-send/Bob-receive Opp-RKEM secret mismatch");
    expect(bob_send_key->first == alice_recv_key->first, "Bob-send/Alice-receive Opp-RKEM epoch mismatch");
    expect(bob_send_key->second == alice_recv_key->second, "Bob-send/Alice-receive Opp-RKEM secret mismatch");
    expect(alice_send_key->first == message_output(3), "Alice's first Opp-RKEM output should be message epoch 3");
    expect(bob_send_key->first == message_output(4), "Bob's first Opp-RKEM output should be message epoch 4");
}

void opportunistic_rkem_ping_pong_progresses_multiple_epochs() {
    auto alice = OppRkem::init_alice();
    auto bob = OppRkem::init_bob();
    RkemOutputMap alice_outputs;
    RkemOutputMap bob_outputs;

    for (int round = 0; round < 1600 && alice_outputs.size() < 4; ++round) {
        auto a_send = alice.send();
        record_output(alice_outputs, a_send.output_key);
        record_output(bob_outputs, bob.receive(a_send.message, a_send.sending_output).output_key);

        auto b_send = bob.send();
        record_output(bob_outputs, b_send.output_key);
        record_output(alice_outputs, alice.receive(b_send.message, b_send.sending_output).output_key);
    }

    expect_matching_prefix("opportunistic_rkem_ping_pong_progresses_multiple_epochs",
                           alice_outputs, bob_outputs, 4);
}

struct QueuedOppRkemMessage {
    int deliver_at = 0;
    bool to_alice = false;
    OppRkem::Message message;
    SckaOutputId sending_output;
};

void run_random_raw_opp_rkem_delivery(const char* test_name, unsigned seed, bool allow_drops,
                                      bool allow_reordering) {
    auto alice = OppRkem::init_alice();
    auto bob = OppRkem::init_bob();
    RkemOutputMap alice_outputs;
    RkemOutputMap bob_outputs;
    std::vector<QueuedOppRkemMessage> queue;
    std::mt19937 rng(seed);
    const auto drop_percent = allow_drops ? 15U : 0U;
    const auto max_delay = allow_reordering ? 7 : 0;

    for (int tick = 0; tick < 12000; ++tick) {
        if (portable_percent_chance(rng, 70)) {
            auto out = alice.send();
            record_output(alice_outputs, out.output_key);
            if (!portable_percent_chance(rng, drop_percent)) {
                queue.push_back({tick + portable_delay(rng, max_delay), false, out.message,
                                 out.sending_output});
            }
        }
        if (portable_percent_chance(rng, 70)) {
            auto out = bob.send();
            record_output(bob_outputs, out.output_key);
            if (!portable_percent_chance(rng, drop_percent)) {
                queue.push_back({tick + portable_delay(rng, max_delay), true, out.message,
                                 out.sending_output});
            }
        }

        for (std::size_t i = 0; i < queue.size();) {
            if (queue[i].deliver_at > tick) {
                ++i;
                continue;
            }
            auto item = queue[i];
            queue.erase(queue.begin() + static_cast<std::ptrdiff_t>(i));
            if (item.to_alice) {
                record_output(alice_outputs, alice.receive(item.message, item.sending_output).output_key);
            } else {
                record_output(bob_outputs, bob.receive(item.message, item.sending_output).output_key);
            }
        }

        if (alice_outputs.size() >= 5 && bob_outputs.size() >= 5) {
            break;
        }
    }

    expect_matching_prefix(test_name, alice_outputs, bob_outputs, 5);
}

void opportunistic_rkem_random_traffic_progresses_with_reordering() {
    run_random_raw_opp_rkem_delivery("opportunistic_rkem_random_traffic_progresses_with_reordering",
                                     24680, false, true);
}

void opportunistic_rkem_random_traffic_progresses_with_drops_and_reordering() {
    run_random_raw_opp_rkem_delivery("opportunistic_rkem_random_traffic_progresses_with_drops_and_reordering",
                                     13579, true, true);
}

void opportunistic_rkem_reports_epoch_patterns() {
    auto alice = OppRkem::init_alice();

    for (int round = 0; round < 120 && alice.compromised_secret_patterns().empty(); ++round) {
        (void)alice.send();
    }

    auto patterns = alice.compromised_secret_patterns();
    expect(!patterns.empty(), "Alice should report Opp-RKEM resident protocol secrets");
    bool has_opp_epoch = false;
    for (const auto& pattern : patterns) {
        has_opp_epoch = has_opp_epoch || std::holds_alternative<OppUniKemOutputPattern>(pattern);
    }
    expect(has_opp_epoch, "Opp-RKEM resident secret pattern should name message epochs");
}

void opportunistic_rkem_usenix_ping_pong_progresses_multiple_epochs() {
    auto alice = OppRkemUsenix::init_alice();
    auto bob = OppRkemUsenix::init_bob();
    RkemOutputMap alice_outputs;
    RkemOutputMap bob_outputs;

    for (int round = 0; round < 2400 && alice_outputs.size() < 4; ++round) {
        auto a_send = alice.send();
        record_output(alice_outputs, a_send.output_key);
        record_output(bob_outputs, bob.receive(a_send.message, a_send.sending_output).output_key);

        auto b_send = bob.send();
        record_output(bob_outputs, b_send.output_key);
        record_output(alice_outputs, alice.receive(b_send.message, b_send.sending_output).output_key);
    }

    expect_matching_prefix("opportunistic_rkem_usenix_ping_pong_progresses_multiple_epochs",
                           alice_outputs, bob_outputs, 4);
}

void opportunistic_rkem_usenix_reports_queued_output_patterns() {
    auto alice = OppRkemUsenix::init_alice();
    auto bob = OppRkemUsenix::init_bob();

    bool saw_pattern = false;
    for (int round = 0; round < 400 && !saw_pattern; ++round) {
        auto a_send = alice.send();
        (void)bob.receive(a_send.message, a_send.sending_output);
        auto b_send = bob.send();
        (void)alice.receive(b_send.message, b_send.sending_output);
        for (const auto& pattern : alice.compromised_secret_patterns()) {
            saw_pattern = saw_pattern || std::holds_alternative<OppUniKemOutputPattern>(pattern);
        }
    }

    expect(saw_pattern, "Opp-RKEM-USENIX should report RKEM and queued-output epoch patterns");
}

void aggressive_rukem_first_epoch_agrees() {
    auto alice = AggRukem::init_alice();
    auto bob = AggRukem::init_bob();

    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> alice_send_key;
    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_recv_key;

    for (int round = 0; round < 300 && (!alice_send_key || !bob_recv_key); ++round) {
        auto a_send = alice.send();
        if (a_send.output_key && !alice_send_key) {
            alice_send_key = a_send.output_key;
        }
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key && !bob_recv_key) {
            bob_recv_key = b_recv.output_key;
        }

        auto b_send = bob.send();
        (void)alice.receive(b_send.message, b_send.sending_output);
    }

    expect(alice_send_key.has_value(), "Alice did not emit send-side Agg-RUKEM key");
    expect(bob_recv_key.has_value(), "Bob did not emit receive-side Agg-RUKEM key");
    expect(alice_send_key->first == bob_recv_key->first,
           "Alice-send/Bob-receive Agg-RUKEM epoch mismatch");
    expect(alice_send_key->second == bob_recv_key->second,
           "Alice-send/Bob-receive Agg-RUKEM secret mismatch");
    expect(alice_send_key->first == message_output(1),
           "Alice's first Agg-RUKEM output should be message epoch 1");
}

void aggressive_rukem_ping_pong_progresses_multiple_epochs() {
    auto alice = AggRukem::init_alice();
    auto bob = AggRukem::init_bob();
    RkemOutputMap alice_outputs;
    RkemOutputMap bob_outputs;

    for (int round = 0; round < 1600 && alice_outputs.size() < 5; ++round) {
        auto a_send = alice.send();
        record_output(alice_outputs, a_send.output_key);
        record_output(bob_outputs, bob.receive(a_send.message, a_send.sending_output).output_key);

        auto b_send = bob.send();
        record_output(bob_outputs, b_send.output_key);
        record_output(alice_outputs, alice.receive(b_send.message, b_send.sending_output).output_key);
    }

    expect_matching_prefix("aggressive_rukem_ping_pong_progresses_multiple_epochs",
                           alice_outputs, bob_outputs, 4);
}

void aggressive_rukem_reports_updated_key_patterns() {
    auto alice = AggRukem::init_alice();
    auto bob = AggRukem::init_bob();

    for (int round = 0; round < 120 && !alice.last_emitted_epoch_id(); ++round) {
        auto a_send = alice.send();
        (void)bob.receive(a_send.message, a_send.sending_output);

        auto b_send = bob.send();
        (void)alice.receive(b_send.message, b_send.sending_output);
    }

    auto patterns = alice.compromised_secret_patterns();
    expect(contains_agg_rukem_pattern(patterns, AggRukemOutputPattern{{Party::Alice, 1, 1}}),
           "Agg-RUKEM should report Alice's updated current DK");
}

void aggressive_rukem_update_limit_counts_peer_updates_only() {
    auto alice = AggRukem::init_alice();
    auto bob = AggRukem::init_bob();

    for (std::uint64_t update = 0; update < AggRukem::kMaxUpdates; ++update) {
        for (int chunk = 0; chunk < 42; ++chunk) {
            auto a_send = alice.send();
            (void)bob.receive(a_send.message, a_send.sending_output);
        }

        auto b_ack = bob.send();
        (void)alice.receive(b_ack.message, b_ack.sending_output);

        std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_recv_key;
        for (int chunk = 0; chunk < 10 && !bob_recv_key; ++chunk) {
            auto a_send = alice.send();
            bob_recv_key = bob.receive(a_send.message, a_send.sending_output).output_key;
        }
        expect(bob_recv_key.has_value(), "Bob should receive each fast-Alice Agg-RUKEM update");

        auto b_advance = bob.send();
        (void)alice.receive(b_advance.message, b_advance.sending_output);
    }

    std::vector<std::uint64_t> bob_initial_key_updates;
    for (const auto& record : alice.emitted_output_records()) {
        if (record.receiver_key.party == Party::Bob && record.receiver_key.key_epoch == 0) {
            bob_initial_key_updates.push_back(record.receiver_key.update);
        }
    }

    expect_in_test(bob_initial_key_updates.size() == AggRukem::kMaxUpdates,
                   "aggressive_rukem_update_limit_counts_peer_updates_only",
                   "Agg-RUKEM should permit the configured RUKEM update budget: expected "
                       + std::to_string(AggRukem::kMaxUpdates) + ", got "
                       + std::to_string(bob_initial_key_updates.size()));
    for (std::uint64_t i = 0; i < bob_initial_key_updates.size(); ++i) {
        expect(bob_initial_key_updates[i] == i + 1,
               "Agg-RUKEM should not charge ordinary RKEM updates against the RUKEM limit");
    }
}

void aggressive_rkem_reuses_receiver_key_for_fast_sender_outputs() {
    auto alice = AggRkem::init_alice();
    auto bob = AggRkem::init_bob();

    for (int output = 0; output < 3; ++output) {
        for (int chunk = 0; chunk < 42; ++chunk) {
            auto a_send = alice.send();
            (void)bob.receive(a_send.message, a_send.sending_output);
        }

        auto b_ack = bob.send();
        (void)alice.receive(b_ack.message, b_ack.sending_output);

        std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_recv_key;
        for (int chunk = 0; chunk < 10 && !bob_recv_key; ++chunk) {
            auto a_send = alice.send();
            bob_recv_key = bob.receive(a_send.message, a_send.sending_output).output_key;
        }
        expect(bob_recv_key.has_value(), "Bob should receive each fast-Alice Agg-RKEM output");

        auto b_advance = bob.send();
        (void)alice.receive(b_advance.message, b_advance.sending_output);
    }

    std::vector<AggRukemKeyRef> bob_receiver_keys;
    for (const auto& record : alice.emitted_output_records()) {
        if (record.receiver_key.party == Party::Bob) {
            bob_receiver_keys.push_back(record.receiver_key);
        }
    }

    expect_in_test(bob_receiver_keys.size() >= 3,
                   "aggressive_rkem_reuses_receiver_key_for_fast_sender_outputs",
                   "Agg-RKEM should permit repeated fast-sender outputs");
    for (const auto& key : bob_receiver_keys) {
        expect(key.key_epoch == 0 && key.update == 1,
               "Agg-RKEM fast-sender outputs should reuse the receiver's retained key");
    }
}

void aggressive_rkem_secrets_agree_after_role_switch() {
    auto alice = AggRkem::init_alice();
    auto bob = AggRkem::init_bob();

    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_send_key;
    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> alice_recv_key;
    for (int chunk = 0; chunk < 42; ++chunk) {
        auto b_send = bob.send();
        if (b_send.output_key) {
            bob_send_key = b_send.output_key;
        }
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_recv_key = a_recv.output_key;
        }
    }

    auto a_ack = alice.send();
    (void)bob.receive(a_ack.message, a_ack.sending_output);

    for (int chunk = 0; chunk < 10 && (!bob_send_key || !alice_recv_key); ++chunk) {
        auto b_send = bob.send();
        if (b_send.output_key) {
            bob_send_key = b_send.output_key;
        }
        auto a_recv = alice.receive(b_send.message, b_send.sending_output);
        if (a_recv.output_key) {
            alice_recv_key = a_recv.output_key;
        }
    }
    expect(bob_send_key.has_value(), "Bob should emit initial Agg-RKEM send key");
    expect(alice_recv_key.has_value(), "Alice should receive initial Agg-RKEM key");
    expect(bob_send_key->first == alice_recv_key->first,
           "Bob-send/Alice-receive Agg-RKEM epoch mismatch before role switch");
    expect(bob_send_key->second == alice_recv_key->second,
           "Bob-send/Alice-receive Agg-RKEM secret mismatch before role switch");

    for (int chunk = 1; chunk < 42; ++chunk) {
        auto a_send = alice.send();
        (void)bob.receive(a_send.message, a_send.sending_output);
    }

    auto b_ack = bob.send();
    (void)alice.receive(b_ack.message, b_ack.sending_output);

    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> alice_send_key;
    std::optional<std::pair<SckaOutputId, MockRkemSharedSecret>> bob_recv_key;
    for (int chunk = 0; chunk < 10 && (!alice_send_key || !bob_recv_key); ++chunk) {
        auto a_send = alice.send();
        if (a_send.output_key) {
            alice_send_key = a_send.output_key;
        }
        auto b_recv = bob.receive(a_send.message, a_send.sending_output);
        if (b_recv.output_key) {
            bob_recv_key = b_recv.output_key;
        }
    }

    expect(alice_send_key.has_value(), "Alice should emit Agg-RKEM send key after role switch");
    expect(bob_recv_key.has_value(), "Bob should receive Agg-RKEM key after role switch");
    expect(alice_send_key->first == bob_recv_key->first,
           "Alice-send/Bob-receive Agg-RKEM epoch mismatch after role switch");
    expect(alice_send_key->second == bob_recv_key->second,
           "Alice-send/Bob-receive Agg-RKEM secret mismatch after role switch");
}

void secure_messaging_records_message_secrets() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();

    auto m0 = alice.send();
    auto received = bob.receive(m0);

    expect(m0.message_secret == received, "receiver must process exact message secret id");
    expect(m0.message_secret.chain_id == ChainId::AliceSender, "Alice message must use Alice chain");
    expect(!alice.message_records().empty(), "sender ledger record missing");
    expect(!bob.message_records().empty(), "receiver ledger record missing");
}

void secure_messaging_compromise_snapshot_includes_protocol_and_messaging_secrets() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();
    (void)bob;

    auto message = alice.send();
    auto patterns = alice.compromised_secret_patterns();
    auto protocol_patterns = alice.compromised_protocol_secret_patterns();

    expect(!protocol_patterns.empty(), "secure-messaging snapshot should expose wrapped protocol secrets");
    expect(!patterns.empty(), "secure-messaging snapshot should include root/chain/message secrets");
    expect(!contains_pattern(patterns, message_key(message.message_secret)),
           "secure-messaging snapshot should not retain sent message key");
}

void secure_messaging_processes_scka_before_message_key_derivation() {
    auto alice = SecureMessaging<ReceiveInstallsEpochScka>(ReceiveInstallsEpochScka::init_alice(),
                                                           Party::Alice);
    SecureMessaging<ReceiveInstallsEpochScka>::Message message{
        {},
        {message_output(1), ChainId::BobSender, 0},
    };

    auto received = alice.receive(message);

    expect(received == message.message_secret,
           "SCKA output must be installed before deriving the received message key");
}

void secure_messaging_send_deletes_message_key_and_retains_next_chain_key() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();
    (void)bob;

    auto message = alice.send();
    auto patterns = alice.compromised_secret_patterns();

    expect(std::find(patterns.begin(), patterns.end(), message_key(message.message_secret))
               == patterns.end(),
           "sent message key should be deleted after encryption");
    expect(std::find(patterns.begin(), patterns.end(),
                     chain_key(message.message_secret.output,
                               message.message_secret.chain_id,
                               message.message_secret.chain_counter + 1))
               != patterns.end(),
           "next sending chain key should remain after encryption");
}

void secure_messaging_receive_deletes_message_key_and_retains_next_chain_key() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();

    auto message = alice.send();
    auto received = bob.receive(message);
    auto patterns = bob.compromised_secret_patterns();

    expect(received == message.message_secret, "receiver should use the transmitted message key id");
    expect(std::find(patterns.begin(), patterns.end(), message_key(message.message_secret))
               == patterns.end(),
           "received message key should be deleted after decryption");
    expect(std::find(patterns.begin(), patterns.end(),
                     chain_key(message.message_secret.output,
                               message.message_secret.chain_id,
                               message.message_secret.chain_counter + 1))
               != patterns.end(),
           "next receiving chain key should remain after decryption");
}

void secure_messaging_generates_monotone_chain_counters() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();

    auto first = alice.send();
    auto second = alice.send();

    expect(first.message_secret.chain_counter == 0, "first chain counter should be zero");
    expect(second.message_secret.chain_counter == 1, "second chain counter should increment");

    (void)bob.receive(first);
    (void)bob.receive(second);
}

void secure_messaging_out_of_order_delivery_reports_then_deletes_skipped_key() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();

    auto first = alice.send();
    auto second = alice.send();

    (void)bob.receive(second);
    auto patterns = bob.compromised_secret_patterns();
    expect(std::find(patterns.begin(), patterns.end(), message_key(first.message_secret))
               != patterns.end(),
           "out-of-order secure-message receive should store skipped message key");

    (void)bob.receive(first);
    patterns = bob.compromised_secret_patterns();
    expect(std::find(patterns.begin(), patterns.end(), message_key(first.message_secret))
               == patterns.end(),
           "receipt of skipped secure message should delete only that skipped key");
    expect(std::find(patterns.begin(), patterns.end(), message_key(second.message_secret))
               == patterns.end(),
           "already received out-of-order message key should not be retained");
}

void secure_messaging_skipped_key_is_reported_then_deleted() {
    SecureMessagingChains chains(message_output(0), Party::Bob);
    MessageSecretId second{message_output(0), ChainId::AliceSender, 1};
    MessageSecretId first{message_output(0), ChainId::AliceSender, 0};

    chains.receive_message(second);
    auto patterns = chains.compromised_secret_patterns();
    expect(std::find(patterns.begin(), patterns.end(), message_key(first)) != patterns.end(),
           "skipped message key should be resident after out-of-order receive");

    chains.receive_message(first);
    patterns = chains.compromised_secret_patterns();
    expect(std::find(patterns.begin(), patterns.end(), message_key(first)) == patterns.end(),
           "skipped message key should be deleted after use");
}

void secure_messaging_agg_unikem_runs_multiple_epochs_in_order() {
    auto [alice, bob] = SecureMessaging<AggUniKem>::create_pair();
    std::set<Epoch> committed_message_epochs;

    for (int round = 0; round < 300; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice);
        if (const auto* output = std::get_if<AggUniKemOutputId>(&from_alice.message_secret.output)) {
            committed_message_epochs.insert(output->message_epoch);
        }

        auto from_bob = bob.send();
        (void)alice.receive(from_bob);
        if (const auto* output = std::get_if<AggUniKemOutputId>(&from_bob.message_secret.output)) {
            committed_message_epochs.insert(output->message_epoch);
        }
    }

    expect(committed_message_epochs.size() >= 2,
           "SecureMessaging<AggUniKem> should run in-order traffic across multiple committed epochs");
}

void secure_messaging_opp_unikem_runs_multiple_epochs_in_order() {
    auto [alice, bob] = SecureMessaging<OppUniKem>::create_pair();
    std::set<Epoch> committed_message_epochs;

    for (int round = 0; round < 500; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice);
        if (const auto* output = std::get_if<MessageEpoch>(&from_alice.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }

        auto from_bob = bob.send();
        (void)alice.receive(from_bob);
        if (const auto* output = std::get_if<MessageEpoch>(&from_bob.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }
    }

    expect(committed_message_epochs.size() >= 2,
           "SecureMessaging<OppUniKem> should run in-order traffic across multiple committed epochs");
}

void secure_messaging_opp_rkem_runs_multiple_epochs_in_order() {
    auto [alice, bob] = SecureMessaging<OppRkem>::create_pair();
    std::set<Epoch> committed_message_epochs;

    for (int round = 0; round < 500; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice);
        if (const auto* output = std::get_if<MessageEpoch>(&from_alice.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }

        auto from_bob = bob.send();
        (void)alice.receive(from_bob);
        if (const auto* output = std::get_if<MessageEpoch>(&from_bob.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }
    }

    expect(committed_message_epochs.size() >= 2,
           "SecureMessaging<OppRkem> should run in-order traffic across multiple committed epochs");
}

void secure_messaging_agg_rkem_runs_multiple_epochs_in_order() {
    auto [alice, bob] = SecureMessaging<AggRkem>::create_pair();
    std::set<Epoch> committed_message_epochs;

    for (int round = 0; round < 500; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice);
        if (const auto* output = std::get_if<MessageEpoch>(&from_alice.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }

        auto from_bob = bob.send();
        (void)alice.receive(from_bob);
        if (const auto* output = std::get_if<MessageEpoch>(&from_bob.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }
    }

    expect(committed_message_epochs.size() >= 2,
           "SecureMessaging<AggRkem> should run in-order traffic across multiple committed epochs");
}

void secure_messaging_agg_rukem_runs_multiple_epochs_in_order() {
    auto [alice, bob] = SecureMessaging<AggRukem>::create_pair();
    std::set<Epoch> committed_message_epochs;

    for (int round = 0; round < 500; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice);
        if (const auto* output = std::get_if<MessageEpoch>(&from_alice.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }

        auto from_bob = bob.send();
        (void)alice.receive(from_bob);
        if (const auto* output = std::get_if<MessageEpoch>(&from_bob.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }
    }

    expect(committed_message_epochs.size() >= 2,
           "SecureMessaging<AggRukem> should run in-order traffic across multiple committed epochs");
}

void secure_messaging_opp_rkem_usenix_runs_multiple_epochs_in_order() {
    auto [alice, bob] = SecureMessaging<OppRkemUsenix>::create_pair();
    std::set<Epoch> committed_message_epochs;

    for (int round = 0; round < 1600; ++round) {
        auto from_alice = alice.send();
        (void)bob.receive(from_alice);
        if (const auto* output = std::get_if<MessageEpoch>(&from_alice.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }

        auto from_bob = bob.send();
        (void)alice.receive(from_bob);
        if (const auto* output = std::get_if<MessageEpoch>(&from_bob.message_secret.output)) {
            committed_message_epochs.insert(output->value);
        }
    }

    expect(committed_message_epochs.size() >= 2,
           "SecureMessaging<OppRkemUsenix> should run in-order traffic across multiple committed epochs");
}

void agg_unikem_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto result = run_agg_unikem_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(), "runner global message IDs must be unique");
    expect(!result.rows.empty(), "runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result, "agg_unikem_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "runner should record emitted Agg-UniKEM outputs");
}

void agg_unikem_runner_ratio_traffic_skews_sender_counts() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::Ratio;
    config.ratio = 5.0;
    config.ticks = 120;
    auto result = run_agg_unikem_simulation(config);

    auto alice_messages =
        std::count_if(result.message_senders.begin(), result.message_senders.end(),
                      [](const auto& item) { return item.second == Party::Alice; });
    auto bob_messages =
        std::count_if(result.message_senders.begin(), result.message_senders.end(),
                      [](const auto& item) { return item.second == Party::Bob; });

    expect(alice_messages > bob_messages, "ratio > 1 should make Alice the fast sender");
    expect(bob_messages > 0, "ratio traffic should still include Bob sends");
}

void agg_unikem_runner_bob_fast_ratio_keeps_progressing() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::Ratio;
    config.ratio = 0.3;
    config.ticks = 30000;
    auto result = run_agg_unikem_simulation(config);

    expect(result.emitted_outputs.size() > 150,
           "Agg-UniKEM should keep emitting outputs when Bob is the fast sender");
}

void ratio_traffic_probabilities_match_expected_message_ratio() {
    auto balanced = ratio_traffic_probabilities(1.0);
    expect(balanced.alice == 0.5, "ratio 1 should make Alice's send probability 0.5");
    expect(balanced.bob == 0.5, "ratio 1 should make Bob's send probability 0.5");

    auto fast_alice = ratio_traffic_probabilities(5.0);
    expect(fast_alice.alice == 5.0 / 6.0, "ratio 5 should make Alice's send probability 5/6");
    expect(fast_alice.bob == 1.0 / 6.0, "ratio 5 should make Bob's send probability 1/6");

    auto fast_bob = ratio_traffic_probabilities(0.25);
    expect(fast_bob.alice == 0.2, "ratio 0.25 should make Alice's send probability 0.2");
    expect(fast_bob.bob == 0.8, "ratio 0.25 should make Bob's send probability 0.8");
}

void healing_histogram_groups_vms_samples_by_compromised_party() {
    std::vector<VmsSampleRow> rows(4);
    rows[0].compromised_party = Party::Alice;
    rows[0].vms_total = 2;
    rows[1].compromised_party = Party::Alice;
    rows[1].vms_total = 2;
    rows[2].compromised_party = Party::Bob;
    rows[2].vms_total = 0;
    rows[3].compromised_party = Party::Bob;
    rows[3].vms_total = 3;

    auto histogram = healing_histogram_from_rows(rows);
    expect(histogram.size() == 3, "histogram should have one row per VMS size");
    expect(histogram[0].num_msgs == 0 && histogram[0].tot_by_alice == 0
               && histogram[0].tot_by_bob == 1,
           "histogram should count Bob's zero-exposure sample");
    expect(histogram[1].num_msgs == 2 && histogram[1].tot_by_alice == 2
               && histogram[1].tot_by_bob == 0,
           "histogram should group Alice's matching exposure samples");
    expect(histogram[2].num_msgs == 3 && histogram[2].tot_by_alice == 0
               && histogram[2].tot_by_bob == 1,
           "histogram should count Bob's nonzero exposure sample");
}

void healing_stats_compute_party_distributions() {
    std::vector<HealingHistogramEntry> histogram{
        {0, 0, 1},
        {2, 2, 0},
        {3, 0, 1},
    };

    auto stats = stats_from_histogram(histogram);
    expect(stats[0].mean == 2.0, "Alice histogram mean should be 2");
    expect(stats[0].stddev == 0.0, "Alice histogram stddev should be 0");
    expect(stats[0].deciles[0] == 2 && stats[0].deciles[10] == 2,
           "Alice histogram min/max should be 2");
    expect(stats[1].mean == 1.5, "Bob histogram mean should be 1.5");
    expect(stats[1].stddev == 1.5, "Bob histogram stddev should be 1.5");
    expect(stats[1].deciles[0] == 0 && stats[1].deciles[10] == 3,
           "Bob histogram min/max should cover both samples");
}

void agg_unikem_runner_snapshot_resolution_is_deterministic() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto first = run_agg_unikem_simulation(config);
    auto second = run_agg_unikem_simulation(config);

    expect(first.rows.size() == second.rows.size(), "deterministic runs should have same row count");
    for (std::size_t i = 0; i < first.rows.size(); ++i) {
        expect(first.rows[i].vms_total == second.rows[i].vms_total,
               "deterministic runs should resolve identical VMS totals");
        expect(first.rows[i].compromised_scka_outputs_count
                   == second.rows[i].compromised_scka_outputs_count,
               "deterministic runs should resolve identical compromised SCKA outputs");
    }
}

void expect_vms_columns_track_compromised_party(const std::vector<VmsSampleRow>& rows) {
    bool saw_alice = false;
    bool saw_bob = false;
    for (const auto& row : rows) {
        if (row.compromised_party == Party::Alice) {
            saw_alice = true;
            expect(row.vms_alice == row.vms_total,
                   "Alice-compromise row should put total exposure in vms_alice");
            expect(row.vms_bob == 0,
                   "Alice-compromise row should not put exposure in vms_bob");
        } else {
            saw_bob = true;
            expect(row.vms_bob == row.vms_total,
                   "Bob-compromise row should put total exposure in vms_bob");
            expect(row.vms_alice == 0,
                   "Bob-compromise row should not put exposure in vms_alice");
        }
    }
    expect(saw_alice, "runner should include Alice compromise samples");
    expect(saw_bob, "runner should include Bob compromise samples");
}

void agg_unikem_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto result = run_agg_unikem_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

void opp_unikem_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto result = run_opp_unikem_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(), "Opp-UniKEM runner global message IDs must be unique");
    expect(!result.rows.empty(), "Opp-UniKEM runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result, "opp_unikem_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "Opp-UniKEM runner should record emitted outputs");
}

void opp_unikem_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto result = run_opp_unikem_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

void opp_unikem_usenix_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto result = run_opp_unikem_usenix_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(),
           "Opp-UniKEM-USENIX runner global message IDs must be unique");
    expect(!result.rows.empty(), "Opp-UniKEM-USENIX runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result,
                                        "opp_unikem_usenix_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "Opp-UniKEM-USENIX runner should record emitted outputs");
}

void opp_unikem_usenix_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 120;
    auto result = run_opp_unikem_usenix_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

void opp_rkem_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 160;
    auto result = run_opp_rkem_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(), "Opp-RKEM runner global message IDs must be unique");
    expect(!result.rows.empty(), "Opp-RKEM runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result, "opp_rkem_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "Opp-RKEM runner should record emitted outputs");
}

void opp_rkem_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 160;
    auto result = run_opp_rkem_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

void agg_rkem_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 160;
    auto result = run_agg_rkem_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(), "Agg-RKEM runner global message IDs must be unique");
    expect(!result.rows.empty(), "Agg-RKEM runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result, "agg_rkem_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "Agg-RKEM runner should record emitted outputs");
}

void agg_rkem_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 160;
    auto result = run_agg_rkem_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

void agg_rukem_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 160;
    auto result = run_agg_rukem_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(), "Agg-RUKEM runner global message IDs must be unique");
    expect(!result.rows.empty(), "Agg-RUKEM runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result, "agg_rukem_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "Agg-RUKEM runner should record emitted outputs");
}

void agg_rukem_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 160;
    auto result = run_agg_rukem_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

void opp_rkem_usenix_runner_assigns_global_message_ids() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 180;
    auto result = run_opp_rkem_usenix_simulation(config);

    std::set<MessageId> ids;
    for (const auto& message : result.messages) {
        ids.insert(message.id);
    }

    expect(ids.size() == result.messages.size(), "Opp-RKEM-USENIX runner global message IDs must be unique");
    expect(!result.rows.empty(), "Opp-RKEM-USENIX runner should emit compromise sample rows");
    expect_runner_samples_each_party_once_per_tick(result, "opp_rkem_usenix_runner_assigns_global_message_ids");
    expect(!result.emitted_outputs.empty(), "Opp-RKEM-USENIX runner should record emitted outputs");
}

void opp_rkem_usenix_runner_vms_columns_track_compromised_party() {
    AggUniKemRunnerConfig config;
    config.traffic_model = TrafficModel::PingPong;
    config.ticks = 180;
    auto result = run_opp_rkem_usenix_simulation(config);

    expect_vms_columns_track_compromised_party(result.rows);
}

} // namespace

int main() {
    resolver_root_alone_exposes_nothing();
    resolver_scka_output_alone_exposes_nothing();
    resolver_root_plus_matching_output_exposes_epoch();
    resolver_root_iteration_exposes_later_epoch();
    resolver_future_output_from_current_secret_is_counted();
    resolver_chain_key_exposes_suffix();
    resolver_message_key_exposes_exact_message();
    agg_unikem_resolver_ek_pattern_matches_committed_outputs();
    agg_unikem_resolver_ct0_pattern_matches_committed_outputs();
    agg_unikem_resolver_exact_pattern_matches_one_output();
    agg_unikem_resolver_nonmatching_pattern_exposes_no_outputs();
    agg_unikem_resolver_unions_and_deduplicates_patterns();
    opp_unikem_resolver_maps_epoch_patterns_to_message_outputs();
    chunking_requires_threshold_chunks();
    mock_unikem_agrees_and_rejects_wrong_key();
    mock_rkem_agrees_across_update();
    aggressive_unikem_first_epoch_agrees();
    aggressive_unikem_ping_pong_progresses_multiple_epochs();
    aggressive_unikem_switches_roles_after_epoch();
    aggressive_unikem_random_traffic_progresses_with_reordering();
    aggressive_unikem_random_traffic_progresses_with_drops_and_reordering();
    aggressive_unikem_reports_wildcard_secrets();
    aggressive_unikem_state_names_show_protocol_progress();
    aggressive_unikem_deletes_acked_ek_when_sampling_next();
    aggressive_unikem_frozen_ek_ack_does_not_introduce_new_ek_subepoch();
    aggressive_unikem_ct_sender_aggressive_loop_reports_acked_and_current_ct0();
    aggressive_unikem_send_ct1_reports_exact_committed_output();
    aggressive_unikem_ek_ack_ct0_completion_race_chooses_frozen_path();
    aggressive_unikem_ct0_ack_ek_completion_race_commits();
    aggressive_unikem_invalid_event_policy_can_throw();
    aggressive_unikem_every_ct1_chunk_carries_commit_indices();
    opportunistic_unikem_first_epoch_agrees();
    opportunistic_unikem_ping_pong_progresses_multiple_epochs();
    opportunistic_unikem_switches_roles_after_epoch();
    opportunistic_unikem_state_names_show_protocol_progress();
    opportunistic_unikem_reports_epoch_patterns();
    opportunistic_unikem_usenix_first_epoch_agrees();
    opportunistic_unikem_usenix_ping_pong_progresses_multiple_epochs();
    opportunistic_unikem_usenix_state_names_show_old_protocol_progress();
    opportunistic_unikem_usenix_reports_held_secret_epoch_patterns();
    opportunistic_rkem_first_epoch_agrees();
    opportunistic_rkem_ping_pong_progresses_multiple_epochs();
    opportunistic_rkem_random_traffic_progresses_with_reordering();
    opportunistic_rkem_random_traffic_progresses_with_drops_and_reordering();
    opportunistic_rkem_reports_epoch_patterns();
    opportunistic_rkem_usenix_ping_pong_progresses_multiple_epochs();
    opportunistic_rkem_usenix_reports_queued_output_patterns();
    aggressive_rukem_first_epoch_agrees();
    aggressive_rukem_ping_pong_progresses_multiple_epochs();
    aggressive_rukem_reports_updated_key_patterns();
    aggressive_rukem_update_limit_counts_peer_updates_only();
    aggressive_rkem_reuses_receiver_key_for_fast_sender_outputs();
    aggressive_rkem_secrets_agree_after_role_switch();
    secure_messaging_records_message_secrets();
    secure_messaging_compromise_snapshot_includes_protocol_and_messaging_secrets();
    secure_messaging_processes_scka_before_message_key_derivation();
    secure_messaging_send_deletes_message_key_and_retains_next_chain_key();
    secure_messaging_receive_deletes_message_key_and_retains_next_chain_key();
    secure_messaging_generates_monotone_chain_counters();
    secure_messaging_out_of_order_delivery_reports_then_deletes_skipped_key();
    secure_messaging_skipped_key_is_reported_then_deleted();
    secure_messaging_agg_unikem_runs_multiple_epochs_in_order();
    secure_messaging_opp_unikem_runs_multiple_epochs_in_order();
    secure_messaging_opp_rkem_runs_multiple_epochs_in_order();
    secure_messaging_agg_rkem_runs_multiple_epochs_in_order();
    secure_messaging_agg_rukem_runs_multiple_epochs_in_order();
    secure_messaging_opp_rkem_usenix_runs_multiple_epochs_in_order();
    agg_unikem_runner_assigns_global_message_ids();
    agg_unikem_runner_ratio_traffic_skews_sender_counts();
    agg_unikem_runner_bob_fast_ratio_keeps_progressing();
    ratio_traffic_probabilities_match_expected_message_ratio();
    healing_histogram_groups_vms_samples_by_compromised_party();
    healing_stats_compute_party_distributions();
    agg_unikem_runner_snapshot_resolution_is_deterministic();
    agg_unikem_runner_vms_columns_track_compromised_party();
    opp_unikem_runner_assigns_global_message_ids();
    opp_unikem_runner_vms_columns_track_compromised_party();
    opp_unikem_usenix_runner_assigns_global_message_ids();
    opp_unikem_usenix_runner_vms_columns_track_compromised_party();
    opp_rkem_runner_assigns_global_message_ids();
    opp_rkem_runner_vms_columns_track_compromised_party();
    agg_rkem_runner_assigns_global_message_ids();
    agg_rkem_runner_vms_columns_track_compromised_party();
    agg_rukem_runner_assigns_global_message_ids();
    agg_rukem_runner_vms_columns_track_compromised_party();
    opp_rkem_usenix_runner_assigns_global_message_ids();
    opp_rkem_usenix_runner_vms_columns_track_compromised_party();

    std::cout << "framework_tests passed\n";
    return 0;
}
