#pragma once

#include "ids.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace smsim {

template <typename Key, typename Message>
struct SparseSendResult {
    std::optional<std::pair<SckaOutputId, Key>> output_key;
    SckaOutputId sending_output = message_output(0);
    Message message;
};

template <typename Key>
struct SparseReceiveResult {
    std::optional<std::pair<SckaOutputId, Key>> output_key;
    SckaOutputId receiving_output = message_output(0);
};

template <typename Message>
struct SecureMessage {
    Message scka_message;
    MessageSecretId message_secret;

    auto operator<=>(const SecureMessage&) const = default;
};

class SecureMessagingChains {
public:
    SecureMessagingChains(SckaOutputId initial_output, Party party)
        : root_key_(root_key_epoch_for_scka_output(initial_output)),
          party_(party) {
        chains_[{initial_output, ChainId::AliceSender}] = 0;
        chains_[{std::move(initial_output), ChainId::BobSender}] = 0;
    }

    void ratchet_root(SckaOutputId output) {
        root_key_ = next_root_key_epoch_after_scka_output(output);
        chains_[{output, ChainId::AliceSender}] = 0;
        chains_[{std::move(output), ChainId::BobSender}] = 0;
    }

    MessageSecretId send_message(SckaOutputId output, ChainId chain_id) {
        auto key = std::pair{output, chain_id};
        auto it = chains_.find(key);
        if (it == chains_.end()) {
            throw std::runtime_error("missing sending chain for " + canonical_string(output));
        }
        auto secret = MessageSecretId{output, chain_id, it->second++};
        erase_older_chains(chain_id, output);
        return secret;
    }

    MessageSecretId receive_message(const MessageSecretId& id) {
        if (skipped_message_keys_.erase(id) > 0) {
            return id;
        }
        auto key = std::pair{id.output, id.chain_id};
        auto it = chains_.find(key);
        if (it == chains_.end()) {
            throw std::runtime_error("missing receiving chain for " + canonical_string(id.output));
        }
        while (it->second < id.chain_counter) {
            skipped_message_keys_.insert({id.output, id.chain_id, it->second++});
        }
        ++it->second;
        erase_older_chains(id.chain_id, id.output);
        return id;
    }

    std::vector<SecretPattern> compromised_secret_patterns() const {
        std::vector<SecretPattern> patterns;
        patterns.push_back(root_key(root_key_));
        for (const auto& [chain, counter] : chains_) {
            patterns.push_back(chain_key(chain.first, chain.second, counter));
        }
        for (auto id : skipped_message_keys_) {
            patterns.push_back(message_key(id));
        }
        std::sort(patterns.begin(), patterns.end());
        patterns.erase(std::unique(patterns.begin(), patterns.end()), patterns.end());
        return patterns;
    }

private:
    void erase_older_chains(ChainId chain_id, const SckaOutputId& retained_output) {
        auto retained_epoch = root_key_epoch_for_scka_output(retained_output);
        for (auto it = chains_.begin(); it != chains_.end();) {
            if (it->first.second == chain_id
                && root_key_epoch_for_scka_output(it->first.first) < retained_epoch) {
                it = chains_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = skipped_message_keys_.begin(); it != skipped_message_keys_.end();) {
            if (it->chain_id == chain_id
                && root_key_epoch_for_scka_output(it->output) < retained_epoch) {
                it = skipped_message_keys_.erase(it);
            } else {
                ++it;
            }
        }
    }

    MessageEpoch root_key_;
    Party party_;
    std::map<std::pair<SckaOutputId, ChainId>, std::uint64_t> chains_;
    std::set<MessageSecretId> skipped_message_keys_;
};

template <typename Scka>
class SecureMessaging {
public:
    using SckaMessage = typename Scka::Message;
    using OutputKey = typename Scka::OutputKey;
    using Message = SecureMessage<SckaMessage>;

    SecureMessaging(Scka scka, Party party)
        : scka_(std::move(scka)),
          chains_(Scka::initial_epoch(), party),
          party_(party),
          last_message_output_(Scka::initial_epoch()) {}

    static std::pair<SecureMessaging, SecureMessaging> create_pair() {
        return {
            SecureMessaging(Scka::init_alice(), Party::Alice),
            SecureMessaging(Scka::init_bob(), Party::Bob),
        };
    }

    Message send() {
        auto out = scka_.send();
        install_output_key(out.output_key);
        auto secret = chains_.send_message(out.sending_output, chain_from_sender(party_));
        last_message_output_ = secret.output;
        records_.push_back({next_message_id_++, secret});
        return {out.message, secret};
    }

    MessageSecretId receive(const Message& message) {
        if (message.message_secret.chain_id != chain_from_sender(other(party_))) {
            throw std::runtime_error("wrong receiving chain");
        }
        auto out = scka_.receive(message.scka_message, message.message_secret.output);
        if (out.receiving_output != message.message_secret.output) {
            throw std::runtime_error("SCKA receiving output mismatch");
        }
        install_output_key(out.output_key);
        auto secret = chains_.receive_message(message.message_secret);
        last_message_output_ = secret.output;
        records_.push_back({next_message_id_++, secret});
        return secret;
    }

    std::vector<SecretPattern> compromised_secret_patterns() const {
        auto patterns = chains_.compromised_secret_patterns();
        std::sort(patterns.begin(), patterns.end());
        patterns.erase(std::unique(patterns.begin(), patterns.end()), patterns.end());
        return patterns;
    }

    std::vector<ProtocolSecretPattern> compromised_protocol_secret_patterns() const {
        return scka_.compromised_secret_patterns();
    }

    const std::vector<MessageRecord>& message_records() const {
        return records_;
    }

    const Scka& scka() const {
        return scka_;
    }

private:
    void install_output_key(const std::optional<std::pair<SckaOutputId, OutputKey>>& output_key) {
        if (output_key) {
            chains_.ratchet_root(output_key->first);
        }
    }

    Scka scka_;
    SecureMessagingChains chains_;
    Party party_;
    SckaOutputId last_message_output_;
    std::vector<MessageRecord> records_;
    MessageId next_message_id_ = 0;
};

} // namespace smsim
