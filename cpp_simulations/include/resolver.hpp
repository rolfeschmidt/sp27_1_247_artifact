#pragma once

#include "ids.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace smsim {

struct VmsCounts {
    std::uint64_t total = 0;
    std::uint64_t alice = 0;
    std::uint64_t bob = 0;
};

class VmsResolver {
public:
    explicit VmsResolver(std::vector<MessageRecord> messages)
        : messages_(std::move(messages)) {
        std::sort(messages_.begin(), messages_.end(),
                  [](const MessageRecord& left, const MessageRecord& right) {
                      return left.id < right.id;
                  });
        for (const auto& message : messages_) {
            auto chain = std::pair{message.secret.output, message.secret.chain_id};
            auto& length = chain_lengths_[chain];
            length = std::max(length, message.secret.chain_counter + 1);
            message_index_[message.secret] = message;
        }
    }

    std::set<MessageId> resolve(const std::vector<SecretPattern>& patterns,
                                const std::set<SckaOutputId>& compromised_outputs = {}) const {
        std::set<MessageEpoch> known_roots;
        std::set<SckaOutputId> known_outputs = compromised_outputs;
        std::set<MessageId> exposed;

        for (const auto& pattern : patterns) {
            std::visit(
                [&](const auto& concrete) {
                    using T = std::decay_t<decltype(concrete)>;
                    if constexpr (std::is_same_v<T, RootKeyPattern>) {
                        known_roots.insert(concrete.epoch);
                    } else if constexpr (std::is_same_v<T, ChainKeyPattern>) {
                        expose_chain(concrete.output, concrete.chain_id, concrete.chain_counter, exposed);
                    } else if constexpr (std::is_same_v<T, MessageKeyPattern>) {
                        expose_message_key(concrete.id, exposed);
                    }
                },
                pattern);
        }

        bool changed = true;
        while (changed) {
            changed = false;
            for (auto output_epoch : known_outputs) {
                auto needed_root = root_key_epoch_for_scka_output(output_epoch);
                if (!known_roots.contains(needed_root)) {
                    continue;
                }

                expose_chain(output_epoch, ChainId::AliceSender, 0, exposed);
                expose_chain(output_epoch, ChainId::BobSender, 0, exposed);

                auto next_root = next_root_key_epoch_after_scka_output(output_epoch);
                if (known_roots.insert(next_root).second) {
                    changed = true;
                }
            }
        }

        return exposed;
    }

    VmsCounts resolve_counts(const std::vector<SecretPattern>& patterns,
                             const std::set<SckaOutputId>& compromised_outputs = {}) const {
        std::set<MessageEpoch> known_roots;
        std::map<std::pair<SckaOutputId, ChainId>, std::uint64_t> exposed_chains;
        std::set<MessageSecretId> exact_messages;

        for (const auto& pattern : patterns) {
            std::visit(
                [&](const auto& concrete) {
                    using T = std::decay_t<decltype(concrete)>;
                    if constexpr (std::is_same_v<T, RootKeyPattern>) {
                        known_roots.insert(concrete.epoch);
                    } else if constexpr (std::is_same_v<T, ChainKeyPattern>) {
                        expose_chain_from(exposed_chains, concrete.output, concrete.chain_id,
                                          concrete.chain_counter);
                    } else if constexpr (std::is_same_v<T, MessageKeyPattern>) {
                        exact_messages.insert(concrete.id);
                    }
                },
                pattern);
        }

        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& output : compromised_outputs) {
                auto needed_root = root_key_epoch_for_scka_output(output);
                if (!known_roots.contains(needed_root)) {
                    continue;
                }

                expose_chain_from(exposed_chains, output, ChainId::AliceSender, 0);
                expose_chain_from(exposed_chains, output, ChainId::BobSender, 0);

                auto next_root = next_root_key_epoch_after_scka_output(output);
                if (known_roots.insert(next_root).second) {
                    changed = true;
                }
            }
        }

        VmsCounts counts;
        for (const auto& [chain, first_counter] : exposed_chains) {
            auto length = chain_length(chain.first, chain.second);
            if (length <= first_counter) {
                continue;
            }
            auto exposed_count = length - first_counter;
            counts.total += exposed_count;
            if (chain.second == ChainId::AliceSender) {
                counts.alice += exposed_count;
            } else {
                counts.bob += exposed_count;
            }
        }

        for (const auto& id : exact_messages) {
            if (is_covered_by_chain(exposed_chains, id)) {
                continue;
            }
            if (!message_index_.contains(id)) {
                continue;
            }
            ++counts.total;
            if (id.chain_id == ChainId::AliceSender) {
                ++counts.alice;
            } else {
                ++counts.bob;
            }
        }

        return counts;
    }

private:
    static void expose_chain_from(std::map<std::pair<SckaOutputId, ChainId>, std::uint64_t>& chains,
                                  const SckaOutputId& output, ChainId chain_id,
                                  std::uint64_t counter) {
        auto key = std::pair{output, chain_id};
        auto [it, inserted] = chains.insert({key, counter});
        if (!inserted) {
            it->second = std::min(it->second, counter);
        }
    }

    std::uint64_t chain_length(const SckaOutputId& output, ChainId chain_id) const {
        auto it = chain_lengths_.find({output, chain_id});
        if (it == chain_lengths_.end()) {
            return 0;
        }
        return it->second;
    }

    static bool is_covered_by_chain(
        const std::map<std::pair<SckaOutputId, ChainId>, std::uint64_t>& chains,
        const MessageSecretId& id) {
        auto it = chains.find({id.output, id.chain_id});
        return it != chains.end() && id.chain_counter >= it->second;
    }

    void expose_chain(const SckaOutputId& output, ChainId chain_id, std::uint64_t counter,
                      std::set<MessageId>& exposed) const {
        for (const auto& message : messages_) {
            if (message.secret.output == output
                && message.secret.chain_id == chain_id
                && message.secret.chain_counter >= counter) {
                exposed.insert(message.id);
            }
        }
    }

    void expose_message_key(MessageSecretId id, std::set<MessageId>& exposed) const {
        for (const auto& message : messages_) {
            if (message.secret == id) {
                exposed.insert(message.id);
            }
        }
    }

    std::vector<MessageRecord> messages_;
    std::map<std::pair<SckaOutputId, ChainId>, std::uint64_t> chain_lengths_;
    std::map<MessageSecretId, MessageRecord> message_index_;
};

} // namespace smsim
