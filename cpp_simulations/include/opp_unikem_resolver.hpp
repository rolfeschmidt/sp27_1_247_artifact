#pragma once

#include "ids.hpp"

#include <set>
#include <vector>

namespace smsim {

inline std::set<SckaOutputId>
resolve_opp_unikem_outputs(const std::vector<MessageEpoch>& emitted_outputs,
                            const std::vector<ProtocolSecretPattern>& patterns) {
    std::set<Epoch> compromised_epochs;
    for (const auto& pattern : patterns) {
        if (const auto* opp_pattern = std::get_if<OppUniKemOutputPattern>(&pattern)) {
            compromised_epochs.insert(opp_pattern->epoch);
        }
    }

    std::set<SckaOutputId> compromised_outputs;
    for (auto output : emitted_outputs) {
        if (compromised_epochs.contains(output.value)) {
            compromised_outputs.insert(message_output(output.value));
        }
    }
    return compromised_outputs;
}

} // namespace smsim
