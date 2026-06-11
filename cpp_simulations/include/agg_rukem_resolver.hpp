#pragma once

#include "ids.hpp"

#include <set>
#include <vector>

namespace smsim {

inline std::set<SckaOutputId>
resolve_agg_rukem_outputs(const std::vector<AggRukemOutputRecord>& emitted_outputs,
                           const std::vector<ProtocolSecretPattern>& patterns) {
    std::set<AggRukemOutputPattern> compromised_patterns;
    for (const auto& pattern : patterns) {
        if (const auto* agg_pattern = std::get_if<AggRukemOutputPattern>(&pattern)) {
            compromised_patterns.insert(*agg_pattern);
        }
    }

    std::set<SckaOutputId> compromised_outputs;
    for (const auto& output : emitted_outputs) {
        for (auto pattern : compromised_patterns) {
            if (output.matches(pattern)) {
                compromised_outputs.insert(message_output(output.output.value));
                break;
            }
        }
    }
    return compromised_outputs;
}

} // namespace smsim
