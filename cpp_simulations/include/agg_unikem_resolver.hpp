#pragma once

#include "ids.hpp"

#include <set>
#include <vector>

namespace smsim {

inline std::set<SckaOutputId>
resolve_agg_unikem_outputs(const std::vector<AggUniKemOutputId>& emitted_outputs,
                            const std::vector<ProtocolSecretPattern>& patterns) {
    std::set<AggUniKemOutputPattern> compromised_patterns;
    for (const auto& pattern : patterns) {
        if (const auto* agg_pattern = std::get_if<AggUniKemOutputPattern>(&pattern)) {
            compromised_patterns.insert(*agg_pattern);
        }
    }

    std::set<SckaOutputId> compromised_outputs;
    for (auto output : emitted_outputs) {
        for (const auto& pattern : compromised_patterns) {
            if (pattern.matches(output)) {
                compromised_outputs.insert(agg_uni_kem_output(output));
                break;
            }
        }
    }
    return compromised_outputs;
}

} // namespace smsim
