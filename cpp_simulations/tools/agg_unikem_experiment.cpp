#include "simulation_runner.hpp"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

using namespace smsim;

namespace {

enum class Protocol {
    AggUniKem,
    AggRkem,
    AggRukem,
    OppUniKem,
    OppUniKemUsenix,
    OppRkem,
    OppRkemUsenix,
};

struct ParsedArgs {
    Protocol protocol = Protocol::AggUniKem;
    AggUniKemRunnerConfig config;
    std::optional<std::string> sample_output_path;
    std::optional<std::string> histogram_output_path;
    std::optional<std::string> stats_output_path;
};

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0
              << " [--protocol agg-uni-kem|agg-rkem|agg-rukem|opp-uni-kem|opp-unikem-usenix|opp-rkem|opp-rkem-usenix] [--traffic ping-pong|ratio] [--ratio R] [--ticks N]"
                 " [--seed N] [--run-id N] [--output samples.csv] [--hist-output hist.csv] [--stats-output stats.csv]\n";
}

std::uint64_t parse_u64(const std::string& value) {
    return static_cast<std::uint64_t>(std::stoull(value));
}

std::string default_sample_output_path(Protocol protocol) {
    switch (protocol) {
    case Protocol::AggUniKem:
        return "agg_unikem_results.csv";
    case Protocol::AggRkem:
        return "agg_rkem_results.csv";
    case Protocol::AggRukem:
        return "agg_rukem_results.csv";
    case Protocol::OppUniKem:
        return "opp_unikem_results.csv";
    case Protocol::OppUniKemUsenix:
        return "opp_unikem_usenix_results.csv";
    case Protocol::OppRkem:
        return "opp_rkem_results.csv";
    case Protocol::OppRkemUsenix:
        return "opp_rkem_usenix_results.csv";
    }
    throw std::runtime_error("unknown protocol");
}

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs parsed;
    bool any_output_requested = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto require_value = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string("missing value for ") + name);
            }
            return argv[++i];
        };

        if (arg == "--protocol") {
            auto value = require_value("--protocol");
            if (value == "agg-uni-kem") {
                parsed.protocol = Protocol::AggUniKem;
            } else if (value == "agg-rkem") {
                parsed.protocol = Protocol::AggRkem;
            } else if (value == "agg-rukem") {
                parsed.protocol = Protocol::AggRukem;
            } else if (value == "opp-uni-kem") {
                parsed.protocol = Protocol::OppUniKem;
            } else if (value == "opp-unikem-usenix") {
                parsed.protocol = Protocol::OppUniKemUsenix;
            } else if (value == "opp-rkem") {
                parsed.protocol = Protocol::OppRkem;
            } else if (value == "opp-rkem-usenix") {
                parsed.protocol = Protocol::OppRkemUsenix;
            } else {
                throw std::runtime_error("unknown protocol");
            }
        } else if (arg == "--traffic") {
            auto value = require_value("--traffic");
            if (value == "ping-pong") {
                parsed.config.traffic_model = TrafficModel::PingPong;
            } else if (value == "ratio") {
                parsed.config.traffic_model = TrafficModel::Ratio;
            } else {
                throw std::runtime_error("unknown traffic model");
            }
        } else if (arg == "--ratio") {
            parsed.config.ratio = std::stod(require_value("--ratio"));
            parsed.config.traffic_model = TrafficModel::Ratio;
        } else if (arg == "--ticks") {
            parsed.config.ticks = parse_u64(require_value("--ticks"));
        } else if (arg == "--seed") {
            parsed.config.seed = parse_u64(require_value("--seed"));
        } else if (arg == "--run-id") {
            parsed.config.run_id = parse_u64(require_value("--run-id"));
        } else if (arg == "--output") {
            parsed.sample_output_path = require_value("--output");
            any_output_requested = true;
        } else if (arg == "--hist-output") {
            parsed.histogram_output_path = require_value("--hist-output");
            any_output_requested = true;
        } else if (arg == "--stats-output") {
            parsed.stats_output_path = require_value("--stats-output");
            any_output_requested = true;
        } else if (arg == "--help" || arg == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }

    if (!any_output_requested) {
        parsed.sample_output_path = default_sample_output_path(parsed.protocol);
    }

    return parsed;
}

template <typename RunResult>
void write_requested_outputs(const RunResult& result, const ParsedArgs& parsed) {
    if (parsed.sample_output_path) {
        write_csv(result, *parsed.sample_output_path);
        std::cout << "samples_output=" << *parsed.sample_output_path << "\n";
    }
    if (parsed.histogram_output_path) {
        write_histogram_csv(result, *parsed.histogram_output_path);
        std::cout << "hist_output=" << *parsed.histogram_output_path << "\n";
    }
    if (parsed.stats_output_path) {
        write_stats_csv(result, *parsed.stats_output_path);
        std::cout << "stats_output=" << *parsed.stats_output_path << "\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        auto parsed = parse_args(argc, argv);
        if (parsed.protocol == Protocol::AggUniKem) {
            auto result = run_agg_unikem_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        } else if (parsed.protocol == Protocol::AggRkem) {
            auto result = run_agg_rkem_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        } else if (parsed.protocol == Protocol::AggRukem) {
            auto result = run_agg_rukem_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        } else if (parsed.protocol == Protocol::OppUniKem) {
            auto result = run_opp_unikem_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        } else if (parsed.protocol == Protocol::OppUniKemUsenix) {
            auto result = run_opp_unikem_usenix_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        } else if (parsed.protocol == Protocol::OppRkem) {
            auto result = run_opp_rkem_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        } else {
            auto result = run_opp_rkem_usenix_simulation(parsed.config);
            std::cout << summary(result);
            write_requested_outputs(result, parsed);
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        usage(argv[0]);
        return 1;
    }
    return 0;
}
