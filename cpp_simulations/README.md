# C++ Secure Messaging Simulation Framework

This directory contains the supported secure-messaging simulation framework.
The older Rust simulator and pre-framework C++ simulator have been retired; new
simulation work should live here.

The framework models the paper's security semantics directly: compromise
reveals resident secrets, and vulnerable messages are resolved from those
secrets after the run.

## Quick Start

Prerequisites:

* CMake 3.16 or newer;
* a C++20 compiler;
* `gnuplot`, only if generating chart PNGs.

Configure and build from the repository root:

```sh
cmake -S cpp_simulations -B cpp_simulations/build
cmake --build cpp_simulations/build
```

Run the framework tests:

```sh
ctest --test-dir cpp_simulations/build --output-on-failure
```

Run one simulation and write sample rows:

```sh
cpp_simulations/build/agg_unikem_experiment \
  --protocol agg-uni-kem \
  --traffic ratio \
  --ratio 5 \
  --ticks 100 \
  --output cpp_simulations/build/agg_unikem_results.csv
```

Supported `--protocol` values are:

```text
agg-uni-kem
agg-rukem
opp-uni-kem
opp-unikem-usenix
opp-rkem
opp-rkem-usenix
```

Supported traffic models are `ping-pong` and `ratio`. Ratio traffic uses
`--ratio R` to control Alice/Bob send imbalance. Use `--seed N` and
`--run-id N` for deterministic experiment labeling.

Each simulation tick samples which parties wake up. A waking party drains its
incoming queue and sends one message. If both parties wake on the same tick,
their order is randomized. After the tick's traffic is processed, the runner
records one compromise sample for Alice and one for Bob.

To write histogram and summary-stat CSVs instead of sample rows:

```sh
cpp_simulations/build/agg_unikem_experiment \
  --protocol agg-rukem \
  --traffic ratio \
  --ratio 1 \
  --ticks 1000000 \
  --hist-output cpp_simulations/build/agg_ratio1_hist.csv \
  --stats-output cpp_simulations/build/agg_ratio1_stats.csv
```

The summary printed to stdout includes:

```text
vms_total_mean=...
vms_alice_mean=...
vms_bob_mean=...
vms_total_max=...
```

To run the built-in ratio comparison for the modeled protocols and generate
chart data/PNGs:

```sh
cpp_simulations/charts/run_ratio_comparison.sh
```

Set `TICKS`, `SEED`, `BUILD_DIR`, `DATA_DIR`, or `PLOT_DIR` in the environment
to override the chart script defaults.

## Design Goal

Keep three concerns separate:

```text
SCKA protocol state machine
        |
        v
SecureMessaging<SCKA>
        |
        v
VmsResolver
```

The SCKA implementation models only the sparse key agreement protocol. It sends
and receives SCKA control messages, emits SCKA output keys, and reports resident
protocol secrets at compromise time. It should not decide which application
messages are exposed.

`SecureMessaging<SCKA>` models the generic double-ratchet layer. It owns root
keys, per-direction chain keys, message-key deletion, skipped message keys, and
message-secret labels. It asks the SCKA for new output keys and installs them
into the root schedule.

On receive, the wrapper always processes the SCKA protocol message before
deriving or consuming the ciphertext's message key. Any SCKA output is mixed
into the root schedule first, because the received protocol message may create
the epoch chains required to decrypt the associated ciphertext.

`VmsResolver` maps compromised secrets to application messages. It runs after
the transcript is known, so a secret compromised at time `t` can expose a future
SCKA output if that future output is later derived from the compromised secret.
This matches the paper model: the attacker can corrupt now and read later.

## Experiment Data Model

Experiments should run a complete secure-messaging session first and record
facts, not conclusions. Protocol and wrapper code should emit enough structured
identity data for a later pass to compute VMS:

* concrete SCKA outputs emitted during the run, with detailed protocol-specific
  output IDs;
* root-key and chain-key identities, including the message epoch and the SCKA
  output IDs used to derive them;
* chain lengths for each sender chain;
* exact message ledger entries keyed by `MessageSecretId`;
* compromise snapshots containing the resident protocol and secure-messaging
  secrets exposed at that event.

After the session finishes, protocol-specific resolvers expand compromised
protocol secrets into concrete SCKA outputs by matching against the full
transcript. The generic VMS resolver then iteratively combines those concrete
SCKA outputs with matching compromised root keys to derive newly compromised
chain keys and later root keys. Once no more keys can be derived, the
compromised chain keys and exact message keys determine the vulnerable message
set.

## Secret Identity

The framework uses three identity layers.

`MessageEpoch` labels the secure-messaging root-key epoch.

`SckaOutputId` labels a concrete SCKA output used by the secure-messaging root
KDF. A simple protocol can use `MessageEpoch(e)` as its output ID. Protocols
with subepoch structure add a protocol-specific output ID, such as
`AggUniKemOutputId{e, i, j}`.

`MessageSecretId` labels an application message key:

```text
(scka_output_id, sender_chain, chain_counter)
```

`SecretPattern` labels generic secure-messaging secrets that `VmsResolver`
understands directly: root keys, chain keys, and exact message keys.

`ProtocolSecretPattern` labels protocol-resident secrets. Protocol-specific
resolvers map those patterns to concrete `SckaOutputId` values after the full
transcript is known. The Agg-UniKEM patterns are intentionally wildcard-shaped:

```text
EK-side DK:      (message_epoch, ek_subepoch, *)
CT0-side state:  (message_epoch, *, ct0_subepoch)
exact output:    (message_epoch, ek_subepoch, ct0_subepoch)
```

This is the recommended structure for future SCKAs: keep each protocol's
internal secret IDs local, then expose only the patterns needed by that
protocol's resolver.

## VMS Resolution

VMS resolution is KDF-aware:

* `RootKey(ep)` alone exposes no application messages.
* a known SCKA output alone exposes no application messages.
* `RootKey(root_epoch(output))` plus a matching SCKA output derives both
  direction chain keys for that output epoch and the next root key.
* `ChainKey(output, direction, step)` exposes messages from that chain step
  onward.
* `MessageKey(id)` exposes exactly one message.

This is the main correction relative to coarse vulnerable-epoch accounting. A
protocol secret does not directly mean "all messages in an epoch are exposed";
it becomes dangerous when combined with the right root key.

## Implementation Style

Prefer simple, explicit C++20:

* small value types with ordering;
* `std::optional` for absent outputs;
* `std::variant` only where a real sum type is needed;
* deterministic mock cryptography for tests;
* focused tests for every semantic rule.

Avoid hiding protocol behavior behind inheritance. Use concepts/templates for
the generic secure-messaging wrapper, and keep each protocol state machine as a
normal type with a small required API.

## Organization

Current files:

* Public headers: `ids.hpp`, `resolver.hpp`, `secure_messaging.hpp`, and
  `simulation_runner.hpp`.
* Mock crypto helpers: `chunking.hpp`, `mock_unikem.hpp`, and
  `mock_rkem.hpp`.
* Aggressive protocol models: `aggressive_unikem.hpp`,
  `agg_unikem_resolver.hpp`, `aggressive_rukem.hpp`, and
  `agg_rukem_resolver.hpp`.
* Opportunistic protocol models: `opportunistic_unikem.hpp`,
  `opp_unikem_resolver.hpp`, `opportunistic_rkem.hpp`,
  `opportunistic_rkem_usenix.hpp`, and
  `opportunistic_unikem_usenix.hpp`.
* `tools/agg_unikem_experiment.cpp`: command-line CSV generator.
* `tests/framework_tests.cpp`: standalone unit tests.

As the project grows, split tests by ownership:

```text
tests/resolver_tests.cpp
tests/secure_messaging_tests.cpp
tests/aggressive_unikem_tests.cpp
tests/mock_unikem_tests.cpp
```

Keep protocol-specific helpers next to the protocol. Agg-RUKEM uses its own
`AggRukemOutputPattern` because its resident secrets are updated DK versions
rather than Agg-UniKEM EK/CT0 subepochs.

## Protocol State Machines

Protocol implementations should prefer explicit state variants over a flat bag
of mutable fields. For Agg-UniKEM, the useful abstraction is the full role-level
state machine rather than independent EK/CT submachines:

```text
EK-sender role state: Init, SendFirstEkRecvFirstCt0, EkFrozenCtAwait, ...
CT-sender role state: Init, SendFirstCt0RecvFirstEk, Ct0FrozenEkAwait, ...
```

This is more verbose than the paper exposition, but it is easier to test and
much harder to put into an impossible mixed state. It also leaves a clearer path
to model extraction or formal verification: each transition can become a small
rule, race behavior is visible at the role level, and resident-secret reporting
can be checked as a pure function of the current variant.

The paper does not need to present the protocol this way. The implementation can
faithfully refine the prose protocol into state-machine transitions for audit
and testing.

## Agg-UniKEM Model

The Agg-UniKEM model alternates roles after every completed message epoch,
matching the Signal deployment strategy used for Opp-UniKEM-style protocols:

* in epoch 1, party A is the EK sender and CT0/CT1 receiver;
* in epoch 1, party B is the CT0/CT1 sender and EK receiver;
* after the EK side decodes CT1 it advances to the next epoch as the CT0/CT1
  sender;
* after the CT side sees a peer message for the next epoch it advances as the
  EK sender;
* the EK side may send multiple EK subepochs per message epoch;
* the CT side may send multiple CT0 subepochs per message epoch;
* the committed SCKA output is identified by `(message_epoch, ek_subepoch,
  ct0_subepoch)`.

The experiment runner records global message IDs, compromise snapshots, emitted
SCKA outputs, and raw VMS samples. Early compromise rows may expose future
messages because the resolver intentionally applies the paper model's "corrupt
now, read later" rule over the full transcript.

The histogram CSV matches the retired Rust chart input shape:

```text
num exposed,freq exposed by a,freq exposed by b,cumulative exposed by a,cumulative exposed by b
```

The stats CSV contains mean, standard deviation, min, deciles, and max for
Alice-compromise and Bob-compromise samples.

## Testing Expectations

Tests should be thorough and local. At minimum, every SCKA should have tests
for:

* key agreement and epoch agreement;
* output-key labels;
* sending/receiving epoch labels;
* resident-secret snapshots before and after acknowledgements;
* stale message handling;
* state deletion after commit or epoch advance.

The generic framework should have tests for:

* root key alone exposes no messages;
* SCKA output alone exposes no messages;
* root key plus SCKA output exposes both chains for that output epoch;
* derived root keys iterate into later outputs;
* chain keys expose only messages at or after their counter;
* exact message keys expose exactly one message;
* two compromise sets union and deduplicate;
* secure messaging records exact `MessageSecretId`s and deletes message keys
  after use.
