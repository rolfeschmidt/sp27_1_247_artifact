# Agg-RUKEM Protocol Notes

This note describes the Agg-RUKEM model implemented in
`include/aggressive_rukem.hpp`.  It is based on the prose in
`Input_Section/SCKA.tex` and on the commented `fig:aggrukem` pseudocode in that
file.

The model is an SCKA protocol.  It does not implement concrete lattice
cryptography.  Instead, it uses `MockRkem` to model the protocol-relevant facts:
fresh keypairs, ciphertexts, emitted shared secrets, and key updates.

## High-Level Idea

Opp-RKEM is a ping-pong protocol: after Alice samples and sends a key, Bob is
expected to perform the next key-sampling step, and the parties alternate.
Agg-RUKEM relaxes that strict turn-taking.  Both parties may continuously sample
and send fresh encapsulation keys.  Whichever party finishes sending a fresh key
first gets to encapsulate next, subject to a simple rule that only one
ciphertext may be in flight at a time.

The RUKEM primitive differs from RKEM in the key update performed by each
ciphertext:

* `ruenc_P(dk_P, ek_Q)` updates the sender's decapsulation key `dk_P`;
* it also updates the peer encapsulation key `ek_Q` as seen by the sender;
* `rudec_Q(dk_Q, ek_P, ct_P)` performs the matching update on the receiver's
  decapsulation key `dk_Q` and the sender's encapsulation key `ek_P`.

That second update is the important Agg-RUKEM feature.  In Agg-RKEM, if Alice is
much faster and repeatedly sends fresh keys, Bob's old decapsulation key may
need to stay live for many ciphertexts.  In Agg-RUKEM, every ciphertext advances
Bob's key state, so Bob does not keep using the same vulnerable DK version
forever.

## Local State

Each party stores:

* a current local decapsulation key `old_dk`;
* the peer's current encapsulation key `old_ek`;
* optionally, one fresh local keypair currently being sent;
* optionally, one peer key currently being decoded;
* optionally, one ciphertext currently being sent;
* chunk decoders for the peer's EK and CT streams;
* counters for the global message epoch and for each party's key epoch;
* ACK/permission flags controlling when a ciphertext may be sent.

The C++ implementation represents resident protocol secrets as
`AggRukemOutputPattern`.  A pattern names a party, a key epoch, and an update
number.  When resolving VMS samples, that pattern matches any emitted SCKA
output that used the compromised key version or a later update of that same key.

## Message Shape

Every application message carries at most one protocol chunk:

```text
AggRukemMessage {
    chunk_type: none | EK | CT
    chunk: optional chunk
    epoch: current global SCKA epoch
    sender_key_epoch: sender's current key epoch
    receiver_key_epoch: sender's view of receiver's key epoch
    ack_receiver_ek: sender has completed receiver's EK
    permit_receiver_ct: receiver may send its CT
}
```

`ack_receiver_ek` tells the peer that its EK was received.  `permit_receiver_ct`
is the extra coordination bit used to preserve a linear epoch order: even if
both parties finish EKs around the same time, only one party should start
sending a ciphertext.

## Send Logic

On each application send, a party performs these steps:

1. If no unacknowledged local EK is active and the peer's update bound has not
   been exhausted, sample a fresh keypair and begin sending its EK chunks.
2. If a local EK is active and has not been acknowledged, send the next EK
   chunk.
3. Otherwise, if the local EK has been acknowledged and the peer has granted CT
   permission, compute a RUKEM ciphertext if needed and send the next CT chunk.
4. Piggyback the current ACK and CT-permission flags.

The implementation currently uses `k = 6` as the maximum number of RUKEM updates
against one peer key, matching the Level 3 value discussed in the paper draft.

## Receive Logic

On receive:

1. If the message says the peer has advanced past one of our key epochs, clear
   the local EK/CT send state for the acknowledged epoch and move to the next
   local key epoch.
2. If an EK chunk for the current peer key epoch arrives, add it to the EK
   decoder.  Once complete, store the peer EK and set `ack_peer_ek`.
3. If a CT chunk for the current peer key epoch arrives, add it to the CT
   decoder.  Once complete, decapsulate using the current local DK and the
   completed peer EK.
4. Decapsulation emits the current SCKA epoch, updates the local DK, updates the
   stored peer EK, clears the peer EK/CT receive state, and advances the global
   epoch.
5. Process any ACK and CT-permission bits the peer included for our current key
   epoch.

The send side emits an SCKA output when it computes the ciphertext.  The receive
side emits the matching output when it finishes decoding and decapsulating that
ciphertext.  The secure-messaging wrapper installs the output before deriving
message keys for the application message that carried it.

## CT Permission And Tie-Breaking

Most of the time, both parties are sending EK chunks in parallel.  When one
party completes the other's EK, it can allow the other party to send a CT if
doing so cannot conflict with its own CT send.

The implemented permission rule is:

* grant permission if the peer EK is complete;
* do not grant permission if this party is already preparing/sending its own CT;
* otherwise grant permission if this party has not yet sent enough EK chunks for
  the peer to complete its EK;
* if both sides could finish together, break ties by epoch parity.

The parity rule follows the commented LaTeX pseudocode: Alice has priority in
odd epochs, Bob in even epochs.  In the code this is expressed by granting CT
permission to the peer only when the tie-break goes to the peer.

## Fast-Alice Scenario

Suppose Alice sends application messages much more frequently than Bob.  For
concreteness, assume an EK needs 42 chunks and a CT needs 3 chunks, as in the
C++ simulator.

Initial state:

```text
Alice stores: dk_A^0, ek_B^0
Bob stores:   dk_B^0, ek_A^0
epoch = 1
```

Both parties start streaming fresh EKs:

```text
Alice sends chunks of ek_A^1
Bob sends chunks of ek_B^1
```

Because Alice is faster, Bob receives all 42 chunks of `ek_A^1` before Alice
has received all 42 chunks of `ek_B^1`.  Bob then acknowledges Alice's EK and,
if the ordering rule permits it, tells Alice she may send a CT.

Alice now computes:

```text
(dk_A^1, ek_B^1, ct_A^1, K_1) = ruenc_A(dk_A^0, ek_B^0)
```

The important point is that this updates Alice's own DK and Alice's view of
Bob's EK.  Alice sends the 3 chunks of `ct_A^1`.  Bob decapsulates:

```text
(dk_B^1, ek_A^1, K_1) = rudec_B(dk_B^0, ek_A^1, ct_A^1)
```

Now both sides have emitted `K_1`, and Bob's DK has advanced from `dk_B^0` to
`dk_B^1`.

If Alice is still much faster, she may again finish sending the next EK before
Bob finishes his next EK:

```text
Alice sends ek_A^2 quickly
Bob is still slowly sending ek_B^1 or ek_B^2
```

Once Bob receives `ek_A^2` and permits the CT, Alice encapsulates again, but not
to Bob's original key.  She uses her updated view of Bob's key:

```text
(dk_A^2, ek_B^2, ct_A^2, K_2) = ruenc_A(dk_A^1, ek_B^1)
```

Bob decapsulates with his updated DK:

```text
(dk_B^2, ek_A^2, K_2) = rudec_B(dk_B^1, ek_A^2, ct_A^2)
```

After several fast-Alice rounds, the pattern is:

```text
K_1 uses Alice key (A, 1, 0) and Bob key (B, 0, 1)
K_2 uses Alice key (A, 2, 0) and Bob key (B, 0, 2)
K_3 uses Alice key (A, 3, 0) and Bob key (B, 0, 3)
...
```

In words, Alice keeps sampling fresh local keys, while Bob's local key is
updated once per Alice ciphertext.  This is the behavior Agg-RKEM lacks: in
Agg-RKEM, Bob may need to keep the same old DK live across several ciphertexts;
in Agg-RUKEM, Bob's DK version advances with each ciphertext.

The simulator's compromise accounting follows that structure.  If Bob is
compromised after the third Alice ciphertext, his state contains Bob key
`(B, 0, 3)`.  That compromise does not retroactively reveal outputs that only
used `(B, 0, 1)` or `(B, 0, 2)`.  It does reveal outputs that use `(B, 0, 3)` or
later updates of that same key, because RUKEM updates are forward-secure but do
not heal a key once the current version has leaked.

## Current Modeling Limits

This is still a simulator model, not a final cryptographic specification.
Important limits:

* the concrete RUKEM primitive is mocked;
* the update bound is fixed at `k = 6`;
* the runner currently delivers messages immediately and in order;
* stale/future protocol chunks are tolerated rather than modeled as explicit
  network errors;
* the protocol description follows the draft/commented LaTeX pseudocode and may
  need adjustment if the paper's final SCKA algorithm changes.
