Platform trust gates -- the loader-side measurement/claim/gate/policy
engine behind a tamper-DETECTION boot chain: providers measure the
platform (Secure Boot state, key store, board identity, boot marker,
prerequisites, load origin), claims weigh measurements against
expectations, gates aggregate claims, per-phase policies decide what
fires (publish/unlock/...). Detection, not enforcement: findings are
published to kenv (loader.trust.<gate>.<leaf>), never silently acted
upon.

Two files here are GENERATED -- do not edit:

  foundation/foundation.c   the compiled decisions: baseline macro
                            blocks, prerequisites lists, GATE_DEFINEs,
                            per-phase policy tables, phase_policies()
  site.mk                   this machine's baselines as -D flags
                            (site fingerprints, not source)

Their compiler is elebake, part of the elvboot project:

  https://github.com/enk-ode/elvboot

Design documentation (catalogs, arsenal records, binding contract,
acceptance) lives there under docs/. The catalogs elebake offers are
parsed from the headers in THIS directory -- new measurements, actions
and whens are born as patches here, reviewed as code.
