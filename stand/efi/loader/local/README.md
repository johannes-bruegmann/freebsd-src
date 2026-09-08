Platform trust gates -- the loader-side measurement/claim/gate/policy
engine behind a tamper-DETECTION boot chain: providers measure the
platform, claims weigh measurements against expectations, gates
aggregate claims, per-phase policies decide what fires. Detection, not
enforcement: findings are published to kenv (loader.trust.<gate>.<leaf>)
or handed to earlboot inside the handover word, never silently acted
upon.

Three phases (policy.h): BOOT before the boot medium is engaged, LOADER
before the interactive loader, KERNEL after the interactive window and
before ExitBootServices. What one phase saw is evidence for the next
(evidence.h, the ledger).

The catalogs (parsed by elebake from the headers here):

  measurement.h   providers: firmware state, key store, board, marker,
                  prerequisites, load origin (measurement.c); the EFI
                  image inventory, ACPI tables, non-volatile variables,
                  PCI devices (measure_platform.c); GELI metadata and
                  GPT digests (measure_disk.c); the sealed boot record
                  and its anchors -- TPM reset count, clock and NV
                  counter, NVMe power cycles, the chain link on the
                  medium -- plus PCR bank and hour window
                  (measure_record.c); boot duration, prompt dwell and
                  cadence, RTC-against-TSC, attempts (measure_time.c);
                  howto flags, guarded kenv, preload verification,
                  the soft PCR, the ledger (measure_kernel.c)
  action.h        the responses: publish/silence, report/message/display/
                  prompt/sentinel/record, confirm/lock/unlock/tarpit/
                  lockout/reveal/taint/expire/single/divert/nextboot/
                  handover, halt/panic/reboot/poweroff
  policy.h        the phases and the firing predicates (when_*)
  earlboot/tools.sh  the tools table: every external command the sh
                  catalogs run, one variable each ($KENV, $SYSCTL ...);
                  the emitter bakes it in as readonly constants, a test
                  run replaces it with mocks
  gate.h          GATE_DEFINE(id, secret, duress, claims...) -- two
                  compiled-in passphrase hashes per gate; the duress
                  one unlocks identically and marks the ledger

Internal (not catalogs): evidence.h (ledger), clock.h (RTC + TSC
stamps, calibrated at efi_main entry), record.h (encrypt-then-MAC
NVRAM record, chain file on the medium), tpm.h (TCG2 read-only client),
nvme.h (SMART log page via pass-through).

Every provider and action states in its header comment what it
ASSUMES of the threat model: which hardware must be present, what the
owner must carry, which physical protection (case seal, SPI write
protect) it relies on. A feature without its assumption is a feature
that misleads.

Two files here are GENERATED -- do not edit:

  foundation/foundation.c   the compiled decisions: baseline macro
                            blocks, prerequisites lists, GATE_DEFINEs,
                            per-phase policy tables, phase_policies().
                            The file in this tree is the EMPTY SHELL
                            (no gates, no policies) that keeps an
                            unprovisioned tree linking.
  site.mk                   this machine's baselines as -D flags
                            (site fingerprints, windows, partition
                            lists, secret slots -- not source)

Their compiler is elebake, part of the elvboot project:

  https://github.com/enk-ode/elvboot

Design documentation (catalogs, arsenal records, binding contract,
acceptance) lives there under docs/. New measurements, actions and
whens are born as patches here, reviewed as code.
