# Protocol provenance

The inherited repository included protocol notes and vectors derived from
analysis of a third-party trial implementation. This work has not established
the licence or redistribution rights for every inherited artifact. Removing
vendor names or dependencies does not resolve that question. Do not describe the
whole project as a clean-room implementation or as MetaQuotes-endorsed.

The current native runtime uses this repository's Rust codecs and direct broker
TCP. The former hosted login-value client has been removed. The build-6182 challenge interpreters were recovered and compared through local
inspection of the authorized terminal and generated calculator inputs. They use
ordinary Rust arithmetic; no captured executable code is distributed. Synthetic
reference inputs and outputs are included only in tests. Connection metadata,
raw captures and credential files remain outside version control. No third-party binaries or source packages were
downloaded or incorporated during the online research pass.

The research sources in [NATIVE_RESEARCH.md](NATIVE_RESEARCH.md) document behavior
and available approaches. Vendor descriptions are vendor claims, not independent
compatibility evidence or a grant of rights. An applicable licence review is still
needed before redistribution of inherited material whose origin is unresolved.
