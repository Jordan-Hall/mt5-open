# Native challenge reference cases

`challenges-6182.tsv` contains 1,280 synthetic programs and outputs from the
build-6182 terminal calculator. It contains no account credentials, broker
challenge captures, terminal code or host metadata. Only the conformance test
reads the file; the runtime computes answers from each incoming program.

Coverage includes all 256 instruction selectors for both interpreters, 256
complete programs with mixed literal/accumulator operands and optional halts,
and all 256 footer operand selectors on each side of the tag-35 footer.
Generated arithmetic inputs cover overflow, shifts, division and remainder.
The complete private research corpus also compared 2,048 composed programs
per interpreter and 405 individual arithmetic cases per interpreter.

The last column is the terminal result, not the output of the Rust solver.
Version 3 means tag 35; version 4 means tag 28. Seeds and results are hexadecimal
u64 values. Programs are the exact little-endian input bytes.
