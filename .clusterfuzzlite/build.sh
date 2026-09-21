#!/bin/bash -eu
# The fuzz target imports from dist/, so the TypeScript has to be compiled
# before the target is packaged - not after, and not by the target itself.
npm ci
npm run build
compile_javascript_fuzzer webhook-rewind fuzz/parse.fuzz.js --sync
# Three real seeds: a recorded event line, a Stripe signature header and a
# JSON body. Starting
# from valid input finds the interesting cases far sooner than starting from
# random bytes.
zip -j "$OUT/parse.fuzz_seed_corpus.zip" fuzz/seeds/*
