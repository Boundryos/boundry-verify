"""Pipeline stages.

Each stage is a pure function over the prior stage's output plus any
substrate-facing abstractions it requires. Stages may emit audit
envelopes; only the orchestrator wires them together.
"""
