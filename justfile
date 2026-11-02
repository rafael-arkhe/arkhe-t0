default: check test

check:
    cargo check --workspace

test:
    cargo test --workspace

test-pipeline:
    cargo run -p arkhe-test
