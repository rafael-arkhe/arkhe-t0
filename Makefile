.PHONY: check test clean test-pipeline

check:
	cargo check --workspace

test:
	cargo test --workspace

test-pipeline:
	cargo run -p arkhe-test

clean:
	cargo clean
