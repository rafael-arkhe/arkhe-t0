.PHONY: check test clean

check:
	cargo check --workspace

test:
	cargo test --workspace

clean:
	cargo clean
