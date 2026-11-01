# CHANGELOG — Proveniência e Versões Refutadas

Este documento regista a história evolutiva da formulação Arkhe, especificando hipóteses que foram formuladas, refutadas e corrigidas.

## v0.1 → v0.2 (AKG-META-0001)
- **Refutado**: `"verify_sigstore_bundle devolve Ok(true)"` — assinatura não verificada.
- **Refutado**: `"v.len() == 64 aceita qualquer digest"` — binding meramente decorativo.
- **Corrigido**: `sigstore-verify = "=0.7.0"` com teste de API pinada.
- **Estado**: execução PENDING.

## Arkhe-B Order Spec v0.1 → v0.2
- **Refutado**: `"canonicalidade Ed25519 exige S/A/R"` — faltavam verificações para small-order e cofactorless.
- **Corrigido**: Cinco verificações canónicas exigidas (S, A, R, small-order, cofactorless); falsificadores `small_order_A` e `torsion_component_R`.
- **Fonte**: RFC 8032; Rhizomatic.
