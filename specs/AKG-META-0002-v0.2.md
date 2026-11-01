# AKG-META-0002 v0.2: Provenance and Attestation

## 1. Escopo
Especificação da cadeia de proveniência Rekor, atestações Sigstore e amarração de bundles aos binários executáveis WASM.

## 2. Assinatura e Rekor
A assinatura isolada não comprova integridade causal. A verificação exige:
- Validação offline do bundle Sigstore contra o TrustedRoot local.
- Confirmação de inclusão no log Rekor amarrado explicitamente ao hash SHA-256 do binário.

## 3. Estado de Verificação
- Classificação: `PENDING`.
