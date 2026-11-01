# AKG-MOB-0001 v0.1: ArkheOS Mobile Local Evidence Specification

## 1. Escopo e Propósito
Esta especificação define o arcabouço de evidência local do ArkheOS Mobile, composto pelo `MobileWER` (Work Evidence Record), o acumulador Merkle Mountain Range (MMR) append-only selado por hardware seguro (Titan M2 / StrongBox), o binding determinístico de atestação e o pacote de verificação offline (`OfflineVerificationBundle`).

## 2. Estrutura Canónica do MobileWER
O `MobileWER` registra deterministicamente cada ação ou inferência de agentes no dispositivo, utilizando o domínio canônico `AKG:MOBILE:ACT:v1\0`:

```rust
pub struct MobileWER {
    pub version: u8,
    pub device_attestation_hash: [u8; 32], // H(attestation_blob || first_wer_nonce || app_measurement)
    pub app_id: [u8; 32],
    pub action: MobileAction,
    pub input_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub performed_at: u64,
    pub evidence_refs: Vec<[u8; 32]>,
}
```

### 2.1 Ações Suportadas (`MobileAction`)
- `Inference`: Execução de inferência neural local (NPU) ou remota com digest de pesos e proveniência.
- `ToolInvocation`: Disparo de chamadas a ferramentas de sistema, sensores ou barramentos de comunicação.
- `PolicyEvaluation`: Avaliação de políticas de contenção e permissão.
- `StateTransition`: Atualização do estado do agente ou transição de ciclo de vida.

## 3. Binding Criptográfico de Hardware
O binding de hardware ancora a ação ao elemento seguro Titan M2 / StrongBox:
1. `attestation_blob`: Certificado emitido pelo KeyMint/StrongBox atestando o estado do Verified Boot (`verifiedBootState = VERIFIED`), chaves e versão do sistema operacional.
2. `first_wer_nonce`: Nonce estritamente monotonicamente crescente ou aleatório de 256 bits emitido pelo StrongBox por sessão de boot, prevenindo replay inter-sessões.
3. `app_measurement`: Hash canônico BLAKE3 do executável APK/APEX verificado e assinado.

O campo `device_attestation_hash` é computado como:
$$\text{device\_attestation\_hash} = \text{BLAKE3}(\text{attestation\_blob} \parallel \text{first\_wer_nonce} \parallel \text{app\_measurement})$$

## 4. MMR Local Selado e Checkpoint Híbrido Distribuído
- **Append-Only Invariant**: Folhas inseridas no MMR não podem ser removidas ou modificadas retroativamente.
- **Envelope de Assinatura Híbrida**: O StrongBox do Pixel e Android 17 suporta ML-DSA (FIPS 204), mas não suporta Ed25519 em hardware seguro (TEE-only). Por conseguinte, o checkpoint agrega:
  - Assinatura ML-DSA-65 executada no StrongBox.
  - Assinatura Ed25519 executada no TEE / software.
  - Raiz canônica dos picos do MMR (bagged peak root).

## 5. OfflineVerificationBundle
O pacote auto-contido permite a auditabilidade sem rede por parte de reguladores ou pares:
- Registro `MobileWER`.
- Prova de inclusão de folha no MMR.
- Envelope de checkpoint assinado.
- Blob de atestação do hardware e nonce de boot.
- Prova de consistência histórica entre checkpoints sucessivos.

## 6. Estado de Verificação
- Classificação: `PENDING` (aguarda implementação executável e falsificadores de contenção).
