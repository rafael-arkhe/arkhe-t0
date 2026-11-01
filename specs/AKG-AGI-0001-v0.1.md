# AKG-AGI-0001 v0.1: AGI-P2P 4-Layer Verification Stack

## 1. Escopo e Propósito
Esta especificação descreve a pilha de verificação em profundidade do ecossistema AGI-P2P, articulando as camadas de distribuição de pesos, proveniência de inferência, evidência local móvel e governança coletiva de agentes autônomos.

## 2. Camadas do Stack (L1–L4)

### L1 — Distribuição e Consenso
- **OmniNode**: Endereçamento de pesos de modelo por conteúdo via `BLAKE3 -> CIDv1` e chunking por *transformer block*. Permite verificação de integridade dos pesos recebidos por nós P2P.
- **Hyperspace**: Consenso de liquidação (Mysticeti DAG) e canais de streaming de pagamento para inferências distribuídas.
- **Petals Adapter**: Fallback em enxame para modelos fracionados em camadas por nó heterogêneo.

### L2 — Proveniência da Inferência
- **IETF SPICE**: Merkle Tree append-only registrando `inference_root`.
- **AFiR**: Perfil pós-quântico TEE-free leve (0.785 ms overhead, 384 bytes, assinado com ML-DSA-65).
- **ZKML / TEE**: Verificação matemática de alto custo ou aceleração em enclave seguro.

### L3 — Evidência Local e Consistência Histórica (ArkheOS Mobile)
- **MobileWER**: Registro estruturado vinculando `inference_root` (L2), `model_weights_hash` (L1), digests de input/output e medição da aplicação.
- **MMR Selado**: Armazenamento append-only ancorado pelo Titan M2 / StrongBox.
- **OfflineVerificationBundle**: Verificação offline pontual e histórica sem dependência de servidores centrais.

### L4 — Governança e Incentivos
- **OpenCLAW-P2P**: BFT para consenso sobre resultados e propostas de auto-melhoria de agentes.
- **A.N.N. Spec**: Especificação formal de ausência de autoridade central de pesos.

## 3. Estado de Verificação
- Classificação: `CONJECTURE` (arquitetura global integrada) / `LEMMA` (premissas isoladas comprovadas) / `PENDING` (execução end-to-end ArkheOS Mobile).
