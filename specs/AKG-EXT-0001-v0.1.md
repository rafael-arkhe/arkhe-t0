# AKG-EXT-0001 v0.1: Especificação de Extensões de Arquivos do Ecossistema Arkhe

## 1. Escopo e Propósito
Esta especificação estabelece os formatos normativos e extensões de arquivos em todas as camadas e módulos do ecossistema Arkhe AGI-P2P e ArkheOS Mobile: CBOR determinístico, CIDv1/BLAKE3, recibos AFiR, MMR selado, checkpoints híbridos, WASM, GGUF, contratos e artefatos de supply chain / auditoria.

## 2. Regra Geral de Formatos

- **Dados de protocolo:** `.cbor` — determinístico, compacto e compatível com MobileWER, recibos e checkpoints.
- **Documentação e configuração:** `.json` canônico (RFC 8785 / JCS) quando interoperabilidade web for necessária; `.toml` para configuração de build/nó.
- **Modelos:** `.gguf` como formato de referência para modelos locais, com chunks endereçados por CIDv1 (BLAKE3).
- **Auditoria:** `.arkbundle` como contêiner do `OfflineVerificationBundle`.
- **Código:** `.rs`, `.ts`, `.sol` ou equivalente, conforme o módulo.
- **Proibido:** `.dll`, `.exe` ou binários nativos não assinados como parte do protocolo; eles podem existir na distribuição apenas se atestados com proveniência e hash, mas não são formatos normativos do protocolo Arkhe.

---

## 3. Extensões por Camada / Categoria

### 3.1 Identidade e Conteúdo

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.cid` | `model.cid`, `chunk.cid` | Representação textual de CIDv1/BLAKE3 | Obrigatória |
| `.multihash` | `digest.multihash` | Hash autodescritivo | Opcional |
| `.pub` | `publisher.pub`, `device.pub` | Chave pública ML-DSA-65 ou Ed25519 | Obrigatória |
| `.sig` | `manifest.sig`, `checkpoint.sig` | Assinatura destacada | Obrigatória |
| `.cert` | `device.cert` | Certificado/atualização de identidade | Opcional |
| `.crl` | `revocation.crl` | Revogação de chaves/identidades | Recomendada |
| `.keystore` | `node.keystore` | Contêiner criptografado de chaves locais | Obrigatória em nó |
| `.seed` | `node.seed` | Material de identidade criptografado | Opcional; nunca plaintext |

*O Arkhe usa CIDv1 com multihash BLAKE3 para endereçar chunks e manifestos; a assinatura cobre os bytes canônicos completos da estrutura.*

### 3.2 Manifestos e Modelos

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.arkmanifest` | `model.arkmanifest` | Manifesto canônico CBOR do modelo | Obrigatória |
| `.arkmanifest.sig` | `model.arkmanifest.sig` | Assinatura ML-DSA do publisher | Obrigatória |
| `.gguf` | `model.gguf` | Modelo local de referência | Obrigatória para inference local |
| `.gguf.part` | `model.gguf.part0001` | Chunk de peso | Obrigatória na distribuição |
| `.gguf.index` | `model.gguf.index` | Índice de chunks/CIDs | Recomendada |
| `.quant` | `nvfp4.quant` | Perfil de quantização | Obrigatória se quantizado |
| `.lineage` | `training.lineage` | Cadeia de checkpoints de treinamento | Obrigatória para payment-grade |
| `.eval` | `evaluation.eval` | Registro de avaliação por checkpoint | Obrigatória no lineage |
| `.dataset` | `cohort.dataset` | Descritor de coorte/dataset | Obrigatória no lineage |
| `.tokenizer` | `tokenizer.json` | Tokenizador do modelo | Obrigatória para LLM |
| `.vocab` | `vocab.txt` | Vocabulário legado | Opcional |

*O manifesto deve conter identificador, arquitetura, lista ordenada de chunks com CIDv1, perfil de quantização, políticas e árvore de digest; qualquer nova versão cria novo manifesto/CIDs, nunca edita o antigo.*

### 3.3 Recibos e Evidência

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.afir` | `fragment.afir` | Recibo AFiR binário de 384 bytes | Obrigatória |
| `.afir.json` | `fragment.afir.json` | Representação JCS para debug/interop | Opcional |
| `.afirtree` | `session.afirtree` | Árvore Merkle de recibos MoE | Obrigatória para MoE |
| `.wer` | `session.wer` | MobileWER / registro testemunhal | Obrigatória |
| `.mmr` | `device.mmr` | Estado/peaks da Merkle Mountain Range | Obrigatória |
| `.mmrproof` | `inclusion.mmrproof` | Prova de inclusão | Obrigatória |
| `.consistency` | `history.consistency` | Prova de consistência entre roots | Obrigatória |
| `.checkpoint` | `device.checkpoint` | Checkpoint híbrido ML-DSA + Ed25519 | Obrigatória |
| `.attest` | `boot.attest` | Blob de Verified Boot/KeyMint | Obrigatória em mobile |
| `.arkbundle` | `audit.arkbundle` | Bundle offline completo | Obrigatória para auditoria |
| `.wasm` | `arkverify.wasm` | Verificador offline | Obrigatória |

*O recibo AFiR é um perfil binário de 384 bytes com ML-DSA-65; a serialização canônica usa RFC 8785 para JSON e CBOR determinístico para binário.*

### 3.4 Rede e Descoberta

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.peers` | `peers.dat` | PeerBook: endereços, buckets, tried/new | Obrigatória |
| `.peerledger` | `service.peerledger` | Serviço, receipts, latência, disponibilidade | Obrigatória |
| `.seeds` | `seeds.toml` | Seeds constitucionais e política de rotação | Obrigatória |
| `.dhtcache` | `dht.cache` | Cache de lookup/announce | Opcional |
| `.announce` | `chunk.announce` | Anúncio de chunk com token | Opcional |
| `.gossip` | `topic.gossip` | Configuração de tópicos GossipSub | Obrigatória |
| `.netpolicy` | `network.netpolicy` | Limites, classes de conexão, bandwidth | Obrigatória |
| `.pcap` | `debug.pcap` | Captura de rede apenas em diagnóstico | Opcional; nunca em produção |

*O PeerBook deve ser fail-closed: se não puder ser parseado, é reconstruído a partir de seeds, nunca confiável.*

### 3.5 Inferência e Execução

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.policy` | `inference.policy` | Política declarada da inferência | Obrigatória |
| `.policy.sig` | `inference.policy.sig` | Assinatura da política | Obrigatória |
| `.request` | `inference.request` | Pedido canônico/política-scoped | Obrigatória |
| `.response` | `inference.response` | Resposta + referência ao recibo | Obrigatória |
| `.session` | `inference.session` | Sessão com nonce, política e recibos | Obrigatória |
| `.router` | `moe.router` | Decisão de roteamento MoE | Obrigatória para MoE |
| `.expertmap` | `moe.expertmap` | Mapa de experts/shards | Obrigatória para MoE |
| `.kv` | `kvcache.bin` | Cache de atenção local | Opcional; nunca evidência |
| `.gpu` | `gpu.profile` | Capacidade, backend e limits | Obrigatória para worker GPU |
| `.onnx` | `model.onnx` | Modelo interoperável alternativo | Opcional |
| `.safetensors` | `model.safetensors` | Formato alternativo de pesos | Opcional |

*Recibos nunca devem conter prompt ou output em claro; apenas compromissos/hash.*

### 3.6 Verificação e Fraudes

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.fraudproof` | `receipt.fraudproof` | Prova de recibo inválido/fraudulento | Obrigatória |
| `.reexec` | `reexecution.reexec` | Resultado de re-execução amostral | Obrigatória no tier 1 |
| `.zkproof` | `fragment.zkproof` | Prova ZKML de amostra de alto valor | Opcional / tier 2 |
| `.teequote` | `attestation.teequote` | Quote TEE como acelerador | Opcional |
| `.verdict` | `adjudication.verdict` | Decisão assinada de disputa | Obrigatória |
| `.slash` | `slashing.slash` | Ordem de slashing vinculada a prova | Obrigatória |
| `.golden` | `vectors.golden` | Vetores de teste canônicos | Obrigatória em CI |

*O Arkhe prevê três tiers de verificação: assinatura/MMR, re-execução amostral e ZKML para sessões de alto valor.*

### 3.7 Economia e Governança

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.constitution` | `arkhe.constitution` | Constituição content-addressed | Obrigatória |
| `.constitution.sig` | `arkhe.constitution.sig` | Assinaturas de quorum | Obrigatória |
| `.proposal` | `upgrade.proposal` | Proposta de upgrade/mudança | Obrigatória |
| `.vote` | `quorum.vote` | Voto assinado do quorum | Obrigatória |
| `.canon` | `canonification.canon` | Ata de canonificação humana | Obrigatória |
| `.emission` | `emission.schedule` | Parâmetros de burn-and-mint | Obrigatória |
| `.reward` | `poi.reward` | Recompensa vinculada a receipt root | Obrigatória |
| `.stake` | `validator.stake` | Bond/estado de stake | Obrigatória |
| `.epoch` | `roles.epoch` | Conjuntos disjuntos worker/validator | Obrigatória |
| `.gini` | `emission.gini` | Métrica publicada de distribuição | Recomendada |

*A constituição é content-addressed, replicada pela CAL e só pode ser alterada por quorum qualificado mais canonificação humana.*

### 3.8 Integração com Chains (CAL)

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.anchor` | `checkpoint.anchor` | Ancoragem de root em chain | Opcional |
| `.ibc` | `cal.ibc` | Configuração/adapters IBC | Opcional |
| `.ccip` | `cal.ccip` | Adapter Chainlink CCIP | Opcional |
| `.layerzero` | `cal.layerzero` | Adapter LayerZero | Opcional |
| `.abi` | `ISettlement.abi` | Interface de contrato | Obrigatória se EVM |
| `.sol` | `ArkheSettlement.sol` | Contrato EVM | Opcional |
| `.move` | `arkhe.move` | Contrato Move/Sui | Opcional |
| `.tx` | `anchor.tx` | Transação de ancoragem | Opcional |
| `.receiptroot` | `settlement.receiptroot` | Root usado no settlement | Obrigatória para PoI |

*A CAL (Chain Abstraction Layer) expõe somente três primitivas: `anchor`, `reward` e `slash`; a evidência permanece válida independentemente da chain.*

### 3.9 Build, Testes e Supply Chain

| Extensão | Arquivo | Função | Obrigatoriedade |
|---|---|---|---|
| `.toml` | `Cargo.toml`, `arkhe.toml` | Configuração Rust/nó | Obrigatória |
| `.rs` | `*.rs` | Código Rust do núcleo | Obrigatória |
| `.ts` | `*.ts` | SDK TypeScript | Obrigatória para SDK |
| `.cs` | `*.cs` | Implementação C#, se adotada | Opcional |
| `.csproj` | `Arkhe.csproj` | Projeto C# | Opcional |
| `.wasm` | `arkverify.wasm` | Verificador portátil | Obrigatória |
| `.wat` | `arkverify.wat` | Representação textual WASM | Opcional |
| `.json` | `package.json`, `tsconfig.json` | Configuração SDK | Obrigatória para SDK |
| `.lock` | `Cargo.lock`, `package-lock.json` | Pinning de dependências | Obrigatória |
| `.sbom` | `release.sbom` | Inventário de componentes | Obrigatória |
| `.provenance` | `build.provenance` | Proveniência SLSA da build | Obrigatória |
| `.sha256` | `artifact.sha256` | Hash de artefatos | Obrigatória |
| `.sigstore` | `artifact.sigstore` | Assinatura/proveniência de release | Recomendada |
| `.log` | `node.log` | Log operacional | Opcional |
| `.trace` | `consensus.trace` | Rastro de consenso/testnet | Obrigatória em F5 |

*O roadmap exige builds herméticas, proveniência atestada, vetores dourados e artefatos de testnet content-addressed.*

---

## 4. Extensões Proibidas ou Restritas (Fail-Closed)

| Extensão | Status | Motivo |
|---|---|---|
| `.dll` | Restrita | Binário nativo; só com hash, assinatura e proveniência |
| `.exe` | Restrita | Distribuição, não formato de protocolo |
| `.so` / `.dylib` | Restritas | Mesma regra de binário nativo |
| `.pem` sem criptografia | Proibida | Chaves privadas não devem ficar em texto claro |
| `.env` em produção | Proibida | Segredos não devem viver em arquivo simples |
| `.bak` de MMR/checkpoint | Proibida | Pode criar histórico paralelo e quebrar append-only |
| `.tmp` de recibos | Restrita | Deve ser atomicamente renomeado ou descartado |
| `.dump` com payload | Proibida | Pode vazar prompts/saídas |

---

## 5. Manifesto Mínimo de Release

Uma release Arkhe canônica e auditável deve incluir os seguintes artefatos:

```text
arkhe-node
arkhe-node.sha256
arkhe-node.provenance
arkhe-node.sbom
arkhe-node.sigstore
arkhe.toml
seeds.toml
network.netpolicy
arkhe.constitution
arkhe.constitution.sig
arkverify.wasm
vectors.golden
```

---

## 6. Procedimento de Auditoria e Conformidade

1. **Formato normativo:** verificar se recibos, checkpoints e manifestos usam CBOR determinístico e RFC 8785 (JCS) quando serializados em JSON.
2. **Integridade:** todo `.gguf.part`, `.afir`, `.checkpoint` e `.arkbundle` deve possuir digest CIDv1/BLAKE3 verificável.
3. **Privacidade:** garantir que `.afir`, `.wer`, `.mmr` e logs nunca contenham prompt ou output em claro.
4. **Governança:** `.constitution`, `.proposal`, `.vote` e `.canon` devem formar cadeia criptograficamente assinada e reproduzível.
5. **Supply chain:** `.sbom`, `.provenance`, `.sha256` e `.sigstore` devem cobrir todos os binários distribuídos e dependências.
6. **Fail-closed:** qualquer arquivo corrompido, não assinado, de extensão proibida ou com hash divergente deve abortar a execução imediatamente.

---

## 7. Estado de Verificação
- Classificação: `LEMMA` (especificação estrutural e formal normatizada com validação em `arkhe-core`).
