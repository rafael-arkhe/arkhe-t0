# Arkhe-B Order Spec v0.2: Canonicality & Field Order

## 1. Escopo
Especificação da ordenação de mensagens e canonização criptográfica de ordens e intenções financeiras/executivas.

## 2. Canonicalidade Ed25519
Conforme RFC 8032 e extensões de contenção rigorosa, a canonicalidade total de assinaturas e chaves Ed25519 exige 5 verificações indispensáveis:
1. Verificação canónica do escalar $S < L$.
2. Verificação canónica da codificação do ponto $A$.
3. Verificação canónica da codificação do ponto $R$.
4. Rejeição estrita de pontos de ordem pequena (small-order check).
5. Verificação livre de cofatores (cofactorless verification / torsão nula).

Falsificadores associados: `small_order_A_rejected`, `torsion_component_R_rejected`.

## 3. Estado de Verificação
- Classificação: `PENDING`.
