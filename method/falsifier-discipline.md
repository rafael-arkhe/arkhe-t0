# Falsifier Discipline (Disciplina de Falsificação)

A validade de qualquer reivindicação no ecossistema Arkhe é fundamentada no critério de falseabilidade de Popper:

1. **Requisito de Falsificador Mínimo**:
   - Um claim sem falsificador explícito não é admitido no T0.
   - Cada claim normativo deve estipular o teste exato, perturbação ou contra-exemplo que refutaria a formulação se o gate falhar em rejeitá-lo.

2. **Propriedades Falsificáveis Principais**:
   - `IntentBinding`: Alteração de qualquer campo estrutural (como `amount_cents` ou `recipient`) preservando digests/assinaturas antigas deve forçar rejeição imediata (`tampered_amount_rejected`).
   - `ContainmentGate Fail-Closed`: Quatro estados formais de validação onde qualquer ambiguidade, erro de parsing ou timeout culmina em recusa determinística.
   - `Ed25519 Canonicality`: Rejeição de pontos de ordem pequena (`small_order_A_rejected`) e componentes de torção (`torsion_component_R_rejected`).
