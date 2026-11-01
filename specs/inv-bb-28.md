# INV-BB-28: Invariantes Caixa-Preta (28 Invariants)

## 1. Escopo
Catálogo normativo dos 28 invariantes fundamentais de comportamento caixa-preta (Black-Box Invariants) que o ContainmentGate e os núcleos de execução Arkhe devem garantir.

## 2. Invariantes Fundamentais
Os invariantes cobrem:
- Preservação de não-ambiguidade causal.
- Imutabilidade da intenção registrada vs intenção despachada.
- Fail-closed sob falhas de rede, transiente ou timeout.
- Ausência de side-effects em caso de recusa.
- Verificação canónica estrita de tipos e representações binárias.

## 3. Estado de Verificação
- Classificação: `PENDING`.
