# Arkhe T0 — 2026-10-31

Este repositório congela, com data e assinatura verificável, a formulação
específica do método Arkhe: τ classification, T0 discipline, IntentBinding
campo-a-campo, ContainmentGate fail-closed com quatro estados, e o conjunto
de invariantes INV-BB-*.

## O que este T0 afirma
- A formulação específica descrita em `specs/` e `method/` existia nesta data.
- Os claims em `T0.json` são os que o autor considera atribuíveis.
- O método é falsificável: cada claim tem um falsificador quando aplicável.

## O que este T0 NÃO afirma
- Não afirma prioridade sobre a ideia de "verificação de execução de IA".
- Não afirma que o Arkhe está implementado ou que os testes correram.
- Não afirma que outros não chegaram a formulações semelhantes.
- Não substitui patente, trademark, ou proteção legal.

## Como verificar
1. `sha256sum` de cada ficheiro contra `T0.json` executando `./verify_t0.sh`.
2. `cosign verify-blob` contra `T0.json.bundle`.
3. `git verify-commit` do commit assinado.

## Procedimento de comparação com reivindicações posteriores
Quando alguém publicar algo parecido, a comparação é **campo a campo**, não por impressão. É o `IntentBinding` aplicado à autoria.

| Campo | T0 (data) | Reivindicação (data) | Match? |
|:---|:---|:---|:---|
| Operação (o que é proposto) | `IntentBinding` com serialização canónica + campo a campo | "ligar intenção a execução" | Parcial — falta o mecanismo |
| Âmbito (a que se aplica) | Gate de execução de IA | Gate de execução de IA | Sim |
| Evidência (o que sustenta) | Falsificador `tampered_amount_rejected` | Nenhum falsificador | Não |
| Data | 2026-10-31 | Data da reivindicação | T0 anterior |

A resposta pública não é "copiaram". É: "a formulação em T0.json §claims cobre X, Y, Z com falsificadores F1, F2; a reivindicação cobre X sem Y nem F1. A prioridade sobre a formulação específica é de T0; a ideia geral é de todos."

## Procedimento de emenda — T1
T0 é imutável. Qualquer alteração — execução de testes, correção de um erro, extensão do conjunto — exige **T1**: novo commit, novo `T0.json`, nova assinatura, nova data. O T0 antigo **permanece público**. A cadeia `T0 → T1 → T2` é a memória viva, e cada elo referencia o hash do anterior (`record_hash` chaining aplicado à proveniência).
