# Arkhe-B Test Suite Specification v0.2

## 1. Escopo
Definição dos requisitos mínimos para a suíte de testes de contenção, testes de falsificação e vetores adversariais.

## 2. Requisitos de Falsificadores
- Falsificador `tampered_amount_rejected`: mutação deliberada do campo `amount_cents` deve rejeitar mesmo com digests correspondentes a estados intermediários.
- Falsificadores criptográficos de chaves malformadas e maleabilidade de assinatura.

## 3. Estado de Verificação
- Classificação: `PENDING`.
