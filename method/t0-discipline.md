# T0 Discipline (Disciplina de Congelamento)

A disciplina T0 rege a criação, proveniência e imutabilidade dos pacotes de congelamento:

1. **Escopo Normativo vs Descritivo**:
   - `normative`: Especificações (`specs/`), critérios formais (`criteria/`), método (`method/`).
   - `descriptive`: Proveniência e contexto (`CHANGELOG.md`, `golden_vectors/`, `README.md`, `non-claims.md`, `verify_t0.sh`).
   - `excluded`: Implementações executáveis e execuções empíricas.

2. **Integridade Determinística**:
   - Hashes SHA-256 brutos dos ficheiros, ordenação lexicográfica estrita dos caminhos.
   - O próprio manifesto `T0.json` e a sua assinatura são excluídos do cálculo interno de hashes.

3. **Imutabilidade e Chaining T0 → T1**:
   - Uma vez assinado e publicado, o pacote T0 é imutável.
   - Qualquer correção ou transição de `PENDING` para `LEMMA` exige a emissão de um pacote subsequente (T1), preservando T0 integralmente público e encadeando o hash do registo anterior.
