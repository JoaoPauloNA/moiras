# Moiras

**Quando um agente parece parado ou pede autoridade, qual evidência deve
chegar ao humano — e o que precisa continuar mecanicamente bloqueado?**

Moiras é um laboratório independente de supervisão de execução agêntica em
modo sombra. Ele transforma snapshots allowlisted do ciclo de vida, uma ação
categórica e pareceres injetados de um conselho em uma recomendação inerte.
Também oferece um broker inteiramente sintético, evidência sanitizada para
pesquisa e um gate offline de cenários.

Moiras não executa, autoriza, repete, cancela, digita confirmação, fornece
credencial nem chama modelos. Toda decisão permanece `executed=false` e
`mode=shadow`.

[English](README.md)

## Por que existe

Um timeout absoluto não diferencia processo morto, trabalho lento válido, CLI
aguardando aprovação ou dependência externa. Ao mesmo tempo, permitir que outro
modelo aprove ações silenciosamente cria um novo problema de autoridade. A
Moiras separa essas responsabilidades:

- a Sentinela classifica evidência temporal, mas nunca cancela;
- pisos determinísticos impedem que o conselho reduza um hard stop por média;
- quatro papéis exigem modelos declarados capazes/frontier;
- recomendação não vira rótulo verdadeiro; apenas revisão humana posterior
  pode alimentar métricas;
- registros usam categorias e contadores, nunca o conteúdo do trabalho.

Os valores da política são hipóteses de pesquisa codificadas em regras
testáveis. Não são certificação de segurança nem benchmark validado.

## Protocolo

```text
Par de snapshots ───────> Sentinela ─────────────────┐
Ação categórica ────────> risco determinístico ─────┼─> ShadowReport
Pareceres injetados ────> conselho conservador ─────┘   executed=false

Relatório ──> recomendação sanitizada ──> rótulo posterior HUMAN_REVIEW
Candidato ──> capability sintética ─────> somente status, sem autoridade
```

O conselho exige segurança, integridade, governança e operações. Qualquer
parecer `EDGE` ou `UNKNOWN` invalida o painel. Veto e divergência excessiva
exigem humano. Nota 10 e hard stops encerram a deliberação e param para decisão
humana.

Os detalhes estão no [protocolo](docs/protocol.md) e no
[modelo de ameaças](docs/threat-model.md).

## Instalação local

Python 3.10 ou superior; nenhuma dependência de runtime fora da biblioteca
padrão.

```bash
python -m pip install -e ".[dev]"
```

Esse comando instala o checkout-fonte atual. A versão 0.1.1 é publicada como
tag de código-fonte; isso não implica pacote no PyPI nem suporte de produção.

## Validação reproduzível

```bash
ruff check .
pytest
python -m moiras
python -m moiras --json /tmp/moiras-gate.json
```

O gate cobre 12 cenários sintéticos: progresso, inatividade provável, esperas,
três hard stops, ação baixa descartável, ambiente não descartável, modelo de
borda, veto e divergência. O JSON contém apenas versão genérica de
plataforma/Python, nomes dos cenários e contagens. O caminho de saída não entra
no artefato.

Snapshot de validação registrado em 2026-08-15: 380 testes passaram no checkout
0.1.1 revisado, e o gate offline fixo passou 12/12. A contagem é uma propriedade
datada desse checkout, não uma promessa permanente de tamanho ou cobertura da
suíte. Execute novamente os comandos acima na revisão exata sob avaliação.

A proteção contra regressão inclui um guardião AST para superfícies não
aprovadas de processo, rede, código dinâmico, reflexão e filesystem, além de um
audit hook isolado sobre o caminho puro do gate, supervisor e broker sintético.
O gate rejeita uma sequência vazia e exige `executed=false` e `mode=shadow`.
Esses guardas detectam regressões específicas; não são verificação formal nem
certificação de segurança.

## Escopo M0–M9

| Marco | Escopo implementado |
| --- | --- |
| M0–M1 | fronteira, contratos imutáveis e sanitização fail-closed |
| M2 | risco determinístico e hard stops |
| M3 | Sentinela temporal com dois snapshots |
| M4–M5 | conselho capable-only e agregação conservadora |
| M6 | broker sintético em memória, uso único e TTL curto |
| M7 | supervisor sombra e contrafactual categórico |
| M8 | JSONL em três níveis e métricas somente com rótulo humano |
| M9 | harness offline, CLI e definições de CI |

## Limites honestos

- Não é motor de execução, cofre de credenciais, serviço de autorização,
  sandbox ou roteador de modelos.
- Não há código de integração Athena neste repositório. O Athena expõe um
  [observador separado, opcional e desativado por padrão](https://github.com/JoaoPauloNA/athena),
  preservando a Moiras como consultiva e fail-closed.
- Não está pronto para produção ou multi-tenant. Locks e broker são locais ao
  processo; JSONL não é ledger multiprocesso.
- Não há resultados de modelos reais. Advisory não é ground truth e não há
  alegação de benchmark ou paper.
- A Sentinela não prova que um agente está vivo ou morto; apenas classifica a
  diferença entre dois snapshots permitidos.
- O sanitizador não é detector universal de PII, DLP ou segredos. Ele é defesa
  em profundidade para registros tipados e allowlisted e formas sensíveis
  conhecidas; conteúdo arbitrário do trabalho deve permanecer fora dos
  contratos desde a origem.

## Licença

MIT — consulte [LICENSE](LICENSE).
