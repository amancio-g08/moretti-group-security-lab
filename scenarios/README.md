# scenarios/ — Cenários de ponta a ponta

**Português** | [English](README.en.md)

Cada cenário (`SCN-xx`) é um evento que eu provoco no laboratório e depois sigo por todas as
fontes onde ele deixa rastro: captura de tráfego, VPC Flow Logs, alertas do Wazuh, relatórios do
Python, ações de IAM e o relatório do incidente. O ID do cenário aparece no nome dos arquivos e nas
referências, então dá para acompanhar o mesmo evento pelo laboratório inteiro.

**Status:** os run books e as ferramentas de apoio estão prontos e testados offline; falta executar (checklist, seção G). Veja [documentation-note.md](documentation-note.md).

| ID | Cenário (rascunho) |
|---|---|
| SCN-01 | Tentativas de adivinhar senha a partir do GUEST01 contra máquinas do lab |
| SCN-02 | Tentativa de login com a conta de um funcionário desligado |
| SCN-03 | Alguém adicionado a um grupo privilegiado sem estar previsto |
| SCN-04 | Violação de segmentação: GUEST tentando chegar no FINANCE |
| SCN-05 | Alteração não autorizada de configuração na aplicação financeira |
| FP-01 | Atividade autorizada que gera alerta e vira exceção documentada |

Tudo que envolve ataque segue as regras de [docs/lab-safety.md](../docs/lab-safety.md).
