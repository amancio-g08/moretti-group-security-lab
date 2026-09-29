# Projeto 03 — SOC com Wazuh

**Português** | [English](README.en.md)

Centralização de logs, regras de detecção, triagem de alertas e resposta a incidentes. O Wazuh
roda no SIEM01 e recebe eventos dos agentes (DC01, WS-FIN01, WS-DEV01) e da AWS (CloudTrail e
Flow Logs).

**Status:** fase 6 com o código pronto e testado offline; ainda **não foi instalado** no lab. Os
alertas e incidentes reais entram na fase 7, com os cenários.

## O que eu quis mostrar

Regra de SIEM costuma ser genérica: "muitas falhas de login". Aqui as regras sabem quem é quem na
empresa. As listas de contas desligadas, afastadas, de serviço e de emergência são **geradas do
`data/`**. Se alguém é desligado no `employees.csv`, a lista muda e o Wazuh passa a alertar
qualquer uso daquela conta, sem ninguém editar regra.

As regras usam os mesmos nomes das detecções do `moretti-sec` (ACC-01, BF-01...), então um achado
no relatório em Python e um alerta no Wazuh contam a mesma história. Cada regra tem técnica do
MITRE ATT&CK e um playbook de triagem.

| Regra | Detecta |
|---|---|
| ACC-01 a ACC-06 | Conta de desligado, de afastado, conta expirada, break-glass, conta de serviço em login interativo, admin barrado pela GPO de tiering |
| BF-01 | Força bruta vinda da rede de visitantes (Windows e SSH) |
| NET-01 | Visitante tentando acessar a rede interna, barrado pelo Security Group (Flow Logs) |
| CT-01 a CT-03 | Mudança em Security Group, uso da conta root, auditoria desligada (CloudTrail) |

## Estrutura

```
project-03-soc/
├── wazuh/           # instalação do SIEM01 e publicação das regras (deploy-ruleset.sh)
├── agents/          # instaladores dos agentes (Linux; Windows com Sysmon) e configuração por grupo
├── detections/
│   ├── rules/       # regras próprias (IDs 100100-100199)
│   ├── lists/       # listas de contas geradas do data/, não editar
│   └── tests/       # eventos sintéticos e o script que testa as regras no SIEM01
├── tools/           # gerador das listas
└── documentation/   # desenho do SOC, playbooks e plano de validação
```

`alerts/` e `incidents/` aparecem na fase 7, com alertas e incidentes de verdade.

## Verificações

```bash
python3 project-03-soc/tools/render_wazuh_lists.py --check   # listas batem com o data/
pytest project-05-python/tests/test_wazuh.py                 # regras, listas e casos de teste
```

Elas conferem que os arquivos fazem sentido entre si. Se as regras disparam no Wazuh de verdade,
só o `run_logtest.py` no SIEM01 vai dizer ([checklist](../docs/operator-checklist.md), seção E).
Mais detalhes em [documentation/soc-design.md](documentation/soc-design.md).
