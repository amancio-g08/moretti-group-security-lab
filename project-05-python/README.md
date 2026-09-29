# Projeto 05 — Automação de segurança (Python)

**Português** | [English](README.en.md)

O `moretti-sec` é uma ferramenta de linha de comando que faz o trabalho repetitivo de um analista:
lê logs de autenticação, cruza cada evento com os dados da empresa em `data/` e gera um relatório
em Markdown com o que precisa de atenção.

O que me interessava aqui não era só contar falhas de login. Um alerta dizendo "6 falhas do
10.10.50.10" obriga o analista a descobrir sozinho de quem é aquele IP e daquela conta. Com o
enriquecimento, o relatório já diz que o IP é o **WS-DEV01, do Desenvolvimento**, e que a conta é
de um **terceiro** ou de um funcionário **desligado**, com base na fonte da verdade do laboratório
(ADR-001).

**Status:** fase 3 concluída (núcleo). Novos leitores de log entram nas fases 6 (Wazuh) e 7
(cenários e PCAP).

## Como funciona

```
logs (sshd do Linux, eventos 4624/4625 do Windows)
  → parsers          → evento padronizado (hora, host, usuário, IP, resultado)
  → enriquecimento   → IP vira ativo + segmento; usuário vira funcionário, status, tipo de conta
  → detecções        → força bruta e uso indevido de contas
  → timeline + relatório em Markdown
```

## Detecções

| Regra | O que detecta | Severidade |
|---|---|---|
| BF-01 | Força bruta: N falhas do mesmo IP dentro da janela (padrão: 5 em 10 min) | média (1 conta) / alta (várias) |
| BF-02 | Força bruta seguida de login com sucesso do mesmo IP | crítica |
| ACC-01 | Login com conta de funcionário desligado | crítica (sucesso) / média (falha) |
| ACC-02 | Login de funcionário afastado | média |
| ACC-03 | Login de terceiro depois do fim do contrato | alta |
| ACC-04 | Uso da conta de emergência (break-glass) | crítica |
| ACC-05 | Login interativo com conta de serviço | alta |
| ACC-06 | Conta administrativa usada fora do JUMP01 (regra NM-032) | alta |

## Como usar

```bash
cd project-05-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# relatório a partir dos logs de exemplo
moretti-sec analyze examples/logs/* --year 2026 --report relatorio.md

# extrair IOCs de um texto (aceita indicadores "defanged", como hxxp e [.])
moretti-sec ioc chamado.txt
```

O relatório gerado com os logs de exemplo está em
[`examples/reports/sample-auth-report.md`](examples/reports/sample-auth-report.md).

### Exportar os logs do Windows

O parser do Windows lê JSON com os campos do próprio evento. No controlador de domínio, em
PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 5000 |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); EventID = $_.Id
      Computer = $_.MachineName; TargetUserName = $d.TargetUserName
      TargetDomainName = $d.TargetDomainName; IpAddress = $d.IpAddress; LogonType = $d.LogonType
    }
  } | ConvertTo-Json | Out-File logons.json -Encoding utf8
```

## Testes

```bash
pytest          # 66 testes
ruff check . && ruff format --check .
```

Os mesmos comandos rodam no CI (`.github/workflows/ci.yml`) e no `pre-commit`.

## Limitações

- Os logs de exemplo e os dados de teste são **sintéticos**: foram escritos à mão e não saíram de
  nenhum sistema real.
- O contexto vem do `data/` como ele está hoje. Se alguém mudou de status depois do evento, o
  relatório não reflete isso.
- Linhas de syslog não têm ano; ele vem do `--year` ou do ano atual.

## Estrutura

```
project-05-python/
├── src/moretti_sec/   # pacote: parsers, enriquecimento, detecções, IOC, timeline, relatório, CLI
│   └── render/        # data/ → Security Groups (infrastructure/), plano do AD (project-04-iam/) e listas do Wazuh (project-03-soc/)
├── tests/             # testes (fixtures marcadas como sintéticas)
└── examples/          # logs sintéticos e o relatório gerado a partir deles
```
