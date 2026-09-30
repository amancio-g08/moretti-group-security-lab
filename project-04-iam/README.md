# Projeto 04 — Gestão de identidades e acessos (IAM)

**Português** | [English](README.en.md)

Controle de acesso por função e menor privilégio na Moretti Group, começando no Active Directory,
passando por identidade híbrida e chegando no Entra ID
([ADR-006](../docs/adr/ADR-006-identity-evolution.md)).

**Status:** fase 5 (Active Directory) com o código pronto e testado offline; ainda **não foi
aplicado** num controlador de domínio. A fase 8 (Entra ID) também está com o código pronto: políticas de Conditional Access geradas do `data/`, script de aplicação e a revisão de acesso em Python (`moretti-sec access-review`). Falta aplicar num tenant.

## A ideia

Eu não queria um script cheio de nomes de usuário escritos à mão. Tudo sai do `data/`: quem
trabalha na empresa, qual o papel de cada um e o que cada papel pode acessar. Um gerador em Python
transforma isso num plano do AD (`generated/ad-plan.json`), e um script PowerShell faz o domínio
ficar igual ao plano. Se alguém muda de papel ou é desligado no `employees.csv`, o próximo run
ajusta os grupos sozinho.

```
data/ → gerador (Python, testado) → ad-plan.json (revisado no Git) → PowerShell no DC01
```

## O que o domínio garante

- **AGDLP:** usuário → grupo do papel (`GG-Role-*`) → grupo da permissão (`DL-*`) → recurso.
- **Segregação de funções:** quem lança pagamento não aprova pagamento.
- **Contas admin separadas** (`adm-*`), por camada (Tier 0, 1 e 2). Só duas contas chegam a
  Domain Admins: o admin nomeado de Tier 0 e a conta de emergência.
- **Ciclo de vida:** desligado é desativado, vai para a OU Disabled e perde todos os grupos;
  afastado fica desativado até voltar; terceiro tem a conta expirando no fim do contrato.
- **Senhas** aleatórias, guardadas só no SSM Parameter Store, nunca no Git.
- **Delegação mínima:** o suporte só reseta senha e o SOC só desativa conta, e nenhum dos dois
  alcança contas admin. Estações entram no domínio com a conta de Tier 2, nunca com Domain Admin.
- **GPOs como código:** auditoria que o Wazuh vai precisar, LLMNR/SMBv1/NTLMv1 desligados, firewall,
  bloqueio de tela e contas de serviço sem login interativo.

O desenho completo está em [documentation/ad-design.md](documentation/ad-design.md).

## Estrutura

```
project-04-iam/
├── generated/ad-plan.json   # gerado do data/, não editar
├── scripts/                 # PowerShell: criar o domínio, provisionar, GPOs, entrar no domínio
├── tests/                   # simulações em PowerShell (domínio falso, sem AD de verdade)
├── tools/render_ad_plan.py  # gera o plano
└── documentation/           # desenho do AD e plano de validação
```

## Verificações

```bash
python3 project-04-iam/tools/render_ad_plan.py --check        # plano bate com o data/
pytest project-05-python/tests/test_ad_plan.py                # regras do plano
pwsh -File project-04-iam/tests/Test-ProvisioningDryRun.ps1   # simulação: domínio vazio e desligado
pwsh -File project-04-iam/tests/Test-GpoTemplates.ps1         # arquivos das GPOs
```

Tudo isso roda no CI, junto com o PSScriptAnalyzer. Os testes provam que o código faz o que o
desenho diz; se o AD de verdade se comporta igual, só o [plano de validação](documentation/validation-plan.md)
vai dizer, quando eu rodar no lab (passos no [checklist](../docs/operator-checklist.md), seção D).
