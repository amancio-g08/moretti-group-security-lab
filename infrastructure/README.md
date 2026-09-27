# infrastructure/ — Laboratório na AWS como código

**Português** | [English](README.en.md)

Terraform e scripts para subir, desligar e destruir o laboratório na AWS. A regra que eu segui
aqui é a mesma do resto do projeto: a política vem do `data/`. As sub-redes e as regras dos
Security Groups são **geradas** a partir do `network-matrix.yaml`, então a AWS não tem como ficar
diferente do que está documentado.

**Status:** fase 4 com o código pronto e testado offline; ainda **não foi aplicado** numa conta
AWS. Os resultados reais entram no [plano de validação](docs/validation-plan.md) quando eu rodar.

## Como está montado

- **Nada entra pela internet.** Nenhum Security Group aceita tráfego de `0.0.0.0/0`, nenhuma
  máquina tem IP público (só a NAT instance, justificada na ADR-009) e não existe chave SSH: o
  acesso é só pelo SSM Session Manager.
- **Máquinas por fase.** O campo `aws_phase` do `data/assets.yaml` decide quando cada máquina
  existe. Na fase 4 são só o WS-DEV01 e o GUEST01.
- **Custo sob controle.** Orçamento com alertas em US$ 10, 20 e 30, criado antes de tudo;
  máquinas em Spot e ARM (Graviton); NAT instance no lugar do NAT Gateway; desligamento
  automático toda noite (ADR-009).
- **Evidência.** VPC Flow Logs (agregação de 1 minuto) e CloudTrail num bucket S3 criptografado.

## Estrutura

```
infrastructure/
├── terraform/
│   ├── bootstrap/   # orçamento, CloudTrail e bucket de logs (aplicado primeiro)
│   └── lab/         # VPC, sub-redes, NAT instance, Security Groups, Flow Logs, máquinas, desligamento
│       ├── generated/security-groups.json   # gerado do data/, não editar
│       └── tests/   # testes do plano com o provider da AWS simulado (sem conta)
├── scripts/         # lab-up, lab-down, lab-destroy, cost-check
├── tools/           # render_security_groups.py (matriz → Security Groups)
└── docs/            # guia de implantação e plano de validação
```

## Como usar

O passo a passo, incluindo criar a conta e o acesso com MFA, está no
[guia de implantação](docs/deployment-guide.md). Resumo:

```bash
cd infrastructure/terraform/bootstrap && terraform init && terraform apply
cd ../lab && terraform init && terraform plan -out phase4.tfplan && terraform apply phase4.tfplan
infrastructure/scripts/lab-down.sh     # desliga tudo no fim da sessão
```

## Verificações

```bash
python3 infrastructure/tools/render_security_groups.py --check   # regras batem com a matriz
terraform -chdir=infrastructure/terraform/lab test                # testes offline do plano
```

As duas rodam no CI e a primeira também no `pre-commit`.

## Decisões

[ADR-002](../docs/adr/ADR-002-cloud-platform.md), [003](../docs/adr/ADR-003-single-az.md),
[004](../docs/adr/ADR-004-egress-strategy.md), [007](../docs/adr/ADR-007-minimum-footprint.md) e
[009](../docs/adr/ADR-009-cost-optimized-aws-lab.md).
