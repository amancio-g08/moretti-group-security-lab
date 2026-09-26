# Projeto 01 — Rede corporativa (Packet Tracer)

**Português** | [English](README.en.md)

A rede completa da Moretti Group desenhada no Cisco Packet Tracer: 12 VLANs, roteamento entre
VLANs no switch core, firewall ASA no perímetro com DMZ, NAT no roteador de borda e hardening
dos equipamentos. Tudo segue o [`data/network-matrix.yaml`](../data/network-matrix.yaml).

**Status:** configurações e documentação prontas; a montagem no Packet Tracer e os testes ainda
não foram feitos.

## O que tem aqui

| Pasta / arquivo | Conteúdo |
|---|---|
| [`configs/`](configs/) | Configuração de cada equipamento, pronta para colar |
| [`configs/generated/CORE-SW01-acls.txt`](configs/generated/CORE-SW01-acls.txt) | ACLs entre VLANs, **geradas** a partir da matriz (não edite à mão) |
| [`tools/render_core_acls.py`](tools/render_core_acls.py) | Gera as ACLs do core a partir da matriz |
| [`tools/verify_core_acls.py`](tools/verify_core_acls.py) | Confere se as ACLs geradas fazem exatamente o que a matriz diz |
| [`documentation/build-guide.md`](documentation/build-guide.md) | Passo a passo para montar a rede no Packet Tracer |
| [`documentation/addressing-plan.md`](documentation/addressing-plan.md) | VLANs, IPs, portas e pools de DHCP |
| [`documentation/acl-design.md`](documentation/acl-design.md) | Como a matriz vira ACL, e as limitações de ACL sem estado |
| [`documentation/hardening.md`](documentation/hardening.md) | Proteções dos equipamentos, ataques de camada 2 e o que ficou de fora |
| [`documentation/validation-plan.md`](documentation/validation-plan.md) | Testes a executar no Packet Tracer |
| [`topology.yaml`](topology.yaml) | Modelos, posições na tela e cabos da topologia |
| [`packet-tracer/build-topology.js`](packet-tracer/build-topology.js) | Script **gerado** que monta a rede dentro do Packet Tracer (extensão PTBuilder) |
| [`tools/build_ptbuilder_script.py`](tools/build_ptbuilder_script.py) | Gera o script a partir de `topology.yaml`, `data/` e `configs/` |
| `packet-tracer/` | Onde fica o arquivo `.pkt` depois de montado |

## Montagem automática (experimental)

Em vez de arrastar 33 equipamentos e ligar 32 cabos na mão, dá para rodar um script dentro do
Packet Tracer usando a extensão open-source [PTBuilder](https://github.com/kimmknight/PTBuilder).
O script cria a topologia, configura os IPs e aplica as configurações dos equipamentos. Ele foi
testado só contra uma simulação da API da extensão, então o primeiro teste de verdade no Packet
Tracer ainda vai mostrar o que precisa de ajuste. O passo a passo está no
[build guide](documentation/build-guide.md#automated-build-ptbuilder).

## Por que as ACLs são geradas

Eu não escrevi as ACLs do switch core à mão. Um script lê a matriz de comunicação e gera uma ACL
por VLAN, e outro script simula todas as combinações de origem, destino e porta para confirmar
que a ACL decide igual à matriz. Se alguém muda a matriz e esquece de regenerar, o `pre-commit`
barra o commit.

```bash
python3 project-01-network/tools/render_core_acls.py --write   # gera de novo
python3 project-01-network/tools/verify_core_acls.py           # tem que dar 0 mismatches
```

Essa verificação é análise estática do texto da configuração. Ela não substitui os testes no
Packet Tracer, que estão no plano de validação.

## Onde cada coisa é bloqueada

| Tráfego | Quem bloqueia |
|---|---|
| Entre VLANs internas | Switch core (CORE-SW01), ACL na entrada de cada VLAN |
| Rede interna ↔ internet | Core e firewall (FW01) |
| Internet → DMZ / rede interna | Firewall e anti-spoofing no roteador de borda (R-EDGE01) |
| Dentro da mesma VLAN | Ninguém (não passa por roteamento) — na AWS, os Security Groups resolvem isso |

A decisão está registrada na [ADR-008](../docs/adr/ADR-008-network-enforcement-points.md).
