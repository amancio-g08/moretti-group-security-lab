# Projeto 02 — Análise de tráfego de rede

**Português** | [English](README.en.md)

Investigações feitas em cima das capturas geradas pelos cenários do laboratório. Cada uma responde
quem, o quê, quando, onde e como, com timeline, os filtros do Wireshark usados e o raciocínio por
trás de cada conclusão.

**Status:** o **plugin do Wireshark em Lua** está pronto e testado. As investigações entram na
fase 7, quando os cenários rodarem no lab e houver captura de verdade.

## Plugin do Wireshark (Lua)

Lua é uma das linguagens que eu mais uso, e é a linguagem de plugins do Wireshark. Então, em vez
de só analisar captura, eu fiz o Wireshark entender a empresa: cada pacote ganha um bloco
**Moretti Group** dizendo de qual máquina e segmento ele saiu, para onde foi, e se aquele fluxo é
**permitido ou proibido pela matriz de rede**, com a regra que decidiu.

```
Moretti Group: GUEST01 (guest) -> WS-FIN01 (finance): deny (NM-004)
```

Com isso dá para filtrar `moretti.verdict == "deny"` e ver na hora todo o tráfego que viola a
política, ou `moretti.src.segment == "guest"` para seguir o visitante.

- A tabela de ativos e regras é **gerada do `data/`**, como o resto do projeto.
- Ele entende conexão como um firewall de verdade: só o início do fluxo é julgado, e a resposta
  herda o veredito.
- Funciona com as regras da AWS ou do Packet Tracer (preferência no Wireshark).

**Como eu provei que está certo:**
- testes do motor em Lua puro;
- um **teste diferencial** que compara o motor em Lua com um avaliador independente em Python em
  **203.228 fluxos**, sem nenhuma divergência;
- um teste de ponta a ponta com `tshark` numa captura sintética.

Tudo roda no CI.

Instalação, uso e limitações: [documentation/wireshark-plugin.md](documentation/wireshark-plugin.md).

## Estrutura

```
project-02-pcap/
├── wireshark/       # plugin Lua: moretti.lua, policy_engine.lua, moretti_policy.lua (gerado)
├── tools/           # gerador da tabela de política
├── tests/           # testes do motor e gerador da captura sintética
├── nse/             # auditoria de segmentação em Lua (Nmap), alvos gerados do data/
├── documentation/   # documentação do plugin
├── reports/         # modelo de relatório de investigação
└── (fase 7)         # pcaps/curated com as capturas revisadas
```

As capturas brutas ficam fora do Git; só as revisadas entram. Nenhuma evidência é inventada: o que
a captura não mostra fica escrito como não determinado.
