# RC TP2 - Packet Sniffer (Python)

Implementacao simples em Python com `scapy`, focada nos requisitos do enunciado.

## Funcionalidades

- Captura de pacotes numa interface (`--interface`)
- Modo live (consola) por omissao
- Modo live agregado por conversas bidirecionais (`--live-conversations`)
- Logging opcional em simultaneo para `txt`, `csv` e `json`
- Filtros por:
  - protocolo (`--protocol`)
  - IP (`--ip`)
  - MAC (`--mac`)
  - expressao BPF (`--bpf`)
- Campos por pacote (live e logs):
  - timestamp
  - interface
  - protocolo identificado
  - MAC/IP origem e destino
  - tamanho
  - resumo (ex.: ARP request, ICMP echo request, DHCP Discover)

## Estatisticas no final da captura

Ao terminar com `Ctrl+C`, o sniffer imprime automaticamente um relatorio final com:

1. Distribuicao de protocolos
- Transporte: percentagem TCP/UDP/ICMP
- Aplicacao: percentagem WEB (80/443/8080/8443), DNS (53), OUTROS

2. Top Talkers
- Top 5 IPs de origem (por bytes e pacotes)
- Top 5 IPs de destino (por bytes e pacotes)
- Top 5 conversas IP (A <-> B) por bytes e pacotes

3. Analise de tamanho
- Tamanho medio e maximo
- Distribuicao de tamanhos (pequenos/intermedios/perto MTU)
- Taxa de fragmentacao IPv4

4. Caca aos erros
- Taxa de erros ICMP
- Retransmissoes TCP (estimativa)

5. Desempenho e volume
- Volume total capturado (MiB)
- Pico de pacotes por segundo (PPS)

## Requisitos

- Linux
- Python 3.10+
- permissoes root para captura

## Instalacao

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Descobrir interfaces

```bash
ip -br a
```

Exemplos comuns:
- CORE: `eth0` (ou similar)
- PC: `wlan0`, `wlp2s0`, `enp3s0`, `eth0`

## Uso rapido

```bash
cd /home/rafabass1/RC/Rc-Sniffer
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo .venv/bin/python sniffer.py -i eth0
```

## Todas as flags disponiveis

```text
-i, --interface          (obrigatorio) Interface de rede
--protocol               Filtro por protocolo: ARP, IPv4, IPv6, ICMP, TCP, UDP, DHCP, DNS
--ip                     Filtro por IP de origem ou destino
--mac                    Filtro por MAC de origem ou destino
--bpf                    Filtro BPF (libpcap), ex.: "icmp or arp"
--no-live                Desativa output live (mantem logs/estatisticas)
--live-conversations     Output live agregado por conversa/protocolo (A <-> B)
--log-txt                Caminho para ficheiro de log TXT
--log-csv                Caminho para ficheiro de log CSV
--log-json               Caminho para ficheiro de log JSON
```

## Execucao (exemplos)

### Live sem logs

```bash
sudo .venv/bin/python sniffer.py -i eth0
```

### Live agregado por conversas bidirecionais

```bash
sudo .venv/bin/python sniffer.py -i eth0 --live-conversations
```

No modo agregado, o live output deixa de mostrar cada direcao separada e passa a mostrar eventos por par de hosts (A <-> B). Para ICMP echo, aparece como evento `PING`.

### Live + logs em simultaneo

```bash
sudo .venv/bin/python sniffer.py -i eth0 \
  --log-txt captura.txt \
  --log-csv captura.csv \
  --log-json captura.json
```

### Filtro por protocolo

```bash
sudo .venv/bin/python sniffer.py -i eth0 --protocol ICMP
```

### Filtro por IP

```bash
sudo .venv/bin/python sniffer.py -i eth0 --ip 10.0.0.2
```

### Filtro por MAC

```bash
sudo .venv/bin/python sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
```

### Filtro BPF (exemplo)

```bash
sudo .venv/bin/python sniffer.py -i eth0 --bpf "icmp or arp"
```

### Apenas logging (sem imprimir live)

```bash
sudo .venv/bin/python sniffer.py -i eth0 --no-live --log-json captura.json
```

### ICMP agregado por conversa (bom para testes de ping)

```bash
sudo .venv/bin/python sniffer.py -i eth0 --protocol ICMP --live-conversations
```

### Combinar filtros + logs + agregado

```bash
sudo .venv/bin/python sniffer.py -i eth0 \
  --protocol ICMP \
  --ip 10.0.0.2 \
  --live-conversations \
  --log-txt captura.txt \
  --log-csv captura.csv \
  --log-json captura.json
```

## Como ver as estatisticas

1. Inicia a captura com qualquer comando acima.
2. Gera trafego (ex.: `ping -c 4 8.8.8.8`, `curl`, DNS).
3. Para com `Ctrl+C`.
4. Lê no terminal o bloco `=== RELATORIO DE CAPTURA ===`.

## Troubleshooting

### `sudo: python: command not found`

Usa `python3` ou, de preferencia, o Python da virtualenv:

```bash
sudo .venv/bin/python sniffer.py -i eth0
```

### `ModuleNotFoundError: No module named 'scapy'`

Instala dependencias na virtualenv e executa com o interpretador da virtualenv:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo .venv/bin/python sniffer.py -i eth0
```

## Sugestao de demonstracao (CORE)

1. Levantar topologia no CORE.
2. Correr sniffer num no/interface.
3. Gerar trafego:
   - `ping`
   - `nc` (netcat) para TCP/UDP
   - opcionalmente DNS/DHCP se topologia o permitir
4. Guardar logs e usar no relatorio.