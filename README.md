# RC TP2 - Packet Sniffer (Python)

Implementacao simples em Python com `scapy`, focada nos requisitos do enunciado.

## Funcionalidades

- Captura de pacotes numa interface (`--interface`)
- Modo live (consola) por omissao
- Logging opcional em simultaneo para `txt`, `csv` e `json`
- Filtros por:
  - protocolo (`--protocol`)
  - IP (`--ip`)
  - MAC (`--mac`)
  - expressao BPF (`--bpf`)
- Campos por pacote:
  - timestamp
  - interface
  - protocolo identificado
  - MAC/IP origem e destino
  - tamanho
  - resumo (ex.: ARP request, ICMP echo request, DHCP Discover)

## Requisitos

- Linux
- Python 3.10+
- permissoes root para captura

## Instalacao

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Descobrir interfaces

```bash
ip -br a
```

Exemplos comuns:
- CORE: `eth0` (ou similar)
- PC: `wlan0`, `wlp2s0`, `enp3s0`, `eth0`

## Execucao

### Live sem logs

```bash
sudo .venv/bin/python sniffer.py -i eth0
```

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

## Sugestao de demonstracao (CORE)

1. Levantar topologia no CORE.
2. Correr sniffer num no/interface.
3. Gerar trafego:
   - `ping`
   - `nc` (netcat) para TCP/UDP
   - opcionalmente DNS/DHCP se topologia o permitir
4. Guardar logs e usar no relatorio.