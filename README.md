# Scanner de Vulnerabilidades

Este projeto é uma aplicação gráfica desenvolvida em Python que permite realizar diversas análises de segurança em redes e sistemas. A interface gráfica foi criada usando a biblioteca `tkinter`, e várias funcionalidades foram implementadas para ajudar na identificação de vulnerabilidades, detecção de malware, análise de tráfego e muito mais.

## Funcionalidades

1. **Scan de portas**
   - Realiza a varredura de portas abertas em um IP informado.
   - Utiliza a biblioteca `nmap` para realizar o scan.

2. **Detecção de Malware**
   - Faz o upload de arquivos para análise no VirusTotal.
   - Realiza varredura local de arquivos usando o `clamdscan`.

3. **Análise de Tráfego**
   - Exibe estatísticas sobre bytes recebidos e enviados.
   - Utiliza a biblioteca `psutil`.

4. **Verificação de Patch**
   - Exibe informações sobre o sistema operacional e sua versão.

5. **Descoberta de Dispositivos**
   - Realiza uma varredura em uma rede para identificar dispositivos conectados.

6. **Mapeamento de Rede**
   - Mostra informações detalhadas dos hosts na rede.

7. **Análise de Protocolos**
   - Detecta pacotes de rede e identifica o protocolo usado.

8. **Relatório Detalhado**
   - Gera um relatório completo em formato de texto.
   - Cria gráficos para visualização de dados sobre portas e vulnerabilidades.

## Requisitos

Certifique-se de ter as seguintes dependências instaladas:

- Python 3.8 ou superior
- Bibliotecas Python:
  - `nmap`
  - `tkinter`
  - `psutil`
  - `platform`
  - `csv`
  - `json`
  - `matplotlib`
  - `scapy`
  - `requests`
- Ferramentas externas:
  - `clamdscan`
  - `Nmap`

Para instalar as dependências Python, use:
```bash
pip install python-nmap psutil matplotlib scapy requests
```

## Como usar  

Clone este repositório:  

```bash
git clone https://github.com/GabrielAugustoFerreiraMaia/Nmap_Python
cd scanner-vulnerabilidades  
```
Instale as dependências:
```bash
pip install -r requirements.txt
```
Execute o arquivo principal:
```bash
python scanner.py  
```

## Contribuição

Contribuições são bem-vindas! Para contribuir, faça um fork do repositório e envie uma pull request.

## Licença

Este projeto é licenciado sob a licença MIT.
