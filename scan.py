import nmap
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil
import platform
import csv
import json
import matplotlib.pyplot as plt
from scapy.all import sniff
from scapy.layers.inet import IP
import subprocess
import requests
import os
import threading
from datetime import datetime
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ScannerGUI:
    def __init__(self):
        self.janela = tk.Tk()
        self.janela.title("Scanner de Vulnerabilidades")
        self.janela.geometry("800x600")
        
        # Variáveis de controle
        self.scan_em_andamento = False
        
        # Criar menu
        self.criar_menu()
        
        # Frame principal
        main_frame = ttk.Frame(self.janela, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid
        self.janela.columnconfigure(0, weight=1)
        self.janela.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # IP/Host alvo
        ttk.Label(main_frame, text="Alvo (IP/Host):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_ip = ttk.Entry(main_frame, width=30)
        self.entry_ip.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Portas
        ttk.Label(main_frame, text="Portas:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_portas = ttk.Entry(main_frame, width=30)
        self.entry_portas.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.entry_portas.insert(0, "1-1024")
        
        # Botões principais
        botoes_frame = ttk.Frame(main_frame)
        botoes_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        botoes = [
            ("Scan de Portas", self.scan_portas),
            ("Detecção de Malware", self.detecao_malware),
            ("Análise de Tráfego", self.analise_trafego),
            ("Verificação de Patch", self.verificacao_patch),
            ("Descoberta de Dispositivos", self.descoberta_dispositivos),
            ("Mapeamento de Rede", self.mapeamento_rede),
            ("Análise de Protocolos", self.analise_protocolos),
            ("Gerar Relatório", self.relatorio_detalhado)
        ]
        
        for i, (texto, comando) in enumerate(botoes):
            btn = ttk.Button(botoes_frame, text=texto, command=comando)
            btn.grid(row=i//2, column=i%2, padx=5, pady=2, sticky=tk.W)
        
        # Área de resultado com scrollbar
        frame_resultado = ttk.Frame(main_frame)
        frame_resultado.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        frame_resultado.columnconfigure(0, weight=1)
        frame_resultado.rowconfigure(0, weight=1)
        
        self.text_result = tk.Text(frame_resultado, wrap=tk.WORD, height=20)
        self.text_result.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(frame_resultado, orient=tk.VERTICAL, command=self.text_result.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.text_result.configure(yscrollcommand=scrollbar.set)
        
        # Barra de progresso
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Pronto")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Carregar configurações
        self.carregar_config()
        
    def criar_menu(self):
        menubar = tk.Menu(self.janela)
        self.janela.config(menu=menubar)
        
        # Menu Arquivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Arquivo", menu=file_menu)
        file_menu.add_command(label="Salvar Relatório", command=self.salvar_relatorio)
        file_menu.add_separator()
        file_menu.add_command(label="Sair", command=self.janela.quit)
        
        # Menu Configurações
        config_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Configurações", menu=config_menu)
        config_menu.add_command(label="Configurar API VirusTotal", command=self.configurar_api)
        
    def carregar_config(self):
        """Carregar configurações do arquivo"""
        try:
            with open('config.json', 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {
                'virustotal_api_key': '',
                'scan_timeout': 30,
                'max_threads': 10
            }
            
    def salvar_config(self):
        """Salvar configurações"""
        with open('config.json', 'w') as f:
            json.dump(self.config, f, indent=4)
            
    def configurar_api(self):
        """Configurar API do VirusTotal"""
        dialog = tk.Toplevel(self.janela)
        dialog.title("Configurar API VirusTotal")
        dialog.geometry("400x150")
        
        ttk.Label(dialog, text="API Key:").pack(pady=5)
        api_entry = ttk.Entry(dialog, width=50, show="*")
        api_entry.pack(pady=5)
        api_entry.insert(0, self.config.get('virustotal_api_key', ''))
        
        def salvar():
            self.config['virustotal_api_key'] = api_entry.get()
            self.salvar_config()
            dialog.destroy()
            messagebox.showinfo("Sucesso", "Configuração salva com sucesso!")
            
        ttk.Button(dialog, text="Salvar", command=salvar).pack(pady=10)
        
    def log_resultado(self, texto):
        """Adicionar texto ao resultado com timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.text_result.insert(tk.END, f"[{timestamp}] {texto}\n")
        self.text_result.see(tk.END)
        
    def executar_com_loading(self, funcao):
        """Executar função com indicador de loading"""
        def wrapper():
            self.progress.start()
            self.status_var.set("Processando...")
            try:
                funcao()
            except Exception as e:
                self.log_resultado(f"Erro: {str(e)}")
                messagebox.showerror("Erro", f"Ocorreu um erro: {str(e)}")
            finally:
                self.progress.stop()
                self.status_var.set("Pronto")
        
        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()
        
    def scan_portas(self):
        """Escaneamento de portas"""
        def scan():
            alvo = self.entry_ip.get()
            if not alvo:
                messagebox.showwarning("Aviso", "Digite um IP ou hostname!")
                return
                
            portas = self.entry_portas.get()
            self.log_resultado(f"Iniciando scan de portas em {alvo}...")
            
            try:
                nm = nmap.PortScanner()
                nm.scan(alvo, portas)
                resultado = ""
                for host in nm.all_hosts():
                    resultado += f"\nHost: {host} ({nm[host].hostname()})\n"
                    resultado += f"Estado: {nm[host].state()}\n"
                    
                    for proto in nm[host].all_protocols():
                        resultado += f"\nProtocolo: {proto}\n"
                        lport = nm[host][proto].keys()
                        for port in sorted(lport):
                            estado = nm[host][proto][port]['state']
                            servico = nm[host][proto][port].get('name', 'desconhecido')
                            resultado += f"  Porta {port}: {estado} ({servico})\n"
                            
                self.log_resultado(resultado)
                self.log_resultado(f"Scan concluído! Total de hosts: {len(nm.all_hosts())}")
                
            except Exception as e:
                raise Exception(f"Erro no scan: {str(e)}")
                
        self.executar_com_loading(scan)
        
    def detecao_malware(self):
        """Detecção de malware usando VirusTotal"""
        def detect():
            arquivo = filedialog.askopenfilename(title="Selecione o arquivo para análise")
            if not arquivo:
                return
                
            if not self.config.get('virustotal_api_key'):
                messagebox.showwarning("Aviso", "Configure a API key do VirusTotal nas configurações!")
                return
                
            self.log_resultado(f"Enviando arquivo {os.path.basename(arquivo)} para análise...")
            
            try:
                url = "https://www.virustotal.com/api/v3/files"
                headers = {"x-apikey": self.config['virustotal_api_key']}
                
                with open(arquivo, "rb") as f:
                    files = {"file": f}
                    resposta = requests.post(url, headers=headers, files=files, timeout=30)
                    
                if resposta.status_code == 200:
                    resultado = resposta.json()
                    id_arquivo = resultado["data"]["id"]
                    self.buscar_analise(id_arquivo)
                else:
                    raise Exception(f"Erro {resposta.status_code}: {resposta.text}")
                    
            except Exception as e:
                raise Exception(f"Erro ao enviar arquivo: {str(e)}")
                
        self.executar_com_loading(detect)
        
    def buscar_analise(self, id_arquivo):
        """Buscar resultado da análise no VirusTotal"""
        api_key = self.config['virustotal_api_key']
        url = f"https://www.virustotal.com/api/v3/analyses/{id_arquivo}"
        headers = {"x-apikey": api_key}
        
        try:
            resposta = requests.get(url, headers=headers, timeout=30)
            if resposta.status_code == 200:
                resultado = resposta.json()
                
                if 'data' in resultado and 'attributes' in resultado['data']:
                    atributos = resultado['data']['attributes']
                    
                    if 'results' in atributos:
                        resultados = atributos['results']
                        self.log_resultado("\n=== RESULTADOS DA ANÁLISE ===\n")
                        
                        # Contar malwares detectados
                        malwares_detectados = []
                        for antivirus, resultado_antivirus in resultados.items():
                            if resultado_antivirus.get('category') == 'malicious':
                                malwares_detectados.append(antivirus)
                                
                        if malwares_detectados:
                            self.log_resultado(f"⚠️  MALWARE DETECTADO por: {', '.join(malwares_detectados)}")
                        else:
                            self.log_resultado("✅ Nenhum malware detectado")
                            
                        # Estatísticas
                        if 'stats' in atributos:
                            stats = atributos['stats']
                            self.log_resultado("\nEstatísticas:")
                            self.log_resultado(f"  Maliciosos: {stats.get('malicious', 0)}")
                            self.log_resultado(f"  Suspeitos: {stats.get('suspicious', 0)}")
                            self.log_resultado(f"  Não detectados: {stats.get('undetected', 0)}")
                    else:
                        self.log_resultado("Nenhum resultado encontrado na análise")
                else:
                    self.log_resultado("Erro ao processar resposta da API")
            else:
                raise Exception(f"Erro {resposta.status_code}: {resposta.text}")
                
        except Exception as e:
            raise Exception(f"Erro ao buscar análise: {str(e)}")
            
    def analise_trafego(self):
        """Análise de tráfego de rede"""
        def analisar():
            self.log_resultado("\n=== ANÁLISE DE TRÁFEGO ===\n")
            
            try:
                # Estatísticas de rede
                trafego = psutil.net_io_counters()
                self.log_resultado("Tráfego de rede:")
                self.log_resultado(f"  Bytes recebidos: {trafego.bytes_recv:,}")
                self.log_resultado(f"  Bytes enviados: {trafego.bytes_sent:,}")
                self.log_resultado(f"  Pacotes recebidos: {trafego.packets_recv:,}")
                self.log_resultado(f"  Pacotes enviados: {trafego.packets_sent:,}")
                
                # Conexões ativas
                self.log_resultado("\nConexões ativas:")
                conexoes = psutil.net_connections()
                conexoes_por_estado = {}
                
                for conn in conexoes:
                    estado = conn.status
                    if estado:
                        conexoes_por_estado[estado] = conexoes_por_estado.get(estado, 0) + 1
                        
                for estado, count in conexoes_por_estado.items():
                    self.log_resultado(f"  {estado}: {count}")
                    
            except Exception as e:
                raise Exception(f"Erro na análise de tráfego: {str(e)}")
                
        self.executar_com_loading(analisar)
        
    def verificacao_patch(self):
        """Verificação de patches do sistema"""
        def verificar():
            self.log_resultado("\n=== INFORMAÇÕES DO SISTEMA ===\n")
            
            try:
                sistema = platform.system()
                versao = platform.release()
                arquitetura = platform.machine()
                
                self.log_resultado(f"Sistema Operacional: {sistema}")
                self.log_resultado(f"Versão: {versao}")
                self.log_resultado(f"Arquitetura: {arquitetura}")
                self.log_resultado(f"Processador: {platform.processor()}")
                
                # Verificar atualizações disponíveis (apenas para Windows)
                if sistema == "Windows":
                    self.log_resultado("\nVerificando atualizações pendentes...")
                    try:
                        resultado = subprocess.run(['wmic', 'qfe', 'list', 'brief'], 
                                                 capture_output=True, text=True, timeout=10)
                        linhas = resultado.stdout.strip().split('\n')
                        if len(linhas) > 1:
                            self.log_resultado(f"Últimas {min(5, len(linhas)-1)} atualizações:")
                            for linha in linhas[1:6]:
                                self.log_resultado(f"  {linha[:100]}")
                        else:
                            self.log_resultado("  Nenhuma atualização encontrada")
                    except:
                        self.log_resultado("  Não foi possível verificar atualizações")
                        
            except Exception as e:
                raise Exception(f"Erro na verificação: {str(e)}")
                
        self.executar_com_loading(verificar)
        
    def descoberta_dispositivos(self):
        """Descoberta de dispositivos na rede"""
        def descobrir():
            self.log_resultado("\n=== DESCOBERTA DE DISPOSITIVOS ===\n")
            
            try:
                nm = nmap.PortScanner()
                self.log_resultado("Escaneando rede local (192.168.1.0/24)...")
                nm.scan('192.168.1.0/24', arguments='-sn')  # Ping scan
                
                hosts_encontrados = []
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        nome = nm[host].hostname() or "desconhecido"
                        hosts_encontrados.append((host, nome))
                        
                self.log_resultado(f"\nDispositivos encontrados: {len(hosts_encontrados)}")
                for host, nome in hosts_encontrados:
                    self.log_resultado(f"  {host} - {nome}")
                    
            except Exception as e:
                raise Exception(f"Erro na descoberta: {str(e)}")
                
        self.executar_com_loading(descobrir)
        
    def mapeamento_rede(self):
        """Mapeamento detalhado da rede"""
        def mapear():
            self.log_resultado("\n=== MAPEAMENTO DE REDE ===\n")
            
            try:
                nm = nmap.PortScanner()
                self.log_resultado("Realizando mapeamento detalhado...")
                nm.scan('192.168.1.0/24', '1-1000')
                
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        self.log_resultado(f"\nHost: {host}")
                        self.log_resultado(f"  Nome: {nm[host].hostname() or 'desconhecido'}")
                        self.log_resultado(f"  Estado: {nm[host].state()}")
                        
                        # Portas abertas
                        portas_abertas = []
                        for proto in nm[host].all_protocols():
                            for port in nm[host][proto].keys():
                                if nm[host][proto][port]['state'] == 'open':
                                    servico = nm[host][proto][port].get('name', 'desconhecido')
                                    portas_abertas.append(f"{port}/{proto} ({servico})")
                                    
                        if portas_abertas:
                            self.log_resultado(f"  Portas abertas: {', '.join(portas_abertas)}")
                            
            except Exception as e:
                raise Exception(f"Erro no mapeamento: {str(e)}")
                
        self.executar_com_loading(mapear)
        
    def analise_protocolos(self):
        """Análise de protocolos de rede"""
        def analisar():
            self.log_resultado("\n=== ANÁLISE DE PROTOCOLOS ===\n")
            
            try:
                self.log_resultado("Capturando pacote para análise...")
                pacotes = sniff(count=5, timeout=5)
                
                protocolos = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
                
                for i, pacote in enumerate(pacotes, 1):
                    if pacote.haslayer(IP):
                        ip = pacote[IP]
                        proto = ip.proto
                        nome_proto = protocolos.get(proto, f'Desconhecido ({proto})')
                        
                        self.log_resultado(f"Pacote {i}:")
                        self.log_resultado(f"  Origem: {ip.src}")
                        self.log_resultado(f"  Destino: {ip.dst}")
                        self.log_resultado(f"  Protocolo: {nome_proto}")
                        self.log_resultado(f"  Tamanho: {len(pacote)} bytes")
                        self.log_resultado("")
                        
            except Exception as e:
                raise Exception(f"Erro na análise de protocolos: {str(e)}")
                
        self.executar_com_loading(analisar)
        
    def salvar_relatorio(self):
        """Salvar relatório atual em arquivo"""
        try:
            nome_arquivo = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Arquivos de texto", "*.txt"), ("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")]
            )
            
            if nome_arquivo:
                conteudo = self.text_result.get('1.0', tk.END)
                with open(nome_arquivo, 'w', encoding='utf-8') as f:
                    f.write(conteudo)
                messagebox.showinfo("Sucesso", f"Relatório salvo em {nome_arquivo}")
                
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar relatório: {str(e)}")
            
    def relatorio_detalhado(self):
        """Gerar relatório detalhado com gráficos"""
        def gerar():
            self.log_resultado("\n=== GERANDO RELATÓRIO DETALHADO ===\n")
            
            try:
                # Primeiro fazer um scan
                nm = nmap.PortScanner()
                nm.scan('192.168.1.0/24', '1-1024')
                
                hosts = nm.all_hosts()
                portas_abertas = []
                portas_fechadas = []
                servicos = {}
                
                for host in hosts:
                    if nm[host].state() == 'up':
                        for proto in nm[host].all_protocols():
                            for port in nm[host][proto].keys():
                                estado = nm[host][proto][port]['state']
                                if estado == 'open':
                                    portas_abertas.append(port)
                                    servico = nm[host][proto][port].get('name', 'desconhecido')
                                    servicos[servico] = servicos.get(servico, 0) + 1
                                else:
                                    portas_fechadas.append(port)
                
                # Criar gráficos
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
                
                # Gráfico de barras
                ax1.bar(['Portas Abertas', 'Portas Fechadas'], 
                       [len(portas_abertas), len(portas_fechadas)],
                       color=['green', 'red'])
                ax1.set_xlabel('Tipo de Porta')
                ax1.set_ylabel('Quantidade')
                ax1.set_title('Distribuição de Portas')
                
                # Gráfico de pizza para serviços
                if servicos:
                    servicos_ordenados = sorted(servicos.items(), key=lambda x: x[1], reverse=True)[:5]
                    nomes, valores = zip(*servicos_ordenados)
                    ax2.pie(valores, labels=nomes, autopct='%1.1f%%')
                    ax2.set_title('Top 5 Serviços Encontrados')
                
                plt.tight_layout()
                plt.show()
                
                self.log_resultado(f"Total de hosts escaneados: {len(hosts)}")
                self.log_resultado(f"Portas abertas: {len(portas_abertas)}")
                self.log_resultado(f"Portas fechadas: {len(portas_fechadas)}")
                
                if servicos:
                    self.log_resultado("\nServiços encontrados:")
                    for servico, count in sorted(servicos.items(), key=lambda x: x[1], reverse=True):
                        self.log_resultado(f"  {servico}: {count}")
                        
            except Exception as e:
                raise Exception(f"Erro ao gerar relatório: {str(e)}")
                
        self.executar_com_loading(gerar)
        
    def run(self):
        self.janela.mainloop()

if __name__ == "__main__":
    scanner = ScannerGUI()
    scanner.run()