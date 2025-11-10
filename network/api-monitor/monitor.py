#!/usr/bin/env python3
"""
Service Monitor - Ferramenta CLI para monitoramento de disponibilidade de serviços
Detecta indisponibilidade até em escala de milissegundos
"""

import argparse
import time
import sys
import requests
import socket
from datetime import datetime
from typing import Optional, Dict
from dataclasses import dataclass
import signal
import statistics
from urllib.parse import urlparse
import urllib3

# Desabilitar warnings de SSL quando necessário
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class MonitorStats:
    """Estatísticas do monitoramento"""
    total_checks: int = 0
    successful_checks: int = 0
    failed_checks: int = 0
    response_times: list = None
    downtime_events: list = None
    start_time: float = None
    
    def __post_init__(self):
        if self.response_times is None:
            self.response_times = []
        if self.downtime_events is None:
            self.downtime_events = []
        if self.start_time is None:
            self.start_time = time.time()
    
    def get_uptime_percentage(self) -> float:
        """Calcula porcentagem de uptime"""
        if self.total_checks == 0:
            return 0.0
        return (self.successful_checks / self.total_checks) * 100
    
    def get_avg_response_time(self) -> float:
        """Retorna tempo médio de resposta em ms"""
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    def get_median_response_time(self) -> float:
        """Retorna tempo mediano de resposta em ms"""
        if not self.response_times:
            return 0.0
        return statistics.median(self.response_times)


class ServiceMonitor:
    """Monitor de serviços com detecção de alta precisão"""
    
    def __init__(self, target: str, check_type: str, interval: float, 
                 timeout: float, threshold: float, log_file: Optional[str] = None,
                 verify_ssl: bool = True):
        self.target = target
        self.check_type = check_type
        self.interval = interval
        self.timeout = timeout
        self.threshold = threshold
        self.log_file = log_file
        self.verify_ssl = verify_ssl
        self.stats = MonitorStats()
        self.running = True
        
        # Configurar handler para Ctrl+C
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handler para interrupção graceful"""
        print("\n\n🛑 Interrompendo monitoramento...")
        self.running = False
    
    def _log(self, message: str):
        """Registra mensagem em arquivo se configurado"""
        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                f.write(f"[{timestamp}] {message}\n")
    
    def _check_http(self) -> tuple[bool, float, Optional[str]]:
        """
        Verifica disponibilidade via HTTP/HTTPS
        Retorna: (sucesso, tempo_resposta_ms, mensagem_erro)
        """
        try:
            start_time = time.perf_counter()
            response = requests.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
                headers={'User-Agent': 'ServiceMonitor/1.0'}
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            
            # Considera sucesso status codes 2xx e 3xx
            if 200 <= response.status_code < 400:
                return True, elapsed_ms, None
            else:
                return False, elapsed_ms, f"HTTP {response.status_code}"
                
        except requests.exceptions.Timeout:
            elapsed_ms = self.timeout * 1000
            return False, elapsed_ms, "Timeout"
        except requests.exceptions.ConnectionError as e:
            return False, 0.0, f"Connection Error: {str(e)}"
        except Exception as e:
            return False, 0.0, f"Error: {str(e)}"
    
    def _check_tcp(self) -> tuple[bool, float, Optional[str]]:
        """
        Verifica disponibilidade via TCP
        Retorna: (sucesso, tempo_resposta_ms, mensagem_erro)
        """
        try:
            # Parse host e porta
            if ':' in self.target:
                host, port = self.target.rsplit(':', 1)
                port = int(port)
            else:
                return False, 0.0, "Formato inválido. Use host:porta"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.perf_counter()
            result = sock.connect_ex((host, port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            sock.close()
            
            if result == 0:
                return True, elapsed_ms, None
            else:
                return False, elapsed_ms, f"Connection refused (code: {result})"
                
        except socket.timeout:
            elapsed_ms = self.timeout * 1000
            return False, elapsed_ms, "Timeout"
        except socket.gaierror:
            return False, 0.0, "DNS resolution failed"
        except Exception as e:
            return False, 0.0, f"Error: {str(e)}"
    
    def _check_icmp(self) -> tuple[bool, float, Optional[str]]:
        """
        Verifica disponibilidade via ICMP (ping)
        Retorna: (sucesso, tempo_resposta_ms, mensagem_erro)
        """
        import subprocess
        import platform
        
        try:
            # Determina comando ping baseado no SO
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            
            start_time = time.perf_counter()
            result = subprocess.run(
                ['ping', param, '1', timeout_param, str(int(self.timeout)), self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 1
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            
            if result.returncode == 0:
                # Tenta extrair tempo de resposta do output
                output = result.stdout.decode()
                if 'time=' in output:
                    try:
                        time_str = output.split('time=')[1].split()[0]
                        actual_time = float(time_str.replace('ms', ''))
                        return True, actual_time, None
                    except:
                        pass
                return True, elapsed_ms, None
            else:
                return False, elapsed_ms, "Host unreachable"
                
        except subprocess.TimeoutExpired:
            return False, self.timeout * 1000, "Timeout"
        except Exception as e:
            return False, 0.0, f"Error: {str(e)}"
    
    def _check_service(self) -> tuple[bool, float, Optional[str]]:
        """Executa verificação baseada no tipo configurado"""
        if self.check_type == 'http':
            return self._check_http()
        elif self.check_type == 'tcp':
            return self._check_tcp()
        elif self.check_type == 'icmp':
            return self._check_icmp()
        else:
            raise ValueError(f"Tipo de verificação inválido: {self.check_type}")
    
    def _print_status(self, success: bool, response_time: float, error_msg: Optional[str]):
        """Imprime status da verificação com cores"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Cores ANSI
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        
        if success:
            # Verifica se tempo de resposta excede threshold
            if response_time > self.threshold:
                color = YELLOW
                status = "⚠️  LENTO"
                details = f"({response_time:.2f}ms > {self.threshold}ms threshold)"
            else:
                color = GREEN
                status = "✅ UP"
                details = f"({response_time:.2f}ms)"
            
            print(f"{timestamp} | {color}{BOLD}{status}{RESET} {details}")
        else:
            color = RED
            status = "❌ DOWN"
            details = error_msg if error_msg else "Unknown error"
            if response_time > 0:
                details += f" (após {response_time:.2f}ms)"
            
            print(f"{timestamp} | {color}{BOLD}{status}{RESET} {details}")
            
            # Log evento de downtime
            log_msg = f"DOWNTIME: {details}"
            self._log(log_msg)
    
    def _print_statistics(self):
        """Imprime estatísticas finais"""
        uptime = self.stats.get_uptime_percentage()
        avg_time = self.stats.get_avg_response_time()
        median_time = self.stats.get_median_response_time()
        duration = time.time() - self.stats.start_time
        
        print("\n" + "="*60)
        print("📊 ESTATÍSTICAS DO MONITORAMENTO")
        print("="*60)
        print(f"⏱️  Duração total: {duration:.2f}s")
        print(f"🔍 Total de verificações: {self.stats.total_checks}")
        print(f"✅ Verificações bem-sucedidas: {self.stats.successful_checks}")
        print(f"❌ Verificações falhadas: {self.stats.failed_checks}")
        print(f"📈 Uptime: {uptime:.2f}%")
        
        if self.stats.response_times:
            print(f"\n⚡ Tempos de resposta:")
            print(f"   Média: {avg_time:.2f}ms")
            print(f"   Mediana: {median_time:.2f}ms")
            print(f"   Mínimo: {min(self.stats.response_times):.2f}ms")
            print(f"   Máximo: {max(self.stats.response_times):.2f}ms")
        
        if self.stats.downtime_events:
            print(f"\n🚨 Total de eventos de downtime: {len(self.stats.downtime_events)}")
            print(f"   Primeiros eventos:")
            for event in self.stats.downtime_events[:5]:
                print(f"   - {event}")
            if len(self.stats.downtime_events) > 5:
                print(f"   ... e mais {len(self.stats.downtime_events) - 5} eventos")
        
        print("="*60)
        
        if self.log_file:
            print(f"\n📝 Log completo salvo em: {self.log_file}")
    
    def run(self):
        """Executa loop de monitoramento"""
        print(f"🔍 Iniciando monitoramento de {self.target}")
        print(f"📡 Tipo: {self.check_type.upper()}")
        print(f"⏱️  Intervalo: {self.interval}s")
        print(f"⏳ Timeout: {self.timeout}s")
        print(f"🎯 Threshold: {self.threshold}ms")
        if self.check_type == 'http':
            ssl_status = "✅ Habilitada" if self.verify_ssl else "⚠️  Desabilitada"
            print(f"🔒 Verificação SSL: {ssl_status}")
        if self.log_file:
            print(f"📝 Log: {self.log_file}")
        print(f"\n{'='*60}\n")
        
        try:
            while self.running:
                success, response_time, error_msg = self._check_service()
                
                self.stats.total_checks += 1
                if success:
                    self.stats.successful_checks += 1
                    self.stats.response_times.append(response_time)
                else:
                    self.stats.failed_checks += 1
                    downtime_event = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} - {error_msg}"
                    self.stats.downtime_events.append(downtime_event)
                
                self._print_status(success, response_time, error_msg)
                
                # Log todos os eventos
                log_status = "SUCCESS" if success else "FAILURE"
                self._log(f"{log_status}: {response_time:.2f}ms - {error_msg if error_msg else 'OK'}")
                
                time.sleep(self.interval)
        
        finally:
            self._print_statistics()


def main():
    parser = argparse.ArgumentParser(
        description='Monitor de disponibilidade de serviços com detecção de alta precisão',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  # Monitorar site HTTP a cada 100ms
  %(prog)s https://exemplo.com.br -i 0.1
  
  # Monitorar porta TCP a cada 50ms com threshold de 10ms
  %(prog)s exemplo.com:5432 -t tcp -i 0.05 -T 10
  
  # Monitorar via ICMP com log
  %(prog)s 8.8.8.8 -t icmp -l monitor.log
  
  # Verificação ultra-rápida (10ms de intervalo)
  %(prog)s https://api.exemplo.com/health -i 0.01 -T 5
  
  # Ignorar validação SSL (certificados auto-assinados)
  %(prog)s https://dev.interno.com -k -i 0.1
        """
    )
    
    parser.add_argument(
        'target',
        help='Alvo do monitoramento (URL, host:porta ou IP)'
    )
    
    parser.add_argument(
        '-t', '--type',
        choices=['http', 'tcp', 'icmp'],
        default='http',
        help='Tipo de verificação (padrão: http)'
    )
    
    parser.add_argument(
        '-i', '--interval',
        type=float,
        default=1.0,
        help='Intervalo entre verificações em segundos (padrão: 1.0, mínimo: 0.001)'
    )
    
    parser.add_argument(
        '-o', '--timeout',
        type=float,
        default=5.0,
        help='Timeout para cada verificação em segundos (padrão: 5.0)'
    )
    
    parser.add_argument(
        '-T', '--threshold',
        type=float,
        default=100.0,
        help='Threshold de latência em ms para alertas (padrão: 100.0)'
    )
    
    parser.add_argument(
        '-l', '--log-file',
        help='Arquivo para salvar log detalhado'
    )
    
    parser.add_argument(
        '-k', '--no-verify',
        action='store_true',
        help='Ignorar verificação de certificado SSL (apenas HTTP/HTTPS)'
    )
    
    args = parser.parse_args()
    
    # Validações
    if args.interval < 0.001:
        print("❌ Erro: intervalo mínimo é 0.001s (1ms)", file=sys.stderr)
        sys.exit(1)
    
    if args.timeout <= 0:
        print("❌ Erro: timeout deve ser maior que 0", file=sys.stderr)
        sys.exit(1)
    
    # Auto-detectar tipo se não especificado
    if args.type == 'http' and not args.target.startswith(('http://', 'https://')):
        if ':' in args.target and args.target.split(':')[-1].isdigit():
            print(f"ℹ️  Auto-detectado tipo TCP (porta especificada)")
            args.type = 'tcp'
    
    # Adicionar http:// se necessário
    if args.type == 'http' and not args.target.startswith(('http://', 'https://')):
        args.target = f"http://{args.target}"
    
    # Criar e executar monitor
    monitor = ServiceMonitor(
        target=args.target,
        check_type=args.type,
        interval=args.interval,
        timeout=args.timeout,
        threshold=args.threshold,
        log_file=args.log_file,
        verify_ssl=not args.no_verify
    )
    
    monitor.run()


if __name__ == '__main__':
    main()
