import os
import ssl
import socket
import datetime as dt
import time
import threading
import json
from flask import Flask, render_template, jsonify, request
import OpenSSL.crypto as crypto
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytz
from collections import deque
import logging
import sys

# Configuración de logging para Azure
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)

logger = logging.getLogger(__name__)

DATA_FILE = 'data.json'  # Archivo donde se guardan los dominios
CACHE_DURATION = 300  # 5 minutos de caché
MAX_WORKERS = 10  # Número máximo de hilos para verificación paralela
MAX_LOGS = 100  # Máximo número de logs a mantener

app = Flask(__name__)

class DomainMonitor:
    def __init__(self):
        try:
            self.domains = {}
            self.alert_days = [10, 5, 4, 3, 2, 1]  # Días para enviar alertas
            self.alerts_sent = {}
            self.cache = {}
            self.cache_timestamp = {}
            self.last_alert_date = None
            self.last_update_time = None
            self.update_interval = 180  # 3 minutos entre actualizaciones
            self.logs = deque(maxlen=MAX_LOGS)  # Cola para almacenar logs
            self.file_lock = threading.Lock()

            # Configuración de email
            self.email_config = {
                'sender': os.getenv('EMAIL_SENDER', 'konciliabyskit@gmail.com'),
                'password': os.getenv('EMAIL_PASSWORD', 'jeueaqarntuyguie'),
                'recipient': os.getenv('EMAIL_RECIPIENT', 'soporte@koncilia.com.co')
            }

            self.add_log("🚀 Sistema iniciado")
            self.load_domains()
            
            # Iniciar hilos
            self.start_scheduled_notifications()
            self.start_domain_updater()
            
            logger.info("DomainMonitor inicializado correctamente")
        except Exception as e:
            logger.error(f"Error al inicializar DomainMonitor: {str(e)}")
            raise

    def add_log(self, message):
        """Añade un mensaje al registro de logs"""
        try:
            timestamp = dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = {
                'timestamp': timestamp,
                'message': message
            }
            self.logs.append(log_entry)
            logger.info(message)
        except Exception as e:
            logger.error(f"Error al agregar log: {str(e)}")

    def get_logs(self):
        """Retorna los logs almacenados"""
        return list(self.logs)

    def start_scheduled_notifications(self):
        """Inicia el hilo para enviar notificaciones programadas"""
        def notification_thread():
            while True:
                try:
                    now = dt.datetime.now(pytz.timezone('America/Bogota'))
                    current_time = now.strftime('%H:%M:%S')
                    current_date = now.date()
                    
                    self.add_log(f"🕒 Verificación de hora: {current_time}")
                    
                    if now.hour == 9 and now.minute == 0 and (self.last_alert_date is None or self.last_alert_date != current_date):
                        self.add_log("🕛 Iniciando envío de alertas (9:00 AM Bogotá)")
                        self.check_and_send_daily_alerts()
                        self.last_alert_date = current_date
                        self.add_log("✅ Proceso de alertas completado")
                    else:
                        time_until_next = dt.datetime.combine(
                            now.date() if now.hour < 9 else (now + dt.timedelta(days=1)).date(),
                            dt.time(9, 0)
                        )
                        if now.hour >= 9:
                            time_until_next += dt.timedelta(days=1)
                        
                        time_diff = time_until_next - now
                        hours = time_diff.seconds // 3600
                        minutes = (time_diff.seconds % 3600) // 60
                        
                        self.add_log(f"⏳ Próxima verificación de alertas en {hours}:{minutes:02d} horas")
                    
                    time.sleep(180)  # Verificar cada 3 minutos
                except Exception as e:
                    logger.error(f"Error en notification_thread: {str(e)}")
                    time.sleep(60)  # Esperar 1 minuto antes de reintentar

        thread = threading.Thread(target=notification_thread, daemon=True)
        thread.start()
        logger.info("Hilo de notificaciones iniciado")

    def check_and_send_daily_alerts(self):
        """Verifica y envía alertas diarias para certificados próximos a vencer"""
        self.add_log("🔍 Iniciando verificación de alertas diarias")
        print("=========================================")
        
        if not self.domains:
            self.add_log("⚠️ No hay dominios configurados para monitorear")
            return
            
        for domain, info in self.domains.items():
            self.add_log(f"📋 Verificando dominio: {domain}")
            self.add_log(f"📊 Información del dominio: {info}")
            
            if info.get('has_ssl', False) and 'days_remaining' in info:
                days_remaining = info['days_remaining']
                self.add_log(f"📅 Días restantes para {domain}: {days_remaining}")
                
                if days_remaining in self.alert_days:
                    self.add_log(f"⚠️ {domain} necesita alerta ({days_remaining} días restantes)")
                    self.add_log("📧 Iniciando envío de correo...")
                    self.send_alert_email(domain, days_remaining)
                else:
                    self.add_log(f"✅ {domain} no requiere alerta (días restantes: {days_remaining})")
            else:
                self.add_log(f"❌ {domain} no tiene información de SSL válida")
        
        self.add_log("✅ Verificación de alertas completada")
        print("=========================================\n")

    def send_alert_email(self, domain, days_remaining):
        """Envía una alerta por correo si el certificado está por vencer"""
        try:
            self.add_log("\n📨 Preparando correo de alerta")
            logger.info(f"Preparando correo de alerta para {domain}")
            
            if not self.email_config['password']:
                logger.error("No se ha configurado la contraseña del email")
                return

            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender']
            msg['To'] = self.email_config['recipient']
            msg['Subject'] = f'⚠️ Alerta: Certificado SSL próximo a vencer - {domain}'

            body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{
                        font-family: 'Segoe UI', Arial, sans-serif;
                        line-height: 1.4;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background: white;
                        border-radius: 10px;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        overflow: hidden;
                    }}
                    .header {{
                        background: #dc3545;
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 24px;
                        font-weight: 600;
                    }}
                    .content {{
                        padding: 30px;
                    }}
                    .domain-box {{
                        background: #f8f9fa;
                        border: 1px solid #dee2e6;
                        border-radius: 8px;
                        padding: 20px;
                        margin: 20px 0;
                        text-align: center;
                    }}
                    .domain-name {{
                        color: #0056b3;
                        font-size: 18px;
                        font-weight: bold;
                        word-break: break-all;
                    }}
                    .expiry-alert {{
                        background: #fff5f5;
                        color: #dc3545;
                        padding: 20px;
                        margin: 20px 0;
                        border-radius: 8px;
                        text-align: center;
                        font-size: 24px;
                        font-weight: bold;
                    }}
                    .warning-icon {{
                        font-size: 36px;
                        margin-bottom: 10px;
                    }}
                    .action-text {{
                        color: #495057;
                        text-align: center;
                        margin: 20px 0;
                    }}
                    .button {{
                        display: inline-block;
                        background: #0056b3;
                        color: white;
                        text-decoration: none;
                        padding: 12px 30px;
                        border-radius: 6px;
                        font-weight: 600;
                        margin: 20px 0;
                        text-align: center;
                    }}
                    .footer {{
                        background: #f8f9fa;
                        padding: 15px;
                        text-align: center;
                        font-size: 12px;
                        color: #6c757d;
                        border-top: 1px solid #dee2e6;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>⚠️ Alerta de Certificado SSL</h1>
                    </div>
                    
                    <div class="content">
                        <div class="domain-box">
                            <strong>El certificado SSL del dominio:</strong><br>
                            <div class="domain-name">{domain}</div>
                        </div>

                        <div class="expiry-alert">
                            <div class="warning-icon">⚠️</div>
                            Vence en {days_remaining} días
                        </div>

                        <div class="action-text">
                            Para evitar interrupciones en el servicio, es necesario renovar el certificado lo antes posible.
                        </div>

                        <div style="text-align: center;">
                            <a href="https://portal.azure.com/#home" class="button">
                                Ir a Azure Portal →
                            </a>
                        </div>
                    </div>

                    <div class="footer">
                        <p>Alerta diaria programada a las 9:00 AM (Bogotá)</p>
                        <p>© {dt.datetime.now().year} SSL Monitor - Koncilia</p>
                    </div>
                </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            logger.info("Conectando al servidor SMTP...")
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                logger.info("Iniciando conexión segura...")
                server.starttls()
                logger.info("Iniciando sesión...")
                server.login(self.email_config['sender'], self.email_config['password'])
                logger.info("Enviando correo...")
                server.send_message(msg)
                logger.info("Correo enviado exitosamente")

            self.add_log(f"✅ Alerta enviada para {domain}")
            self.alerts_sent.setdefault(domain, set()).add(days_remaining)

        except smtplib.SMTPAuthenticationError:
            logger.error("Error de autenticación SMTP")
            self.add_log("❌ Error de autenticación al enviar email")
        except smtplib.SMTPException as e:
            logger.error(f"Error SMTP: {str(e)}")
            self.add_log(f"❌ Error SMTP al enviar email: {str(e)}")
        except Exception as e:
            logger.error(f"Error inesperado al enviar email: {str(e)}")
            self.add_log(f"❌ Error inesperado al enviar email: {str(e)}")

    def check_and_send_alerts(self, domain, days_remaining):
        """Este método ya no se usa, mantenido por compatibilidad"""
        pass

    def save_domains(self):
        """Guarda los dominios en un archivo JSON de manera optimizada"""
        try:
            with self.file_lock:
                temp_file = f"{DATA_FILE}.tmp"
                with open(temp_file, 'w') as f:
                    json.dump(self.domains, f, indent=2)
                
                # Reemplazar archivo de manera segura
                os.replace(temp_file, DATA_FILE)
                self.add_log("💾 Dominios guardados correctamente")
        except Exception as e:
            self.add_log(f"❌ Error al guardar data.json: {e}")

    def load_domains(self):
        """Carga los dominios desde un archivo JSON de manera optimizada"""
        try:
            with self.file_lock:
                if os.path.exists(DATA_FILE):
                    with open(DATA_FILE, 'r') as f:
                        self.domains = json.load(f)
                    self.add_log("📂 Dominios cargados correctamente")
                else:
                    self.add_log("⚠️ data.json no encontrado, iniciando con lista vacía")
        except Exception as e:
            self.add_log(f"❌ Error al cargar data.json: {e}")
            self.domains = {}

    def get_certificate_info(self, domain):
        """Obtiene la información SSL del dominio con caché optimizada"""
        try:
            current_time = time.time()
            
            # Verificar caché válida
            if (domain in self.cache and 
                domain in self.cache_timestamp and 
                current_time - self.cache_timestamp[domain] < CACHE_DURATION):
                return self.cache[domain]

            # Timeout reducido para conexiones más rápidas
            context = ssl.create_default_context()
            context.timeout = 5  # 5 segundos de timeout
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)

                    # Calcular fechas una sola vez
                    now = dt.datetime.now()
                    expiry_date = dt.datetime.strptime(
                        x509.get_notAfter().decode(), 
                        '%Y%m%d%H%M%SZ'
                    )
                    
                    result = {
                        'status': 'Online',
                        'has_ssl': True,
                        'common_name': dict(x509.get_subject().get_components()).get(b'CN', b'').decode(),
                        'valid_from': dt.datetime.strptime(
                            x509.get_notBefore().decode(), 
                            '%Y%m%d%H%M%SZ'
                        ).strftime('%d/%m/%Y'),
                        'valid_until': expiry_date.strftime('%d/%m/%Y'),
                        'days_remaining': (expiry_date - now).days,
                        'last_check': now.strftime('%H:%M:%S')
                    }

                    # Actualizar caché
                    self.cache[domain] = result
                    self.cache_timestamp[domain] = current_time

                    return result

        except socket.timeout:
            logger.warning(f"Timeout al verificar certificado para {domain}")
            return {
                'status': 'Offline',
                'has_ssl': False,
                'error': 'Timeout al conectar',
                        'last_check': dt.datetime.now().strftime('%H:%M:%S')
            }
        except ssl.SSLError as e:
            logger.warning(f"Error SSL al verificar certificado para {domain}: {str(e)}")
            return {
                'status': 'Offline',
                'has_ssl': False,
                'error': f'Error SSL: {str(e)}',
                'last_check': dt.datetime.now().strftime('%H:%M:%S')
            }
        except Exception as e:
            logger.error(f"Error inesperado al verificar certificado para {domain}: {str(e)}")
            return {
                'status': 'Offline',
                'has_ssl': False,
                'error': str(e),
                'last_check': dt.datetime.now().strftime('%H:%M:%S')
            }

    def start_domain_updater(self):
        """Inicia un hilo separado para actualizar la información de los dominios"""
        def update_thread():
            while True:
                current_time = time.time()
                
                # Solo actualizar si han pasado 5 minutos o es la primera vez
                if self.last_update_time is None or (current_time - self.last_update_time) >= self.update_interval:
                    self.add_log("🔄 Actualizando información de dominios...")
                    self.update_domains_parallel()
                    self.last_update_time = current_time
                    self.add_log("✅ Actualización completada")
                else:
                    minutes_left = (self.update_interval - (current_time - self.last_update_time)) // 60
                    seconds_left = (self.update_interval - (current_time - self.last_update_time)) % 60
                    self.add_log(f"⏳ Próxima actualización en {int(minutes_left)}:{int(seconds_left):02d} minutos")
                
                time.sleep(30)  # Verificar cada 30 segundos

        thread = threading.Thread(target=update_thread, daemon=True)
        thread.start()

    def update_domains_parallel(self):
        """Actualiza la información de los dominios en paralelo de manera optimizada"""
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Crear un diccionario de futuros
                future_to_domain = {
                    executor.submit(self.get_certificate_info, domain): domain 
                    for domain in self.domains.keys()
                }

                # Procesar resultados a medida que se completan
                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result(timeout=10)  # Timeout de 10 segundos por dominio
                        self.domains[domain].update(result)
                    except Exception as e:
                        self.add_log(f"❌ Error procesando {domain}: {str(e)}")
                        # Mantener datos anteriores en caso de error
                        if domain not in self.domains:
                            self.domains[domain] = {
                                'status': 'Error',
                                'error': str(e),
                                'last_check': dt.datetime.now().strftime('%H:%M:%S')
                            }

            # Guardar en archivo solo si hubo cambios
            self.save_domains()
            
        except Exception as e:
            self.add_log(f"❌ Error en actualización paralela: {str(e)}")

monitor = DomainMonitor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/add_domain', methods=['POST'])
def add_domain():
    data = request.get_json()
    domain = data.get('domain')
    if domain:
        monitor.domains[domain] = monitor.get_certificate_info(domain)
        monitor.save_domains()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'No domain provided'}), 400

@app.route('/api/remove_domain', methods=['POST'])
def remove_domain():
    data = request.get_json()
    domain = data.get('domain')
    if domain in monitor.domains:
        del monitor.domains[domain]
        monitor.save_domains()
    return jsonify({'status': 'success'})

@app.route('/api/get_domains')
def get_domains():
    return jsonify(monitor.domains)

@app.route('/api/update_notes', methods=['POST'])
def update_notes():
    data = request.get_json()
    domain = data.get('domain')
    note = data.get('note')
    
    if domain in monitor.domains:
        monitor.domains[domain]['note'] = note
        monitor.save_domains()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Domain not found'}), 404

@app.route('/api/logs')
def get_logs():
    """Endpoint para obtener los logs del sistema"""
    return jsonify(monitor.get_logs())

def update_domains():
    """Actualiza periódicamente la información de los dominios"""
    while True:
        print("🔄 Actualizando dominios y verificando alertas...")
        monitor.update_domains_parallel()
        time.sleep(300)  # 5 minutos

if __name__ == '__main__':
    # Iniciar el hilo de actualización de dominios y alertas
    update_thread = threading.Thread(target=update_domains, daemon=True)
    update_thread.start()
    
    # Iniciar la aplicación Flask
    app.run(debug=False, use_reloader=False, port=5000)