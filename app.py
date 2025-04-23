import os
import ssl
import socket
import datetime
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

DATA_FILE = 'data.json'  # Archivo donde se guardan los dominios
CACHE_DURATION = 300  # 5 minutos de caché
MAX_WORKERS = 10  # Número máximo de hilos para verificación paralela

app = Flask(__name__)

class DomainMonitor:
    def __init__(self):
        self.domains = {}
        self.alert_days = [10, 5, 3]
        self.alerts_sent = {}
        self.cache = {}
        self.cache_timestamp = {}

        # Configuración de email con variables de entorno
        self.email_config = {
            'sender': os.getenv('EMAIL_SENDER', 'konciliabyskit@gmail.com'),
            'password': os.getenv('EMAIL_PASSWORD', 'jeueaqarntuyguie'),
            'recipient': os.getenv('EMAIL_RECIPIENT', 'soporte@koncilia.com.co')
        }

        # Cargar dominios desde archivo JSON
        self.load_domains()
        
        # Iniciar el hilo de notificaciones programadas
        self.start_scheduled_notifications()

    def start_scheduled_notifications(self):
        """Inicia el hilo para enviar notificaciones programadas"""
        def notification_thread():
            while True:
                now = datetime.datetime.now(pytz.timezone('America/Bogota'))
                if now.hour == 9 and now.minute == 0:
                    self.send_daily_report()
                time.sleep(60)  # Verificar cada minuto

        thread = threading.Thread(target=notification_thread, daemon=True)
        thread.start()

    def send_daily_report(self):
        """Envía un reporte diario de todos los dominios"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender']
            msg['To'] = self.email_config['recipient']
            msg['Subject'] = '📊 Reporte Diario de Certificados SSL'

            # Preparar el cuerpo del email
            total_domains = len(self.domains)
            online_domains = sum(1 for info in self.domains.values() if info.get('has_ssl'))
            expiring_domains = sum(1 for info in self.domains.values() 
                                 if info.get('has_ssl') and info.get('days_remaining', 0) <= 30)

            body = f"""
            <h2>📊 Reporte Diario de Certificados SSL</h2>
            <p>Fecha: {datetime.datetime.now(pytz.timezone('America/Bogota')).strftime('%d/%m/%Y %H:%M')}</p>
            
            <h3>Resumen:</h3>
            <ul>
                <li>Total de dominios monitoreados: {total_domains}</li>
                <li>Dominios con SSL válido: {online_domains}</li>
                <li>Dominios por vencer (30 días o menos): {expiring_domains}</li>
            </ul>

            <h3>Dominios por vencer:</h3>
            <ul>
            """

            # Agregar dominios por vencer al reporte
            for domain, info in self.domains.items():
                if info.get('has_ssl') and info.get('days_remaining', 0) <= 30:
                    body += f"<li>{domain}: {info.get('days_remaining')} días restantes</li>"

            body += """
            </ul>
            """

            msg.attach(MIMEText(body, 'html'))

            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(self.email_config['sender'], self.email_config['password'])
                server.send_message(msg)

            print("✅ Reporte diario enviado")

        except Exception as e:
            print(f"❌ Error enviando reporte diario: {e}")

    def save_domains(self):
        """Guarda los dominios en un archivo JSON"""
        try:
            with open(DATA_FILE, 'w') as f:
                json.dump(self.domains, f, indent=4)
            print("💾 Dominios guardados en data.json")
        except Exception as e:
            print(f"❌ Error al guardar data.json: {e}")

    def load_domains(self):
        """Carga los dominios desde un archivo JSON"""
        try:
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, 'r') as f:
                    self.domains = json.load(f)
                print("📂 Dominios cargados desde data.json")
            else:
                print("⚠️ data.json no encontrado, iniciando con lista vacía.")
        except Exception as e:
            print(f"❌ Error al cargar data.json: {e}")

    def send_alert_email(self, domain, days_remaining):
        """Envía una alerta por correo si el certificado está por vencer"""
        if not self.email_config['password']:
            print("⚠️ No se ha configurado la contraseña del email. Cancelando envío.")
            return

        try:
            print(f"🚀 Enviando alerta para {domain} ({days_remaining} días restantes)...")

            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender']
            msg['To'] = self.email_config['recipient']
            msg['Subject'] = f'🔔 Alerta SSL - {domain} ({days_remaining} días restantes)'

            body = f"""
            <h2>⚠️ Alerta de Vencimiento de Certificado SSL</h2>
            <p>El certificado SSL de <strong>{domain}</strong> vence en {days_remaining} días.</p>
            <p>Para evitar interrupciones en el servicio, te recomendamos renovarlo lo antes posible.</p>
            """

            msg.attach(MIMEText(body, 'html'))

            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(self.email_config['sender'], self.email_config['password'])
                server.send_message(msg)

            print(f"✅ Alerta enviada para {domain}.")
            self.alerts_sent.setdefault(domain, set()).add(days_remaining)

        except Exception as e:
            print(f"❌ Error enviando email: {e}")

    def check_and_send_alerts(self, domain, days_remaining):
        """Verifica si se debe enviar una alerta"""
        if days_remaining in self.alert_days and days_remaining not in self.alerts_sent.get(domain, set()):
            self.send_alert_email(domain, days_remaining)

    def get_certificate_info(self, domain):
        """Obtiene la información SSL del dominio con caché"""
        # Verificar caché
        current_time = time.time()
        if (domain in self.cache and 
            domain in self.cache_timestamp and 
            current_time - self.cache_timestamp[domain] < CACHE_DURATION):
            return self.cache[domain]

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:  # Reducido a 5 segundos
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)

                    expiry_date = datetime.datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
                    days_remaining = (expiry_date - datetime.datetime.now()).days

                    result = {
                        'status': 'Online',
                        'has_ssl': True,
                        'common_name': dict(x509.get_subject().get_components()).get(b'CN', b'').decode(),
                        'valid_from': datetime.datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ').strftime('%d/%m/%Y'),
                        'valid_until': expiry_date.strftime('%d/%m/%Y'),
                        'days_remaining': days_remaining,
                        'last_check': datetime.datetime.now().strftime('%H:%M:%S')
                    }

                    # Actualizar caché
                    self.cache[domain] = result
                    self.cache_timestamp[domain] = current_time

                    return result

        except Exception as e:
            print(f"❌ Error en {domain}: {e}")
            result = {
                'status': 'Offline',
                'has_ssl': False,
                'error': 'No se pudo obtener el certificado.',
                'last_check': datetime.datetime.now().strftime('%H:%M:%S')
            }
            # Actualizar caché incluso para errores
            self.cache[domain] = result
            self.cache_timestamp[domain] = current_time
            return result

    def update_domains_parallel(self):
        """Actualiza la información de los dominios en paralelo"""
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
                    result = future.result()
                    self.domains[domain] = result
                except Exception as e:
                    print(f"❌ Error procesando {domain}: {e}")

        self.save_domains()

monitor = DomainMonitor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/add_domain', methods=['POST'])
def add_domain():
    """Añade un dominio y lo guarda en data.json"""
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Dominio requerido'}), 400

    info = monitor.get_certificate_info(domain)
    monitor.domains[domain] = info
    monitor.save_domains()  # Guardar cambios
    return jsonify(info)

@app.route('/api/remove_domain', methods=['POST'])
def remove_domain():
    """Elimina un dominio y actualiza data.json"""
    domain = request.json.get('domain')
    if domain in monitor.domains:
        del monitor.domains[domain]
        monitor.save_domains()  # Guardar cambios
    return jsonify({'status': 'success'})

@app.route('/api/get_domains')
def get_domains():
    """Devuelve la lista de dominios monitoreados"""
    return jsonify(monitor.domains)

@app.route('/api/send_test_email')
def send_test_email():
    """Envía un correo de prueba"""
    print("🔔 Enviando correo de prueba...")
    monitor.send_alert_email('dominio-prueba.com', 10)
    return jsonify({'status': 'Correo de prueba enviado'})

@app.route('/api/update_notes', methods=['POST'])
def update_notes():
    """Actualiza la nota de un dominio y la guarda en data.json"""
    data = request.json
    domain = data.get('domain')
    note = data.get('note')

    if not domain or domain not in monitor.domains:
        return jsonify({'error': 'Dominio no encontrado'}), 404

    if note is None:  # Evitar que se guarde como null
        return jsonify({'error': 'Nota vacía'}), 400

    # Guardar la observación en el JSON
    monitor.domains[domain]['note'] = note
    monitor.save_domains()  # Guardar en data.json

    return jsonify({'status': 'success', 'saved_note': note})

def update_domains():
    """Actualiza periódicamente la información de los dominios"""
    while True:
        print("🔄 Actualizando dominios...")
        monitor.update_domains_parallel()
        time.sleep(300)  # 5 minutos

if __name__ == '__main__':
    threading.Thread(target=update_domains, daemon=True).start()
    app.run(debug=True, port=5000)