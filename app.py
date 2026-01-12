from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
from paho.mqtt import client as mqtt_classic
from paho.mqtt.enums import CallbackAPIVersion
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
MQTT_BROKER = os.getenv("MQTT_BROKER")
MQTT_TOPIC = os.getenv("MQTT_TOPIC")
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
mqtt_status = {"connected": False}

def send_telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"Telegram Error: {e}")

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        mqtt_status["connected"] = True
        print("Connected to MQTT Broker!")
        client.subscribe(MQTT_TOPIC)
    else:
        mqtt_status["connected"] = False

last_saved_data = {"temp": None, "hum": None, "time": None}
last_alert_time = datetime.now(timezone.utc) - timedelta(minutes=10)

def on_disconnect(client, userdata, flags, rc, properties=None):
    mqtt_status["connected"] = False
    print(f"Disconnected from MQTT. Code: {rc}")

def on_message(client, userdata, msg):
    global last_saved_data, last_alert_time
    now = datetime.now(timezone.utc)

    try:
        payload = msg.payload.decode()
        data = json.loads(payload)
        
        if "command" in data:
            return

        r_temp = data.get('temperature')
        r_hum = data.get('humidity')

        temp = float(r_temp)
        hum = float(r_hum)

        if temp > 30.0 and (now - last_alert_time).total_seconds() > 600:
            send_telegram_alert(f"🔥 Teplota je príliš vysoká: {temp}°C")
            last_alert_time = now
        
        if hum < 20.0:
            send_telegram_alert(f"💧 POZOR! Nízka vlhkosť: {hum}%")

        if r_temp is None or r_hum is None:
            print("MQTT Warning: Skip None values")
            return

        temp = float(r_temp)
        hum = float(r_hum)
        now = datetime.now(timezone.utc)

        if last_saved_data["time"] is not None:
            is_same_val = (last_saved_data["temp"] == temp and last_saved_data["hum"] == hum)
            diff = (now - last_saved_data["time"]).total_seconds()
            if is_same_val and diff < 10:
                return

        with app.app_context():
            new_reading = SensorData(temp=temp, hum=hum, user_id=1) 
            db.session.add(new_reading)
            db.session.commit()

            message = f"📊 Prijaté nové údaje:\n🌡 Teplota: {temp}°C\n💧 Vlhkosť: {hum}%"
            send_telegram_alert(message)
            
            last_saved_data = {"temp": temp, "hum": hum, "time": now}
            
    except Exception as e:
        print(f"MQTT Error: {e}")

mqtt_client = mqtt_classic.Client(CallbackAPIVersion.VERSION2)

if MQTT_USER and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

    mqtt_client.tls_set()

mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.on_disconnect = on_disconnect

db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    readings = db.relationship('SensorData', backref='owner', lazy=True)

class SensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    temp = db.Column(db.Float, nullable=False)
    hum = db.Column(db.Float, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.context_processor
def inject_now():
    from datetime import timedelta
    return {'timedelta': timedelta}

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    current_user.last_seen = datetime.now(timezone.utc)
    db.session.commit()
    limit = request.args.get('limit', 5, type=int)
    all_readings = SensorData.query.filter_by(user_id=current_user.id)\
        .order_by(SensorData.date_posted.desc()).limit(50).all()
    display_update_time = (current_user.last_seen + timedelta(hours=1)).strftime('%H:%M:%S')
    graph_readings = all_readings[::-1]
    labels = [(r.date_posted + timedelta(hours=1)).strftime('%H:%M:%S') for r in graph_readings]
    temp_data = [r.temp for r in graph_readings]
    hum_data = [r.hum for r in graph_readings]

    return render_template('dashboard.html', readings=all_readings, labels=labels, temp_data=temp_data, hum_data=hum_data, update_time=display_update_time, limit=limit, mqtt_connected=mqtt_status["connected"])

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            flash('This username is already taken. Please choose another one.', 'danger')
            return render_template('register.html', title='Register')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('There was an error while registering. Please try again.', 'danger')
            print(f"Registration Error: {e}")
            
    return render_template('register.html', title='Register')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            send_telegram_alert(f"🔐 Používateľ {user.username} je prihlásený!")
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/trigger_measurement")
@login_required
def trigger_measurement():
    command = json.dumps({"command": "measure"})
    mqtt_client.publish(MQTT_TOPIC, command)
    flash('The command has been sent! Wait for the data to update.', 'info')
    return redirect(url_for('dashboard'))

@app.route("/shutdown")
@login_required
def shutdown():
    command = json.dumps({"command": "shutdown"})
    mqtt_client.publish(MQTT_TOPIC, command)
    flash('The command has been sent!', 'info')
    return redirect(url_for('dashboard'))

@app.route("/mqtt_status")
def get_mqtt_status():
    return {"connected": mqtt_status["connected"]}

@app.route("/ping")
def ping():
    return "OK", 200

with app.app_context():
    try:
        db.session.execute(db.text('SELECT 1'))
        print("DATABASE CONNECTION SUCCESSFUL: PostgreSQL is ready!")
        db.create_all()
    except Exception as e:
        print(f"DATABASE CONNECTION FAILED: {e}")

if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    try:
        mqtt_client.reconnect_delay_set(min_delay=1, max_delay=120)
        mqtt_client.connect(MQTT_BROKER, 8883, 60)
        mqtt_client.loop_start()
        send_telegram_alert("🚀 Monitorovací systém je spustený!")
    except Exception as e:
        print(f"MQTT Connect Error: {e}")

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)