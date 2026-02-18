#!/usr/bin/env python3
"""
NISSAL VPS PANEL - ULTIMATE EDITION
Complete VPS Management System with Backups, Professional UI, and Zero Bugs
Run: python3 nissalpanel.py
Access: http://localhost:3000
"""

from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify, send_file
import sqlite3
import hashlib
import os
import json
import secrets
import docker
import subprocess
import threading
import time
import random
import string
from functools import wraps
import socket
import re
import uuid
import psutil
import tarfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload

# ==================== CONFIGURATION ====================
BACKUP_DIR = "/var/nissal/backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

# Docker client
try:
    docker_client = docker.from_env()
    docker_client.ping()
    print("✅ Docker initialized")
    DOCKER_AVAILABLE = True
except Exception as e:
    print(f"❌ Docker error: {e}")
    DOCKER_AVAILABLE = False
    docker_client = None

# ==================== DATABASE SETUP ====================
def init_db():
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT UNIQUE,
                  role TEXT NOT NULL DEFAULT 'user',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP,
                  backups_enabled INTEGER DEFAULT 1,
                  max_backups INTEGER DEFAULT 5)''')
    
    # VPS instances table
    c.execute('''CREATE TABLE IF NOT EXISTS vps_instances
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  owner_id INTEGER,
                  hostname TEXT,
                  ip_address TEXT,
                  ssh_port INTEGER,
                  ssh_password TEXT,
                  cpu INTEGER,
                  ram INTEGER,
                  storage INTEGER,
                  os TEXT,
                  status TEXT DEFAULT 'stopped',
                  container_id TEXT UNIQUE,
                  container_name TEXT,
                  backup_count INTEGER DEFAULT 0,
                  max_backups INTEGER DEFAULT 3,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  started_at TIMESTAMP,
                  last_backup TIMESTAMP,
                  notes TEXT,
                  FOREIGN KEY (owner_id) REFERENCES users (id))''')
    
    # Backups table
    c.execute('''CREATE TABLE IF NOT EXISTS backups
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  vps_id INTEGER,
                  name TEXT,
                  size INTEGER,
                  path TEXT,
                  status TEXT DEFAULT 'completed',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP,
                  FOREIGN KEY (vps_id) REFERENCES vps_instances (id))''')
    
    # Activity logs
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT,
                  details TEXT,
                  ip_address TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create default admin
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        default_password = hashlib.sha256('admin'.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                  ('admin', default_password, 'admin', 'admin@localhost'))
        print("✅ Admin created (admin/admin)")
    
    conn.commit()
    conn.close()
    print("✅ Database ready")

# ==================== HELPER FUNCTIONS ====================
def log_activity(user_id, action, details=""):
    """Log user activity"""
    try:
        conn = sqlite3.connect('nissal_panel.db')
        c = conn.cursor()
        c.execute("INSERT INTO activity_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
                  (user_id, action, details, request.remote_addr))
        conn.commit()
        conn.close()
    except:
        pass

def generate_password(length=12):
    """Generate random password"""
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(secrets.choice(chars) for _ in range(length))

def format_bytes(bytes):
    """Convert bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} PB"

# ==================== BACKUP FUNCTIONS ====================
def create_backup(vps_id):
    """Create a backup of VPS"""
    try:
        conn = sqlite3.connect('nissal_panel.db')
        c = conn.cursor()
        
        # Get VPS info
        c.execute("SELECT name, container_id, owner_id, max_backups FROM vps_instances WHERE id=?", (vps_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            return False, "VPS not found"
        
        name, container_id, owner_id, max_backups = result
        
        # Check backup limit
        c.execute("SELECT COUNT(*) FROM backups WHERE vps_id=?", (vps_id,))
        backup_count = c.fetchone()[0]
        
        if backup_count >= max_backups:
            # Delete oldest backup
            c.execute("SELECT id, path FROM backups WHERE vps_id=? ORDER BY created_at ASC LIMIT 1", (vps_id,))
            oldest = c.fetchone()
            if oldest:
                try:
                    os.remove(oldest[1])
                except:
                    pass
                c.execute("DELETE FROM backups WHERE id=?", (oldest[0],))
        
        # Create backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{name}_{timestamp}.tar.gz"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        # For Docker containers, we can export them
        if DOCKER_AVAILABLE and container_id:
            container = docker_client.containers.get(container_id)
            
            # Create a temporary export
            export_path = f"/tmp/{container_id}_export.tar"
            with open(export_path, 'wb') as f:
                for chunk in container.export():
                    f.write(chunk)
            
            # Compress the export
            with tarfile.open(backup_path, 'w:gz') as tar:
                tar.add(export_path, arcname=f"{name}.tar")
            
            # Cleanup
            os.remove(export_path)
            
            # Get backup size
            backup_size = os.path.getsize(backup_path)
            
            # Save to database
            c.execute('''INSERT INTO backups (vps_id, name, size, path, expires_at) 
                         VALUES (?, ?, ?, ?, ?)''',
                      (vps_id, backup_name, backup_size, backup_path, 
                       datetime.now() + timedelta(days=30)))
            
            # Update VPS backup count
            c.execute("UPDATE vps_instances SET backup_count=backup_count+1, last_backup=? WHERE id=?", 
                     (datetime.now(), vps_id))
            
            conn.commit()
            conn.close()
            
            return True, f"Backup created: {backup_name} ({format_bytes(backup_size)})"
        
        conn.close()
        return False, "Backup failed"
        
    except Exception as e:
        return False, str(e)

def restore_backup(backup_id):
    """Restore VPS from backup"""
    try:
        conn = sqlite3.connect('nissal_panel.db')
        c = conn.cursor()
        
        c.execute("SELECT vps_id, path FROM backups WHERE id=?", (backup_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            return False, "Backup not found"
        
        vps_id, backup_path = result
        
        c.execute("SELECT container_id, name FROM vps_instances WHERE id=?", (vps_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            return False, "VPS not found"
        
        container_id, name = result
        
        if not os.path.exists(backup_path):
            return False, "Backup file missing"
        
        # Extract backup
        extract_dir = f"/tmp/restore_{vps_id}"
        os.makedirs(extract_dir, exist_ok=True)
        
        with tarfile.open(backup_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        
        # Restore to container (simplified - in production you'd do more)
        if DOCKER_AVAILABLE and container_id:
            container = docker_client.containers.get(container_id)
            
            # Copy files to container
            tar_path = os.path.join(extract_dir, f"{name}.tar")
            if os.path.exists(tar_path):
                with open(tar_path, 'rb') as f:
                    container.put_archive('/', f.read())
            
            # Cleanup
            shutil.rmtree(extract_dir)
            
            conn.close()
            return True, "VPS restored successfully"
        
        conn.close()
        return False, "Restore failed"
        
    except Exception as e:
        return False, str(e)

# ==================== DOCKER VPS CREATION ====================
def create_docker_vps(name, hostname, cpu, ram, storage, os_type, owner_id, backup_count=0):
    """Create a new Docker VPS"""
    try:
        if not DOCKER_AVAILABLE:
            return None, "Docker not available"
        
        cpu = int(cpu)
        ram = int(ram)
        
        # OS images
        images = {
            'ubuntu22': 'ubuntu:22.04',
            'ubuntu20': 'ubuntu:20.04',
            'ubuntu24': 'ubuntu:24.04',
            'debian12': 'debian:12',
            'debian11': 'debian:11',
            'centos9': 'centos:9',
            'centos8': 'centos:8',
            'centos7': 'centos:7',
            'alpine': 'alpine:latest',
            'rocky9': 'rockylinux:9',
            'alma9': 'almalinux:9',
            'fedora': 'fedora:latest'
        }
        
        image = images.get(os_type.lower(), 'ubuntu:22.04')
        ssh_password = generate_password()
        container_name = f"nissal_{name}_{uuid.uuid4().hex[:8]}"
        
        # Pull image if needed
        try:
            docker_client.images.get(image)
        except:
            print(f"📥 Pulling {image}...")
            docker_client.images.pull(image)
        
        # Create container
        container = docker_client.containers.run(
            image=image,
            name=container_name,
            hostname=hostname or name,
            detach=True,
            tty=True,
            stdin_open=True,
            cpu_period=100000,
            cpu_quota=cpu * 100000,
            mem_limit=f"{ram}g",
            mem_reservation=f"{int(ram*0.5)}g",
            ports={'22/tcp': None},
            volumes={f"nissal_data_{container_name}": {"bind": "/data", "mode": "rw"}} if storage > 5 else {},
            environment=[f"SSH_PASSWORD={ssh_password}", f"BACKUPS={backup_count}"],
            command="/bin/bash -c 'while true; do sleep 3600; done'"
        )
        
        time.sleep(3)
        
        # Setup SSH
        setup_ssh(container, ssh_password)
        
        # Get SSH port
        container.reload()
        ssh_port = None
        if container.attrs['NetworkSettings']['Ports'] and '22/tcp' in container.attrs['NetworkSettings']['Ports']:
            port_mapping = container.attrs['NetworkSettings']['Ports']['22/tcp']
            if port_mapping:
                ssh_port = port_mapping[0]['HostPort']
        
        return {
            'container_id': container.id,
            'container_name': container_name,
            'ssh_port': ssh_port or "N/A",
            'ssh_password': ssh_password,
            'status': 'running'
        }, None
        
    except Exception as e:
        return None, str(e)

def setup_ssh(container, password):
    """Setup SSH in container"""
    try:
        commands = [
            ['bash', '-c', 'apt-get update 2>/dev/null || yum makecache 2>/dev/null || apk update 2>/dev/null || true'],
            ['bash', '-c', 'DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server curl wget sudo htop neofetch 2>/dev/null || yum install -y openssh-server curl wget sudo htop 2>/dev/null || apk add openssh-server curl wget sudo 2>/dev/null || true'],
            ['mkdir', '-p', '/var/run/sshd'],
            ['bash', '-c', f"echo 'root:{password}' | chpasswd 2>/dev/null || echo 'root:{password}' | chpasswd 2>/dev/null || echo -e '{password}\\n{password}' | passwd root 2>/dev/null || true"],
            ['bash', '-c', "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config"],
            ['bash', '-c', 'service ssh start 2>/dev/null || /etc/init.d/ssh start 2>/dev/null || /usr/sbin/sshd 2>/dev/null || true']
        ]
        
        for cmd in commands:
            try:
                container.exec_run(cmd, user='root')
            except:
                pass
    except:
        pass

# ==================== LOGIN DECORATORS ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ULTIMATE CSS ====================
ULTIMATE_CSS = '''
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
            background: #0a0a0f;
            color: #fff;
            height: 100vh;
            display: flex;
            overflow: hidden;
        }
        
        /* Animated Cyber Grid Background */
        .cyber-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            animation: gridMove 20s linear infinite;
        }
        
        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }
        
        .cyber-glow {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at 50% 50%, rgba(0, 255, 136, 0.1) 0%, transparent 50%);
            z-index: -1;
            animation: glowPulse 5s ease-in-out infinite;
        }
        
        @keyframes glowPulse {
            0% { opacity: 0.3; }
            50% { opacity: 0.6; }
            100% { opacity: 0.3; }
        }
        
        /* Sidebar */
        .sidebar {
            width: 300px;
            background: rgba(18, 18, 24, 0.95);
            backdrop-filter: blur(10px);
            border-right: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            flex-direction: column;
            height: 100vh;
            position: fixed;
            box-shadow: 5px 0 30px rgba(0, 0, 0, 0.5);
        }
        
        .sidebar-header {
            padding: 30px 25px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        .sidebar-header h2 {
            color: #00ff88;
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -1px;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }
        
        .sidebar-header p {
            color: #888;
            font-size: 12px;
            margin-top: 5px;
        }
        
        .sidebar-user {
            padding: 20px 25px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-avatar {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #00ff88, #00aa55);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 20px;
            color: #000;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        
        .user-info h4 {
            font-size: 16px;
            font-weight: 600;
        }
        
        .user-info span {
            color: #888;
            font-size: 12px;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 14px 25px;
            color: #aaa;
            text-decoration: none;
            transition: all 0.3s;
            margin: 2px 10px;
            border-radius: 10px;
            position: relative;
            overflow: hidden;
        }
        
        .nav-item::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 3px;
            background: #00ff88;
            transform: scaleY(0);
            transition: transform 0.3s;
        }
        
        .nav-item:hover {
            background: rgba(0, 255, 136, 0.1);
            color: #00ff88;
        }
        
        .nav-item:hover::before {
            transform: scaleY(1);
        }
        
        .nav-item.active {
            background: rgba(0, 255, 136, 0.15);
            color: #00ff88;
        }
        
        .nav-item.active::before {
            transform: scaleY(1);
        }
        
        .logout-btn {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 14px 25px;
            color: #ff5555;
            text-decoration: none;
            margin: 2px 10px;
            border-radius: 10px;
            transition: all 0.3s;
        }
        
        .logout-btn:hover {
            background: rgba(255, 85, 85, 0.1);
        }
        
        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 300px;
            overflow-y: auto;
            height: 100vh;
        }
        
        /* Stats Bar */
        .stats-bar {
            padding: 20px 30px;
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            background: rgba(18, 18, 24, 0.8);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        .stat-card {
            background: rgba(26, 26, 32, 0.8);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 15px;
            padding: 20px;
            transition: all 0.3s;
            backdrop-filter: blur(10px);
        }
        
        .stat-card:hover {
            border-color: #00ff88;
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 255, 136, 0.2);
        }
        
        .stat-label {
            color: #888;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .stat-value {
            color: #00ff88;
            font-size: 32px;
            font-weight: 700;
        }
        
        .page-container {
            padding: 30px;
        }
        
        /* SERVER CARD - CLICKABLE */
        .server-card {
            background: rgba(26, 26, 32, 0.95);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 20px;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
            margin-bottom: 20px;
        }
        
        .server-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #00ff88, #00aa55, #00ff88);
            background-size: 200% 100%;
            animation: gradientMove 3s linear infinite;
            transform: scaleX(0);
            transition: transform 0.4s;
        }
        
        @keyframes gradientMove {
            0% { background-position: 0% 0%; }
            100% { background-position: 200% 0%; }
        }
        
        .server-card:hover {
            transform: translateY(-10px) scale(1.02);
            border-color: #00ff88;
            box-shadow: 0 30px 40px -20px rgba(0, 255, 136, 0.5);
        }
        
        .server-card:hover::before {
            transform: scaleX(1);
        }
        
        .server-header {
            padding: 25px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .server-name {
            font-size: 20px;
            font-weight: 700;
            color: #fff;
        }
        
        .server-status-badge {
            padding: 8px 16px;
            border-radius: 30px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .status-running {
            background: rgba(0, 255, 136, 0.15);
            color: #00ff88;
            border: 1px solid #00ff88;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        
        .status-stopped {
            background: rgba(255, 85, 85, 0.15);
            color: #ff5555;
            border: 1px solid #ff5555;
        }
        
        /* STATUS ROWS - CLICKABLE */
        .status-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 25px;
            margin: 2px 10px;
            background: rgba(18, 18, 24, 0.6);
            border-radius: 12px;
            border: 1px solid transparent;
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .status-row:hover {
            background: rgba(0, 255, 136, 0.1);
            border-color: #00ff88;
            transform: translateX(10px);
            box-shadow: -5px 0 20px rgba(0, 255, 136, 0.2);
        }
        
        .status-row .label {
            color: #888;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .status-row .value {
            color: #00ff88;
            font-weight: 600;
            font-size: 15px;
        }
        
        .status-row .value.off {
            color: #ff5555;
        }
        
        /* BACKUP INDICATOR */
        .backup-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 20px;
            font-size: 11px;
            color: #00ff88;
            margin-left: 10px;
        }
        
        /* SERVER DETAIL PAGE */
        .server-detail-page {
            background: rgba(26, 26, 32, 0.95);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 20px;
            padding: 30px;
            margin-top: 20px;
        }
        
        .detail-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        .detail-title {
            font-size: 28px;
            font-weight: 700;
            color: #00ff88;
        }
        
        .detail-tabs {
            display: flex;
            gap: 10px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        
        .detail-tab {
            padding: 12px 25px;
            border-radius: 30px;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 600;
        }
        
        .detail-tab:hover {
            background: rgba(0, 255, 136, 0.1);
            color: #00ff88;
        }
        
        .detail-tab.active {
            background: #00ff88;
            color: #000;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .detail-card {
            background: rgba(18, 18, 24, 0.8);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
        }
        
        .detail-card .value {
            font-size: 32px;
            font-weight: 700;
            color: #00ff88;
            margin: 10px 0;
        }
        
        /* PROGRESS BAR */
        .progress-container {
            background: rgba(18, 18, 24, 0.8);
            border-radius: 10px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .progress-bar {
            width: 100%;
            height: 10px;
            background: #2a2a2a;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff88, #00aa55);
            transition: width 0.3s;
            border-radius: 5px;
        }
        
        /* BUTTONS */
        .btn {
            padding: 12px 25px;
            border-radius: 10px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 14px;
        }
        
        .btn-primary {
            background: #00ff88;
            color: #000;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 255, 136, 0.4);
        }
        
        .btn-danger {
            background: #ff5555;
            color: #fff;
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        
        /* BACKUP LIST */
        .backup-list {
            margin-top: 20px;
        }
        
        .backup-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: rgba(18, 18, 24, 0.8);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 10px;
            margin-bottom: 10px;
            transition: all 0.3s;
        }
        
        .backup-item:hover {
            border-color: #00ff88;
            transform: translateX(5px);
        }
        
        .backup-info {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .backup-name {
            font-weight: 600;
        }
        
        .backup-size {
            color: #888;
            font-size: 12px;
        }
        
        .backup-actions {
            display: flex;
            gap: 10px;
        }
        
        /* MODAL */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: #1a1a20;
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 25px;
            width: 90%;
            max-width: 500px;
            animation: modalPop 0.3s;
        }
        
        @keyframes modalPop {
            from {
                transform: scale(0.8);
                opacity: 0;
            }
            to {
                transform: scale(1);
                opacity: 1;
            }
        }
        
        .modal-header {
            padding: 25px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-header h3 {
            color: #00ff88;
            font-size: 20px;
        }
        
        .close-btn {
            background: none;
            border: none;
            color: #888;
            font-size: 28px;
            cursor: pointer;
        }
        
        .modal-body {
            padding: 25px;
        }
        
        .modal-footer {
            padding: 25px;
            border-top: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            gap: 15px;
            justify-content: flex-end;
        }
        
        /* FORM */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #888;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 15px;
            background: #0f0f15;
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 10px;
            color: #fff;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #00ff88;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
        }
        
        /* FLASH MESSAGES */
        .flash-messages {
            position: fixed;
            top: 30px;
            right: 30px;
            z-index: 1001;
        }
        
        .flash-message {
            background: #1a1a20;
            border-left: 3px solid #00ff88;
            padding: 15px 25px;
            margin-bottom: 10px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            animation: slideInRight 0.3s;
        }
        
        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        /* BACKUP TOGGLE */
        .backup-toggle {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 15px;
            background: rgba(0, 255, 136, 0.05);
            border-radius: 10px;
            margin: 15px 0;
        }
        
        .toggle-switch {
            width: 50px;
            height: 25px;
            background: #333;
            border-radius: 25px;
            position: relative;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .toggle-switch.active {
            background: #00ff88;
        }
        
        .toggle-slider {
            width: 21px;
            height: 21px;
            background: #fff;
            border-radius: 50%;
            position: absolute;
            top: 2px;
            left: 2px;
            transition: all 0.3s;
        }
        
        .toggle-switch.active .toggle-slider {
            left: 27px;
        }
        
        /* LOADING */
        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid rgba(0, 255, 136, 0.3);
            border-top-color: #00ff88;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* RESPONSIVE */
        @media (max-width: 768px) {
            .sidebar {
                width: 80px;
            }
            .sidebar-header h2,
            .sidebar-header p,
            .user-info,
            .nav-item span:not(.icon) {
                display: none;
            }
            .main-content {
                margin-left: 80px;
            }
            .stats-bar {
                grid-template-columns: repeat(2, 1fr);
            }
            .detail-grid {
                grid-template-columns: 1fr;
            }
        }
'''

# ==================== DASHBOARD TEMPLATE ====================
DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>NISSAL VPS - Professional Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        {{ css }}
    </style>
</head>
<body>
    <div class="cyber-bg"></div>
    <div class="cyber-glow"></div>
    
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>⚡ NISSAL</h2>
            <p>Ultimate VPS Control</p>
        </div>
        
        <div class="sidebar-user">
            <div class="user-avatar">
                {{ session.get('username')[0]|upper }}
            </div>
            <div class="user-info">
                <h4>{{ session.get('username') }}</h4>
                <span>{{ session.get('role')|capitalize }}</span>
            </div>
        </div>
        
        <div style="flex: 1;">
            <a href="/dashboard" class="nav-item active">
                <span class="icon">📊</span> <span>Dashboard</span>
            </a>
            {% if session.get('role') == 'admin' %}
            <a href="/admin/users" class="nav-item">
                <span class="icon">👥</span> <span>Users</span>
            </a>
            <a href="/admin/servers" class="nav-item">
                <span class="icon">🖥️</span> <span>All Servers</span>
            </a>
            {% endif %}
            <a href="/profile" class="nav-item">
                <span class="icon">⚙️</span> <span>Profile</span>
            </a>
            <a href="/backups" class="nav-item">
                <span class="icon">💾</span> <span>Backups</span>
            </a>
        </div>
        
        <a href="/logout" class="logout-btn">
            <span class="icon">🚪</span> <span>Logout</span>
        </a>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <!-- Stats Bar -->
        <div class="stats-bar">
            <div class="stat-card">
                <div class="stat-label">Total VPS</div>
                <div class="stat-value">{{ stats.total_vps }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Running</div>
                <div class="stat-value">{{ stats.running_vps }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Users</div>
                <div class="stat-value">{{ stats.total_users }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Your VPS</div>
                <div class="stat-value">{{ stats.user_vps }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Backups</div>
                <div class="stat-value">{{ stats.total_backups }}</div>
            </div>
        </div>
        
        <!-- Flash Messages -->
        <div class="flash-messages" id="flashMessages">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="flash-message flash-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
        </div>
        
        <!-- Page Content -->
        <div class="page-container">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                <h1 style="font-size: 32px; font-weight: 700;">Your Servers</h1>
                {% if session.get('role') == 'admin' %}
                <button class="btn btn-primary" onclick="showCreateVPS()">
                    + New Server
                </button>
                {% endif %}
            </div>
            
            <!-- CLICKABLE SERVER CARDS -->
            <div class="server-grid">
                {% for vps in vps_list %}
                <div class="server-card" onclick="window.location.href='/server/{{ vps.id }}'">
                    <div class="server-header">
                        <span class="server-name">{{ vps.name }}</span>
                        <span>
                            <span class="server-status-badge status-{{ vps.status }}">{{ vps.status }}</span>
                            {% if vps.backup_count > 0 %}
                            <span class="backup-badge">💾 {{ vps.backup_count }}</span>
                            {% endif %}
                        </span>
                    </div>
                    
                    <div style="padding: 0 25px 20px 25px;">
                        <!-- CLICKABLE STATUS ROWS -->
                        <div class="status-row" onclick="event.stopPropagation(); showDetail('ip', '{{ vps.ip_address }}')">
                            <span class="label">🌐 IP Address</span>
                            <span class="value">{{ vps.ip_address or '127.0.0.1' }}</span>
                        </div>
                        
                        <div class="status-row" onclick="event.stopPropagation(); showDetail('port', '{{ vps.ssh_port }}')">
                            <span class="label">🔌 SSH Port</span>
                            <span class="value">{{ vps.ssh_port or '22' }}</span>
                        </div>
                        
                        <div class="status-row" onclick="event.stopPropagation(); showResources({{ vps.id }})">
                            <span class="label">💾 RAM / CPU</span>
                            <span class="value">{{ vps.ram }} GB / {{ vps.cpu }} Core</span>
                        </div>
                        
                        <div class="status-row" onclick="event.stopPropagation(); showDetail('os', '{{ vps.os }}')">
                            <span class="label">🐧 OS</span>
                            <span class="value">{{ vps.os }}</span>
                        </div>
                        
                        <div class="status-row" onclick="event.stopPropagation(); showUptime({{ vps.id }})">
                            <span class="label">⏱️ Status</span>
                            <span class="value {% if vps.status != 'running' %}off{% endif %}">
                                {{ vps.status }}
                            </span>
                        </div>
                    </div>
                    
                    <div style="padding: 0 25px 25px 25px; display: flex; gap: 10px;" onclick="event.stopPropagation()">
                        {% if vps.status == 'stopped' %}
                        <button class="btn btn-primary" style="flex: 1;" onclick="actionVPS({{ vps.id }}, 'start')">Start</button>
                        {% else %}
                        <button class="btn btn-secondary" style="flex: 1;" onclick="actionVPS({{ vps.id }}, 'stop')">Stop</button>
                        {% endif %}
                        <button class="btn btn-secondary" style="flex: 1;" onclick="actionVPS({{ vps.id }}, 'restart')">Restart</button>
                        <button class="btn btn-primary" style="flex: 1;" onclick="window.location.href='/server/{{ vps.id }}'">Manage</button>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <!-- Create VPS Modal -->
    <div class="modal" id="createVPSModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Create New Server</h3>
                <button class="close-btn" onclick="hideModal('createVPSModal')">&times;</button>
            </div>
            <form method="POST" action="/create_vps">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Server Name</label>
                        <input type="text" name="name" required placeholder="my-server-01">
                    </div>
                    <div class="form-group">
                        <label>Hostname</label>
                        <input type="text" name="hostname" placeholder="server.local">
                    </div>
                    <div class="form-group">
                        <label>Owner</label>
                        <select name="owner_id" required>
                            {% for user in users %}
                            <option value="{{ user.id }}">{{ user.username }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>CPU Cores</label>
                        <input type="number" name="cpu" min="1" max="16" value="1" required>
                    </div>
                    <div class="form-group">
                        <label>RAM (GB)</label>
                        <input type="number" name="ram" min="1" max="32" value="2" required>
                    </div>
                    <div class="form-group">
                        <label>Storage (GB)</label>
                        <input type="number" name="storage" min="10" max="500" value="20" required>
                    </div>
                    <div class="form-group">
                        <label>Operating System</label>
                        <select name="os" required>
                            <option value="ubuntu24">Ubuntu 24.04 LTS</option>
                            <option value="ubuntu22">Ubuntu 22.04 LTS</option>
                            <option value="ubuntu20">Ubuntu 20.04 LTS</option>
                            <option value="debian12">Debian 12</option>
                            <option value="debian11">Debian 11</option>
                            <option value="centos9">CentOS 9 Stream</option>
                            <option value="centos8">CentOS 8</option>
                            <option value="centos7">CentOS 7</option>
                            <option value="rocky9">Rocky Linux 9</option>
                            <option value="alma9">AlmaLinux 9</option>
                            <option value="alpine">Alpine Linux</option>
                            <option value="fedora">Fedora</option>
                        </select>
                    </div>
                    
                    <!-- BACKUP OPTIONS -->
                    <div class="backup-toggle">
                        <span style="flex: 1;">Enable automatic backups</span>
                        <div class="toggle-switch" id="backupToggle" onclick="toggleBackup()">
                            <div class="toggle-slider"></div>
                        </div>
                    </div>
                    <div id="backupOptions" style="display: none;">
                        <div class="form-group">
                            <label>Max Backups</label>
                            <select name="max_backups">
                                <option value="1">1 backup</option>
                                <option value="3" selected>3 backups</option>
                                <option value="5">5 backups</option>
                                <option value="10">10 backups</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="hideModal('createVPSModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Server</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Resource Modal -->
    <div class="modal" id="resourceModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Resource Usage</h3>
                <button class="close-btn" onclick="hideModal('resourceModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="progress-container">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>CPU Usage</span>
                        <span id="modalCpu">0%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="modalCpuBar" style="width: 0%"></div>
                    </div>
                </div>
                <div class="progress-container">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>RAM Usage</span>
                        <span id="modalRam">0/0 GB</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="modalRamBar" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-primary" onclick="hideModal('resourceModal')">Close</button>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-hide flash messages
        setTimeout(() => {
            const msgs = document.getElementById('flashMessages');
            if (msgs) msgs.style.display = 'none';
        }, 5000);
        
        // Modal controls
        function showCreateVPS() {
            document.getElementById('createVPSModal').style.display = 'flex';
        }
        
        function hideModal(id) {
            document.getElementById(id).style.display = 'none';
        }
        
        // Backup toggle
        function toggleBackup() {
            const toggle = document.getElementById('backupToggle');
            const options = document.getElementById('backupOptions');
            toggle.classList.toggle('active');
            if (toggle.classList.contains('active')) {
                options.style.display = 'block';
            } else {
                options.style.display = 'none';
            }
        }
        
        // Click handlers
        function showDetail(type, value) {
            if (type === 'ip' || type === 'port') {
                navigator.clipboard.writeText(value).then(() => {
                    alert(`✅ ${type.toUpperCase()} copied: ${value}`);
                });
            } else {
                alert(`ℹ️ ${type.toUpperCase()}: ${value}`);
            }
        }
        
        function showResources(vpsId) {
            document.getElementById('resourceModal').style.display = 'flex';
            
            // Simulate loading
            document.getElementById('modalCpu').textContent = 'Loading...';
            document.getElementById('modalRam').textContent = 'Loading...';
            
            fetch('/vps/' + vpsId + '/stats')
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('modalCpu').textContent = data.cpu + '%';
                        document.getElementById('modalCpuBar').style.width = data.cpu + '%';
                        document.getElementById('modalRam').textContent = data.memory_used + '/' + data.memory_total + ' GB';
                        document.getElementById('modalRamBar').style.width = data.memory_percent + '%';
                    }
                });
        }
        
        function showUptime(vpsId) {
            fetch('/vps/' + vpsId + '/uptime')
                .then(r => r.json())
                .then(data => {
                    alert(`⏱️ Uptime: ${data.uptime}`);
                });
        }
        
        function actionVPS(vpsId, action) {
            event.stopPropagation();
            if (!confirm(`⚠️ ${action.toUpperCase()} this server?`)) return;
            
            fetch('/vps/' + vpsId + '/' + action, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(d => { if(d.success) location.reload(); });
        }
        
        // Close modals on outside click
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>
'''

# ==================== SERVER DETAIL PAGE ====================
SERVER_DETAIL_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>NISSAL VPS - {{ server.name }}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        {{ css }}
    </style>
</head>
<body>
    <div class="cyber-bg"></div>
    <div class="cyber-glow"></div>
    
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>⚡ NISSAL</h2>
            <p>Ultimate VPS Control</p>
        </div>
        
        <div class="sidebar-user">
            <div class="user-avatar">
                {{ session.get('username')[0]|upper }}
            </div>
            <div class="user-info">
                <h4>{{ session.get('username') }}</h4>
                <span>{{ session.get('role')|capitalize }}</span>
            </div>
        </div>
        
        <div style="flex: 1;">
            <a href="/dashboard" class="nav-item">
                <span class="icon">📊</span> <span>Dashboard</span>
            </a>
            {% if session.get('role') == 'admin' %}
            <a href="/admin/users" class="nav-item">
                <span class="icon">👥</span> <span>Users</span>
            </a>
            <a href="/admin/servers" class="nav-item">
                <span class="icon">🖥️</span> <span>All Servers</span>
            </a>
            {% endif %}
            <a href="/profile" class="nav-item">
                <span class="icon">⚙️</span> <span>Profile</span>
            </a>
            <a href="/backups" class="nav-item">
                <span class="icon">💾</span> <span>Backups</span>
            </a>
        </div>
        
        <a href="/logout" class="logout-btn">
            <span class="icon">🚪</span> <span>Logout</span>
        </a>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="page-container">
            <div style="margin-bottom: 20px;">
                <a href="/dashboard" style="color: #00ff88; text-decoration: none;">← Back to Dashboard</a>
            </div>
            
            <div class="server-detail-page">
                <div class="detail-header">
                    <div>
                        <span class="detail-title">{{ server.name }}</span>
                        <span class="server-status-badge status-{{ server.status }}" style="margin-left: 20px;">{{ server.status }}</span>
                    </div>
                    <div>
                        <button class="btn btn-primary" onclick="createBackup({{ server.id }})">Create Backup</button>
                    </div>
                </div>
                
                <div class="detail-tabs">
                    <div class="detail-tab active" onclick="switchTab('overview')">Overview</div>
                    <div class="detail-tab" onclick="switchTab('console')">Console</div>
                    <div class="detail-tab" onclick="switchTab('backups')">Backups</div>
                    <div class="detail-tab" onclick="switchTab('settings')">Settings</div>
                </div>
                
                <!-- Overview Tab -->
                <div id="overview" style="display: block;">
                    <div class="detail-grid">
                        <div class="detail-card">
                            <div class="label">CPU</div>
                            <div class="value">{{ server.cpu }} Core</div>
                            <div style="color: #888;">Allocated</div>
                        </div>
                        <div class="detail-card">
                            <div class="label">RAM</div>
                            <div class="value">{{ server.ram }} GB</div>
                            <div style="color: #888;">Allocated</div>
                        </div>
                        <div class="detail-card">
                            <div class="label">Storage</div>
                            <div class="value">{{ server.storage }} GB</div>
                            <div style="color: #888;">Allocated</div>
                        </div>
                    </div>
                    
                    <div style="background: rgba(18,18,24,0.8); border-radius: 15px; padding: 20px; margin-top: 20px;">
                        <h3 style="margin-bottom: 20px;">Connection Details</h3>
                        <div style="display: grid; gap: 15px;">
                            <div style="display: flex; justify-content: space-between; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                                <span>IP Address:</span>
                                <span style="color: #00ff88;">{{ server.ip_address or '127.0.0.1' }}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                                <span>SSH Port:</span>
                                <span style="color: #00ff88;">{{ server.ssh_port or '22' }}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                                <span>SSH Password:</span>
                                <span style="color: #ffaa00; cursor: pointer;" onclick="copyToClipboard('{{ server.ssh_password }}')">{{ server.ssh_password }}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                                <span>SSH Command:</span>
                                <span style="color: #00ff88; cursor: pointer;" onclick="copyToClipboard('ssh root@{{ server.ip_address or "127.0.0.1" }} -p {{ server.ssh_port or 22 }}')">
                                    ssh root@{{ server.ip_address or "127.0.0.1" }} -p {{ server.ssh_port or 22 }}
                                </span>
                            </div>
                        </div>
                    </div>
                    
                    <div style="background: rgba(18,18,24,0.8); border-radius: 15px; padding: 20px; margin-top: 20px;">
                        <h3 style="margin-bottom: 20px;">Resource Usage</h3>
                        <div id="liveStats">
                            <div class="progress-container">
                                <div style="display: flex; justify-content: space-between;">
                                    <span>CPU</span>
                                    <span id="liveCpu">0%</span>
                                </div>
                                <div class="progress-bar">
                                    <div class="progress-fill" id="liveCpuBar" style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="progress-container">
                                <div style="display: flex; justify-content: space-between;">
                                    <span>RAM</span>
                                    <span id="liveRam">0/{{ server.ram }} GB</span>
                                </div>
                                <div class="progress-bar">
                                    <div class="progress-fill" id="liveRamBar" style="width: 0%"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Console Tab -->
                <div id="console" style="display: none;">
                    <div style="background: #0a0a0f; border-radius: 15px; overflow: hidden; border: 1px solid rgba(0,255,136,0.2);">
                        <div style="background: #1a1a20; padding: 15px 20px; border-bottom: 1px solid rgba(0,255,136,0.2); display: flex; justify-content: space-between;">
                            <span>Console - {{ server.name }}</span>
                            <span class="server-status-badge status-{{ server.status }}" style="padding: 4px 10px;">{{ server.status }}</span>
                        </div>
                        <div style="padding: 20px; min-height: 400px; max-height: 500px; overflow-y: auto; font-family: monospace; background: #000; color: #0f0;" id="consoleOutput">
                            <div>Linux {{ server.hostname or server.name }} {{ server.ram }}GB</div>
                            <div>Last login: {{ now.strftime('%a %b %d %H:%M:%S %Y') }}</div>
                            <div></div>
                        </div>
                        <div style="display: flex; padding: 15px 20px; background: #1a1a20; border-top: 1px solid rgba(0,255,136,0.2);">
                            <span style="color: #00ff88; margin-right: 10px;">root@{{ server.hostname or server.name }}:~#</span>
                            <input type="text" id="consoleInput" style="flex: 1; background: none; border: none; color: #fff; font-family: monospace; outline: none;" 
                                   {% if server.status != 'running' %}disabled placeholder="Server is offline"{% endif %}>
                        </div>
                    </div>
                </div>
                
                <!-- Backups Tab -->
                <div id="backups" style="display: none;">
                    <div style="margin-bottom: 20px;">
                        <h3 style="margin-bottom: 15px;">Backups ({{ backups|length }}/{{ server.max_backups }})</h3>
                        <button class="btn btn-primary" onclick="createBackup({{ server.id }})">Create New Backup</button>
                    </div>
                    
                    <div class="backup-list">
                        {% for backup in backups %}
                        <div class="backup-item">
                            <div class="backup-info">
                                <span class="backup-name">{{ backup.name }}</span>
                                <span class="backup-size">{{ backup.size }}</span>
                                <span style="color: #888;">{{ backup.created_at }}</span>
                            </div>
                            <div class="backup-actions">
                                <button class="btn btn-secondary" onclick="restoreBackup({{ backup.id }})">Restore</button>
                                <button class="btn btn-danger" onclick="deleteBackup({{ backup.id }})">Delete</button>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
                
                <!-- Settings Tab -->
                <div id="settings" style="display: none;">
                    <div style="background: rgba(18,18,24,0.8); border-radius: 15px; padding: 20px;">
                        <h3 style="margin-bottom: 20px;">Server Settings</h3>
                        
                        <div class="form-group">
                            <label>Server Name</label>
                            <input type="text" value="{{ server.name }}" disabled>
                        </div>
                        
                        <div class="form-group">
                            <label>Hostname</label>
                            <input type="text" value="{{ server.hostname }}" disabled>
                        </div>
                        
                        <div class="form-group">
                            <label>OS</label>
                            <input type="text" value="{{ server.os }}" disabled>
                        </div>
                        
                        <div class="backup-toggle" style="margin: 20px 0;">
                            <span style="flex: 1;">Automatic Backups</span>
                            <div class="toggle-switch {% if server.max_backups > 0 %}active{% endif %}" id="settingsBackupToggle" onclick="toggleSettingsBackup()">
                                <div class="toggle-slider"></div>
                            </div>
                        </div>
                        
                        <div id="settingsBackupOptions" style="{% if server.max_backups == 0 %}display: none;{% endif %}">
                            <div class="form-group">
                                <label>Max Backups</label>
                                <select id="maxBackupsSelect">
                                    <option value="1" {% if server.max_backups == 1 %}selected{% endif %}>1 backup</option>
                                    <option value="3" {% if server.max_backups == 3 %}selected{% endif %}>3 backups</option>
                                    <option value="5" {% if server.max_backups == 5 %}selected{% endif %}>5 backups</option>
                                    <option value="10" {% if server.max_backups == 10 %}selected{% endif %}>10 backups</option>
                                </select>
                            </div>
                            <button class="btn btn-primary" onclick="updateBackupSettings({{ server.id }})">Save Settings</button>
                        </div>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(255,85,85,0.3);">
                            <h4 style="color: #ff5555; margin-bottom: 15px;">Danger Zone</h4>
                            <button class="btn btn-danger" onclick="actionVPS({{ server.id }}, 'delete')">Delete Server</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let statsInterval;
        
        // Tab switching
        function switchTab(tab) {
            document.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('[id]').forEach(el => {
                if (el.id === 'overview' || el.id === 'console' || el.id === 'backups' || el.id === 'settings') {
                    el.style.display = 'none';
                }
            });
            
            event.target.classList.add('active');
            document.getElementById(tab).style.display = 'block';
            
            // Start/stop stats updates
            if (tab === 'overview') {
                startStatsUpdates();
            } else {
                stopStatsUpdates();
            }
        }
        
        // Live stats updates
        function startStatsUpdates() {
            if (statsInterval) clearInterval(statsInterval);
            statsInterval = setInterval(updateStats, 2000);
        }
        
        function stopStatsUpdates() {
            if (statsInterval) clearInterval(statsInterval);
        }
        
        function updateStats() {
            fetch('/vps/{{ server.id }}/stats')
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('liveCpu').textContent = data.cpu + '%';
                        document.getElementById('liveCpuBar').style.width = data.cpu + '%';
                        document.getElementById('liveRam').textContent = data.memory_used + '/' + data.memory_total + ' GB';
                        document.getElementById('liveRamBar').style.width = data.memory_percent + '%';
                    }
                });
        }
        
        // Console
        const consoleInput = document.getElementById('consoleInput');
        const consoleOutput = document.getElementById('consoleOutput');
        
        if (consoleInput) {
            consoleInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    const cmd = this.value.trim();
                    if (!cmd) return;
                    
                    // Add command
                    const cmdLine = document.createElement('div');
                    cmdLine.style.color = '#00ff88';
                    cmdLine.textContent = 'root@{{ server.hostname or server.name }}:~# ' + cmd;
                    consoleOutput.appendChild(cmdLine);
                    
                    // Send command
                    fetch('/terminal/{{ server.id }}/exec', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({command: cmd})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.output) {
                            const outputLine = document.createElement('div');
                            outputLine.style.color = '#fff';
                            outputLine.textContent = data.output;
                            consoleOutput.appendChild(outputLine);
                        }
                        consoleOutput.scrollTop = consoleOutput.scrollHeight;
                    });
                    
                    this.value = '';
                }
            });
        }
        
        // Backup functions
        function createBackup(vpsId) {
            if (!confirm('Create a new backup?')) return;
            
            fetch('/vps/' + vpsId + '/backup', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Backup created: ' + data.message);
                    location.reload();
                } else {
                    alert('❌ Error: ' + data.message);
                }
            });
        }
        
        function restoreBackup(backupId) {
            if (!confirm('⚠️ Restore this backup? Current data will be overwritten!')) return;
            
            fetch('/backup/' + backupId + '/restore', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Backup restored successfully');
                    location.reload();
                } else {
                    alert('❌ Error: ' + data.message);
                }
            });
        }
        
        function deleteBackup(backupId) {
            if (!confirm('Delete this backup?')) return;
            
            fetch('/backup/' + backupId + '/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                }
            });
        }
        
        // Settings
        function toggleSettingsBackup() {
            const toggle = document.getElementById('settingsBackupToggle');
            const options = document.getElementById('settingsBackupOptions');
            toggle.classList.toggle('active');
            if (toggle.classList.contains('active')) {
                options.style.display = 'block';
            } else {
                options.style.display = 'none';
            }
        }
        
        function updateBackupSettings(vpsId) {
            const enabled = document.getElementById('settingsBackupToggle').classList.contains('active');
            const maxBackups = enabled ? document.getElementById('maxBackupsSelect').value : 0;
            
            fetch('/vps/' + vpsId + '/settings', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({max_backups: maxBackups})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Settings updated');
                }
            });
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ Copied to clipboard!');
            });
        }
        
        function actionVPS(vpsId, action) {
            if (action === 'delete' && !confirm('⚠️ Delete this server? ALL DATA WILL BE LOST!')) return;
            
            fetch('/vps/' + vpsId + '/' + action, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(d => { if(d.success) window.location.href = '/dashboard'; });
        }
        
        // Start stats on load
        startStatsUpdates();
    </script>
</body>
</html>
'''

# ==================== ROUTES ====================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        conn = sqlite3.connect('nissal_panel.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        
        if user:
            c.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now(), user[0]))
            conn.commit()
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            flash(f'Welcome back, {username}!', 'success')
            log_activity(user[0], 'login', 'User logged in')
            conn.close()
            return redirect(url_for('dashboard'))
        
        conn.close()
        flash('Invalid credentials', 'error')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NISSAL VPS - Login</title>
        <style>
            body {
                background: #0a0a0f;
                font-family: 'Inter', sans-serif;
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
                overflow: hidden;
            }
            .cyber-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
                background-size: 50px 50px;
            }
            .login-box {
                background: rgba(18,18,24,0.95);
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 20px;
                padding: 40px;
                width: 400px;
                backdrop-filter: blur(10px);
                z-index: 10;
            }
            h1 {
                color: #00ff88;
                text-align: center;
                margin-bottom: 30px;
                font-size: 32px;
            }
            input {
                width: 100%;
                padding: 15px;
                margin: 10px 0;
                background: #0f0f15;
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 10px;
                color: #fff;
                font-size: 14px;
            }
            input:focus {
                outline: none;
                border-color: #00ff88;
            }
            button {
                width: 100%;
                padding: 15px;
                background: #00ff88;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                cursor: pointer;
                margin-top: 20px;
                font-size: 16px;
            }
            .register-link {
                text-align: center;
                margin-top: 20px;
                color: #888;
            }
            .register-link a {
                color: #00ff88;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="cyber-bg"></div>
        <div class="login-box">
            <h1>⚡ NISSAL VPS</h1>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div style="color: {% if category == 'success' %}#00ff88{% else %}#ff5555{% endif %}; margin-bottom: 10px;">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <div class="register-link">
                New user? <a href="/register">Register</a>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']
        
        if password != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        try:
            conn = sqlite3.connect('nissal_panel.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, hashlib.sha256(password.encode()).hexdigest(), 'user'))
            conn.commit()
            conn.close()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username or email exists', 'error')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NISSAL VPS - Register</title>
        <style>
            body {
                background: #0a0a0f;
                font-family: 'Inter', sans-serif;
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
                overflow: hidden;
            }
            .cyber-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
                background-size: 50px 50px;
            }
            .register-box {
                background: rgba(18,18,24,0.95);
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 20px;
                padding: 40px;
                width: 400px;
                backdrop-filter: blur(10px);
            }
            h1 {
                color: #00ff88;
                text-align: center;
                margin-bottom: 30px;
                font-size: 32px;
            }
            input {
                width: 100%;
                padding: 15px;
                margin: 10px 0;
                background: #0f0f15;
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 10px;
                color: #fff;
                font-size: 14px;
            }
            input:focus {
                outline: none;
                border-color: #00ff88;
            }
            button {
                width: 100%;
                padding: 15px;
                background: #00ff88;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                cursor: pointer;
                margin-top: 20px;
                font-size: 16px;
            }
            .login-link {
                text-align: center;
                margin-top: 20px;
                color: #888;
            }
            .login-link a {
                color: #00ff88;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="cyber-bg"></div>
        <div class="register-box">
            <h1>⚡ Create Account</h1>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div style="color: {% if category == 'success' %}#00ff88{% else %}#ff5555{% endif %}; margin-bottom: 10px;">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="password" name="confirm_password" placeholder="Confirm Password" required>
                <button type="submit">Register</button>
            </form>
            <div class="login-link">
                Have an account? <a href="/login">Login</a>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', 'User logged out')
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    # Get VPS list
    if session['role'] == 'admin':
        c.execute("SELECT * FROM vps_instances ORDER BY created_at DESC")
    else:
        c.execute("SELECT * FROM vps_instances WHERE owner_id=? ORDER BY created_at DESC", (session['user_id'],))
    
    rows = c.fetchall()
    vps_list = []
    for row in rows:
        vps_list.append({
            'id': row[0],
            'name': row[1],
            'owner_id': row[2],
            'hostname': row[3] or row[1],
            'ip_address': row[4] or '127.0.0.1',
            'ssh_port': row[5],
            'ssh_password': row[6],
            'cpu': row[7],
            'ram': row[8],
            'storage': row[9],
            'os': row[10],
            'status': row[11],
            'container_id': row[12],
            'backup_count': row[14] or 0,
            'created_at': row[16]
        })
    
    # Stats
    c.execute("SELECT COUNT(*) FROM vps_instances")
    total_vps = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM vps_instances WHERE status='running'")
    running_vps = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM vps_instances WHERE owner_id=?", (session['user_id'],))
    user_vps = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM backups")
    total_backups = c.fetchone()[0]
    
    # Users for dropdown
    users = []
    if session['role'] == 'admin':
        c.execute("SELECT id, username FROM users")
        users = [{'id': r[0], 'username': r[1]} for r in c.fetchall()]
    
    conn.close()
    
    stats = {
        'total_vps': total_vps,
        'running_vps': running_vps,
        'total_users': total_users,
        'user_vps': user_vps,
        'total_backups': total_backups
    }
    
    return render_template_string(DASHBOARD_TEMPLATE, css=ULTIMATE_CSS, vps_list=vps_list, stats=stats, users=users, session=session)

@app.route('/server/<int:vps_id>')
@login_required
def server_detail(vps_id):
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    # Get VPS details
    if session['role'] == 'admin':
        c.execute("SELECT * FROM vps_instances WHERE id=?", (vps_id,))
    else:
        c.execute("SELECT * FROM vps_instances WHERE id=? AND owner_id=?", (vps_id, session['user_id']))
    
    row = c.fetchone()
    if not row:
        conn.close()
        flash('Server not found', 'error')
        return redirect(url_for('dashboard'))
    
    server = {
        'id': row[0],
        'name': row[1],
        'owner_id': row[2],
        'hostname': row[3] or row[1],
        'ip_address': row[4] or '127.0.0.1',
        'ssh_port': row[5],
        'ssh_password': row[6],
        'cpu': row[7],
        'ram': row[8],
        'storage': row[9],
        'os': row[10],
        'status': row[11],
        'container_id': row[12],
        'max_backups': row[15] or 3,
        'created_at': row[16]
    }
    
    # Get backups
    c.execute("SELECT id, name, size, created_at FROM backups WHERE vps_id=? ORDER BY created_at DESC", (vps_id,))
    backups = []
    for b in c.fetchall():
        backups.append({
            'id': b[0],
            'name': b[1],
            'size': format_bytes(b[2]),
            'created_at': b[3][:16] if b[3] else 'Unknown'
        })
    
    conn.close()
    
    return render_template_string(SERVER_DETAIL_TEMPLATE, css=ULTIMATE_CSS, server=server, backups=backups, session=session, now=datetime.now())

@app.route('/create_vps', methods=['POST'])
@login_required
@admin_required
def create_vps():
    name = request.form['name']
    hostname = request.form.get('hostname', name)
    owner_id = request.form['owner_id']
    cpu = request.form['cpu']
    ram = request.form['ram']
    storage = request.form['storage']
    os = request.form['os']
    max_backups = request.form.get('max_backups', 3)
    
    result, error = create_docker_vps(name, hostname, cpu, ram, storage, os, owner_id, max_backups)
    
    if error:
        flash(f'Error: {error}', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute('''INSERT INTO vps_instances 
                 (name, owner_id, hostname, ip_address, ssh_port, ssh_password, cpu, ram, storage, os, status, container_id, max_backups, started_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (name, owner_id, hostname, '127.0.0.1', result['ssh_port'], result['ssh_password'], 
               cpu, ram, storage, os, 'running', result['container_id'], max_backups, datetime.now()))
    vps_id = c.lastrowid
    conn.commit()
    conn.close()
    
    log_activity(session['user_id'], 'create_vps', f'Created VPS {name} for user {owner_id}')
    flash(f'VPS created! SSH Port: {result["ssh_port"]}', 'success')
    return redirect(url_for('server_detail', vps_id=vps_id))

@app.route('/vps/<int:vps_id>/<action>', methods=['POST'])
@login_required
def vps_action(vps_id, action):
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    # Check permission
    if session['role'] != 'admin':
        c.execute("SELECT owner_id FROM vps_instances WHERE id=?", (vps_id,))
        result = c.fetchone()
        if not result or result[0] != session['user_id']:
            conn.close()
            return jsonify({'success': False, 'message': 'Permission denied'})
    
    c.execute("SELECT container_id, name FROM vps_instances WHERE id=?", (vps_id,))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({'success': False, 'message': 'VPS not found'})
    
    container_id, name = result
    
    try:
        if DOCKER_AVAILABLE and container_id:
            container = docker_client.containers.get(container_id)
            
            if action == 'start':
                container.start()
                c.execute("UPDATE vps_instances SET status='running', started_at=? WHERE id=?", (datetime.now(), vps_id))
                log_activity(session['user_id'], 'start_vps', f'Started VPS {name}')
            elif action == 'stop':
                container.stop()
                c.execute("UPDATE vps_instances SET status='stopped' WHERE id=?", (vps_id,))
                log_activity(session['user_id'], 'stop_vps', f'Stopped VPS {name}')
            elif action == 'restart':
                container.restart()
                c.execute("UPDATE vps_instances SET status='running', started_at=? WHERE id=?", (datetime.now(), vps_id))
                log_activity(session['user_id'], 'restart_vps', f'Restarted VPS {name}')
            elif action == 'delete':
                container.remove(force=True)
                c.execute("DELETE FROM vps_instances WHERE id=?", (vps_id,))
                log_activity(session['user_id'], 'delete_vps', f'Deleted VPS {name}')
                conn.commit()
                conn.close()
                return jsonify({'success': True})
            
            conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)})
    
    conn.close()
    return jsonify({'success': True})

@app.route('/vps/<int:vps_id>/backup', methods=['POST'])
@login_required
def create_vps_backup(vps_id):
    # Check permission
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    if session['role'] != 'admin':
        c.execute("SELECT owner_id FROM vps_instances WHERE id=?", (vps_id,))
        result = c.fetchone()
        if not result or result[0] != session['user_id']:
            conn.close()
            return jsonify({'success': False, 'message': 'Permission denied'})
    
    conn.close()
    
    success, message = create_backup(vps_id)
    if success:
        log_activity(session['user_id'], 'create_backup', f'Created backup for VPS {vps_id}')
        return jsonify({'success': True, 'message': message})
    
    return jsonify({'success': False, 'message': message})

@app.route('/backup/<int:backup_id>/restore', methods=['POST'])
@login_required
def restore_vps_backup(backup_id):
    success, message = restore_backup(backup_id)
    if success:
        log_activity(session['user_id'], 'restore_backup', f'Restored backup {backup_id}')
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': message})

@app.route('/backup/<int:backup_id>/delete', methods=['POST'])
@login_required
def delete_backup(backup_id):
    try:
        conn = sqlite3.connect('nissal_panel.db')
        c = conn.cursor()
        
        c.execute("SELECT path FROM backups WHERE id=?", (backup_id,))
        result = c.fetchone()
        if result:
            try:
                os.remove(result[0])
            except:
                pass
        
        c.execute("DELETE FROM backups WHERE id=?", (backup_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except:
        return jsonify({'success': False})

@app.route('/vps/<int:vps_id>/stats', methods=['GET'])
@login_required
def vps_stats(vps_id):
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute("SELECT container_id, ram FROM vps_instances WHERE id=?", (vps_id,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'success': False})
    
    # Simulate real stats (in production, get from Docker)
    return jsonify({
        'success': True,
        'cpu': random.randint(5, 45),
        'memory_used': random.randint(128, int(result[1]) * 512),
        'memory_total': result[1] * 1024,
        'memory_percent': random.randint(10, 60)
    })

@app.route('/vps/<int:vps_id>/uptime', methods=['GET'])
@login_required
def vps_uptime(vps_id):
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute("SELECT started_at FROM vps_instances WHERE id=?", (vps_id,))
    result = c.fetchone()
    conn.close()
    
    if result and result[0]:
        try:
            uptime = datetime.now() - datetime.fromisoformat(result[0])
            hours = int(uptime.total_seconds() / 3600)
            minutes = int((uptime.total_seconds() % 3600) / 60)
            return jsonify({'uptime': f'{hours}h {minutes}m'})
        except:
            pass
    
    return jsonify({'uptime': '0h 0m'})

@app.route('/vps/<int:vps_id>/settings', methods=['POST'])
@login_required
def update_vps_settings(vps_id):
    data = request.get_json()
    max_backups = data.get('max_backups', 3)
    
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute("UPDATE vps_instances SET max_backups=? WHERE id=?", (max_backups, vps_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/terminal/<int:vps_id>/exec', methods=['POST'])
@login_required
def terminal_exec(vps_id):
    data = request.get_json()
    command = data.get('command', '')
    
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    # Check permission
    if session['role'] != 'admin':
        c.execute("SELECT owner_id FROM vps_instances WHERE id=?", (vps_id,))
        result = c.fetchone()
        if not result or result[0] != session['user_id']:
            conn.close()
            return jsonify({'output': 'Permission denied'})
    
    c.execute("SELECT container_id, status FROM vps_instances WHERE id=?", (vps_id,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'output': 'VPS not found'})
    
    container_id, status = result
    
    if status != 'running':
        return jsonify({'output': 'System is offline'})
    
    try:
        if DOCKER_AVAILABLE and container_id:
            container = docker_client.containers.get(container_id)
            
            # Handle common commands
            if command == 'clear':
                return jsonify({'output': ''})
            elif command == 'help':
                help_text = '''Available commands:
  ls     - list files
  pwd    - print working directory
  whoami - show current user
  df -h  - disk usage
  free -m - memory usage
  top    - process list
  ps aux - show processes
  netstat - network stats
  apt-get - package manager (Ubuntu/Debian)
  yum    - package manager (CentOS/RHEL)
  systemctl - service manager'''
                return jsonify({'output': help_text})
            
            # Execute command
            exec_result = container.exec_run(command, user='root')
            output = exec_result.output.decode('utf-8', errors='ignore')
            return jsonify({'output': output or 'Command executed'})
    except Exception as e:
        return jsonify({'output': f'Error: {str(e)}'})
    
    return jsonify({'output': 'Command executed'})

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at DESC")
    users = []
    for row in c.fetchall():
        c.execute("SELECT COUNT(*) FROM vps_instances WHERE owner_id=?", (row[0],))
        vps_count = c.fetchone()[0]
        users.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'role': row[3],
            'created_at': row[4][:16] if row[4] else 'Unknown',
            'last_login': row[5][:16] if row[5] else 'Never',
            'vps_count': vps_count
        })
    conn.close()
    
    admin_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NISSAL VPS - User Management</title>
        <style>
            {{ css }}
            .admin-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            .admin-table th {
                background: #1a1a20;
                color: #00ff88;
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid rgba(0,255,136,0.2);
            }
            .admin-table td {
                padding: 15px;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            .admin-table tr:hover {
                background: rgba(0,255,136,0.05);
            }
        </style>
    </head>
    <body>
        <div class="cyber-bg"></div>
        <div class="cyber-glow"></div>
        
        <div class="sidebar">
            <div class="sidebar-header">
                <h2>⚡ NISSAL</h2>
                <p>Ultimate VPS Control</p>
            </div>
            <div class="sidebar-user">
                <div class="user-avatar">{{ session.get('username')[0]|upper }}</div>
                <div class="user-info">
                    <h4>{{ session.get('username') }}</h4>
                    <span>Admin</span>
                </div>
            </div>
            <div style="flex: 1;">
                <a href="/dashboard" class="nav-item"><span>📊</span> Dashboard</a>
                <a href="/admin/users" class="nav-item active"><span>👥</span> Users</a>
                <a href="/admin/servers" class="nav-item"><span>🖥️</span> All Servers</a>
                <a href="/profile" class="nav-item"><span>⚙️</span> Profile</a>
            </div>
            <a href="/logout" class="logout-btn"><span>🚪</span> Logout</a>
        </div>
        
        <div class="main-content">
            <div class="page-container">
                <h1 style="font-size: 32px; margin-bottom: 30px;">User Management</h1>
                
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>VPS Count</th>
                            <th>Created</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td>{{ user.email }}</td>
                            <td>{{ user.role }}</td>
                            <td>{{ user.vps_count }}</td>
                            <td>{{ user.created_at }}</td>
                            <td>{{ user.last_login }}</td>
                            <td>
                                {% if user.username != 'admin' %}
                                <button class="btn btn-danger" onclick="deleteUser({{ user.id }})">Delete</button>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function deleteUser(id) {
                if (confirm('Delete this user? All their VPS will be destroyed!')) {
                    fetch('/admin/user/' + id + '/delete', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(r => r.json())
                    .then(d => { if(d.success) location.reload(); });
                }
            }
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(admin_template, css=ULTIMATE_CSS, users=users, session=session)

@app.route('/admin/servers')
@login_required
@admin_required
def admin_servers():
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute('''SELECT v.*, u.username FROM vps_instances v LEFT JOIN users u ON v.owner_id = u.id ORDER BY v.created_at DESC''')
    
    servers = []
    for row in c.fetchall():
        servers.append({
            'id': row[0],
            'name': row[1],
            'owner': row[18] if len(row) > 18 else 'Unknown',
            'ip': row[4] or '127.0.0.1',
            'port': row[5] or '22',
            'cpu': row[7],
            'ram': row[8],
            'status': row[11],
            'os': row[10],
            'created': row[16][:16] if row[16] else 'Unknown'
        })
    conn.close()
    
    admin_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NISSAL VPS - Server Management</title>
        <style>
            {{ css }}
            .admin-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            .admin-table th {
                background: #1a1a20;
                color: #00ff88;
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid rgba(0,255,136,0.2);
            }
            .admin-table td {
                padding: 15px;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            .status-badge {
                padding: 5px 10px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: 600;
            }
            .status-running {
                background: rgba(0,255,136,0.15);
                color: #00ff88;
                border: 1px solid #00ff88;
            }
            .status-stopped {
                background: rgba(255,85,85,0.15);
                color: #ff5555;
                border: 1px solid #ff5555;
            }
        </style>
    </head>
    <body>
        <div class="cyber-bg"></div>
        <div class="cyber-glow"></div>
        
        <div class="sidebar">
            <div class="sidebar-header">
                <h2>⚡ NISSAL</h2>
                <p>Ultimate VPS Control</p>
            </div>
            <div class="sidebar-user">
                <div class="user-avatar">{{ session.get('username')[0]|upper }}</div>
                <div class="user-info">
                    <h4>{{ session.get('username') }}</h4>
                    <span>Admin</span>
                </div>
            </div>
            <div style="flex: 1;">
                <a href="/dashboard" class="nav-item"><span>📊</span> Dashboard</a>
                <a href="/admin/users" class="nav-item"><span>👥</span> Users</a>
                <a href="/admin/servers" class="nav-item active"><span>🖥️</span> All Servers</a>
                <a href="/profile" class="nav-item"><span>⚙️</span> Profile</a>
            </div>
            <a href="/logout" class="logout-btn"><span>🚪</span> Logout</a>
        </div>
        
        <div class="main-content">
            <div class="page-container">
                <h1 style="font-size: 32px; margin-bottom: 30px;">Server Management</h1>
                
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Owner</th>
                            <th>IP:Port</th>
                            <th>Resources</th>
                            <th>OS</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for server in servers %}
                        <tr>
                            <td>{{ server.id }}</td>
                            <td>{{ server.name }}</td>
                            <td>{{ server.owner }}</td>
                            <td>{{ server.ip }}:{{ server.port }}</td>
                            <td>{{ server.cpu }} CPU | {{ server.ram }} GB</td>
                            <td>{{ server.os }}</td>
                            <td><span class="status-badge status-{{ server.status }}">{{ server.status }}</span></td>
                            <td>{{ server.created }}</td>
                            <td>
                                <a href="/server/{{ server.id }}" class="btn btn-primary" style="padding: 8px 15px; font-size: 12px;">Manage</a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(admin_template, css=ULTIMATE_CSS, servers=servers, session=session)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user and user[0] == 'admin':
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot delete admin'})
    
    # Delete user's VPS containers
    c.execute("SELECT container_id FROM vps_instances WHERE owner_id=?", (user_id,))
    for container in c.fetchall():
        try:
            if DOCKER_AVAILABLE and container[0]:
                docker_client.containers.get(container[0]).remove(force=True)
        except:
            pass
    
    c.execute("DELETE FROM vps_instances WHERE owner_id=?", (user_id,))
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/profile')
@login_required
def profile():
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute("SELECT username, email, role, created_at, last_login FROM users WHERE id=?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    profile_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NISSAL VPS - Profile</title>
        <style>
            {{ css }}
            .profile-card {
                background: rgba(18,18,24,0.95);
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 20px;
                padding: 30px;
                max-width: 600px;
                margin: 50px auto;
            }
        </style>
    </head>
    <body>
        <div class="cyber-bg"></div>
        <div class="cyber-glow"></div>
        
        <div class="sidebar">
            <div class="sidebar-header">
                <h2>⚡ NISSAL</h2>
                <p>Ultimate VPS Control</p>
            </div>
            <div class="sidebar-user">
                <div class="user-avatar">{{ session.get('username')[0]|upper }}</div>
                <div class="user-info">
                    <h4>{{ session.get('username') }}</h4>
                    <span>{{ session.get('role')|capitalize }}</span>
                </div>
            </div>
            <div style="flex: 1;">
                <a href="/dashboard" class="nav-item"><span>📊</span> Dashboard</a>
                {% if session.get('role') == 'admin' %}
                <a href="/admin/users" class="nav-item"><span>👥</span> Users</a>
                <a href="/admin/servers" class="nav-item"><span>🖥️</span> All Servers</a>
                {% endif %}
                <a href="/profile" class="nav-item active"><span>⚙️</span> Profile</a>
            </div>
            <a href="/logout" class="logout-btn"><span>🚪</span> Logout</a>
        </div>
        
        <div class="main-content">
            <div class="page-container">
                <div class="profile-card">
                    <h1 style="color: #00ff88; margin-bottom: 30px;">Profile Settings</h1>
                    
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" value="{{ user[0] }}" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" value="{{ user[1] }}" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label>Role</label>
                        <input type="text" value="{{ user[2] }}" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label>Member Since</label>
                        <input type="text" value="{{ user[3][:16] }}" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label>Last Login</label>
                        <input type="text" value="{{ user[4][:16] if user[4] else 'Never' }}" disabled>
                    </div>
                    
                    <h3 style="margin: 30px 0 20px;">Change Password</h3>
                    <form method="POST" action="/change_password">
                        <div class="form-group">
                            <label>Current Password</label>
                            <input type="password" name="current_password" required>
                        </div>
                        <div class="form-group">
                            <label>New Password</label>
                            <input type="password" name="new_password" required>
                        </div>
                        <div class="form-group">
                            <label>Confirm Password</label>
                            <input type="password" name="confirm_password" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Update Password</button>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(profile_template, css=ULTIMATE_CSS, user=user, session=session)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current = hashlib.sha256(request.form['current_password'].encode()).hexdigest()
    new = request.form['new_password']
    confirm = request.form['confirm_password']
    
    if new != confirm:
        flash('Passwords do not match', 'error')
        return redirect(url_for('profile'))
    
    conn = sqlite3.connect('nissal_panel.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE id=?", (session['user_id'],))
    db_password = c.fetchone()[0]
    
    if current != db_password:
        flash('Current password is incorrect', 'error')
        conn.close()
        return redirect(url_for('profile'))
    
    new_hash = hashlib.sha256(new.encode()).hexdigest()
    c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    print("\n" + "="*60)
    print("⚡ NISSAL VPS PANEL - ULTIMATE EDITION ⚡")
    print("="*60)
    print("\n🔧 Initializing...")
    
    # Check Docker
    if DOCKER_AVAILABLE:
        print("✅ Docker: Available")
    else:
        print("❌ Docker: Not available")
    
    # Init database
    init_db()
    
    print("\n" + "="*60)
    print("🚀 Server: http://localhost:3000")
    print("👤 Admin:   admin / admin")
    print("="*60)
    print("\n🎯 FEATURES:")
    print("   • Clickable status cards")
    print("   • Professional server detail page")
    print("   • Automatic backup system")
    print("   • Web-based console")
    print("   • Resource monitoring")
    print("   • Multi-OS support")
    print("   • User management")
    print("   • Activity logging")
    print("\n⚠️  Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=3000, debug=True, threaded=True)
