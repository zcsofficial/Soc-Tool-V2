import psutil
import socket
import logging
from pymongo import MongoClient
from urllib.parse import quote_plus
import datetime
from scapy.all import sniff, IP, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse
import re
import os
import platform
import subprocess

# Configure logging
logging.basicConfig(
    filename="agent.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Function to get the MAC address
def get_mac_address():
    mac_address = None
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                mac_address = addr.address
                return mac_address
    return mac_address

# Function to get the hostname
def get_hostname():
    return socket.gethostname()

# Function to get system health metrics (CPU, memory, disk usage)
def get_system_health():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # Return a dictionary with system health metrics
    return {
        "cpu_usage": cpu_usage,
        "memory_usage": memory.percent,
        "disk_usage": disk.percent
    }

# Function to get detailed CPU information
def get_cpu_info():
    cpu_info = {
        "cpu_count": psutil.cpu_count(logical=False),  # Physical cores
        "cpu_count_logical": psutil.cpu_count(logical=True),  # Logical cores (including hyper-threading)
        "cpu_frequency": psutil.cpu_freq().current,  # Current frequency in MHz
        "cpu_model": psutil.cpu_info()[0].model if hasattr(psutil, 'cpu_info') else "N/A"  # CPU model
    }
    return cpu_info

# Function to send alert if system health is critical
def check_system_health(health_metrics):
    if health_metrics['cpu_usage'] > 85:
        logging.warning(f"High CPU usage detected: {health_metrics['cpu_usage']}%")
    if health_metrics['memory_usage'] > 90:
        logging.warning(f"High memory usage detected: {health_metrics['memory_usage']}%")
    if health_metrics['disk_usage'] > 90:
        logging.warning(f"High disk usage detected: {health_metrics['disk_usage']}%")

# Function to capture network traffic using scapy
def capture_network_traffic():
    # This function will be used for packet sniffing
    def packet_callback(packet):
        # Extract network traffic details
        if IP in packet:
            # Capture basic packet details
            packet_data = {
                "timestamp": datetime.datetime.now(),
                "src_ip": packet[IP].src,  # Source IP
                "dst_ip": packet[IP].dst,  # Destination IP
                "protocol": packet[IP].proto,  # Protocol (e.g., TCP)
                "packet_size": len(packet),  # Packet size in bytes
            }

            # Check for HTTP requests (potential login attempts)
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                if http_layer.Method == b"POST":
                    # Check for login attempts (basic username and password in POST requests)
                    if b"username" in http_layer.fields and b"password" in http_layer.fields:
                        login_data = {
                            "timestamp": datetime.datetime.now(),
                            "src_ip": packet[IP].src,
                            "dst_ip": packet[IP].dst,
                            "protocol": "HTTP",
                            "username": http_layer.fields.get(b"username", b"Unknown").decode(),
                            "password": http_layer.fields.get(b"password", b"Unknown").decode(),
                            "login_status": "unknown",  # Assuming "unknown" here, we would need to infer success/failure from the response
                        }
                        try:
                            result = login_attempts_collection.insert_one(login_data)
                            logging.info(f"Login attempt data inserted with ID: {result.inserted_id}")
                        except Exception as e:
                            logging.error(f"Error inserting login attempt data: {str(e)}")

            # Check for SSH login attempts (e.g., in the packet's payload)
            if packet.haslayer(TCP):
                if packet[IP].dst == "22":  # SSH default port
                    # We would need to inspect the payload for login attempts
                    payload = bytes(packet[TCP].payload)
                    if b"password" in payload or b"username" in payload:
                        login_data = {
                            "timestamp": datetime.datetime.now(),
                            "src_ip": packet[IP].src,
                            "dst_ip": packet[IP].dst,
                            "protocol": "SSH",
                            "username": "SSH_username",  # This needs to be extracted from the payload (if available)
                            "password": "SSH_password",  # Similarly, the password needs to be extracted
                            "login_status": "unknown",  # Inferred from response if possible
                        }
                        try:
                            result = login_attempts_collection.insert_one(login_data)
                            logging.info(f"Login attempt data inserted with ID: {result.inserted_id}")
                        except Exception as e:
                            logging.error(f"Error inserting SSH login attempt data: {str(e)}")

            # Insert packet data into MongoDB
            try:
                result = packet_collection.insert_one(packet_data)
                logging.info(f"Packet data inserted with ID: {result.inserted_id}")
            except Exception as e:
                logging.error(f"Error inserting packet data: {str(e)}")

    # Start sniffing for packets (captures packets every 5 seconds)
    sniff(prn=packet_callback, store=0, timeout=5)

# Function to capture system login activity (successful and failed login attempts)
def capture_system_login_activity():
    if platform.system() == "Linux":
        # Linux: Use the 'last' command to capture login events
        try:
            last_logins = subprocess.check_output("last", shell=True, stderr=subprocess.DEVNULL).decode()
            for line in last_logins.splitlines():
                if "still logged in" not in line:  # Filter out lines showing still active sessions
                    login_data = {
                        "timestamp": datetime.datetime.now(),
                        "username": line.split()[0],  # The first part is the username
                        "login_status": "success" if "logged in" in line else "failed",
                        "protocol": "SSH" if "ssh" in line else "Console",  # Assuming SSH for remote login, or Console for local
                    }
                    try:
                        result = login_attempts_collection.insert_one(login_data)
                        logging.info(f"System login attempt data inserted with ID: {result.inserted_id}")
                    except Exception as e:
                        logging.error(f"Error inserting system login activity: {str(e)}")
        except Exception as e:
            logging.error(f"Error capturing system login activity: {str(e)}")
    
    elif platform.system() == "Windows":
        # Windows: Capture login events using event logs
        try:
            # Check event log for login events (logon event 4624 and logoff event 4634)
            command = 'powershell Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} | Select-Object TimeCreated, Message'
            logins = subprocess.check_output(command, shell=True).decode()
            for line in logins.splitlines():
                if "Logon" in line:
                    login_data = {
                        "timestamp": datetime.datetime.now(),
                        "username": re.search(r"Account Name:\s+(.*)", line).group(1),
                        "login_status": "success",
                        "protocol": "Windows Login",  # Windows login protocol
                    }
                    try:
                        result = login_attempts_collection.insert_one(login_data)
                        logging.info(f"System login attempt data inserted with ID: {result.inserted_id}")
                    except Exception as e:
                        logging.error(f"Error inserting system login attempt data: {str(e)}")
        except Exception as e:
            logging.error(f"Error capturing Windows system login activity: {str(e)}")

# Function to execute system commands (like 'ls', 'ps', 'cd', etc.)
def execute_system_command(command):
    try:
        # Commands that interact with the filesystem (like cd, ls)
        if command.startswith("ls") or command.startswith("ps") or command.startswith("cat") or command.startswith("echo") or command.startswith("pgrep"):
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
            return output
        elif command.startswith("cd"):
            # The 'cd' command changes the current directory, which can't directly return output.
            dir_path = command.split(' ', 1)[1] if len(command.split(' ', 1)) > 1 else ''
            os.chdir(dir_path)
            return f"Changed directory to {dir_path}"
        elif command == "reboot":
            subprocess.call(["sudo", "reboot"])
            return "System reboot initiated."
        elif command == "poweroff":
            subprocess.call(["sudo", "poweroff"])
            return "System shutting down."
        else:
            return "Command not recognized."
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command {command}: {str(e)}")
        return f"Error executing command {command}: {str(e)}"

# Replace <db_password> with the actual password and URL encode it
db_password = "Adnan@66202"  # Replace with the actual password
encoded_password = quote_plus(db_password)

# MongoDB connection URI with encoded password
uri = f"mongodb+srv://adnankstheredteamlabs:{encoded_password}@cluster0.qrppz7h.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Establish a connection to the MongoDB Atlas cluster
client = MongoClient(uri)

# Access the database and collections
db = client["Zyra"]  # database name
device_collection = db["devices"]  # collection for device info
packet_collection = db["packet"]  # collection for network traffic data
login_attempts_collection = db["login_attempts"]  # collection for login attempts
active_apps_collection = db["active_apps"]  # collection for active app activity

# Get the MAC address and hostname
mac_address = get_mac_address()
hostname = get_hostname()

# Get system health metrics
health_metrics = get_system_health()

# Get detailed CPU information
cpu_info = get_cpu_info()

# Check system health
check_system_health(health_metrics)

# Check if MAC address is found
if mac_address:
    # Create a document with the MAC address as the unique identifier and additional system info
    device_info = {
        "mac_address": mac_address,
        "hostname": hostname,
        "last_seen": datetime.datetime.now(),
        "system_health": health_metrics,
        "cpu_info": cpu_info  # Include CPU info in the document
    }

    # Insert or update the document into the collection
    result = device_collection.update_one(
        {"mac_address": mac_address},  # Find the document by MAC address
        {"$set": device_info},  # Update the document with new information
        upsert=True  # Create a new document if it doesn't exist
    )

    # Log the result
    logging.info(f"Device info {'updated' if result.modified_count else 'inserted'} successfully.")
else:
    logging.error("MAC address could not be retrieved.")
    print("MAC address could not be retrieved.")

# Start capturing network traffic in a loop
while True:
    capture_network_traffic()
    capture_system_login_activity()
    
