from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from pydantic import BaseModel
from typing import Optional, List
from urllib.parse import quote_plus
import psutil
from bson import ObjectId
from datetime import datetime
import subprocess
import os

# URL encode the MongoDB password
db_password = "Adnan@66202"  # Replace with the actual password
encoded_password = quote_plus(db_password)

# MongoDB URI with encoded password
uri = f"mongodb+srv://adnankstheredteamlabs:{encoded_password}@cluster0.qrppz7h.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Establish a connection to the MongoDB Atlas cluster
client = MongoClient(uri)

# Access the database and collections
db = client["Zyra"]
device_collection = db["devices"]
packet_collection = db["packet"]
login_attempts_collection = db["login_attempts"]

# Initialize FastAPI app
app = FastAPI()

# Helper function to convert ObjectId to string
def objectid_to_str(doc):
    """Recursively convert all ObjectId fields in a document to strings."""
    if isinstance(doc, dict):
        return {k: objectid_to_str(v) for k, v in doc.items()}
    elif isinstance(doc, list):
        return [objectid_to_str(i) for i in doc]
    elif isinstance(doc, ObjectId):
        return str(doc)
    return doc

# Pydantic model for the device information
class DeviceInfo(BaseModel):
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    last_seen: Optional[str] = None
    system_health: Optional[str] = None
    cpu_info: Optional[str] = None

# Pydantic model for the packet information
class PacketInfo(BaseModel):
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: int
    packet_size: int

# Pydantic model for the login attempt information
class LoginAttemptInfo(BaseModel):
    timestamp: str
    username: str
    login_status: str
    protocol: str

# Pydantic model for a process ID
class ProcessKillRequest(BaseModel):
    pid: int

# Pydantic model for filesystem command request
class FileSystemCommandRequest(BaseModel):
    command: str

# API endpoint to get the device information by MAC address
@app.get("/device/{mac_address}", response_model=DeviceInfo)
async def get_device_info(mac_address: str):
    # Query the MongoDB collection for the device using the MAC address
    device = device_collection.find_one({"mac_address": mac_address})

    # If device is found, return it as a response
    if device:
        device_info = DeviceInfo(
            mac_address=device.get("mac_address"),
            hostname=device.get("hostname"),
            last_seen=device.get("last_seen", "N/A"),
            system_health=device.get("system_health", "N/A"),
            cpu_info=device.get("cpu_info", "N/A")
        )
        return device_info
    else:
        # Return a response with a custom error message and optional fields set to None
        return DeviceInfo(mac_address=None, hostname=None, last_seen=None, system_health=None, cpu_info=None)

# API endpoint to get packet information (all packets or filtered by source IP)
@app.get("/packets", response_model=List[PacketInfo])
async def get_packets(src_ip: Optional[str] = None):
    # If a source IP is provided, filter packets by source IP
    if src_ip:
        packets = packet_collection.find({"src_ip": src_ip})
    else:
        packets = packet_collection.find()

    # Convert the MongoDB cursor to a list of PacketInfo models
    packet_list = []
    for packet in packets:
        packet_info = PacketInfo(
            timestamp=str(packet["timestamp"]),  # Convert datetime to string
            src_ip=packet["src_ip"],
            dst_ip=packet["dst_ip"],
            protocol=packet["protocol"],
            packet_size=packet["packet_size"]
        )
        packet_list.append(packet_info)

    return packet_list

# API endpoint to get login attempt information (filtered by username or protocol)
@app.get("/login_attempts", response_model=List[LoginAttemptInfo])
async def get_login_attempts(
    username: Optional[str] = None,
    protocol: Optional[str] = None,
    login_status: Optional[str] = None
):
    # Build query filter based on provided parameters
    query_filter = {}
    if username:
        query_filter["username"] = username
    if protocol:
        query_filter["protocol"] = protocol
    if login_status:
        query_filter["login_status"] = login_status

    # Query the MongoDB collection for login attempts based on filters
    login_attempts = login_attempts_collection.find(query_filter)

    # Convert the MongoDB cursor to a list of LoginAttemptInfo models
    login_attempt_list = []
    for attempt in login_attempts:
        login_info = LoginAttemptInfo(
            timestamp=str(attempt["timestamp"]),  # Convert datetime to string
            username=attempt["username"],
            login_status=attempt["login_status"],
            protocol=attempt["protocol"]
        )
        login_attempt_list.append(login_info)

    return login_attempt_list

# API endpoint to clear all data in the collections
@app.delete("/clear_data", response_model=dict)
async def clear_data():
    try:
        # Clear all data from the collections
        device_collection.delete_many({})
        packet_collection.delete_many({})
        login_attempts_collection.delete_many({})

        # Return a success message
        return {"message": "All data has been cleared from the collections."}
    except Exception as e:
        # If an error occurs, return an error message
        return {"error": f"An error occurred while clearing the data: {str(e)}"}

# API endpoint to get the latest updates from the database (e.g., last device added)
@app.get("/latest_updates", response_model=dict)
async def get_latest_updates():
    try:
        # Get the latest device, packet, and login attempt
        latest_device = device_collection.find().sort("last_seen", -1).limit(1)
        latest_packet = packet_collection.find().sort("timestamp", -1).limit(1)
        latest_login_attempt = login_attempts_collection.find().sort("timestamp", -1).limit(1)

        latest_device_info = latest_device[0] if latest_device else None
        latest_packet_info = latest_packet[0] if latest_packet else None
        latest_login_attempt_info = latest_login_attempt[0] if latest_login_attempt else None

        # Convert ObjectId to string for MongoDB documents before returning
        return {
            "latest_device": objectid_to_str(latest_device_info),
            "latest_packet": objectid_to_str(latest_packet_info),
            "latest_login_attempt": objectid_to_str(latest_login_attempt_info)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching latest updates: {str(e)}")

# API endpoint to kill a process by PID
@app.post("/kill_process", response_model=dict)
async def kill_process(request: ProcessKillRequest):
    try:
        # Attempt to terminate the process with the given PID
        pid = request.pid
        process = psutil.Process(pid)
        process.terminate()  # Send a termination signal
        process.wait()  # Wait for the process to terminate
        return {"message": f"Process {pid} terminated successfully."}
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found.")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail=f"Permission denied to terminate process {pid}.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error terminating process {pid}: {str(e)}")

# API endpoint to execute filesystem access commands
@app.post("/filesystem_command", response_model=dict)
async def execute_filesystem_command(request: FileSystemCommandRequest):
    command = request.command

    try:
        if command.startswith("ls") or command.startswith("ps") or command.startswith("cat") or command.startswith("echo") or command.startswith("pgrep"):
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
            return {"output": output}
        elif command.startswith("cd"):
            # 'cd' command just changes the directory (no direct output)
            if len(command.split()) > 1:
                dir_path = command.split()[1]
                os.chdir(dir_path)
                return {"message": f"Changed directory to {dir_path}"}
            else:
                return {"message": "No directory specified."}
        elif command == "cd ..":
            os.chdir("..")
            return {"message": "Moved up one directory."}
        elif command == "reboot":
            subprocess.call(["sudo", "reboot"])
            return {"message": "System reboot initiated."}
        elif command == "poweroff":
            subprocess.call(["sudo", "poweroff"])
            return {"message": "System shutdown initiated."}
        else:
            return {"error": "Invalid command."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=400, detail=f"Error executing command: {e.output.decode()}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing command: {str(e)}")
