from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify,flash
import subprocess
import psycopg2
import os
from datetime import datetime
from scapy.all import sniff, wrpcap
import io
import time


app = Flask(__name__)

# Function to Clear ARP Cache 
def clear_arp_cache():
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        if os.name == 'nt':
            result = subprocess.run(['netsh', 'interface', 'ip', 'delete', 'arpcache'], capture_output=True, text=True, shell=True, check=True)
        else:
            result = subprocess.run(['ip', '-s', 'neigh', 'flush', 'all'], capture_output=True, text=True, shell=True, check=True)     
    except Exception as e:
        print("An error occurred:", e)

# Function to get the list of Connected Devices
def get_connected_devices(interface_ip, start_ip, end_ip):
    clear_arp_cache()  # Clear ARP cache before retrieving connected devices
    devices = []
    # Iterate over the IP range
    for i in range(start_ip, end_ip+1):
        ip = f"{interface_ip[:interface_ip.rfind('.')+1]}{i}"
        result = subprocess.Popen(['arp', '-a', ip], stdout=subprocess.PIPE)
        result = result.communicate()[0].decode().split('\n')
        for line in result:
            if len(line.split()) == 3:
                ip, mac, _ = line.split()
                devices.append({'ip': ip, 'mac': mac})
    return devices

# Function for updating device information
def update_device(ip, mac, device_name, device_description):
    try:
        conn = psycopg2.connect(
            dbname="Device Info",
            user="postgres",
            password="admin123#",
            host="localhost",
            port="5432"
        )
        cursor = conn.cursor()
        sql = "SELECT COUNT(*) AS total_count FROM connected_devices WHERE mac = %s"
        val = (mac,)  
        cursor.execute(sql, val)
        total_count = cursor.fetchone()[0]
        print("Total count:", total_count)
        conn.commit()
        if total_count > 0:
            sql = "UPDATE connected_devices SET device_name = %s, device_desc = %s WHERE mac = %s"
            val = (device_name, device_description, mac)
            cursor.execute(sql, val)
            conn.commit()
            sql1= "Select * from connected_devices"
            cursor.execute(sql1)
        else:
            sql = "INSERT INTO connected_devices (ip, mac, device_name, device_desc) VALUES (%s, %s, %s, %s)"
            val = (ip, mac, device_name, device_description)
            cursor.execute(sql, val)
            conn.commit()
    except psycopg2.Error as e:
        print("PostgreSQL error:", e)
    
# Flask Route for Update Device
@app.route('/update_device', methods=['POST'])
def update_device_route():
    try:
        ip = request.form['ip']
        mac = request.form['mac']
        device_name = request.form['device_name']
        device_description = request.form['device_description']
        update_device(ip, mac, device_name, device_description)
        flash('Updated successfully!', 'success')
    except psycopg2.Error as e:
        flash(f'Error updating info..: {str(e)}', 'error')
    return redirect(url_for('dashboard') )
    
# Function for fetching Device Name from DB
def fetch_device_name(mac):
    try:
        conn = psycopg2.connect(
            dbname="Device Info",
            user="postgres",
            password="admin123#",
            host="localhost",
            port="5432"
        )
        cursor = conn.cursor()
        cursor.execute("SELECT device_name FROM connected_devices WHERE mac=%s", (mac,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            return None
    except psycopg2.Error as e:
        print("PostgreSQL error:", e)
        return None

# Function for populating device informa
def populate_list(interface_ip, start_ip, end_ip):
    devices = get_connected_devices(interface_ip, start_ip, end_ip)
    device_list = []
    for device in devices:
        fetched = fetch_device_name(device['mac'])
        if fetched is not None:
            device_list.append({'display_name': fetched, 'ip': device['ip'], 'mac': device['mac']})
        else:
            device_list.append({'ip': device['ip'], 'mac': device['mac']})
    return device_list

# Flask main route
@app.route('/')
def index():
    return render_template('login.html')

# Flask route for login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == 'admin' and password == 'admin!':
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index'))

# Declare a global variable
connected_devices = []

# Flask route for Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'GET':
        return render_template('dashboard.html', devices=None)
    elif request.method == 'POST':
        interface_ip = '192.168.137.1'
        start_ip = 2
        end_ip = 254
        connected_devices = populate_list(interface_ip, start_ip, end_ip)
        print(connected_devices)
        return render_template('dashboard.html', devices=connected_devices)

# Flask Route for PCAP Capture
@app.route('/capture_pcap', methods=['POST'])
def capture_pcap():
    if request.method == 'POST':
        mac = request.form['mac']
        packets = int(request.form['packets'])
        folder = "C:\\Users\\HP\\Documents\\PCAP"  # Change this to your desired folder path
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        file_name = f"{mac}_{timestamp}.pcap"
        interface = "Virtual WLAN"  # Change this to your hosted network interface name see dependencies for the steps 
        
        try:
            # Create the folder if it doesn't exist
            os.makedirs(folder, exist_ok=True)
            # Capture packets and save to PCAP file
            capture_and_save_pcap(folder, file_name, interface, packets)
            # Return the captured pcap file path
            flash('Packet Capture successful!', 'success')
            flash('Saved in C:/Users/HP/Documents/PCAP', 'success')        

        except Exception as e:
            flash(f'Error capturing packets: {str(e)}', 'error')
        return redirect(url_for('dashboard') )

# Function for Capturing PCAP
def capture_and_save_pcap(folder, file_name, interface, count):
    """ Capture packets from the specified interface and save to a PCAP file """        
    print(f"Capturing {count} packets on interface {interface}...")
    packets = sniff(iface=interface, count=count)
    file_path = os.path.join(folder, file_name)
    wrpcap(file_path, packets)
    print(f"Packets captured and saved to {file_path}")
    return send_file(
                os.path.join(folder, file_name),
                as_attachment=True,
                mimetype="application/octet-stream"
            )

# Function for fetching records
def fetch_records():
    try:
        conn = psycopg2.connect(
            dbname="Device Info",
            user="postgres",
            password="admin123#",
            host="localhost",
            port="5432"
        )
        cur = conn.cursor()
        cur.execute("SELECT * FROM connected_devices")
        records = cur.fetchall()
        cur.close()
        conn.close()
        return records

    except psycopg2.Error as e:
        print("PostgreSQL error:", e)

# Flask route for Refresh 
@app.route('/refresh', methods=['GET', 'POST'])
def refresh():
    if request.method == 'POST':
        records = fetch_records()
        return render_template('dashboard.html', records=records)
    else:
        return redirect(url_for('dashboard'))

# Flask route for Logout
@app.route('/logout')
def logout():
    return redirect(url_for('index'))

# Main Function
if __name__ == '__main__':
    app.run(debug=True)


