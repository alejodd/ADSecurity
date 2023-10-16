import tkinter as tk
from tkinter import filedialog
import requests
import threading
import time
import os

API_KEY = "YOUR_APY_KEY" # https://www.virustotal.com/gui/my-apikey
SCAN_URL = "https://www.virustotal.com/api/v3/files"
REPORT_URL = "https://www.virustotal.com/api/v3/analyses"
URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"

def check_ip_reputation(ip_address):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": API_KEY,
            "accept": "application/json",
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            ip_info = response.json()
            reputation = ip_info["data"]["attributes"]["last_analysis_stats"]
            return reputation
        else:
            return {"error": f"No se pudo obtener la reputación de la IP: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}

def check_scan_status(data_id, headers):
    global result_time
    report_url = f"{REPORT_URL}/{data_id}"
    while True:
        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            report = response.json()
            status = report["data"]["attributes"]["status"]
            if status == "completed":
                positives = report["data"]["attributes"]["stats"]["malicious"]
                result_text.set(f"Posibles amenazas detectadas: {positives}")
                result_text_time.set(f"Tiempo de Escaneo: {elapsed_time:.2f} segundos")
                break
            elif status == "queued" or status == "analyzing":
                time.sleep(5)
            else:
                result_text.set("El escaneo no se completó o ocurrió un error.")
                break
        else:
            result_text.set("No se pudo obtener el informe de escaneo.")
            break

def scan_file():
    global upload_time, result_time
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            headers = {
                "x-apikey": API_KEY,
            }

            result_text.set("")
            result_text_time.set("")

            upload_time = time.time()

            with open(file_path, "rb") as file:
                file_name = os.path.basename(file_path)
                result_text.set(f"Cargando y verificando: {file_name}...")

                response = requests.post(SCAN_URL, headers=headers, files={"file": file})
                if response.status_code == 200:
                    data_id = response.json()["data"]["id"]

                    result_time = time.time()

                    t = threading.Thread(target=check_scan_status, args=(data_id, headers))
                    t.start()
                else:
                    result_text.set("No se pudo cargar el archivo :/ (Intente más tarde).")
        except Exception as e:
            result_text.set(f"Error: {str(e)}")

def scan_url():
    global result_time, upload_time
    url = url_entry.get()
    if url:
        try:
            headers = {
                "x-apikey": API_KEY,
            }

            result_text.set("")
            result_text_time.set("")

            upload_time = time.time()

            result_text.set(f"Escaneando URL: {url}...")

            response = requests.post(URL_SCAN_URL, headers=headers, data={"url": url})

            if response.status_code == 200:
                data_id = response.json()["data"]["id"]

                result_time = time.time()

                t = threading.Thread(target=check_scan_status, args=(data_id, headers))
                t.start()
            else:
                result_text.set("No se pudo escanear la URL :/ (Intente más tarde).")
        except Exception as e:
            result_text.set(f"Error: {str(e)}")

def check_ip():
    ip_address = ip_entry.get()
    if ip_address:
        try:
            reputation = check_ip_reputation(ip_address)
            if "error" in reputation:
                result_text.set(reputation["error"])
            else:
                result_text.set(f"Reputación de la IP {ip_address}: {reputation}")
        except Exception as e:
            result_text.set(f"Error: {str(e)}")

root = tk.Tk()
root.title("[AD] Security")
root.resizable(False, False)

newline_label = tk.Label(root, text="ADS Tools [Pro]", anchor="center", justify="center", font=("Helvetica", 12, "bold"), fg="gold")
newline_label.pack()

separator_label_ip = tk.Label(root, text="★██████████★")
separator_label_ip.pack()

instruction_label_file = tk.Label(root, text="Selecciona un archivo para escanear en ADS:")
instruction_label_file.pack()

scan_button_file = tk.Button(root, text="Cargar Archivo", command=scan_file)
scan_button_file.pack()

separator_label_file = tk.Label(root, text="★██████████★")
separator_label_file.pack()

instruction_label_url = tk.Label(root, text="Escanear una URL en ADS:")
instruction_label_url.pack()

url_entry = tk.Entry(root)
url_entry.pack()

scan_button_url = tk.Button(root, text="Escanear URL", command=scan_url)
scan_button_url.pack()

separator_label_ip = tk.Label(root, text="★██████████★")
separator_label_ip.pack()

ip_label = tk.Label(root, text="Buscar Reputación de una IP:")
ip_label.pack()

ip_entry = tk.Entry(root)
ip_entry.pack()

check_ip_button = tk.Button(root, text="Buscar IP", command=check_ip)
check_ip_button.pack()

result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text)
result_label.pack()

result_text_time = tk.StringVar()
result_label_time = tk.Label(root, textvariable=result_text_time)
result_label_time.pack()

newline_label = tk.Label(root, text="\n")
newline_label.pack()

newline_label = tk.Label(root, text="███████████████", fg="yellow")
newline_label.pack()

author_label = tk.Label(root, text="Antivirus Ultra Lite By zerordia#0")
author_label.pack()

donate_label = tk.Label(root, text="PREMIUM Activo! Gracias Por Comprar! :D", fg="green")
donate_label.pack()

root.mainloop()
