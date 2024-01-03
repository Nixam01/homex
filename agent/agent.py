### PCAP I EVTX do wymiany

import os
import subprocess
from threading import Thread
import pyshark
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import FileResponse


class Capture_model(BaseModel):
    interface: str
    filter: str
    timeout: str


class Command_model(BaseModel):
    command: str


app = FastAPI()


def capture_live_packets(network_interface, capture_filter, timeout, file_name):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter=capture_filter, output_file=file_name)
    capture.sniff(timeout=timeout)

# Requirement ON.REM.1.1 Pobierz informację o konfiguracji sieciowej zdalnego hosta.
@app.get("/netconfig")
async def show_():
    output = subprocess.check_output("ip address show", shell=True).decode("utf-8")
    output = str(output)
    return output

# Requirement ON.REM.1.2 - Zbierz plik PCAP ze wskazanymi parametrami: nazwa interfejsu, czas zbierania.
#Przekazać za pomocą JSON konfi gurację zbierania. Plik po zebraniu ma być transferowany na hostgłównej aplikacji

@app.post("/capture")
async def capture_(cm: Capture_model):
    file_name = "agent_files/pcaps/" + str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ".pcap"
    thread = Thread(target=capture_live_packets, args=(cm.interface, cm.filter, int(cm.timeout), file_name))
    thread.start()
    thread.join()
    return FileResponse(file_name)

# Requirement ON.REM.2 - Aplikacja ma możliwość wskazania akcji i wykonania jej na zdalnym agencie w zakresie zarządzania plikami logów

# list pcaps po stronie agenta

@app.get("/list-pcaps")
async def show_files_():
    path = 'agent_files/pcaps/'
    pcap_files = []
    for root, directories, files in os.walk(path, topdown=False):
        for name in files:
            pcap_files.append(str(len(pcap_files) + 1) + ") " + name)
    return pcap_files

# list logs po stronie agenta
@app.get("/list-logs")
async def show_files_():
    path = 'agent_files/logs/'
    log_files = []
    for root, directories, files in os.walk(path, topdown=False):
        for name in files:
            log_files.append(str(len(log_files) + 1) + ") " + name)
    return log_files

# pobierz pcapy po stronie agenta
@app.get("/download-pcap")
async def download_pcap_(nr: str):
    path = 'agent_files/pcaps/'
    file_to_send = ""
    for root, directories, files in os.walk(path, topdown=False):
        counter = 1
        for name in files:
            if counter == int(nr):
                file_to_send = os.path.join(root, name)
            counter += 1
    print(file_to_send)
    return FileResponse(file_to_send)

# pobierz logi po stronie agenta
@app.get("/download-log")
async def download_log_(nr: str):
    path = 'agent_files/logs/'
    file_to_send = ""
    for root, directories, files in os.walk(path, topdown=False):
        counter = 1
        for name in files:
            if counter == int(nr):
                file_to_send = os.path.join(root, name)
            counter += 1

    return FileResponse(file_to_send)

#Aplikacja centralna ma możliwość wykonania polecenia powłoki systemowej na zdalnymagencie.
#wykonanie powłoki systemowej na agencie
@app.post("/command")
async def command_(cm: Command_model):
    output = subprocess.check_output(cm.command, shell=True).decode("utf-8")
    output = str(output)
    return output


if __name__ == '__main__':
    uvicorn.run(app, host="172.17.0.2", port=8003)