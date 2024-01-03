import click
import json
import requests
from tools.detectionrules import *

def file_handling(file_path, re_pattern, grep_pattern, bpf_filter):
    output = ""

    if file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json'):
        if re_pattern != "" and grep_pattern != "":
            output = "Two patterns instead of one."
        elif re_pattern != "":
            with open(file_path, "r") as file:
                for line in file:
                    if re.search(re_pattern, line):
                        output += line

        elif grep_pattern != "":

            try:
                output = subprocess.check_output("grep " + grep_pattern + " " + file_path, shell=True).decode("utf-8")
            except:
                output = ""
            else:
                output = str(output)

        else:
            with open(file_path, "r") as file:
                for line in file:
                    output += line

        return output

    elif file_path.endswith('.pcap') or file_path.endswith('.pcapng'):
        shark_cap = pyshark.FileCapture(file_path, display_filter=bpf_filter)
        for packet in shark_cap:
            output += str(packet)

        return output

    else:
        output = "Bad file extension. Try one of (.txt, .xml, .json, .pcap, .evtx) "
        return output


def scan_file(file_path, rule):
    detection_rules = __import__('detection-rules')
    method = getattr(detection_rules, rule)
    result = method(file_path)
    return result


def process_output(output, firewall, console):
    if output[0] == "remote" and console != "":
        pload = {'action_alert': str(output[0]), 'action_block': str(output[1]), 'description': str(output[2])}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(f'http://{console}/', data=json.dumps(pload), headers=headers)

    if output[1] and firewall != "":
        if output[2].find("suspicious ip") > -1 or output[2].find("suspicious number of ips") > -1 or output[2].find(
                "untrusted ports") > -1:
            pload = {'rule': "BLOCK", 'value': str(output[3])}
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = requests.post(f'http://{firewall}/', data=json.dumps(pload), headers=headers)


@click.group()
def application():
    pass


@application.command()
@click.option('--file_path', multiple=True, type=click.Path(exists=True))
@click.option('--re_pattern', default="")
@click.option('--grep_pattern', default="")
@click.option('--bpf_filter', default="")
def read_file(file_path, re_pattern, grep_pattern, bpf_filter):
    for pth in file_path:
        if os.path.isfile(pth):
            output = file_handling(pth, re_pattern, grep_pattern, bpf_filter)
            click.echo(output)
            f = open('../database/log.txt', 'a')
            f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' cliapp' + '\n' + output + '\n\n')
            f.close()
        elif os.path.isdir(pth):
            for root, directories, files in os.walk(pth, topdown=False):
                for name in files:
                    output = file_handling(os.path.join(root, name), re_pattern, grep_pattern, bpf_filter)
                    click.echo(output)
                    f = open('../database/log.txt', 'a')
                    f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' cliapp' + '\n' + output + '\n\n')
                    f.close()


@application.command()
@click.option('--action', multiple=False, help="Action you want to perform (one of netconfig)")
@click.option('--agent_host', multiple=False, help="ip:port")
@click.option('--interface', multiple=False, help="Interface to capture traffic on")
@click.option('--capture_filter', default="", multiple=False, help="Capture filter")
@click.option('--timeout', multiple=False, help="Time of capturing")
@click.option('--file_number', multiple=True, help="Number of file to download")
@click.option('--command', multiple=False, help="Command to execute")
def agent(action, agent_host, interface, capture_filter, timeout, file_number, command):
    if action == 'netconfig':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get(f'http://{agent_host}/netconfig', headers=headers)
        result = str(r.content).replace('\\n', '\n').replace('\\t', '\t')
        click.echo(result)
        f = open('../database/log.txt', 'a')
        f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' agent' + '\n' + result + '\n\n')
        f.close()

    elif action == 'capture':
        pload = {"interface": interface, "filter": capture_filter, "timeout": str(timeout)}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        response = requests.post(f'http://{agent_host}/capture', data=json.dumps(pload), headers=headers, stream=True)
        time_now = str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S"))
        file_name = "../database/downloads_from_agent/pcaps/" + time_now + ".pcap"
        if response.status_code == 200:
            with open(file_name, 'wb') as f:
                f.write(response.content)
            f = open('../database/log.txt', 'a')
            f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S"))
                    + ' cliapp' + '\n' + 'file ' + time_now
                    + '.pcap dowloaded to folder cliapp/database/downloads_from_agent/pcaps ' + '\n\n')
            f.close()

    elif action == 'list_pcaps':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get(f'http://{agent_host}/list-pcaps', headers=headers)
        click.echo(r.content)
        f = open('../database/log.txt', 'a')
        f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' agent' + '\n' + str(r.content) + '\n\n')
        f.close()

    elif action == 'list_logs':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get(f'http://{agent_host}/list-logs', headers=headers)
        click.echo(r.content)
        f = open('../database/log.txt', 'a')
        f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' agent' + '\n' + str(r.content) + '\n\n')
        f.close()

    elif action == 'download_pcap':
        for file in file_number:
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = requests.get(f'http://{agent_host}/list-pcaps', headers=headers)
            json_str = str(r.content)
            json_str = json_str[3:-2]
            list = json_str.split(',')
            file_name = "../database/downloads_from_agent/pcaps/" + list[int(file) - 1][4:-1]

            parameters = {"nr": file}
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            response = requests.get(f'http://{agent_host}/download-pcap', params=parameters, headers=headers,
                                    stream=True)
            if response.status_code == 200:
                with open(file_name, 'wb') as f:
                    f.write(response.content)
                f = open('../database/log.txt', 'a')
                f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' agent' + '\n'
                        + 'downloaded pcap to /database/downloads_from_agent/pcaps folder' + '\n\n')
                f.close()

    elif action == 'download_log':
        for file in file_number:
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = requests.get(f'http://{agent_host}/list-logs', headers=headers)
            json_str = str(r.content)
            json_str = json_str[3:-2]
            list = json_str.split(',')
            file_name = "../database/downloads_from_agent/logs/" + list[int(file) - 1][4:-1]

            parameters = {"nr": file}
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            response = requests.get(f'http://{agent_host}/download-log', params=parameters, headers=headers,
                                    stream=True)
            if response.status_code == 200:
                with open(file_name, 'wb') as f:
                    f.write(response.content)
                f = open('../database/log.txt', 'a')
                f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' agent' + '\n'
                        + 'downloaded log to /database/downloads_from_agent/logs folder' + '\n\n')
                f.close()
    elif action == 'command':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        payload = {"command": command}
        r = requests.post(f'http://{agent_host}/command', headers=headers, data=json.dumps(payload))
        result = str(r.content).replace('\\n', '\n').replace('\\t', '\t')
        click.echo(result)
        f = open('../database/log.txt', 'a')
        f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ' agent' + '\n' + result + '\n\n')
        f.close()

    else:
        click.echo("Invalid action")
        f = open('../database/log.txt', 'a')
        f.write(str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S") + ' agent' + '\n' + 'Invalid action' + '\n\n'))
        f.close()


@application.command()
@click.option('--file_path', multiple=True, type=click.Path(exists=True))
@click.option('--rule', multiple=False, help="detect_ip or detect_words or detect_anomaly")
def loaddetectionrules(file_path, rule):
    if rule == 'detect_ip':
        for pth in file_path:
            if os.path.isfile(pth):
                output = detect_ip(str(file_path)[2:-3])
                click.echo(output)
            elif os.path.isdir(pth):
                for root, directories, files in os.walk(pth, topdown=False):
                    for name in files:
                        output = detect_ip(name)
                        click.echo(output)
    elif rule == 'detects_words':
        for pth in file_path:
            if os.path.isfile(pth):
                output = detect_ip(file_path)
                click.echo(output)
            elif os.path.isdir(pth):
                for root, directories, files in os.walk(pth, topdown=False):
                    for name in files:
                        output = detect_words(name)
                        click.echo(output)
    elif rule == 'detect_anomaly':
        for pth in file_path:
            if os.path.isfile(pth):
                output = detect_anomaly(file_path)
                click.echo(output)
            elif os.path.isdir(pth):
                for root, directories, files in os.walk(pth, topdown=False):
                    for name in files:
                        output = detect_anomaly(name)
                        click.echo(output)
    else:
        click.echo("Invalid action")

if __name__ == '__main__':
    application()

    print('CLI Application Started...')
