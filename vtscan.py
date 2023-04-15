import requests
import json

archivo = input("Ingrese el nombre del archivo que desea escanear: ")

API_KEY = "CAMBIAR_API_ACA"
url = 'https://www.virustotal.com/vtapi/v2/file/scan'
params = {'apikey': API_KEY}

with open(archivo, 'rb') as file:
    response = requests.post(url, files={'file': file}, params=params)

json_response = json.loads(response.content)
scan_id = json_response['scan_id']

url = 'https://www.virustotal.com/vtapi/v2/file/report'
params = {'apikey': API_KEY, 'resource': scan_id}
response = requests.get(url, params=params)

json_response = json.loads(response.content)
if json_response['response_code'] == 1:
    print(f"Escaneo completo: {json_response['verbose_msg']}\n")
    print(f"MD5: {json_response['md5']}")
    print(f"SHA-1: {json_response['sha1']}")
    print(f"SHA-256: {json_response['sha256']}\n")
    print("Resultados:")
    for scanner, result in json_response['scans'].items():
        if result['detected']:
            print(f"\033[91m{scanner}: Detectado\033[0m")
        else:
            print(f"{scanner}: No detectado")
        if result['result']:
            print(f"Resultado: {result['result']}")
        print(f"Actualizado el: {result['update']}\n")
else:
    print("No se encontraron resultados para el archivo escaneado.")
