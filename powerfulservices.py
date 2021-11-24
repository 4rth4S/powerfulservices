# import libraries to make requests to websites for scan
import requests
import json
from json2html import *
# import libraries to manipulate files and time sleeps ... 
import os
import socket
import time
## import libraries to interact with aws buckets -- S3 
import boto3
# import libraries to interact with virus total api
from virus_total_apis import PublicApi
# import library to interact with shodan API
from shodan import Shodan
# import library to get better logs
import logging
# import libraries to make script useful 
import fire


# START LOGGER

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;21m"
    green = "\x1b[32;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logger = logging.getLogger("SCANNING-TOOL")
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())

logger.addHandler(ch)

## END LOGGER


# AWS BUCKET S3
bucket_name = '_INSERTAR_EL_NOMBRE_DEL_BUCKET_S3'
#AWS CREDENTIALS 
ACCESS_KEY = '_INSERTAR_AUTH_KEY'
SECRET_KEY = '_INSERTAR_AUTH_KEY'


def upload_to_s3(list_of_files):
  try:
    #client = boto3.client('s3')
    client = boto3.client('s3',aws_access_key_id=ACCESS_KEY,aws_secret_access_key=SECRET_KEY)
    for file in list_of_files:
      file_absolute_path=os.path.join('_reports/'+file)
      print(file_absolute_path)
      client.upload_file(file_absolute_path, bucket_name, "_reports/"+file)
      if file == 'index.html':
        client.upload_file(file_absolute_path, bucket_name, file)
  except Exception as e:
    logger.error('Se genero un error intentando subir los files al bucket ---->   %s',e)
  return None

########################################
# PARAMETROS
###################
Api_VirusTotal = 'INSERTAR_EL_AUTH_KEY_DEL_SERVICIO'
Api_Urlscan = 'INSERTAR_EL_AUTH_KEY_DEL_SERVICIO'
Api_Shodan = 'INSERTAR_EL_AUTH_KEY_DEL_SERVICIO'
################

def urlscan_io (url):
  try:
    headers = {'API-Key':Api_Urlscan,'Content-Type':'application/json'}
    timestr= time.strftime("%d_%m_%Y-%HM")
    data = {"url": "https://"+str(url), "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    r= response.json()
    results_api = r['api']
    #Segun documentacion de la api se debe esperar 30 segundos antes de buscar el resultado
    time.sleep(30)
    results_urlscan = requests.get(results_api).json()
    tabla_urlscan = json2html.convert(json = results_urlscan)
    # Exportar como tabla HTML
    with open("_reports/urlscanio_"+str(url)+"__"+timestr+".html", "w") as outfile:
        outfile.write(str(tabla_urlscan))
    # Exportar en formato JSON 
    with open("_reports/urlscanio_"+str(url)+"__"+timestr+".json", "w") as outfile:
        outfile.write(str(results_urlscan))
  except Exception as e:
    logger.warning('Hubo un error en la query a URLSCAN.IO , el mismo es ---> %s',e )
  return None

def virus_total (url):
  try:
    api = PublicApi(Api_VirusTotal)
    timestr= time.strftime("%d_%m_%Y-%H")
  except Exception as e:
    logger.warning('Hubo un error en la query a Virustotal, el mismo es ---> %s',e)
  try:
    get_IP = socket.gethostbyname(str(url))
    results_virustotal_IP = api.get_ip_report(get_IP)
    tabla_virustotal_IP = json2html.convert(json = results_virustotal_IP)
    # Exportar como tabla HTML
    with open("_reports/virustotal_IP_"+str(url)+"__"+timestr+".html", "w") as outfile:
        outfile.write(str(tabla_virustotal_IP))
    # Exportar en formato JSON 
    with open("_reports/virustotal_IP_"+str(url)+"__"+timestr+".json", "w") as outfile:
        outfile.write(str(results_virustotal_IP))
  except Exception as e:
    logger.error('No se pudo obtener la direccion ip del dominio ingresado , el error es --> %s', e)
  try:
    results_virustotal_DOMAIN = api.get_domain_report(str(url))
    tabla_virustotal_DOMAIN = json2html.convert(json = results_virustotal_DOMAIN)
    # Exportar como tabla HTML
    with open("_reports/virustotal_DOMAIN_"+str(url)+"__"+timestr+".html", "w") as outfile:
        outfile.write(str(tabla_virustotal_DOMAIN))
    # Exportar en formato JSON 
    with open("_reports/virustotal_DOMAIN_"+str(url)+"__"+timestr+".json", "w") as outfile:
      outfile.write(str(results_virustotal_DOMAIN))
  except:
    logger.error('No se pudo obtener el reporte para el dominio ingresado')
  return None

def shodan (url):
  api = Shodan(Api_Shodan)
  timestr= time.strftime("%d_%m_%Y-%HM")
  try:
    get_IP = socket.gethostbyname(str(url))
    results_shodan_IP = api.host(str(get_IP))
  except Exception as e:
    logger.error('no se pudo resolver la ip del dominio consultado.. %s',e)
  try:
    tabla_shodan_IP = json2html.convert(json = results_shodan_IP)
    # Exportar como tabla HTML
    with open("_reports/shodan_IP_"+str(url)+"__"+timestr+".html", "w") as outfile:
        outfile.write(str(tabla_shodan_IP))
    # Exportar en formato JSON 
    with open("_reports/shodan_IP_"+str(url)+"__"+timestr+".json", "w") as outfile:
      outfile.write(str(results_shodan_IP))
  except Exception as e:
        logger.error('Error: %s',e)
  return None

def get_reports():
  return os.listdir("./_reports")

def scan (url_to_scan):
  urlscan_io(url_to_scan)
  virus_total(url_to_scan)
  shodan(url_to_scan)
  upload_to_s3(get_reports())
  return None

if __name__ == "__main__":
  fire.Fire()
