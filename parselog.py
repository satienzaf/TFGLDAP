import re
from datetime import datetime
import subprocess

# Expresiones regulares para buscar patrones en los mensajes de log

# inicio de conexion
conn_start_pattern = r'conn=(\d+) fd=\d+ ACCEPT from IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'

# fin de conexion
conn_end_pattern = r'conn=(\d+) fd=\d+ closed'

# inicio de bind
login_pattern = r'conn=(\d+) op=(\d+) BIND dn="uid=(\w+),.*method=\d+'

# búsqueda de usuario
search_pattern = r'conn=(\d+) op=(\d+) SRCH attr=(.*?)$'

# resultado de conexion
result_pattern = r'conn=(\d+) op=(\d+) RESULT tag=\d+ err=(\d+) text=(.*)'


# Archivo de log
log_file = "ldap.log"

# Obtener el año actual
current_year = datetime.now().year

# Saber si un usuario es un usuario local
def is_local_user(username):
    try:
        # Ejecutar el comando `grep` para buscar el nombre de usuario en el archivo `/etc/passwd`
        subprocess.run(["grep", "-q", f"^{username}:", "/etc/passwd"], check=True)
        return True  # El usuario es local
    except subprocess.CalledProcessError:
        return False  # El usuario no es local

def process_log(log_file):
    with open(log_file, 'r') as file:
        lines = file.readlines()

    connections = []
    current_connections = {}
    current_connection = None
    login_detected = False
    current_search = None

    for i, line in enumerate(lines):
        conn_start_match = re.search(conn_start_pattern, line)
        conn_end_match = re.search(conn_end_pattern, line)
        login_match = re.search(login_pattern, line)
        search_match = re.search(search_pattern, line)

        if conn_start_match:
            conn_id = conn_start_match.group(1)
            ip_address = conn_start_match.group(2)
            start_time_str = f"{line[4:6]}-{line[0:3]}-{current_year} {line[7:15]}"
            start_time = datetime.strptime(start_time_str, '%d-%b-%Y %H:%M:%S')
            current_connection = {
                "conn": conn_id,
                "start_time": start_time,
                "ip_address": ip_address
            }
            current_connections[conn_id] = current_connection
            login_detected = False
        elif conn_end_match:
            conn_id = conn_end_match.group(1)
            if conn_id in current_connections:
                if current_connections[conn_id].get("statusUser") == 'LDAP' and i + 1 > 0:  # si se está guardando la conexion de un usuario ldap buscamos la linea que muestra el resultado de la conexion
                    linea_res = lines[i - 2]
                    match_res = re.search(result_pattern, linea_res)
                    if match_res:
                    	err_value = match_res.group(3)
                    	current_connections[conn_id]["codError"] = err_value
                connections.append(current_connections[conn_id])
                del current_connections[conn_id]  # Eliminar la conexión del diccionario
                login_detected = False
        elif login_match:
            conn_id = login_match.group(1)
            username = login_match.group(3)
            if conn_id in current_connections:  # login de un usuario de LDAP
                login_detected = True
                current_connections[conn_id]["username"] = username
                current_connections[conn_id]["statusUser"] = 'LDAP'
        elif search_match:
            conn_id = search_match.group(1)
            if not current_search:  # ya que una búsqueda de usuario se realiza dos veces
                if i < len(lines) - 1:
                    next_line = lines[i + 1]
                    match_nentries = re.search(r"nentries=(\d+)", next_line)
                    if match_nentries:
                        nentries = match_nentries.group(1)
                        if nentries == '0':  # usuario no existente en LDAP
                            start_time_str = f"{line[4:6]}-{line[0:3]}-{current_year} {line[7:15]}"
                            start_time = datetime.strptime(start_time_str, '%d-%b-%Y %H:%M:%S')

                            if i > 0:
                                previous_line = lines[i - 1]
                                match_uid = re.search(r"uid=(\w+)", previous_line)
                                if match_uid:  # obtenemos el uid buscado del usuario no existente
                                    uid = match_uid.group(1)
                                    current_search = {
                                        "conn": conn_id,
                                        "start_time": start_time,
                                        "username": uid,
                                    }
                                    if is_local_user(uid):
                                        current_search["statusUser"] = "Local"
                                    else:
                                        current_search["statusUser"] = "No existe"
                                    if conn_id in current_connections:
                                        current_search['ip_address'] = current_connections[conn_id]['ip_address']
                                        connections.append(current_search)
            else:
                current_search = None

    return connections

# Función para guardar la información de las conexiones en un archivo
def save_connections(connections, output_file):
    with open(output_file, 'w') as file:
        for conn_data in connections:
            if 'username' in conn_data:
                file.write(f"Connection ID: {conn_data['conn']}\n")
                file.write(f"Start Time: {conn_data['start_time'].strftime('%d-%m-%Y %H:%M:%S')}\n")
                file.write(f"IP Address: {conn_data['ip_address']}\n")
                file.write(f"Username: {conn_data['username']}\n")
                file.write(f"Username existente: {conn_data['statusUser']}\n")
                if 'codError' in conn_data:
                    file.write(f"Código de error: {conn_data['codError']}\n")
                file.write("\n")

# Procesar el log y guardar la información de las conexiones
connections = process_log(log_file)
save_connections(connections, "ldap_sessions.log")
