import re
from datetime import datetime
import subprocess
from ldap3 import Server, Connection, ALL, SUBTREE
import pandas as pd
import base64

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

log_file = "/var/log/ldap/ldap.log"

csv_file = "/var/log/ldap/ldap_sessions.csv"

# Obtener el año actual
current_year = datetime.now().year

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
                                    current_search["statusUser"] = "No LDAP"
                                    if conn_id in current_connections:
                                        current_search['ip_address'] = current_connections[conn_id]['ip_address']
                                        connections.append(current_search)
            else:
                current_search = None

    return connections
    
def verify_access(connections):
    ldap_server = 'ldap://Raton.redldap.es'
    ldap_user = 'cn=admin,dc=Raton,dc=redldap,dc=es'
    ldap_password = 'tfginfo'  # Contraseña del usuario LDAP
    base_dn = 'ou=people,dc=Raton,dc=Redldap,dc=es'  # Base DN donde se buscará el usuario
    search_filter = '(uid={})'  # Filtro de búsqueda para el usuario

    server = Server(ldap_server, get_info=ALL)
    conn = Connection(server, user=ldap_user, password=ldap_password, auto_bind=True)
    
    for conn_data in connections:
        if 'username' in conn_data:
            conn_data['admin'] = False
            ip_address = conn_data['ip_address']
            username = conn_data['username']
            hostname = subprocess.run(["dig", "-x", ip_address, "+short"], capture_output=True, text=True).stdout.strip()
            
            if hostname:
                conn_data['host'] = hostname
                
                if conn_data["statusUser"] == "LDAP":
                    conn.search(search_base=base_dn,
                                search_filter=search_filter.format(username),
                                search_scope=SUBTREE,
                                attributes=['host'])

                    if conn.entries:
                        user_hosts = conn.entries[0].host.value
                        if user_hosts is None:  # atributo host vacio
                            conn_data['has_access'] = False
                        elif '*' in user_hosts or hostname in user_hosts + ".redldap.es.":
                            conn_data['has_access'] = True
                        else:  # atributo host no vacío pero no coincide
                            conn_data['has_access'] = False
                    else:  # sin atributo host
                        conn_data['has_access'] = False
                    
                    base_dn = 'dc=Raton,dc=Redldap,dc=es' 
                    search_filter = '(objectClass=*)'
                    attributes = ['gosaAclEntry', 'cn']

                    conn.search(search_base=base_dn, search_filter=search_filter, attributes=attributes, search_scope=SUBTREE)
                    acl_entries = conn.entries
                    
                    for entry in acl_entries:
                        if 'gosaAclEntry' in entry:
                            for acl_entry in entry['gosaAclEntry']:
                                acl = base64.b64decode(acl_entry.split(':')[2]).decode('latin-1')
                                adminACL = "cn=admin,ou=aclroles,dc=Raton,dc=redldap,dc=es"
                                cadena_uid = base64.b64decode(acl_entry.split(':')[3]).decode('latin-1')
                                patron = r'uid=([^,]+)'
                                coincidencias = re.search(patron, cadena_uid)
                                
                                if coincidencias:
                                    uid = coincidencias.group(1)
                                    if uid == username and acl == adminACL:
                                        conn_data["admin"] = True
                                        break  
                else:  # usuario no LDAP
                    conn_data['has_access'] = "NA"
                    conn_data['codError'] = 0
            else:  # hostname no conocido
                conn_data['host'] = "Desconocido"
                conn_data['has_access'] = False

    conn.unbind()


def load_connections(csv_file):
    try:
        return pd.read_csv(csv_file)
        if connections_df.empty:
            return pd.DataFrame(columns=['conn', 'start_time', 'ip_address','host', 'username', 'statusUser', 'has_access','codError','admin'])
        return connections_df
    except FileNotFoundError:
        return pd.DataFrame(columns=['conn', 'start_time', 'ip_address', 'host','username', 'statusUser', 'has_access','codError','admin'])

# Función para guardar la información de las conexiones en un archivo CSV
def save_connectionscsv(connections, output_file):
    connections['index'] = range(1, len(connections) + 1)
    connections.to_csv(output_file, index=False)
"""
# Función para guardar la información de las conexiones en un archivo de texto
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
                    file.write(f"Acceso: {conn_data['has_access']}\n")
                    file.write(f"Código de error: {conn_data['codError']}\n")
                file.write("\n")
"""


# Procesar el log y guardar la información de las conexiones
connections = process_log(log_file)
verify_access(connections)
#save_connections(connections, "/var/log/ldap/ldap_sessions.log")

connections = [conn_data for conn_data in connections if 'username' in conn_data]
# Procesar el log y guardar la información de las conexiones
connections_df = load_connections(csv_file)

last_execution_time = connections_df['start_time'].max() if not connections_df.empty else datetime.min

new_connections_df = pd.DataFrame(connections)
if not new_connections_df.empty:
    new_connections_df['start_time'] = pd.to_datetime(new_connections_df['start_time'])
    new_connections_df = new_connections_df[new_connections_df['start_time'] > last_execution_time]

# Guardar las nuevas conexiones en el archivo CSV
if not new_connections_df.empty:
    if connections_df.empty:
        connections_df = new_connections_df
    else:
        connections_df = pd.concat([connections_df, new_connections_df], ignore_index=True)
    save_connectionscsv(connections_df, csv_file)

