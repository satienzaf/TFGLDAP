from flask import jsonify, request

from app import app

import pandas as pd

import json

from datetime import datetime



# Cargar el archivo CSV en un DataFrame de Pandas

df = pd.read_csv("/var/log/ldap/ldap_sessions.csv")



@app.route('/logs', methods=['GET'])

def get_logs():

    logs = df.to_json(orient="records")

    return logs



@app.route('/logs/latest', methods=['GET'])

def get_latest_logs():

    n = int(request.args.get('n', 10))

    latest_logs = df.tail(n).to_dict(orient="records")

    return json.dumps(latest_logs)



@app.route('/logs/filter', methods=['GET'])

def filter_logs():

    user = request.args.get('user')

    day = request.args.get('day')

    month = request.args.get('month')

    year = request.args.get('year')



    filtered_logs = df



    if user:

        filtered_logs = filtered_logs[filtered_logs['username'] == user]



    if day:

        day = int(day)

        filtered_logs = filtered_logs[filtered_logs['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').day) == day]



    if month:

        month = int(month)

        filtered_logs = filtered_logs[filtered_logs['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').month) == month]



    if year:

        year = int(year)

        filtered_logs = filtered_logs[filtered_logs['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').year) == year]



    filtered_logs = filtered_logs.to_dict(orient="records")



    return json.dumps(filtered_logs)

    

@app.route('/logs/filter/ip', methods=['GET'])

def filter_logs_by_ip():

    ip_address = request.args.get('ip')



    if not ip_address:

        return json.dumps({'error': 'Please provide an IP address parameter'}), 400



    ip_logs = df[df['ip_address'] == ip_address].to_dict(orient='records')

    return json.dumps(ip_logs)



@app.route('/logs/filter/host', methods=['GET'])

def filter_logs_by_host():

    host = request.args.get('host')



    if not host:

        return json.dumps({'error': 'Please provide a host parameter'}), 400



    # Comprueba si el host termina con '.redldap.es'

    if host.endswith('.redldap.es'):

        # Si termina con '.redldap.es', añade un punto al final

        host += '.'

    # Comprueba si el host termina con '.redldap.es.'

    if not host.endswith('.redldap.es.'):

        # Si no termina con '.redldap.es', añádelo al host

        host += '.redldap.es.'



    host_logs = df[df['host'] == host].to_dict(orient='records')

    return json.dumps(host_logs)

    

@app.route('/logs/filter/status', methods=['GET'])

def filter_logs_by_status():

    status = request.args.get('status')



    if not status:

        return json.dumps({'error': 'Please provide a status parameter'}), 400



    status_logs = df[df['statusUser'] == status].to_dict(orient='records')

    return json.dumps(status_logs) 

    

    

@app.route('/logs/filter/access', methods=['GET'])

def filter_logs_by_access():

    access = request.args.get('access')



    if not access:

        return json.dumps({'error': 'Please provide an access parameter'}), 400



    if access.lower() == 'true':

        access_logs = df[df['has_access'] == True].to_dict(orient='records')

    elif access.lower() == 'false':

        access_logs = df[df['has_access'] == False].to_dict(orient='records')

    elif access.lower() == 'nan':

        # Tratar los valores NaN de manera especial o filtrarlos de manera diferente

        access_logs = df[df['has_access'].isna()].to_dict(orient='records')

    else:

        return json.dumps({'error': 'Invalid value for access parameter'}), 400



    return json.dumps(access_logs)

    

@app.route('/logs/filter/error', methods=['GET'])

def filter_logs_by_error():

    error_code = request.args.get('error')



    if not error_code:

        # Si no se proporciona el parámetro 'error_code', devuelve los registros con codError > 0

        error_logs = df[df['codError'] > 0].to_dict(orient='records')

        return json.dumps(error_logs)



    # Si se proporciona el parámetro 'error_code', filtra los registros por ese código de error específico

    error_logs = df[df['codError'] == int(error_code)].to_dict(orient='records')

    return json.dumps(error_logs)

    

@app.route('/logs/filter/admin', methods=['GET'])

def filter_logs_by_admin():

    admin_status = request.args.get('admin')



    if not admin_status:

        return json.dumps({'error': 'Please provide an admin parameter'}), 400



    if admin_status.lower() == 'true':

        admin_logs = df[df['admin'] == True].to_dict(orient='records')

    elif admin_status.lower() == 'false':

        admin_logs = df[df['admin'] == False].to_dict(orient='records')

    else:

        return json.dumps({'error': 'Invalid value for admin parameter'}), 400

    return json.dumps(admin_logs)

    

    

@app.route('/logs/user_statistics', methods=['GET'])

def get_user_statistics():

    day = request.args.get('day')

    month = request.args.get('month')

    year = request.args.get('year')



    filtered_df = df



    if day:

        day = int(day)

        filtered_df = filtered_df[filtered_df['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').day) == day]



    if month:

        month = int(month)

        filtered_df = filtered_df[filtered_df['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').month) == month]



    if year:

        year = int(year)

        filtered_df = filtered_df[filtered_df['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').year) == year]



    user_stats = filtered_df['username'].value_counts().to_dict()

    return json.dumps(user_stats)



@app.route('/logs/ip_statistics', methods=['GET'])

def get_ip_statistics():

    day = request.args.get('day')

    month = request.args.get('month')

    year = request.args.get('year')



    filtered_df = df



    if day:

        day = int(day)

        filtered_df = filtered_df[filtered_df['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').day) == day]



    if month:

        month = int(month)

        filtered_df = filtered_df[filtered_df['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').month) == month]



    if year:

        year = int(year)

        filtered_df = filtered_df[filtered_df['start_time'].apply(lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').year) == year]



    ip_stats = filtered_df['ip_address'].value_counts().to_dict()

    return json.dumps(ip_stats)

