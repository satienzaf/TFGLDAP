# TFGLDAP
Scripts y código asociado a mi TFG de Ingeniería Informática.
En este repositorio se encuentran los siguientes archivos:
1. Parselog.py: Código que procesa logs LDAP y genera un archivo CSV como output
2. Archivos asociados a la interfaz gráfica y REST API:
   2.1 Archivos HTML: archivos necesarios para la visualización de la interfaz web
   2.2 Run.py e init.py: archivos que ejecutan y ponen en funcionamiento el REST API
   2.3 Routes.py: archivo que contiene todos los endpoints del REST API
   2.4 Styles.css: hoja de estilos de la interfaz gráfica
Los archivos anteriores siguen la siguiente estructura de carpetas:
APIrest/
│
├── app/
│   ├── static/
│   │   ├── css/
│   │   │   ├── styles.css
│   │   └── js/
│   │
│   ├── templates/
│   │   ├── filter_logs_by_admin.html
│   │   ├── filter_logs_by_error.html
│   │   ├── filter_logs_by_ip.html
│   │   ├── filter_logs_by_status.html
│   │   ├── filter_logs_by_access.html
│   │   ├── latest_logs.html
│   │   ├── ip_statistics.html
│   │   ├── user_statistics.html
│   │   └── index.html
│   │
│   ├── __init__.py
│   └── routes.py
│
├── venv/
├── requirements.txt
└── run.py
