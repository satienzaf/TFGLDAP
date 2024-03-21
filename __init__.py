from flask import Flask



# Crear la instancia de la aplicación Flask

app = Flask(__name__)



# Configuración de la aplicación Flask

app.config['SECRET_KEY'] = 'tfginfo' 



from app import routes
