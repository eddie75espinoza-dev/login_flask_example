from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/dbname'
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'  # Cambia esto a una clave segura en un entorno de producción
db = SQLAlchemy(app)
jwt = JWTManager(app)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(50), unique=True, nullable=False)
    correo_electronico = db.Column(db.String(100), unique=True, nullable=False)
    contraseña = db.Column(db.String(100), nullable=False)
    rol = db.Column(db.String(20), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)
    ultima_fecha_acceso = db.Column(db.DateTime)
    intentos_fallidos = db.Column(db.Integer, default=0)

@app.route('/login', methods=['POST'])
def login():
    nombre_usuario = request.json['nombre_usuario']
    contraseña = request.json['contraseña']
    
    usuario = Usuario.query.filter_by(nombre_usuario=nombre_usuario).first()
    
    if usuario:
        if bcrypt.checkpw(contraseña.encode('utf-8'), usuario.contraseña.encode('utf-8')):
            session['usuario_id'] = usuario.id
            usuario.intentos_fallidos = 0  # Reiniciar intentos fallidos
            usuario.ultima_fecha_acceso = datetime.utcnow()
            db.session.commit()
            
            # Generar un token JWT utilizando flask_jwt_extended
            token = create_access_token(identity=usuario.id, expires_delta=timedelta(hours=1))
            
            return jsonify({"mensaje": "Inicio de sesión exitoso", "rol": usuario.rol, "token": token})
        else:
            usuario.intentos_fallidos += 1
            if usuario.intentos_fallidos >= 3:
                usuario.intentos_fallidos = 0
                usuario.bloqueado = True  # Marcar la cuenta como bloqueada
            db.session.commit()
            return jsonify({"mensaje": "Credenciales inválidas"}), 401
    else:
        return jsonify({"mensaje": "Credenciales inválidas"}), 401

@app.route('/protegido', methods=['GET'])
@jwt_required()  # Protege esta ruta con un token JWT válido
def ruta_protegida():
    usuario_id = get_jwt_identity()
    return jsonify({"mensaje": "Esta es una ruta protegida", "usuario_id": usuario_id})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)