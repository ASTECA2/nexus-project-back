from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
import bcrypt
from ..models import db, Usuario

# Criação do Blueprint para as rotas de autenticação
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    dados = request.get_json()
    
    # 1. Validação básica de entrada
    if not dados or not dados.get('cpf') or not dados.get('senha'):
        return jsonify({"erro": "CPF e senha corporativa são obrigatórios"}), 400
        
    cpf_informado = dados.get('cpf')
    senha_informada = dados.get('senha').encode('utf-8')
        
    # 2. Busca o usuário no banco de dados
    usuario = Usuario.query.filter_by(cpf=cpf_informado).first()
    
    # 3. Verificação de credenciais
    # Se o usuário existir, comparamos a senha em texto puro com o hash salvo no banco
    if usuario and bcrypt.checkpw(senha_informada, usuario.senha_hash.encode('utf-8')):
        
        # 4. Criação do Token JWT
        # Embutimos o perfil e a empresa no token para facilitar as regras de negócio nas rotas protegidas
        claims_adicionais = {
            "perfil": usuario.perfil,       # ex: 'colaborador', 'gestor'
            "empresa_id": usuario.empresa_id 
        }
        
        # O 'identity' geralmente é a chave primária do usuário
        token_acesso = create_access_token(
            identity=str(usuario.id), 
            additional_claims=claims_adicionais
        )
        
        # TODO (Futuro): Registrar log de auditoria do login (IP e dispositivo)
        ip_acesso = request.remote_addr
        
        # No final da sua função de login no Python:
        return jsonify({
            "token": token_acesso,
            "nome": usuario.nome,
            "perfil": usuario.perfil
        }), 200
        
    # Retorno genérico para não dar dicas a invasores se o CPF existe ou não
    return jsonify({"erro": "Credenciais inválidas"}), 401