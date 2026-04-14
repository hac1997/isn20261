import json
import boto3
import jwt
from passlib.hash import bcrypt

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')

SECRET = "secreta"  # use env var em produção


def lambda_handler(event, context):
    try:
        body = json.loads(event["body"])

        email = body.get("email")
        password = body.get("password")

        # 1. validar entrada
        if not email or not password:
            return response(400, "Email e senha são obrigatórios")

        # 2. buscar usuário
        result = table.get_item(Key={"email": email})

        if "Item" not in result:
            return response(401, "Credenciais inválidas")

        user = result["Item"]

        # 3. comparar senha
        if not bcrypt.verify(password, user["password"]):
            return response(401, "Credenciais inválidas")

        # 4. gerar token
        token = jwt.encode(
            {"email": email},
            SECRET,
            algorithm="HS256"
        )

        # 5. retornar
        return {
            "statusCode": 200,
            "body": json.dumps({
                "token": token
            })
        }

    except Exception as e:
        return response(500, str(e))


def response(status, message):
    return {
        "statusCode": status,
        "body": json.dumps({"error": message})
    }