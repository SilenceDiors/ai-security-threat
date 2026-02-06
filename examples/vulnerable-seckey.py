from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

current_user = {'username': 'user1', 'role': 'user'}
secret_keys = []


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        path = request.path
        
        if path == '/manage/seckey':
            if current_user['role'] != 'admin':
                return jsonify({'error': '权限不足'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


@app.route('/manage/seckey', methods=['POST'])
@admin_required
def add_seckey():
    data = request.get_json()
    
    secret_keys.append({
        'id': len(secret_keys) + 1,
        'name': data.get('key_name'),
        'value': data.get('key_value'),
        'created_by': current_user['username']
    })
    
    return jsonify({
        'success': True,
        'message': 'SecretKey已创建',
        'data': secret_keys[-1]
    }), 201


@app.route('/switch-user/<role>', methods=['POST'])
def switch_user(role):
    global current_user
    current_user = {'username': f'user_{role}', 'role': role}
    return jsonify({'success': True, 'current_user': current_user}), 200


@app.route('/seckeys', methods=['GET'])
def list_seckeys():
    return jsonify({'data': secret_keys, 'total': len(secret_keys)}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5001)
