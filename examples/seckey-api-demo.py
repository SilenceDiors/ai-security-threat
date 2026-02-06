"""
SecretKey管理接口权限控制示例
场景：/manage/seckey 接口只允许admin用户访问
"""

from flask import Flask, request, jsonify
from functools import wraps
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# 模拟数据库
secret_keys = []
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user1': {'password': 'user123', 'role': 'user'},
    'viewer': {'password': 'viewer123', 'role': 'viewer'}
}


# ============================================
# 方式1：不安全的实现（存在漏洞）
# ============================================

def unsafe_admin_required(f):
    """不安全的权限校验装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': '未提供认证令牌'}), 401
        
        try:
            # 漏洞1：没有验证token签名
            # 漏洞2：直接从token中读取role，可被篡改
            payload = jwt.decode(token.replace('Bearer ', ''), 
                                app.config['SECRET_KEY'], 
                                algorithms=['HS256'],
                                options={"verify_signature": False})  # 危险！
            
            # 漏洞3：弱比较，可能被绕过
            if payload.get('role') != 'admin':
                return jsonify({'error': '权限不足，需要admin角色'}), 403
                
        except Exception as e:
            return jsonify({'error': '认证失败'}), 401
            
        return f(*args, **kwargs)
    return decorated_function


@app.route('/unsafe/manage/seckey', methods=['POST'])
@unsafe_admin_required
def unsafe_add_seckey():
    """不安全的SecretKey新增接口"""
    data = request.get_json()
    key_name = data.get('key_name')
    key_value = data.get('key_value')
    
    # 漏洞4：没有对输入进行验证
    secret_keys.append({
        'id': len(secret_keys) + 1,
        'name': key_name,
        'value': key_value,
        'created_at': datetime.datetime.now().isoformat()
    })
    
    return jsonify({
        'success': True,
        'message': 'SecretKey已创建',
        'data': secret_keys[-1]
    }), 201


# ============================================
# 方式2：安全的实现（推荐）
# ============================================

def safe_admin_required(f):
    """安全的权限校验装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        # 检查1：验证token存在
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': '未提供有效的认证令牌'}), 401
        
        try:
            # 检查2：验证token签名（必须）
            token = token.replace('Bearer ', '')
            payload = jwt.decode(token, 
                                app.config['SECRET_KEY'], 
                                algorithms=['HS256'])
            
            # 检查3：验证token是否过期
            exp = payload.get('exp')
            if exp and datetime.datetime.fromtimestamp(exp) < datetime.datetime.now():
                return jsonify({'error': '令牌已过期'}), 401
            
            # 检查4：从数据库验证用户角色（不信任token中的role）
            username = payload.get('username')
            if not username or username not in users:
                return jsonify({'error': '用户不存在'}), 401
            
            user_role = users[username]['role']
            
            # 检查5：严格角色校验
            if user_role != 'admin':
                app.logger.warning(f'用户 {username} (角色: {user_role}) 尝试访问管理接口')
                return jsonify({
                    'error': '权限不足',
                    'message': '此操作需要管理员权限',
                    'required_role': 'admin',
                    'your_role': user_role
                }), 403
            
            # 检查6：记录审计日志
            app.logger.info(f'管理员 {username} 访问敏感接口: {request.path}')
            
            # 将用户信息传递给路由处理函数
            request.current_user = username
            request.current_role = user_role
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': '令牌已过期'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': '无效的令牌'}), 401
        except Exception as e:
            app.logger.error(f'认证异常: {str(e)}')
            return jsonify({'error': '认证失败'}), 401
            
        return f(*args, **kwargs)
    return decorated_function


@app.route('/safe/manage/seckey', methods=['POST'])
@safe_admin_required
def safe_add_seckey():
    """安全的SecretKey新增接口"""
    data = request.get_json()
    
    # 输入验证1：检查必需字段
    if not data or 'key_name' not in data or 'key_value' not in data:
        return jsonify({
            'error': '缺少必需字段',
            'required': ['key_name', 'key_value']
        }), 400
    
    key_name = data.get('key_name')
    key_value = data.get('key_value')
    
    # 输入验证2：字段格式验证
    if not key_name or not isinstance(key_name, str) or len(key_name) > 100:
        return jsonify({'error': 'key_name格式错误（必须是1-100字符的字符串）'}), 400
    
    if not key_value or not isinstance(key_value, str) or len(key_value) > 500:
        return jsonify({'error': 'key_value格式错误（必须是1-500字符的字符串）'}), 400
    
    # 输入验证3：检查重复
    if any(k['name'] == key_name for k in secret_keys):
        return jsonify({'error': f'SecretKey名称 {key_name} 已存在'}), 409
    
    # 创建SecretKey
    new_key = {
        'id': len(secret_keys) + 1,
        'name': key_name,
        'value': key_value,
        'created_by': request.current_user,
        'created_at': datetime.datetime.now().isoformat()
    }
    
    secret_keys.append(new_key)
    
    # 审计日志
    app.logger.info(f'管理员 {request.current_user} 创建了SecretKey: {key_name}')
    
    # 返回时不包含敏感value
    return jsonify({
        'success': True,
        'message': 'SecretKey已创建',
        'data': {
            'id': new_key['id'],
            'name': new_key['name'],
            'created_by': new_key['created_by'],
            'created_at': new_key['created_at']
            # 注意：不返回value
        }
    }), 201


# ============================================
# 辅助接口：登录获取token
# ============================================

@app.route('/login', methods=['POST'])
def login():
    """登录接口"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': '缺少用户名或密码'}), 400
    
    if username not in users or users[username]['password'] != password:
        return jsonify({'error': '用户名或密码错误'}), 401
    
    # 生成token
    payload = {
        'username': username,
        'role': users[username]['role'],  # 这里可以放role，但验证时要从数据库重新获取
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'username': username,
            'role': users[username]['role']
        }
    }), 200


@app.route('/safe/manage/seckey', methods=['GET'])
@safe_admin_required
def list_seckeys():
    """安全的SecretKey列表接口"""
    # 返回列表时不包含value
    safe_list = [{
        'id': k['id'],
        'name': k['name'],
        'created_by': k.get('created_by', 'unknown'),
        'created_at': k['created_at']
    } for k in secret_keys]
    
    return jsonify({
        'success': True,
        'data': safe_list,
        'total': len(safe_list)
    }), 200


# ============================================
# 错误处理
# ============================================

@app.errorhandler(403)
def forbidden(e):
    return jsonify({
        'error': '权限不足',
        'message': '您没有权限访问此资源'
    }), 403


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({
        'error': '未授权',
        'message': '请先登录'
    }), 401


if __name__ == '__main__':
    # 启用调试模式（生产环境必须关闭）
    app.run(debug=True, port=5000)
