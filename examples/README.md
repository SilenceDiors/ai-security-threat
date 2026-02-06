# SecretKey管理接口权限控制示例

## 场景说明

这是一个典型的权限控制场景：
- 接口：`/manage/seckey`（新增SecretKey）
- 权限要求：只有**admin**角色的用户可以访问
- 非admin用户访问时应返回 **403 Forbidden**

## 威胁分析

这个场景涉及以下威胁：

### 1. 封装层服务功能级别的越权 (P1)
**威胁描述：** 如果权限校验不严格，普通用户可能越权执行管理员操作。

**攻击场景：**
```
1. 攻击者以普通用户身份登录获取token
2. 尝试访问 /manage/seckey 接口
3. 如果权限校验有漏洞，可能成功创建SecretKey
4. 导致权限提升，获得敏感配置
```

### 2. 封装层服务未授权 (P0)
**威胁描述：** 如果认证机制有问题，未登录用户可能访问敏感接口。

**攻击场景：**
```
1. 攻击者不提供任何token
2. 直接访问 /manage/seckey
3. 如果缺少认证检查，可能成功
```

### 3. 常见权限控制漏洞

#### 漏洞1：不验证token签名
```python
# 危险代码
payload = jwt.decode(token, options={"verify_signature": False})
# 攻击者可以伪造任意token
```

#### 漏洞2：信任token中的role
```python
# 危险代码
if payload.get('role') == 'admin':
    # 仅检查token中的role，攻击者可以篡改token
```

#### 漏洞3：弱比较
```python
# 危险代码
if role == 'admin':  # 可能被 'Admin', 'ADMIN', 'admin ' 绕过
```

#### 漏洞4：缺少输入验证
```python
# 危险代码
key_name = data.get('key_name')
# 没有验证长度、格式、重复等
```

## 文件说明

### 1. seckey-api-demo.py
Flask应用示例，包含：
- **不安全实现**（`/unsafe/manage/seckey`）：展示常见漏洞
- **安全实现**（`/safe/manage/seckey`）：推荐的权限控制方式

### 2. test-seckey-api.py
自动化测试脚本，测试7种场景：
1. Admin用户访问（应该成功）
2. 普通用户访问（应该403）
3. Viewer用户访问（应该403）
4. 无token访问（应该401）
5. 伪造token访问（应该401）
6. 篡改token中的role（针对不安全实现）
7. 输入验证测试（应该400）

## 快速开始

### 1. 安装依赖

```bash
pip install flask pyjwt requests colorama
```

### 2. 启动Flask服务

```bash
python seckey-api-demo.py
```

服务将在 `http://localhost:5000` 启动。

### 3. 运行测试

在另一个终端：

```bash
python test-seckey-api.py
```

### 4. 手动测试

#### 4.1 登录获取token

**Admin登录：**
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

**普通用户登录：**
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "user123"}'
```

#### 4.2 测试Admin访问（应该成功）

```bash
# 将上面获取的admin token替换到这里
TOKEN="your-admin-token-here"

curl -X POST http://localhost:5000/safe/manage/seckey \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_name": "api_key_prod", "key_value": "sk-abc123xyz"}'
```

预期响应：
```json
{
  "success": true,
  "message": "SecretKey已创建",
  "data": {
    "id": 1,
    "name": "api_key_prod",
    "created_by": "admin",
    "created_at": "2024-02-05T10:30:00"
  }
}
```

#### 4.3 测试普通用户访问（应该403）

```bash
# 将普通用户的token替换到这里
USER_TOKEN="your-user-token-here"

curl -X POST http://localhost:5000/safe/manage/seckey \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_name": "user_key", "key_value": "user-value"}'
```

预期响应：
```json
{
  "error": "权限不足",
  "message": "此操作需要管理员权限",
  "required_role": "admin",
  "your_role": "user"
}
```

#### 4.4 测试无token访问（应该401）

```bash
curl -X POST http://localhost:5000/safe/manage/seckey \
  -H "Content-Type: application/json" \
  -d '{"key_name": "test", "key_value": "test"}'
```

预期响应：
```json
{
  "error": "未提供有效的认证令牌"
}
```

## 安全实现要点

### 1. 强制身份认证
```python
@safe_admin_required
def safe_add_seckey():
    # 确保所有敏感接口都有认证装饰器
```

### 2. 验证token签名
```python
# 正确做法
payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
# 不要使用 verify_signature=False
```

### 3. 从数据库获取角色
```python
# 正确做法
username = payload.get('username')
user_role = users[username]['role']  # 从数据库获取
# 不要直接使用 payload.get('role')
```

### 4. 严格角色比较
```python
# 正确做法
if user_role != 'admin':  # 使用 != 而不是 ==
    return 403
```

### 5. 输入验证
```python
# 验证必需字段
if not data or 'key_name' not in data:
    return 400

# 验证格式
if len(key_name) > 100:
    return 400

# 验证重复
if key_name in existing_keys:
    return 409
```

### 6. 审计日志
```python
app.logger.info(f'管理员 {username} 创建了SecretKey: {key_name}')
app.logger.warning(f'用户 {username} (角色: {role}) 尝试访问管理接口')
```

### 7. 敏感信息保护
```python
# 返回时不包含敏感value
return {
    'id': key_id,
    'name': key_name,
    # 不返回 'value'
}
```

## 对应的威胁文档

- `threats/封装层服务功能级别的越权.txt` (P1)
- `threats/封装层服务未授权.txt` (P0)
- `threats/封装层API越权-IDOR.txt` (P1)
- `threats/敏感日志打印风险.txt` (P1)
- `threats/日志缺失风险.txt` (P2)

## 检查清单

在实现类似接口时，请确保：

- [ ] 所有敏感接口都有认证检查
- [ ] Token签名验证已启用
- [ ] 从数据库获取用户角色，不信任token
- [ ] 实施严格的角色比较
- [ ] 输入验证（必需字段、格式、长度、重复）
- [ ] 审计日志记录关键操作
- [ ] 敏感信息不在响应中返回
- [ ] Token有过期时间
- [ ] 高敏感操作考虑二次确认
- [ ] 错误信息不泄露敏感信息

## 常见错误

### 错误1：只检查HTTP Header，不验证内容
```python
# 错误
if request.headers.get('X-Admin') == 'true':
    # 允许访问
```

### 错误2：客户端控制的权限判断
```python
# 错误
is_admin = request.json.get('is_admin')  # 客户端传来的
if is_admin:
    # 允许访问
```

### 错误3：会话固定
```python
# 错误
session['role'] = 'user'
# 如果不重新生成session ID，可能被会话固定攻击
```

## 参考资料

- OWASP Top 10: A01:2021 – Broken Access Control
- CWE-285: Improper Authorization
- OWASP Authentication Cheat Sheet
- JWT Best Practices (RFC 8725)

## 许可

MIT License
