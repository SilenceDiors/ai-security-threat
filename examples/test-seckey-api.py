"""
SecretKey管理接口测试脚本
测试不同权限用户访问 /manage/seckey 的行为
"""

import requests
import json
from colorama import Fore, Style, init

# 初始化colorama
init(autoreset=True)

BASE_URL = "http://localhost:5000"

def print_test(title):
    """打印测试标题"""
    print(f"\n{'='*60}")
    print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    print('='*60)

def print_success(message):
    """打印成功信息"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_error(message):
    """打印错误信息"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")

def print_info(message):
    """打印信息"""
    print(f"{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

def login(username, password):
    """登录获取token"""
    response = requests.post(f"{BASE_URL}/login", json={
        'username': username,
        'password': password
    })
    
    if response.status_code == 200:
        data = response.json()
        print_success(f"登录成功 - 用户: {username}, 角色: {data['user']['role']}")
        return data['token']
    else:
        print_error(f"登录失败 - {response.json().get('error')}")
        return None

def create_seckey(token, key_name, key_value, endpoint="/safe/manage/seckey"):
    """创建SecretKey"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.post(f"{BASE_URL}{endpoint}", 
                            headers=headers,
                            json={
                                'key_name': key_name,
                                'key_value': key_value
                            })
    
    print(f"状态码: {response.status_code}")
    print(f"响应: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    return response


def run_tests():
    """运行所有测试"""
    
    # ========================================
    # 测试1：Admin用户正常访问（应该成功）
    # ========================================
    print_test("测试1：Admin用户访问 /safe/manage/seckey（预期：成功）")
    
    admin_token = login('admin', 'admin123')
    if admin_token:
        print_info("尝试创建SecretKey...")
        response = create_seckey(admin_token, 'api_key_prod', 'sk-abc123xyz')
        
        if response.status_code == 201:
            print_success("Admin用户成功创建SecretKey")
        else:
            print_error("Admin用户创建SecretKey失败（不应该）")
    
    # ========================================
    # 测试2：普通用户访问（应该被拒绝）
    # ========================================
    print_test("测试2：普通用户访问 /safe/manage/seckey（预期：403 Forbidden）")
    
    user_token = login('user1', 'user123')
    if user_token:
        print_info("尝试创建SecretKey...")
        response = create_seckey(user_token, 'user_key', 'user-value')
        
        if response.status_code == 403:
            print_success("正确拒绝了普通用户的访问")
        else:
            print_error(f"权限控制失效！普通用户不应该能访问（状态码: {response.status_code}）")
    
    # ========================================
    # 测试3：Viewer用户访问（应该被拒绝）
    # ========================================
    print_test("测试3：Viewer用户访问 /safe/manage/seckey（预期：403 Forbidden）")
    
    viewer_token = login('viewer', 'viewer123')
    if viewer_token:
        print_info("尝试创建SecretKey...")
        response = create_seckey(viewer_token, 'viewer_key', 'viewer-value')
        
        if response.status_code == 403:
            print_success("正确拒绝了Viewer用户的访问")
        else:
            print_error(f"权限控制失效！Viewer不应该能访问（状态码: {response.status_code}）")
    
    # ========================================
    # 测试4：无token访问（应该被拒绝）
    # ========================================
    print_test("测试4：无token访问 /safe/manage/seckey（预期：401 Unauthorized）")
    
    print_info("尝试无token访问...")
    response = requests.post(f"{BASE_URL}/safe/manage/seckey",
                            json={'key_name': 'test', 'key_value': 'test'})
    
    print(f"状态码: {response.status_code}")
    print(f"响应: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    
    if response.status_code == 401:
        print_success("正确拒绝了无token的访问")
    else:
        print_error(f"认证控制失效！（状态码: {response.status_code}）")
    
    # ========================================
    # 测试5：伪造token访问（应该被拒绝）
    # ========================================
    print_test("测试5：伪造token访问 /safe/manage/seckey（预期：401 Unauthorized）")
    
    fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.fake"
    
    print_info("使用伪造的token...")
    response = requests.post(f"{BASE_URL}/safe/manage/seckey",
                            headers={'Authorization': f'Bearer {fake_token}'},
                            json={'key_name': 'fake', 'key_value': 'fake'})
    
    print(f"状态码: {response.status_code}")
    print(f"响应: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    
    if response.status_code == 401:
        print_success("正确拒绝了伪造token的访问")
    else:
        print_error(f"Token验证失效！（状态码: {response.status_code}）")
    
    # ========================================
    # 测试6：篡改token中的role（针对不安全实现）
    # ========================================
    print_test("测试6：尝试篡改token中的role字段（测试不安全实现）")
    
    print_info("这个测试针对 /unsafe/manage/seckey 接口")
    print_info("如果该接口存在，普通用户可能通过篡改token中的role绕过权限检查")
    print_info("安全的实现应该从数据库重新获取用户角色，而不是信任token中的role")
    
    # ========================================
    # 测试7：输入验证测试
    # ========================================
    print_test("测试7：输入验证测试（预期：400 Bad Request）")
    
    if admin_token:
        # 测试7.1：缺少必需字段
        print_info("7.1 - 缺少必需字段...")
        response = requests.post(f"{BASE_URL}/safe/manage/seckey",
                                headers={'Authorization': f'Bearer {admin_token}'},
                                json={'key_name': 'test'})  # 缺少key_value
        
        print(f"状态码: {response.status_code}")
        if response.status_code == 400:
            print_success("正确拒绝了不完整的请求")
        
        # 测试7.2：超长字段
        print_info("\n7.2 - 超长key_name...")
        response = requests.post(f"{BASE_URL}/safe/manage/seckey",
                                headers={'Authorization': f'Bearer {admin_token}'},
                                json={
                                    'key_name': 'a' * 200,  # 超过100字符
                                    'key_value': 'value'
                                })
        
        print(f"状态码: {response.status_code}")
        if response.status_code == 400:
            print_success("正确拒绝了超长字段")
        
        # 测试7.3：重复的key_name
        print_info("\n7.3 - 重复的key_name...")
        response = requests.post(f"{BASE_URL}/safe/manage/seckey",
                                headers={'Authorization': f'Bearer {admin_token}'},
                                json={
                                    'key_name': 'api_key_prod',  # 已存在
                                    'key_value': 'new-value'
                                })
        
        print(f"状态码: {response.status_code}")
        if response.status_code == 409:
            print_success("正确拒绝了重复的key_name")
    
    # ========================================
    # 总结
    # ========================================
    print_test("测试总结")
    print("""
权限控制关键点：
1. ✓ Admin用户可以访问
2. ✓ 非Admin用户（user/viewer）被拒绝（403）
3. ✓ 无token访问被拒绝（401）
4. ✓ 伪造token被拒绝（401）
5. ✓ 输入验证（缺失字段、格式错误、重复等）

安全建议：
- 始终验证token签名
- 从数据库获取用户角色，不信任token中的role
- 实施细粒度的输入验证
- 记录审计日志
- 敏感信息不在响应中返回
    """)


if __name__ == '__main__':
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SecretKey管理接口权限控制测试{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}请确保Flask服务已启动：python seckey-api-demo.py{Style.RESET_ALL}\n")
    
    try:
        run_tests()
    except requests.exceptions.ConnectionError:
        print_error("\n无法连接到服务器！请先启动Flask服务：")
        print_info("python seckey-api-demo.py")
    except Exception as e:
        print_error(f"\n测试过程中出现错误: {str(e)}")
