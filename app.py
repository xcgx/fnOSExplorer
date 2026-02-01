from flask import Flask, render_template, request, redirect, url_for, send_file, Response, jsonify
from database import init_db, get_all_targets, get_target_by_id, get_targets_paginated, get_status_counts
from scanner import process_csv, import_all_csv_files, scan_pending_targets
from file_ops import get_remote_content, recursive_zip_download
import io

app = Flask(__name__)

# 初始化数据库
init_db()


def get_flag_emoji(country_code):
    """将国家代码转换为国旗 emoji"""
    if not country_code or len(country_code) != 2:
        return '🏳️'
    
    # 将国家代码转换为区域指示符号（Regional Indicator Symbols）
    # A-Z 对应 Unicode 0x1F1E6-0x1F1FF
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in country_code.upper())


def get_file_icon(filename):
    """根据文件扩展名返回对应的 emoji 图标"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    icon_map = {
        # 图片
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'bmp': '🖼️', 'svg': '🖼️', 'webp': '🖼️', 'ico': '🖼️',
        # 文档
        'pdf': '📕', 'doc': '📘', 'docx': '📘', 'xls': '📗', 'xlsx': '📗', 'ppt': '📙', 'pptx': '📙',
        # 文本
        'txt': '📝', 'log': '📋', 'md': '📝', 'json': '📋', 'xml': '📋', 'csv': '📊',
        # 代码
        'py': '🐍', 'js': '📜', 'html': '🌐', 'css': '🎨', 'java': '☕', 'c': '©️', 'cpp': '©️', 'sh': '🔧',
        # 压缩
        'zip': '📦', 'rar': '📦', 'tar': '📦', 'gz': '📦', '7z': '📦',
        # 音视频
        'mp3': '🎵', 'wav': '🎵', 'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬',
    }
    
    return icon_map.get(ext, '📄')


# 注册为模板函数
app.jinja_env.globals.update(get_flag_emoji=get_flag_emoji)
app.jinja_env.globals.update(get_file_icon=get_file_icon)


@app.route('/')
def index():
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    status_filter = request.args.get('status', 'Vulnerable')  # 默认筛选漏洞
    search_query = request.args.get('search', '')
    
    # 获取分页数据
    pagination = get_targets_paginated(
        page=page,
        per_page=per_page,
        status_filter=status_filter if status_filter != 'all' else None,
        search_query=search_query if search_query else None
    )
    
    # 获取状态统计
    status_counts = get_status_counts()
    
    return render_template('index.html', 
                         targets=pagination['items'],
                         pagination=pagination,
                         status_counts=status_counts,
                         current_status=status_filter,
                         search_query=search_query)


@app.route('/import', methods=['POST'])
def import_csv_route():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    process_csv(file)
    return redirect(url_for('index'))


@app.route('/import_all', methods=['POST'])
def import_all_route():
    """一键导入所有 CSV 文件"""
    result = import_all_csv_files()
    return jsonify(result)


@app.route('/scan_pending', methods=['POST'])
def scan_pending_route():
    """扫描所有待检查的目标"""
    # 获取线程数配置
    data = request.get_json() or {}
    max_workers = data.get('max_workers', 32)
    
    # 验证线程数范围
    if not isinstance(max_workers, int) or max_workers < 1 or max_workers > 100:
        return jsonify({"success": False, "message": "线程数必须在 1-100 之间"})
    
    result = scan_pending_targets(max_workers=max_workers)
    return jsonify(result)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """获取统计数据 API"""
    status_counts = get_status_counts()
    return jsonify(status_counts)


@app.route('/explore/<int:target_id>')
def explore(target_id):
    """文件浏览主视图"""
    target = get_target_by_id(target_id)
    if not target:
        return "Target not found", 404

    # 获取当前请求的路径，默认为根目录
    current_path = request.args.get('path', '/')
    base_url = target['base_url']

    data = get_remote_content(base_url, current_path)

    if data['type'] == 'file':
        # 如果是文件，判断是预览还是下载
        action = request.args.get('action', 'view')

        # 获取文件名
        filename = current_path.split('/')[-1]
        
        # 下载时添加 ID 前缀
        if action == 'download':
            download_filename = f"{target_id}_{filename}"
            return send_file(
                io.BytesIO(data['content']),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=download_filename
            )
        
        # 预览模式
        mimetype = data['mimetype']
        if not mimetype:
            mimetype = 'application/octet-stream'
        
        return send_file(io.BytesIO(data['content']), mimetype=mimetype)

    elif data['type'] == 'directory':
        # 计算面包屑导航
        parts = [p for p in current_path.split('/') if p]
        breadcrumbs = []
        acc = ""
        for p in parts:
            acc += "/" + p
            breadcrumbs.append({'name': p, 'path': acc})

        # 检测 WebDAV 快捷目录
        webdav_shortcuts = []
        
        # 如果在 /share/home 目录，检测子目录
        if current_path.rstrip('/') == '/share/home' or current_path.rstrip('/').startswith('/share/home/'):
            # 获取 home 目录下的所有子目录
            if current_path.rstrip('/') == '/share/home':
                # 当前就在 home 目录，列出所有数字目录
                for item in data['items']:
                    if item['is_dir'] and item['name'].rstrip('/').isdigit():
                        user_id = item['name'].rstrip('/')
                        webdav_path = f"/share/home/{user_id}/webdav"
                        webdav_shortcuts.append({
                            'user_id': user_id,
                            'path': webdav_path
                        })
            else:
                # 在某个用户目录下，检测其他用户目录
                home_data = get_remote_content(base_url, '/share/home')
                if home_data['type'] == 'directory':
                    for item in home_data['items']:
                        if item['is_dir'] and item['name'].rstrip('/').isdigit():
                            user_id = item['name'].rstrip('/')
                            webdav_path = f"/share/home/{user_id}/webdav"
                            webdav_shortcuts.append({
                                'user_id': user_id,
                                'path': webdav_path
                            })

        return render_template('explorer.html',
                               target=target,
                               items=data['items'],
                               current_path=current_path,
                               breadcrumbs=breadcrumbs,
                               target_id=target_id,
                               webdav_shortcuts=webdav_shortcuts)
    else:
        return f"Error: {data.get('msg')}", 500


@app.route('/download_folder/<int:target_id>')
def download_folder_route(target_id):
    """触发递归下载"""
    target = get_target_by_id(target_id)
    path = request.args.get('path', '/')

    zip_stream = recursive_zip_download(target['base_url'], path)

    filename = f"download_{target['ip']}_{path.replace('/', '_')}.zip"
    return send_file(
        zip_stream,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)