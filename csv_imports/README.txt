CSV 导入目录使用说明
===================

1. 将所有 CSV 文件放入此目录
2. CSV 格式要求（支持逗号或 Tab 分隔）：
   - 必须包含列: host, ip, port, protocol, country, region, city
   - 支持 UTF-8, GBK, GB2312 编码
   
3. 在 Web 界面点击"一键导入所有 CSV"按钮
4. 系统会自动去重并写入数据库（状态为 Pending）
5. 点击"开始检查可用性"按钮进行漏洞扫描

示例 CSV 格式（逗号分隔）：
host,ip,port,protocol,country,region,city
https://183.23.162.198:9000,183.23.162.198,9000,https,CN,广东省,Dongguan
dragonsun.top:5666,112.17.144.152,5666,http,CN,浙江省,Hangzhou
8.138.117.131:2000,8.138.117.131,2000,http,CN,广东省,Guangzhou
