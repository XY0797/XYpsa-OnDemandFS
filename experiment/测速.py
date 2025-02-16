import time

file_path = "Z:\\archive.xypsa"
# 读取性能测速
start_time = time.time()
data_len = 0
with open(file_path, "rb") as f:
    while True:
        data = f.read(1024 * 1024)
        if not data:
            break
        data_len += len(data)
    print("读取文件大小：", data_len, "字节")
end_time = time.time()
time_cost = end_time - start_time
print("读取文件用时：", time_cost, "秒")
print("读取速率：", data_len / time_cost / 1024 / 1024, "MB/秒")
# 测试跳过速率
with open(file_path, "rb") as f:
    f.read(1)
    start_time = time.time()
    f.seek(data_len - 1, 0)
    f.read(1)
    end_time = time.time()
time_cost = end_time - start_time
print("跳过文件用时：", time_cost, "秒")
print("跳过速率：", (data_len - 1) / time_cost / 1024 / 1024, "MB/秒")
