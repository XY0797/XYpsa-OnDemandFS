import os
import re
import threading
import time
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk

from XYpsaFormat.XYpsaParseStream import XYpsaCheckError, XYpsaParseStream


def read_xypsa_file(file_path):
    with open(file_path, "rb") as f:
        while chunk := f.read(131072):  # 流式读取
            yield chunk


def read_split_xypsa_file(parent_path, file_name, part_count):
    part_count = int(part_count)
    for i in range(part_count):
        # 生成文件名
        fpath = os.path.join(
            parent_path, f"{file_name}.{i + 1}.{part_count}.part.xypsa"
        )
        # 是否存在
        while not os.path.exists(fpath):
            messagebox.showwarning(
                "错误",
                f"分卷文件 {file_name}.{i + 1}.{part_count}.part.xypsa 不存在！",
            )
            if not messagebox.askyesno(
                "询问？",
                "是否继续解档？\n如果你补全了该文件，请点击是。如果要放弃解档，请点击否。",
            ):
                raise FileNotFoundError(
                    f"分卷文件 {file_name}.{i + 1}.{part_count}.part.xypsa 不存在！"
                )
        with open(fpath, "rb") as f:
            while chunk := f.read(131072):  # 流式读取
                yield chunk


class XYpsaGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XYpsa 解档工具")

        self.cur_size = None
        self.file_size_total = None

        # 创建界面组件
        self.create_widgets()

    def create_widgets(self):
        # 设置网格权重
        for i in range(10):
            self.root.grid_rowconfigure(i, weight=1)
        for i in range(3):
            self.root.grid_columnconfigure(i, weight=1)

        # 输入密码
        tk.Label(self.root, text="密码（无密码直接留空）：").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        # 文件路径选择
        tk.Label(self.root, text="文件路径：").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        self.file_path_entry = tk.Entry(self.root, state="readonly")
        self.file_path_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        tk.Button(self.root, text="浏览", command=self.browse_file).grid(
            row=1, column=2, padx=5, pady=5
        )

        # 解档位置
        tk.Label(self.root, text="解档位置(仅查看目录结构可留空)：").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )
        self.extract_path_entry = tk.Entry(self.root)
        self.extract_path_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        tk.Button(self.root, text="浏览", command=self.browse_directory).grid(
            row=2, column=2, padx=5, pady=5
        )

        # 开始按钮
        self.start_parse_button = tk.Button(
            self.root, text="开始解档", command=self.start_parse
        )
        self.start_parse_button.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

        # 元数据显示区域
        tk.Label(self.root, text="元数据：").grid(
            row=4, column=0, sticky="w", padx=5, pady=5
        )
        self.metadata_text = tk.Text(self.root, height=10, width=80)
        self.metadata_text.grid(
            row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=5
        )

        # 目录结构显示区域
        tk.Label(self.root, text="目录结构：").grid(
            row=6, column=0, sticky="w", padx=5, pady=5
        )
        self.tree = ttk.Treeview(
            self.root, columns=["type", "mtime", "size"], show="tree headings"
        )
        self.tree.heading("#0", text="文件名")
        self.tree.heading("type", text="类型")
        self.tree.heading("mtime", text="修改时间")
        self.tree.heading("size", text="大小")
        tree_scrollbar = ttk.Scrollbar(
            self.root, orient="vertical", command=self.tree.yview
        )
        tree_scrollbar.grid(row=7, column=2, sticky="ns", pady=5)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        self.tree.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # 进度条
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=200)
        self.progress_bar.grid(
            row=8, column=0, columnspan=3, sticky="ew", padx=5, pady=5
        )
        # 速度显示
        self.speed_label = tk.Label(self.root, text="速度：")
        self.speed_label.grid(row=9, column=0, sticky="w", padx=5, pady=5)

    def browse_file(self):
        """打开文件选择对话框"""
        file_path = filedialog.askopenfilename(
            title="选择 XYpsa 文件",
            filetypes=(("XYpsa 文件", "*.xypsa"), ("所有文件", "*.*")),
        )
        if file_path:
            file_path = os.path.abspath(file_path)
            self.file_path_entry.config(state="normal")
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.file_path_entry.config(state="readonly")

    def browse_directory(self):
        """打开目录选择对话框"""
        directory = filedialog.askdirectory(title="选择解档位置")
        if directory:
            directory = os.path.abspath(directory)
            self.extract_path_entry.delete(0, tk.END)
            self.extract_path_entry.insert(0, directory)

    def start_parse(self):
        """开始解档"""
        # 禁用按钮
        self.start_parse_button.config(state="disabled")
        # 工作线程
        threading.Thread(target=self.parse_worker, daemon=True).start()

    def parse_worker(self):
        REFRESH_INTERVAL = 0.3  # 300ms刷新一次
        td = threading.Thread(target=self.start_parse_backend)
        td.start()
        last_size = 0
        while td.is_alive():
            # 300ms刷新一次
            time.sleep(REFRESH_INTERVAL)
            # 更新进度条和速度
            if self.cur_size and self.file_size_total:
                cur_size = self.cur_size
                if cur_size > self.file_size_total:
                    self.file_size_total = cur_size * 2
                self.progress_bar.config(value=cur_size / self.file_size_total * 100)
                speed_B = (cur_size - last_size) / REFRESH_INTERVAL
                last_size = cur_size
                if speed_B < 1024:
                    speed_str = f"{speed_B:.3f}B/s"
                elif speed_B < 1024 * 1024:
                    speed_str = f"{speed_B / 1024:.3f}KB/s"
                elif speed_B < 1024 * 1024 * 1024:
                    speed_str = f"{speed_B / 1024 / 1024:.3f}MB/s"
                else:
                    speed_str = f"{speed_B / 1024 / 1024 / 1024:.3f}GB/s"
                self.speed_label.config(text=f"速度：{speed_str}")
        td.join()
        self.cur_size = None
        self.file_size_total = None
        self.progress_bar.config(value=0)
        self.speed_label.config(text="速度：")

    def start_parse_backend(self):
        try:
            # 获取用户输入
            password = self.password_entry.get()
            file_path = self.file_path_entry.get()
            extract_path = self.extract_path_entry.get()

            if not file_path:
                messagebox.showerror("错误", "请选择一个归档文件！")
                return

            if extract_path:
                extract_path = os.path.abspath(extract_path)

            # 创建解析器
            parser = XYpsaParseStream()

            # 设置密码
            if password:
                parser.set_password(password)

            # 判断文件类型
            # (.*)\.(\d+)\.(\d+)\.part\.xypsa
            # 文件名 当前分卷编号 总分卷数量
            match = re.match(
                r"^(.*)\.(\d+)\.(\d+)\.part\.xypsa$", os.path.basename(file_path)
            )
            # 获取数据源
            if match:
                file_name, part_no, part_count = match.groups()
                data_gen = read_split_xypsa_file(
                    os.path.dirname(file_path), file_name, part_count
                )
            else:
                file_name, ext = os.path.splitext(os.path.basename(file_path))
                data_gen = read_xypsa_file(file_path)

            # 开始解析
            meta_gen, index_gen, file_gen = parser.start_parse(data_gen)

            # 显示元数据
            self.metadata_text.delete(1.0, tk.END)
            encrypt_type = None
            index_section_size = 32
            try:
                for key, value in meta_gen:
                    if key == "encrypt_type":
                        encrypt_type = value
                        key = "加密类型"
                        if value == 1:
                            value = "仅加密文件数据"
                        elif value == 2:
                            value = "加密文件数据和文件名数据"
                        else:
                            value = "未加密"
                    elif key == "comment":
                        key = "归档文件中的备注"
                    elif key == "index_size":
                        assert type(value) is int
                        index_section_size = value
                    self.metadata_text.insert(tk.END, f"{key}: {value}\n")
            except XYpsaCheckError as e:
                if e.code == 6 and encrypt_type == 1:
                    # 这种情况即使元数据损坏，也可以取出目录结构的数据
                    pass
                else:
                    raise e

            # 处理目录结构
            self.tree.delete(*self.tree.get_children())
            self.tree.grid_forget()
            indexes = {}
            root_entity_count = 0
            # 简单预估实体数量
            self.file_size_total = index_section_size // 50 + 1
            self.cur_size = 0
            try:
                for index in index_gen:
                    assert type(index["name"]) is str
                    assert type(index["mtime"]) is int
                    parent_id = index["parent_id"]
                    if parent_id == 0:
                        root_entity_count += 1
                    if index["type"] == 1:
                        # 目录，需要计算路径
                        if parent_id == 0:
                            index["path"] = index["name"]
                        else:
                            index["path"] = os.path.join(
                                indexes[parent_id]["path"], index["name"]
                            )
                    if not extract_path:
                        # 不解档才需要处理树状结构的显示
                        parent_node = (
                            "" if parent_id == 0 else indexes[parent_id]["node"]
                        )
                        if index["type"] == 0:
                            type_str = "文件"
                            assert type(index["size"]) is int
                            if index["size"] < 1024:
                                size_str = f"{index['size']}B"
                            elif index["size"] < 1024 * 1024:
                                size_str = f"{index['size'] / 1024:.3f}KB"
                            elif index["size"] < 1024 * 1024 * 1024:
                                size_str = f"{index['size'] / 1024 / 1024:.3f}MB"
                            else:
                                size_str = f"{index['size'] / 1024 / 1024 / 1024:.3f}GB"
                        else:
                            type_str = "文件夹"
                            size_str = ""
                        # 时间格式化
                        mtime_str = time.strftime(
                            "%Y-%m-%d %H:%M:%S",
                            time.localtime(index["mtime"] / 10000000),
                        )
                        node = self.tree.insert(
                            parent_node,
                            "end" if index["type"] == 0 else 0,
                            text=index["name"],
                            values=(
                                type_str,
                                mtime_str,
                                size_str,
                            ),
                        )
                        index["node"] = node

                    # 存储实体信息
                    indexes[index["id"]] = index
                    # 进度更新
                    self.cur_size += 1
            except XYpsaCheckError as e:
                if e.code == 8 and encrypt_type == 1 and (not extract_path):
                    # 这种情况即使目录结构校验码不匹配，也应该显示
                    self.file_size_total = self.cur_size
                    self.tree.grid(
                        row=7, column=0, columnspan=2, sticky="nsew", padx=5, pady=5
                    )
                    messagebox.showinfo(
                        "成功", "解析完成！不过因为无密码，无法验证文件是否损坏或被篡改"
                    )
                    return
                else:
                    raise e
            # 不需要解档的，在此停止
            self.file_size_total = self.cur_size
            self.tree.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
            if not extract_path:
                messagebox.showinfo("成功", "解析完成！")
                return

            # 规范解档目录
            if (
                os.path.exists(extract_path)
                and os.path.basename(extract_path) != file_name
                and root_entity_count > 1
            ):
                if messagebox.askyesno(
                    "警告",
                    f"解档位置已存在，且名字不等于档案文件名，且档案内含{root_entity_count}个文件或文件夹。\n是否需要在解档位置创建与档案同名的新目录？",
                    icon="warning",
                ):
                    extract_path = os.path.join(extract_path, file_name)
            # 创建解档目录
            os.makedirs(extract_path, exist_ok=True)
            self.file_size_total = 0
            for index in indexes.values():
                if index["type"] == 1:
                    index["path"] = os.path.join(extract_path, index["path"])
                    os.makedirs(index["path"], exist_ok=True)
                else:
                    self.file_size_total += index["size"]
            self.cur_size = 0
            for entity_id, file_data_gen in file_gen:
                index = indexes[entity_id]
                parent_id = index["parent_id"]
                if parent_id == 0:
                    file_path = os.path.join(extract_path, index["name"])
                else:
                    file_path = os.path.join(indexes[parent_id]["path"], index["name"])
                with open(file_path, "wb") as f:
                    for chunk in file_data_gen:
                        self.cur_size += f.write(chunk)
                # 修改文件的修改时间
                mtime = index["mtime"] * 100
                os.utime(file_path, ns=(mtime, mtime))

            messagebox.showinfo("成功", "解档完成！")
        except XYpsaCheckError as e:
            # 捕获 XYpsaCheckError 并显示中文错误信息
            error_map = {
                1: "文件不是有效的 XYpsa 文件。",
                2: "不支持的 XYpsa 版本。",
                3: "未知的加密类型。",
                4: "文件已加密，但未提供密码。",
                5: "元数据损坏。",
                6: "密码错误或元数据损坏。",
                7: "读取元数据时数据源提前结束。",
                8: "索引区损坏。",
                9: "读取索引区时数据源提前结束。",
                10: "文件数据损坏。",
                11: "全局完整性检查失败。",
                12: "读取文件数据时数据源提前结束。",
            }
            if e.code == 4 and encrypt_type == 1:
                error_msg = (
                    error_map[4]
                    + "您可以输入一个错误密码，以获取档案的目录结构(解档会失败)。"
                )
            elif e.code == 8 and encrypt_type == 1:
                error_msg = error_map[8] + "也有可能是密码错误。"
            else:
                error_msg = error_map.get(e.code, str(e))
            messagebox.showerror("错误", f"解档失败：{error_msg}")
        except Exception as e:
            # 显示其他异常的详细信息
            error_msg = traceback.format_exc()
            messagebox.showerror("错误", f"解档失败，发生异常：{str(e)}\n{error_msg}")
        finally:
            # 启用按钮
            self.start_parse_button.config(state="normal")


# 运行 GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = XYpsaGUI(root)
    root.mainloop()
