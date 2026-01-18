import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import os, sys, traceback, threading, queue

from xypsa import XYpsaGenerator
from src.vfs import VirtualFileSystem

vfs = None

BASE_DIR = str(os.path.dirname(os.path.realpath(sys.argv[0])))


def start_virtual_file_system(
    mountpoint,
    work_mode,
    filename,
    comment,
    encryption_type,
    password,
    content_list,
    split_size,
):
    generator = XYpsaGenerator(filename, encryption_type, password)
    if work_mode == 1:
        generator.index_count = 7000
    else:
        generator.index_count = 700
    for item in content_list:
        if os.path.isfile(item):
            generator.add_file(item)
        elif os.path.isdir(item):
            generator.add_dir(item)
    generator.set_comment(comment)
    generator.init(split_size)
    global vfs
    vfs = VirtualFileSystem(mountpoint, generator)
    vfs.start()


class XYpsaGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("XYpsa生成器")

        self.mountpoint_var = tk.StringVar(value="Z:")
        self.gen_work_mode = tk.IntVar(value=0)
        self.filename_var = tk.StringVar(value="archive")
        self.encryption_var = tk.IntVar(value=0)
        self.password_var = tk.StringVar()
        self.split_size_var = tk.StringVar(value="0")

        self.content_list = []
        self.queue = queue.Queue()  # tkinter UI操作队列
        self.whether_handle_queue = False  # 是否需要处理队列

        self.create_widgets()

    def create_widgets(self):
        # 设置网格权重
        for i in range(10):
            self.root.grid_rowconfigure(i, weight=1)
        for i in range(5):
            self.root.grid_columnconfigure(i, weight=1)

        # 左侧栏
        # 虚拟磁盘盘符
        tk.Label(self.root, text="虚拟磁盘盘符:").grid(
            row=0, column=0, padx=10, pady=5, sticky="w"
        )
        tk.Entry(self.root, textvariable=self.mountpoint_var).grid(
            row=0, column=1, padx=10, pady=5, sticky="ew"
        )
        # 生成器工作模式
        tk.Label(self.root, text="生成器工作模式:").grid(
            row=1, column=0, padx=10, pady=5, sticky="w"
        )
        tk.Radiobutton(
            self.root,
            text="一般模式(10MB内存编织索引)",
            variable=self.gen_work_mode,
            value=0,
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        tk.Radiobutton(
            self.root,
            text="大文件模式(100MB内存编织索引)",
            variable=self.gen_work_mode,
            value=1,
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        # 文件名
        tk.Label(self.root, text="文件名(不含后缀):").grid(
            row=4, column=0, padx=10, pady=5, sticky="w"
        )
        tk.Entry(self.root, textvariable=self.filename_var).grid(
            row=4, column=1, padx=10, pady=5, sticky="ew"
        )
        # 归档文件备注
        tk.Label(self.root, text="归档文件备注(不会被加密):").grid(
            row=5, column=0, padx=10, pady=5, sticky="w"
        )
        self.comment_text = tk.Text(self.root, width=30)
        self.comment_text.grid(
            row=6, column=0, columnspan=2, rowspan=3, padx=10, pady=5, sticky="nsew"
        )

        # 竖线分隔符
        ttk.Separator(self.root, orient=tk.VERTICAL).grid(
            row=0, column=2, rowspan=9, sticky="ns"
        )

        # 右侧栏
        # 密码
        tk.Label(self.root, text="密码:").grid(
            row=0, column=3, padx=10, pady=5, sticky="w"
        )
        tk.Entry(self.root, textvariable=self.password_var, show="*").grid(
            row=0, column=4, padx=10, pady=5, sticky="ew"
        )
        # 加密类型
        tk.Label(self.root, text="加密类型:").grid(
            row=1, column=3, padx=10, pady=5, sticky="w"
        )
        tk.Radiobutton(
            self.root, text="不加密", variable=self.encryption_var, value=0
        ).grid(row=2, column=3, columnspan=2, sticky="w", padx=10, pady=5)
        tk.Radiobutton(
            self.root, text="只加密文件数据", variable=self.encryption_var, value=1
        ).grid(row=3, column=3, columnspan=2, sticky="w", padx=10, pady=5)
        tk.Radiobutton(
            self.root,
            text="加密文件名和文件数据",
            variable=self.encryption_var,
            value=2,
        ).grid(row=4, column=3, columnspan=2, sticky="w", padx=10, pady=5)
        # 分卷大小输入框
        tk.Label(self.root, text="分卷大小（MB,0表示不分卷）:").grid(
            row=5, column=3, padx=10, pady=5, sticky="w"
        )
        tk.Entry(self.root, textvariable=self.split_size_var).grid(
            row=5, column=4, padx=10, pady=5, sticky="ew"
        )
        # 归档内容列表
        tk.Label(self.root, text="归档内容列表:").grid(
            row=6, column=3, padx=10, pady=5, sticky="w"
        )
        self.listbox = tk.Listbox(self.root)
        self.listbox.grid(row=7, column=3, columnspan=2, padx=10, pady=5, sticky="nsew")
        tk.Button(self.root, text="添加文件", command=self.add_file).grid(
            row=8, column=3, padx=10, pady=5
        )
        tk.Button(self.root, text="添加文件夹", command=self.add_folder).grid(
            row=8, column=4, padx=10, pady=5
        )
        # 启动按钮
        self._start_button = tk.Button(
            self.root, text="启动", command=self.start_generation, padx=20
        )
        self._start_button.grid(row=9, column=0, columnspan=5, padx=10, pady=5)
        # 加载中标签
        self.loading_label = tk.Label(self.root, text="正在生成，请稍候...")

    def add_file(self):
        path = filedialog.askopenfilename(title="选择文件")
        if path:
            self.content_list.append(path)
            self.listbox.insert(tk.END, path)

    def add_folder(self):
        path = filedialog.askdirectory(title="选择文件夹")
        if path:
            self.content_list.append(path)
            self.listbox.insert(tk.END, path)

    def start_generation(self):
        # 隐藏按钮的显示
        self._start_button.grid_forget()
        # 预处理
        mountpoint = self.mountpoint_var.get()
        work_mode = self.gen_work_mode.get()
        filename = self.filename_var.get()
        comment = self.comment_text.get("1.0", "end-1c")
        encryption_type = self.encryption_var.get()
        password = self.password_var.get()
        try:
            split_size = int(
                float(self.split_size_var.get()) * 1024 * 1024
            )  # 转换为字节
        except ValueError:
            messagebox.showerror("错误", "分卷大小不是一个有效的数值！")
            self._start_button.grid(row=9, column=0, columnspan=5, padx=10, pady=5)
            return
        # 显示提示信息
        self.loading_label.grid(row=9, column=0, columnspan=5, padx=10, pady=5)
        # 启动后台任务
        self.whether_handle_queue = True
        threading.Thread(
            target=self.start_generation_backend,
            args=(
                mountpoint,
                work_mode,
                filename,
                comment,
                encryption_type,
                password,
                split_size,
            ),
            daemon=True,
        ).start()
        # 启动队列处理
        self.root.after(100, self.process_queue)

    def process_queue(self):
        try:
            while True:
                # 从队列中获取任务并执行
                task = self.queue.get_nowait()
                task()
        except queue.Empty:
            pass
        finally:
            # 定期检查队列
            if self.whether_handle_queue:
                self.root.after(300, self.process_queue)
            else:
                print("队列处理结束")

    def start_generation_backend(
        self,
        mountpoint,
        work_mode,
        filename,
        comment,
        encryption_type,
        password,
        split_size,
    ):
        try:
            start_virtual_file_system(
                mountpoint,
                work_mode,
                filename,
                comment,
                encryption_type,
                password,
                self.content_list,
                split_size,
            )
            self.queue.put(lambda: messagebox.showinfo("成功", "虚拟磁盘挂载成功"))
            # 设置按钮为禁止
            self.queue.put(lambda: self._start_button.config(state=tk.DISABLED))
            # 显示按钮
            self.queue.put(lambda: self.loading_label.grid_forget())
            self.queue.put(
                lambda: self._start_button.grid(
                    row=9, column=0, columnspan=5, padx=10, pady=5
                )
            )
            self.whether_handle_queue = False
        except Exception as e:
            error_msg = str(e) + "\n" + traceback.format_exc()
            self.queue.put(lambda: messagebox.showerror("错误", error_msg))
            # 显示按钮
            self.queue.put(lambda: self.loading_label.grid_forget())
            self.queue.put(
                lambda: self._start_button.grid(
                    row=9, column=0, columnspan=5, padx=10, pady=5
                )
            )
            self.whether_handle_queue = False
