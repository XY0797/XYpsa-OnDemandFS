from tkinter import Tk, messagebox

from winfspy.plumbing.get_winfsp_dir import get_winfsp_dir

from src.gui import XYpsaGeneratorApp

if __name__ == "__main__":
    try:
        get_winfsp_dir()
    except RuntimeError:
        messagebox.showerror(
            "错误",
            "您似乎没安装Winfsp，请先安装Winfsp！打开安装包后，保持默认值一直点击Next就行。",
        )
        exit()
    root = Tk()
    app = XYpsaGeneratorApp(root)
    root.mainloop()
