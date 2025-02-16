# -*- mode: python ; coding: utf-8 -*-

# 分析 main.py 和 GUI_unarchive.py
a_main = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

a_gui_unarchive = Analysis(
    ['GUI_unarchive.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# 创建 PYZ 对象，包含所有模块
pyz = PYZ(a_main.pure + a_gui_unarchive.pure)

# 定义第一个 EXE：XYpsa虚拟动态归档器
exe_main = EXE(
    pyz,
    a_main.scripts,
    [],
    exclude_binaries=True,
    name='XYpsa虚拟动态归档器',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# 定义第二个 EXE：XYpsa解档器
exe_gui_unarchive = EXE(
    pyz,
    a_gui_unarchive.scripts,
    [],
    exclude_binaries=True,
    name='XYpsa解档器',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# 使用 COLLECT 将两个 EXE 打包到同一个环境中
coll = COLLECT(
    exe_main,
    exe_gui_unarchive,
    a_main.binaries + a_gui_unarchive.binaries,  # 合并二进制文件
    a_main.datas + a_gui_unarchive.datas,        # 合并数据文件
    strip=False,
    upx=True,
    upx_exclude=[],
    name='XYpsa工具集',  # 输出目录名称
)