import os
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from collections import deque

# ---打开文件 API---

if os.name == "nt":

    def myopen(file_path: str):
        fd = os.open(file_path, os.O_RDONLY | os.O_BINARY)
        try:
            # 使用 os.fdopen 将文件描述符转换为文件对象
            return os.fdopen(fd, "rb")
        except Exception as e:
            os.close(fd)
            raise e

else:

    def myopen(file_path: str):
        return open(file_path, "rb")


# ---打开文件 END---


def check_file_access(file_path: str) -> bool:
    try:
        f = myopen(file_path)
        f.close()
    except Exception as e:
        return False
    return True


class XYpsaGenStream:
    XYPSA_VERSION = 1

    def __init__(self, encrypt_type: int = 0, password: str = None):
        """
        初始化XYpsaGenStream对象
        :param encrypt_type: 加密类型，0表示不加密，1表示加密文件数据，2表示加密文件数据和索引项
        :param password: 加密密码
        """
        self.encrypt_type = encrypt_type  # 加密类型
        self.password = password  # 加密密码
        self.comment = ""  # 文件备注
        self.block_size = 131072  # 默认块大小,128KB
        self.total_size = None  # 归档文件总大小
        self.entity_name_len_sum = None  # 实体名称总长度
        self.file_data_len_sum = None  # 文件数据总长度

        self.indexes = None  # 索引项数组
        self.files = None  # 文件项数组（实体ID，文件路径，文件长度）
        self.pre_open_files = True  # 是否预先打开文件对象
        self.opened_obj_dict = None  # 实体ID->打开的文件对象

        self.abs_file_path = set()  # 存储绝对文件路径
        self.abs_dir_path = set()  # 存储绝对目录路径

        self.iv = None  # 加密IV
        self.secret_key = None  # 密钥
        self.encryptor = None  # 加密上下文

        self.global_hash_ctx = None  # 全局校验码上下文

        self.gen_state = None  # 流的生成状态
        """
        0：metadata
        1：index
        2：file_data
        """
        self.current_generator = None  # 当前生成器
        self.gen_buffer = None  # 数据缓冲区
        self.offset = None  # 当前偏移量

    def __del__(self):
        """
        关闭打开的文件对象
        """
        if self.opened_obj_dict:
            for obj in self.opened_obj_dict.values():
                obj.close()
            self.opened_obj_dict = None

    def add_file(self, file_path: str):
        """添加文件到归档"""
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            raise ValueError(f"File not found: {abs_path}")
        self.abs_file_path.add(abs_path)

    def add_dir(self, dir_path: str):
        """添加目录到归档"""
        abs_path = os.path.abspath(dir_path)
        if not os.path.isdir(abs_path):
            raise ValueError(f"Directory not found: {abs_path}")
        self.abs_dir_path.add(abs_path)

    def set_comment(self, comment: str):
        """设置归档文件的备注"""
        if len(comment) > 65535:
            raise ValueError("Comment is too long")
        self.comment = comment

    def set_block_size(self, block_size: int):
        """设置流式生成时的块大小"""
        self.block_size = block_size

    def copy_init(self, other: "XYpsaGenStream"):
        """从其他XYpsaGenStream对象拷贝参数"""
        if not other.current_generator:
            raise RuntimeError("other XYpsaGenStream object not initialized")
        self.encrypt_type = other.encrypt_type
        self.password = other.password
        self.comment = other.comment
        self.block_size = other.block_size
        self.total_size = None
        self.entity_name_len_sum = other.entity_name_len_sum
        self.file_data_len_sum = other.file_data_len_sum
        # 获取indexes的引用，这是因为后续流式生成没有对indexes的写操作，共享它是安全的
        self.indexes = other.indexes
        self.files = other.files
        # 路径可以不用复制，因为流式生成时不会对它们进行读写
        self.abs_file_path = None
        self.abs_dir_path = None
        # 流式生成相关的参数
        self.opened_obj_dict = dict()
        self.iv = None
        self.secret_key = None
        self.encryptor = None
        self.global_hash_ctx = None
        self.gen_state = None
        self.current_generator = None
        self.gen_buffer = None
        # 计算总大小
        self._calculate_total_size()
        if self.total_size != other.total_size:
            raise ValueError("Total size not match")
        # 初始化加密/完整性校验相关的参数
        self._initialize_encryption(other.iv)
        # 准备数据的生成器
        self._prepare_generators()

    def init(self, iv: bytes = None) -> list[str]:
        """
        初始化归档文件，计算文件大小并准备生成器
        返回无权限访问的文件/文件夹列表
        """
        self.entity_name_len_sum = 0
        self.file_data_len_sum = 0
        self.indexes = []
        self.files = []
        self.opened_obj_dict = dict()
        no_access_list = []
        # 构造索引项和文件项
        for path in self.abs_dir_path:
            self._process_path(path, False, no_access_list)
        for path in self.abs_file_path:
            self._process_path(path, True, no_access_list)
        # 初始化加密/完整性校验相关的参数
        self._initialize_encryption(iv)
        # 计算总大小(需要先修正加密参数,否则长度会错误)
        self._calculate_total_size()
        # 准备数据的生成器
        self._prepare_generators()
        return no_access_list

    def skip(self, target_offset: int):
        """跳过一定的数据，直到到达指定偏移量"""
        if not self.current_generator:
            raise RuntimeError("Archive not initialized")
        if target_offset < 1:
            raise ValueError("Target offset is smaller than 1")
        if self.offset > target_offset:
            raise ValueError("Target offset is smaller than current offset")
        target_size = target_offset - self.offset
        last_buffer_size = len(self.gen_buffer)
        if last_buffer_size >= target_size:
            # 缓冲区中已经有足够的数据，直接跳过
            self.gen_buffer = self.gen_buffer[target_size:]
            self.offset += target_size
            return
        if last_buffer_size > 0:
            # 减去当前缓冲区残留的数据长度
            # 也标志着缓冲区内数据已被放弃
            # 偏移量更新则推迟到缓冲区被覆盖时
            target_size -= last_buffer_size
        while True:
            try:
                # 取出数据
                self.gen_buffer = next(self.current_generator)
                # 上一次的缓冲区被覆写，需要更新偏移量
                self.offset += last_buffer_size
                # 更新上一次缓冲区大小
                last_buffer_size = len(self.gen_buffer)
                if last_buffer_size >= target_size:
                    # 缓冲区中已经有足够的数据，完成跳过
                    self.gen_buffer = self.gen_buffer[target_size:]
                    self.offset += target_size
                    return
                # 更新目标大小，偏移量更新则推迟到下次循环缓冲区被覆盖时
                target_size -= last_buffer_size
            except StopIteration as e:
                if self.gen_state == 0:
                    self.current_generator = self._generate_index()
                    self.gen_state = 1
                elif self.gen_state == 1:
                    self.current_generator = self._generate_file_data()
                    self.gen_state = 2
                else:
                    # 理论上不会执行到这里
                    raise e

    def __iter__(self):
        """返回迭代器，也就是自己"""
        return self

    def __len__(self):
        """返回总大小"""
        if not self.total_size:
            raise RuntimeError("Archive not initialized")
        return self.total_size

    def __next__(self):
        """流式生成数据块"""
        if not self.current_generator:
            raise RuntimeError("Archive not initialized")
        while True:
            if len(self.gen_buffer) >= self.block_size:
                # 达到块大小，需要reutn一次块大小的数据
                buf_mv = memoryview(self.gen_buffer)
                ret_data = bytes(buf_mv[0 : self.block_size])
                self.gen_buffer = bytearray(buf_mv[self.block_size :])
                self.offset += len(ret_data)
                return ret_data
            try:
                self.gen_buffer += next(self.current_generator)
            except StopIteration as e:
                if self.gen_state == 0:
                    self.current_generator = self._generate_index()
                    self.gen_state = 1
                elif self.gen_state == 1:
                    self.current_generator = self._generate_file_data()
                    self.gen_state = 2
                else:
                    if len(self.gen_buffer) >= self.block_size:
                        # 达到块大小，需要reutn一次块大小的数据
                        buf_mv = memoryview(self.gen_buffer)
                        ret_data = bytes(buf_mv[0 : self.block_size])
                        self.gen_buffer = bytearray(buf_mv[self.block_size :])
                        self.offset += len(ret_data)
                        return ret_data
                    if len(self.gen_buffer) > 0:
                        # 还有剩余数据，需要return一次
                        ret_data = bytes(self.gen_buffer)
                        self.gen_buffer = bytearray()
                        self.offset += len(ret_data)
                        return ret_data
                    raise e

    def _process_path(self, root_path: str, is_file: bool, no_access_list: list[str]):
        """
        处理路径并创建实体，同时统计 实体名称总长度 和 文件实体数据总长度
        因为文件都是挂载在根下，因此路径指定实体的父实体ID一定为0
        """
        if is_file:
            # 是文件，直接加，然后返回
            self._add_file_index_item(root_path, 0, no_access_list)
            return
        # 执行到这里，只能是根下的目录
        # 使用栈实现深度优先遍历
        stack = deque()  # (路径, 实体名, 父实体ID)
        root_dir_name = os.path.basename(root_path)
        is_windows_root = False
        if len(root_dir_name) == 0:
            # path中寻找:\
            separation_index = root_path.find(":\\")
            if separation_index != -1:
                # 找到了，说明是Windows系统磁盘根目录
                root_dir_name = root_path[0:separation_index]
                is_windows_root = True
        if is_windows_root:
            # 检查权限
            try:
                dir_scanner = os.scandir(root_path)
            except PermissionError:
                no_access_list.append(root_path)
            else:
                # 把自己添加进索引，生成索引项
                entity_id = len(self.indexes) + 1
                self.indexes.append(
                    {
                        "id": entity_id,
                        "parent_id": 0,
                        "type": 1,
                        "mtime": int(os.path.getmtime(root_path) * 1e7),
                        "name": root_dir_name,
                    }
                )
                # 统计长度
                self.entity_name_len_sum += len(root_dir_name.encode("utf-8"))
                # 遍历自己下面的文件和目录
                for entry in dir_scanner:
                    try:
                        if entry.is_dir():
                            # 是目录
                            is_file = False
                        elif entry.is_file():
                            # 是文件
                            is_file = True
                        else:
                            # 其他类型，跳过
                            continue
                    except PermissionError:
                        # 无权限访问，跳过
                        no_access_list.append(entry.path)
                        continue
                    if is_file:
                        # 先判断黑名单，再添加文件
                        if entry.name not in [
                            "swapfile.sys",
                            "pagefile.sys",
                            "hiberfil.sys",
                            "DumpStack.log",
                            "DumpStack.log.tmp",
                        ]:
                            self._add_file_index_item(
                                entry.path, entity_id, no_access_list
                            )
                    else:
                        # 先判断黑名单，再加入栈
                        if entry.name not in [
                            "$RECYCLE.BIN",
                            "$Recycle.Bin",
                            "System Volume Information",
                        ]:
                            stack.append((entry.path, entry.name, entity_id))
        else:
            # 非Windows系统根目录，使用普通流程即可
            stack.append((root_path, root_dir_name, 0))

        while stack:
            current_path, dir_base_name, parent_id = stack.pop()

            # 检查权限
            try:
                dir_scanner = os.scandir(current_path)
            except PermissionError:
                no_access_list.append(current_path)
                continue

            # 先把自己添加进索引，生成索引项
            entity_id = len(self.indexes) + 1
            self.indexes.append(
                {
                    "id": entity_id,
                    "parent_id": parent_id,
                    "type": 1,
                    "mtime": int(os.path.getmtime(current_path) * 1e7),
                    "name": dir_base_name,
                }
            )
            # 统计长度
            self.entity_name_len_sum += len(dir_base_name.encode("utf-8"))

            # 遍历自己下面的文件和目录
            for entry in dir_scanner:
                try:
                    if entry.is_dir():
                        # 是目录
                        is_file = False
                    elif entry.is_file():
                        # 是文件
                        is_file = True
                    else:
                        # 其他类型，跳过
                        continue
                except PermissionError:
                    # 无权限访问，跳过
                    no_access_list.append(entry.path)
                    continue
                if is_file:
                    # 文件，直接加
                    self._add_file_index_item(entry.path, entity_id, no_access_list)
                else:
                    # 目录，加入栈
                    stack.append((entry.path, entry.name, entity_id))

    def _add_file_index_item(
        self, file_path: str, parent_id: int, no_access_list: list[str]
    ):
        """
        把文件添加进 索引项列表 和 文件项列表

        需要统计 实体名称总长度 和 文件实体数据总长度
        """
        # 检查权限
        if not check_file_access(file_path):
            no_access_list.append(file_path)
            return
        entity_id = len(self.indexes) + 1
        try:
            # 预打开文件
            if self.pre_open_files:
                self.opened_obj_dict[entity_id] = myopen(file_path)
            # 计算文件长度
            file_size = os.path.getsize(file_path)
            file_base_name = os.path.basename(file_path)
            self.indexes.append(
                {
                    "id": entity_id,
                    "parent_id": parent_id,
                    "type": 0,
                    "mtime": int(os.path.getmtime(file_path) * 1e7),
                    "name": file_base_name,
                    "size": file_size,
                }
            )
            self.files.append((entity_id, file_path, file_size))
            # 统计长度
            self.entity_name_len_sum += len(file_base_name.encode("utf-8"))
            self.file_data_len_sum += file_size
        except IOError:
            raise ValueError(f"Could not open file: {file_path}")

    def _calculate_total_size(self):
        """计算归档文件的总大小"""
        comment_len = len(self.comment.encode("utf-8"))
        iv_len = 16 if (self.encrypt_type != 0) else 0
        entity_count = len(self.indexes)
        file_count = len(self.files)
        self.total_size = (
            comment_len
            + iv_len
            + self.entity_name_len_sum
            + self.file_data_len_sum
            + 27 * entity_count
            + 48 * file_count
            + 127
        )

    def _initialize_encryption(self, iv: bytes = None):
        """初始化加密参数"""
        if self.password:
            if self.encrypt_type != 0:
                # 启用了加密
                if iv and (len(iv) == 16):
                    self.iv = iv
                else:
                    self.iv = os.urandom(16)  # 密码学安全随机数生成
                # 从密码得出密钥
                key_hash_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
                key_hash_ctx.update(self.password.encode("utf-8"))
                self.secret_key = key_hash_ctx.finalize()
                # 初始化全局加密上下文
                cipher = Cipher(
                    algorithms.AES(self.secret_key),
                    modes.CFB(self.iv),
                    backend=default_backend(),
                )
                self.encryptor = cipher.encryptor()
                # 初始化全局校验码上下文
                self.global_hash_ctx = hmac.HMAC(
                    self.secret_key, hashes.SHA256(), backend=default_backend()
                )
                return
            else:
                self.password = None
        else:
            self.encrypt_type = 0
        # 不需要加密
        # 初始化全局校验码上下文
        self.global_hash_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())

    def _prepare_generators(self):
        """准备生成器"""
        self.gen_state = 0
        self.offset = 0
        self.current_generator = self._generate_metadata()
        self.gen_buffer = bytearray()

    def _generate_metadata(self):
        """
        生成元数据区
        不管块大小，一次性直接生成完
        """
        comment_bytes = self.comment.encode("utf-8")
        index_size = (
            27 * len(self.indexes) + self.entity_name_len_sum + 8 * len(self.files) + 32
        )
        file_items_size = 40 * len(self.files) + self.file_data_len_sum
        # 构造元数据
        meta_data = bytearray()
        meta_data += b"xyar"
        meta_data += struct.pack(">Q", self.XYPSA_VERSION)
        meta_data += struct.pack("B", self.encrypt_type)
        meta_data += struct.pack(">H", len(comment_bytes))
        meta_data += comment_bytes
        comment_bytes = None
        meta_data += struct.pack(">Q", index_size)
        meta_data += struct.pack(">Q", file_items_size)
        if self.iv:
            meta_data += self.iv
        # 计算校验码
        self.global_hash_ctx.update(meta_data)
        checkcode = self.global_hash_ctx.copy().finalize()
        # 追加校验码
        meta_data += checkcode
        self.global_hash_ctx.update(checkcode)
        yield meta_data

    def _generate_index(self):
        """
        生成索引区
        yield时尽可能接近块大小
        """
        index_data = bytearray()
        target_size = self.block_size - len(self.gen_buffer)
        # 创建索引区校验码上下文
        if self.encrypt_type == 0:
            checkcode_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
        else:
            checkcode_ctx = hmac.HMAC(
                self.secret_key, hashes.SHA256(), backend=default_backend()
            )
        # 构造索引区
        for entity in self.indexes:
            index_data += struct.pack(">Q", entity["id"])
            index_data += struct.pack(">Q", entity["parent_id"])
            index_data += struct.pack("B", entity["type"])
            index_data += struct.pack(">Q", entity["mtime"])
            name_bytes = entity["name"].encode("utf-8")
            index_data += struct.pack(">H", len(name_bytes))
            index_data += name_bytes
            if entity["type"] == 0:
                index_data += struct.pack(">Q", entity["size"])
            if len(index_data) >= target_size:
                # 达到块大小，需要yield一次
                # 更新索引区校验码
                checkcode_ctx.update(index_data)
                # 更新全局哈希
                self.global_hash_ctx.update(index_data)
                # 加密处理
                if self.encrypt_type == 2:
                    index_data = self.encryptor.update(index_data)
                yield index_data
                # 清空已提交的数据
                index_data = bytearray()
                target_size = self.block_size - len(self.gen_buffer)
        if len(index_data) > 0:
            # 更新索引区校验码
            checkcode_ctx.update(index_data)
        # 取出索引区校验码
        checkcode = checkcode_ctx.finalize()
        index_data += checkcode
        # 更新全局哈希
        self.global_hash_ctx.update(index_data)
        # 加密处理
        if self.encrypt_type == 2:
            index_data = self.encryptor.update(index_data)
        yield index_data

    def _generate_file_data(self):
        """生成文件数据区"""
        file_data = bytearray()
        margin_size = self.block_size - len(self.gen_buffer)
        for entity_id, file_path, file_size in self.files:
            # 创建校验码上下文
            if self.encrypt_type == 0:
                checkcode_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
            else:
                checkcode_ctx = hmac.HMAC(
                    self.secret_key, hashes.SHA256(), backend=default_backend()
                )
            # 统计文件大小
            cur_file_size = 0
            # 处理实体ID
            entity_id_bytes = struct.pack(">Q", entity_id)
            checkcode_ctx.update(entity_id_bytes)
            file_data += entity_id_bytes
            margin_size -= 8
            # 如果没打开文件，则打开文件
            if entity_id in self.opened_obj_dict:
                file_obj = self.opened_obj_dict[entity_id]
            else:
                file_obj = myopen(file_path)
                # 如果不记录，无法在析构时垃圾回收
                self.opened_obj_dict[entity_id] = file_obj
            while True:
                if margin_size > 0:
                    # 需要读取数据填充
                    data = file_obj.read(margin_size)
                    if not data:
                        break
                    cur_file_size += len(data)
                    checkcode_ctx.update(data)
                    file_data += data
                    margin_size -= len(data)  # 更新margin_size
                # margin_size可能变化，不能直接else，需要重新判断下
                if margin_size < 1:
                    # 达到块大小，需要yield一次
                    # 更新全局校验码
                    self.global_hash_ctx.update(file_data)
                    # 加密数据
                    if self.encrypt_type != 0:
                        file_data = self.encryptor.update(file_data)
                    yield file_data
                    # 清空已提交的数据，更新margin_size
                    file_data = bytearray()
                    margin_size = self.block_size - len(self.gen_buffer)
            # 关闭文件并从字典中删除
            file_obj.close()
            del self.opened_obj_dict[entity_id]
            # 校验文件大小
            if cur_file_size != file_size:
                raise ValueError(
                    f"File size mismatch: {self.indexes[entity_id-1]["name"]}"
                )
            # 取出文件校验码
            checkcode = checkcode_ctx.finalize()
            file_data += checkcode
            margin_size -= len(checkcode)  # 更新margin_size
        if len(file_data) > 0:
            # 还有剩余数据，需要yield一次
            # 更新全局校验码
            self.global_hash_ctx.update(file_data)
            # 加密数据
            if self.encrypt_type != 0:
                file_data = self.encryptor.update(file_data)
            yield file_data
        # 生成全局校验码
        global_checkcode = self.global_hash_ctx.finalize()
        # 提交剩下的数据
        if self.encrypt_type != 0:
            # 加密全局校验码再提交
            global_checkcode = self.encryptor.update(global_checkcode)
            # 可能有残留数据，取出
            global_checkcode += self.encryptor.finalize()
        yield global_checkcode


if __name__ == "__main__":
    # 使用示例
    type_int = int(
        input("加密类型(0:不加密, 1:仅加密文件数据, 2:加密文件名和文件数据): ")
    )
    archiver = XYpsaGenStream(type_int, "your_password_here")
    archiver.add_file("test A.txt")
    archiver.add_file("test A测 {'a+ aa'}试.txt")
    archiver.add_dir("test.txt")
    archiver.set_comment("归档文件备注")
    print("无权限访问文件列表：", archiver.init())
    print("只加密数据：")
    print(f"预测的大小: {len(archiver)}")
    if type_int == 0:
        xypsa_file_name = "test"
    elif type_int == 1:
        xypsa_file_name = "crypted_data_test"
    elif type_int == 2:
        xypsa_file_name = "crypted_data_and_name_test"
    with open(xypsa_file_name + ".xypsa", "wb") as f:
        for chunk in archiver:
            f.write(chunk)
            print(f"写入 {len(chunk)} 字节")
    with open(xypsa_file_name + " copy.xypsa", "wb") as f:
        archiver2 = XYpsaGenStream()
        archiver2.copy_init(archiver)
        for chunk in archiver2:
            f.write(chunk)
            print(f"写入 {len(chunk)} 字节")
    with open(xypsa_file_name + " partial.xypsa", "wb") as f:
        archiver2 = XYpsaGenStream()
        archiver2.copy_init(archiver)
        archiver2.skip(10240)
        for chunk in archiver2:
            f.write(chunk)
            print(f"写入 {len(chunk)} 字节")
    print(f"生成文件完成: {xypsa_file_name}")
    print(f"实际大小: {os.path.getsize(xypsa_file_name+".xypsa")}")
    print()
