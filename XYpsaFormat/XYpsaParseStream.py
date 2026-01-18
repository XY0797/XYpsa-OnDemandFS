import struct
from typing import Generator, Tuple, Dict
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)
from cryptography.hazmat.backends import default_backend


class XYpsaInvalidIterationSequenceError(Exception):
    def __init__(self, msg: str, code: int):
        self.msg = msg
        self.code = code

    def __str__(self):
        return "code " + str(self.code) + ", " + self.msg


class XYpsaCheckError(Exception):
    def __init__(self, msg: str, code: int):
        self.msg = msg
        self.code = code

    def __str__(self):
        return "code " + str(self.code) + ", " + self.msg


class XYpsaParseStream:
    XYPSA_VERSION = 1

    def __init__(self):
        self.password: str = None  # 解档密码
        self.secret_key: bytes = None  # 密钥
        self.iv: bytearray = None  # 初始化向量
        self.global_hash_ctx: hashes.Hash = None  # 全局校验码上下文
        self.decryptor: CipherContext = None  # 解密器

        self.data_source: Generator[bytes | bytearray, None, None] = None  # 数据源

        self.encrypt_type: int = None  # 加密类型
        self.index_size: int = None  # 索引项大小
        self.file_items_size: int = None  # 文件数据大小

        self.indexes: Dict[int, Dict[str, int | str]] = None  # 实体ID->索引项
        self.gen_state: int = None  # 目前使用的生成器
        """
        0: metadata
        1: index
        2: file_item
        3: file_data
        """
        self.block_size: int = 131072  # 默认块大小, 128KB

        self.buffer: bytearray = None  # 缓冲区
        self.decrypted_buffer: bytearray = None  # 解密后缓冲区

        self.file_item_bytes_read: int = None  # 已读取的文件数据区字节数

    def set_password(self, password: str):
        """设置解档使用的密码"""
        self.password = password

    def set_block_size(self, block_size: int):
        """设置迭代文件数据时返回的数据块大小"""
        self.block_size = block_size

    def start_parse(self, data: Generator[bytes | bytearray, None, None]) -> Tuple[
        Generator[Tuple[str, int | str | bytes | None], None, None],
        Generator[Dict[str, int | str], None, None],
        Generator[Tuple[int, Generator[bytes, None, None]], None, None],
    ]:
        """开始解档，返回三个生成器：元数据信息生成器、索引信息生成器、文件项生成器"""
        self.gen_state = 0
        self.data_source = data
        self.buffer = bytearray()
        return (
            self._metadata_generator(),
            self._index_generator(),
            self._file_item_generator(),
        )

    def _init_global_hash_context(self):
        """初始化全局校验码上下文"""
        if self.password:
            # 从密码得出密钥
            key_hash_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
            key_hash_ctx.update(self.password.encode("utf-8"))
            self.secret_key = key_hash_ctx.finalize()
            # 初始化全局校验码上下文
            self.global_hash_ctx = hmac.HMAC(
                self.secret_key, hashes.SHA256(), backend=default_backend()
            )
        else:
            # 初始化全局校验码上下文
            self.global_hash_ctx = hashes.Hash(
                hashes.SHA256(), backend=default_backend()
            )

    def _init_decryptor(self):
        """初始化解密器，初始化全局校验码上下文之后才能调用"""
        # 初始化解密器
        cipher = Cipher(
            algorithms.AES(self.secret_key),
            modes.CFB(self.iv),
            backend=default_backend(),
        )
        self.decryptor = cipher.decryptor()
        self.decrypted_buffer = bytearray()

    def _read_bytes(self, n: int) -> bytearray:
        """从数据源中读取指定数量的字节"""
        while len(self.buffer) < n:
            self.buffer += next(self.data_source)
        ret = self.buffer[0:n]
        self.buffer = self.buffer[n:]
        return ret

    def _move_buffer_to_decrypted_buffer(self):
        if len(self.buffer) != 0:
            self.decrypted_buffer += self.decryptor.update(self.buffer)
            self.buffer = bytearray()

    def _read_and_decrypt_bytes(self, n: int) -> bytearray:
        """从数据源中读取并解密指定数量的字节"""
        while len(self.decrypted_buffer) < n:
            try:
                crypted_bytes = next(self.data_source)
            except StopIteration as e:
                if self.decryptor:
                    self.decrypted_buffer += self.decryptor.finalize()
                    self.decryptor = None
                else:
                    raise e
            else:
                self.decrypted_buffer += self.decryptor.update(crypted_bytes)
        ret = self.decrypted_buffer[0:n]
        self.decrypted_buffer = self.decrypted_buffer[n:]
        return ret

    def _metadata_generator(self):
        """解析元数据区"""
        if self.gen_state != 0:
            raise XYpsaInvalidIterationSequenceError(
                "metadata generator can only be used once", 1
            )
        try:
            buf = self._read_bytes(15)  # ---->魔数,版本,加密类型,文件备注文本长度
            if buf[0:4] != b"xyar":  # 校验魔数
                raise XYpsaCheckError("file is not a XYpsa", 1)
            version = struct.unpack(">Q", buf[4:12])[0]
            if version != self.XYPSA_VERSION:  # 校验文件版本
                raise XYpsaCheckError("XYpsa version is not supported", 2)
            yield ("version", version)
            # 获取加密类型、文件备注文本长度
            self.encrypt_type, comment_len = struct.unpack(">BH", buf[12:15])
            # 检查加密类型是否匹配
            if self.encrypt_type not in [0, 1, 2]:
                raise XYpsaCheckError("unknown encryption type", 3)
            yield ("encrypt_type", self.encrypt_type)
            if self.password:
                if self.encrypt_type == 0:
                    self.password = None  # 文件没被加密，不需要密码
            else:
                if self.encrypt_type != 0:
                    raise XYpsaCheckError(
                        "XYpsa is encrypted, but no password provided", 4
                    )
            # 初始化全局校验码上下文
            self._init_global_hash_context()
            # 更新全局校验码上下文
            self.global_hash_ctx.update(buf)

            buf = self._read_bytes(comment_len)  # ---->文件备注文本
            # 更新全局校验码上下文
            self.global_hash_ctx.update(buf)
            comment = buf.decode("utf-8")
            buf = None
            yield ("comment", comment)
            comment = None

            buf = self._read_bytes(16)  # ---->索引区大小,文件数据区大小
            self.index_size, self.file_items_size = struct.unpack(">QQ", buf)
            # 更新全局校验码上下文
            self.global_hash_ctx.update(buf)
            buf = None
            yield ("index_size", self.index_size)
            yield ("file_items_size", self.file_items_size)

            if self.encrypt_type == 0:
                # 未加密，无iv
                yield ("iv", None)
            else:
                # 加密，取出iv
                self.iv = self._read_bytes(16)  # ---->iv
                # 更新全局校验码上下文
                self.global_hash_ctx.update(self.iv)
                self._init_decryptor()
                yield ("iv", self.iv)

            # 取计算得到的元数据区校验码
            checkcode = self.global_hash_ctx.copy().finalize()

            meta_data_check_code = self._read_bytes(32)  # ---->元数据区校验码
            yield ("meta_data_check_code", meta_data_check_code)

            # 更新全局校验码上下文
            self.global_hash_ctx.update(meta_data_check_code)

            # 切状态，这是为了错误密码时能读取非加密的索引区
            self.gen_state = 1

            # 验证元数据完整性
            if meta_data_check_code != checkcode:
                if self.encrypt_type == 0:
                    raise XYpsaCheckError("metadata is corrupted", 5)
                else:
                    raise XYpsaCheckError(
                        "password is incorrect or metadata is corrupted", 6
                    )
        except StopIteration:
            raise XYpsaCheckError(
                "data source prematurely ended while reading metadata", 7
            )

    def _index_generator(self):
        """解析索引区"""
        if self.gen_state != 1:
            if self.gen_state < 1:
                raise XYpsaInvalidIterationSequenceError(
                    "index generator can only be used after metadata generator", 2
                )
            else:
                raise XYpsaInvalidIterationSequenceError(
                    "index generator can only be used once", 3
                )
        try:
            # 创建索引区校验码上下文
            if self.encrypt_type == 0:
                checkcode_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
            else:
                checkcode_ctx = hmac.HMAC(
                    self.secret_key, hashes.SHA256(), backend=default_backend()
                )
            # 选择读取函数
            if self.encrypt_type == 2:
                self._move_buffer_to_decrypted_buffer()
                read_bytes = self._read_and_decrypt_bytes
            else:
                read_bytes = self._read_bytes

            # 读取索引项
            self.indexes = dict()
            bytes_read = 0
            target_size = self.index_size - 32  # 留出校验码的32字节
            while bytes_read < target_size:
                buf = read_bytes(
                    27
                )  # ---->实体ID,父实体ID,实体类型,修改时间,实体名长度
                entity_id, parent_id, entity_type, modify_time, name_len = (
                    struct.unpack(">QQBQH", buf)
                )
                # 更新校验码上下文
                checkcode_ctx.update(buf)
                self.global_hash_ctx.update(buf)
                # 累加已读取字节数
                bytes_read += 27

                buf = read_bytes(name_len)  # ---->实体名
                name = buf.decode("utf-8")
                # 更新校验码上下文
                checkcode_ctx.update(buf)
                self.global_hash_ctx.update(buf)
                # 累加已读取字节数
                bytes_read += name_len

                size = None
                if entity_type == 0:  # 文件实体
                    buf = read_bytes(8)  # ---->文件大小
                    size = struct.unpack(">Q", buf)[0]
                    # 更新校验码上下文
                    checkcode_ctx.update(buf)
                    self.global_hash_ctx.update(buf)
                    # 累加已读取字节数
                    bytes_read += 8

                # 构造索引项
                index_item = {
                    "id": entity_id,
                    "parent_id": parent_id,
                    "type": entity_type,
                    "mtime": modify_time,
                    "name": name,
                }
                if size is not None:
                    index_item["size"] = size
                self.indexes[entity_id] = index_item
                yield index_item

            # 读取索引区校验码
            buf = read_bytes(32)  # ---->索引区校验码
            index_check_code = buf
            # 更新全局校验码上下文
            self.global_hash_ctx.update(buf)

            # 验证索引区完整性
            buf = checkcode_ctx.finalize()
            if index_check_code != buf:
                raise XYpsaCheckError("index is corrupted", 8)

        except StopIteration:
            raise XYpsaCheckError(
                "data source prematurely ended while reading index", 9
            )
        self.gen_state = 2

    def _file_data_generator(
        self, file_size: int, checkcode_ctx: hashes.Hash | hmac.HMAC
    ):
        """生成文件数据"""
        # 选择读取函数
        if self.encrypt_type == 0:
            read_bytes = self._read_bytes
        else:
            self._move_buffer_to_decrypted_buffer()
            read_bytes = self._read_and_decrypt_bytes

        # 读取文件数据
        bytes_read = 0
        while bytes_read < file_size:
            data = read_bytes(min(self.block_size, file_size - bytes_read))
            # 更新校验码上下文
            checkcode_ctx.update(data)
            self.global_hash_ctx.update(data)
            # 累加已读取字节数
            bytes_read += len(data)
            yield data

        # 取出文件校验码
        checkcode = checkcode_ctx.finalize()
        file_check_code = read_bytes(32)
        # 更新全局校验码上下文
        self.global_hash_ctx.update(file_check_code)

        # 累加已读取字节数
        self.file_item_bytes_read += bytes_read + 32

        # 验证文件完整性
        if checkcode != file_check_code:
            raise XYpsaCheckError("file data is corrupted", 10)
        self.gen_state = 2
        checkcode_ctx = None

    def _file_item_generator(self):
        """生成文件项"""
        if self.gen_state != 2:
            if self.gen_state < 2:
                raise XYpsaInvalidIterationSequenceError(
                    "file item generator can only be used after index generator", 4
                )
            else:
                raise XYpsaInvalidIterationSequenceError(
                    "file item generator can only be used once", 5
                )
        try:
            # 选择读取函数
            if self.encrypt_type == 0:
                read_bytes = self._read_bytes
            else:
                self._move_buffer_to_decrypted_buffer()
                read_bytes = self._read_and_decrypt_bytes

            # 读取文件项
            self.file_item_bytes_read = 0
            while self.file_item_bytes_read < self.file_items_size:
                # 创建文件项校验码上下文
                if self.encrypt_type == 0:
                    checkcode_ctx = hashes.Hash(
                        hashes.SHA256(), backend=default_backend()
                    )
                else:
                    checkcode_ctx = hmac.HMAC(
                        self.secret_key, hashes.SHA256(), backend=default_backend()
                    )
                # 读取实体ID
                entity_id_bytes = read_bytes(8)
                entity_id = struct.unpack(">Q", entity_id_bytes)[0]
                # 更新校验码上下文
                checkcode_ctx.update(entity_id_bytes)
                self.global_hash_ctx.update(entity_id_bytes)
                # 累加已读取字节数
                self.file_item_bytes_read += 8

                # 获取文件大小
                file_size = self.indexes[entity_id]["size"]

                # 创建文件数据生成器
                file_data_gen = self._file_data_generator(file_size, checkcode_ctx)
                checkcode_ctx = None  # 取消对文件项校验码上下文的引用

                # 设置生成器状态
                self.gen_state = 3
                yield (entity_id, file_data_gen)
                # 检查生成器状态是否还是3，如果是则抛出异常
                if self.gen_state == 3:
                    raise XYpsaInvalidIterationSequenceError(
                        "file data generator must be fully iterated before getting the next file item",
                        6,
                    )

            # 取出全局校验码
            global_check_code = read_bytes(32)
            # 验证全局完整性
            checkcode = self.global_hash_ctx.finalize()
            if global_check_code != checkcode:
                raise XYpsaCheckError("global integrity check failed", 11)
        except StopIteration:
            raise XYpsaCheckError(
                "data source prematurely ended while reading file data", 12
            )


# 示例用法
if __name__ == "__main__":
    import os

    def read_xypsa_file(file_path):
        with open(file_path, "rb") as f:
            while chunk := f.read(131072):  # 流式读取
                yield chunk

    parser = XYpsaParseStream()
    # parser.set_password("your_password_here")
    # meta_gen, index_gen, file_gen = parser.start_parse(
    #     read_xypsa_file("crypted_data_test.xypsa")
    # )
    meta_gen, index_gen, file_gen = parser.start_parse(read_xypsa_file("test.xypsa"))

    base_path = os.path.abspath(".")

    print("Metadata:")
    for key, value in meta_gen:
        print(f"{key}: {value}")

    print("\nIndexes:")
    indexs = dict()
    for index in index_gen:
        print(index)
        # 创建目录
        if index["type"] == 1:
            if index["parent_id"] == 0:
                index["path"] = os.path.join(base_path, index["name"])
            else:
                index["path"] = os.path.join(
                    indexs[index["parent_id"]]["path"], index["name"]
                )
            os.makedirs(index["path"], exist_ok=True)
            # 修改文件夹的修改时间
            mtime = index["mtime"] * 100
            os.utime(index["path"], ns=(mtime, mtime))
        indexs[index["id"]] = index

    print("\nFiles:")
    for entity_id, file_data_gen in file_gen:
        print(f"Entity ID: {entity_id}")
        file_size = 0
        file_dir_id = indexs[entity_id]["parent_id"]
        if file_dir_id == 0:
            file_dir_path = base_path
        else:
            file_dir_path = indexs[file_dir_id]["path"]
        file_path = os.path.join(file_dir_path, indexs[entity_id]["name"])
        with open(file_path, "wb") as f:
            for chunk in file_data_gen:
                file_size += len(chunk)
                f.write(chunk)
        # 修改文件的修改时间
        mtime = indexs[entity_id]["mtime"] * 100
        os.utime(file_path, ns=(mtime, mtime))
        print(f"File size: {file_size} bytes")
