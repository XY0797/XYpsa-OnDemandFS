from sortedcontainers import SortedKeyList

from XYpsaFormat.XYpsaGenStream import XYpsaGenStream

# import time
# log_file = open("log.txt", "a", encoding="utf-8")
# def do_log(msg):
#     log_file.write(str(time.time()) + " " + msg + "\n")
#     log_file.flush()


class XYpsaGenerator:
    def __init__(self, filename, encryption_type, password):
        self.filename = filename
        self.generator = XYpsaGenStream(encryption_type, password)
        self.generator_list = SortedKeyList(key=lambda e: e.offset)
        self.initialized = False
        self.GENOBJAMOUNT = 10
        # 命中率统计
        self.total_cnt = 0
        self.eq_cnt = 0

    def __len__(self):
        return len(self.generator)

    def add_file(self, file_path: str):
        self.generator.add_file(file_path)

    def add_dir(self, dir_path: str):
        self.generator.add_dir(dir_path)

    def set_comment(self, comment: str):
        self.generator.set_comment(comment)

    def init(self, split_size, not_pre_lock) -> list[str]:
        self.generator.pre_open_files = not not_pre_lock
        no_access_list = self.generator.init()
        if split_size != 0:
            file_size = len(self.generator)
            self.split_size = split_size
            # 计算分卷总数和末尾分卷大小
            if file_size % split_size == 0:
                self.split_count = file_size // split_size
                self.last_split_size = split_size
            else:
                self.split_count = file_size // split_size + 1
                self.last_split_size = file_size % split_size
            # 流式生成器的数量需要乘实例数量，但是一般不会超过5个分片同时读取
            self.GENOBJAMOUNT *= min(self.split_count, 5)
        else:
            self.split_size = None
            self.split_count = None
            self.last_split_size = None
        # 添加流式生成器实例
        for i in range(self.GENOBJAMOUNT):
            new_generator = XYpsaGenStream()
            new_generator.copy_init(self.generator)
            self.generator_list.add(new_generator)
        self.initialized = True
        print("初始化完成，流式生成器数量：", self.GENOBJAMOUNT)
        return no_access_list

    def read_split_chunk(self, index: int, offset: int, length: int):
        """
        读取某个分卷的块数据
        index从0开始
        """
        if index >= self.split_count:
            raise ValueError("split index out of range")
        offset = index * self.split_size + offset
        return self.read_chunk(offset, length)

    def read_chunk(self, offset: int, length: int):
        """读取单文件的块数据"""
        self.total_cnt += 1
        index = (
            self.generator_list.bisect_key_right(offset) - 1
        )  # 小于等于目标偏移且尽可能大的元素的位置
        if index < 0:
            # 全部都比目标偏移大
            index = self.GENOBJAMOUNT - 1
            print(
                "重新创建流，目标偏移：",
                offset,
                "，当前最小偏移：",
                self.generator_list[0].offset,
                "，回收流的偏移：",
                self.generator_list[index].offset,
            )
            cur_generator = XYpsaGenStream()
            cur_generator.copy_init(self.generator)
            if offset > 0:
                cur_generator.skip(offset)
            self.generator_list.pop(index)
        else:
            # do_log(f"{index}\t\t\t{offset}\t\t\t{length}")
            cur_generator = self.generator_list.pop(index)
            if cur_generator.offset == offset:
                self.eq_cnt += 1
            elif cur_generator.offset < offset:
                cur_generator.skip(offset)
            else:
                # 不可能执行到这里
                raise RuntimeError("offset error")
        cur_generator.set_block_size(length)
        try:
            data = next(cur_generator)
        except StopIteration as e:
            # 流截止了，重新创建个
            cur_generator = XYpsaGenStream()
            cur_generator.copy_init(self.generator)
            data = b""
        except Exception as e:
            cur_generator = XYpsaGenStream()
            cur_generator.copy_init(self.generator)
            self.generator_list.add(cur_generator)
            raise e
        # 压入回去
        self.generator_list.add(cur_generator)
        return data
