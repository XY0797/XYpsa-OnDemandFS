import threading
from functools import wraps
from pathlib import PureWindowsPath

from winfspy import (
    FILE_ATTRIBUTE,
    CREATE_FILE_CREATE_OPTIONS,
    FileSystem,
    BaseFileSystemOperations,
    NTStatusObjectNameNotFound,
    NTStatusEndOfFile,
    NTStatusDirectoryNotEmpty,
    NTStatusNotADirectory,
    NTStatusObjectNameCollision,
    NTStatusAccessDenied,
)
from winfspy.plumbing.win32_filetime import filetime_now
from winfspy.plumbing.security_descriptor import SecurityDescriptor

FspCleanupDelete = 0x01
FspCleanupSetAllocationSize = 0x02
FspCleanupSetArchiveBit = 0x10
FspCleanupSetLastAccessTime = 0x20
FspCleanupSetLastWriteTime = 0x40
FspCleanupSetChangeTime = 0x80

from xypsa import XYpsaGenerator


def operation(fn):
    name = fn.__name__

    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        head = args[0] if args else None
        tail = args[1:] if args else ()
        try:
            with self._thread_lock:
                result = fn(self, *args, **kwargs)
        except Exception as exc:
            if not isinstance(exc, NTStatusObjectNameNotFound):
                print(f" NOK | {name:20} | {head!r:20} | {tail!r:20} | {exc!r}")
            raise
        else:
            # logging.debug(f" OK! | {name:20} | {head!r:20} | {tail!r:20} | {result!r}")
            return result

    return wrapper


class BaseFileObj:
    @property
    def name(self):
        """File name, without the path"""
        return self.path.name

    @property
    def file_name(self):
        """File name, including the path"""
        return str(self.path)

    def __init__(self, path, attributes, security_descriptor):
        self.path = path
        self.attributes = attributes
        self.security_descriptor = security_descriptor
        now = filetime_now()
        self.creation_time = now
        self.last_access_time = now
        self.last_write_time = now
        self.change_time = now
        self.index_number = 0
        self.file_size = 0

    def get_file_info(self):
        return {
            "file_attributes": self.attributes,
            "allocation_size": self.allocation_size,  # type: ignore 因为子类中有
            "file_size": self.file_size,
            "creation_time": self.creation_time,
            "last_access_time": self.last_access_time,
            "last_write_time": self.last_write_time,
            "change_time": self.change_time,
            "index_number": self.index_number,
        }

    def __repr__(self):
        return f"{type(self).__name__}:{self.file_name}"


class memFileObj(BaseFileObj):

    allocation_unit = 4096

    def __init__(self, path, attributes, security_descriptor, allocation_size=0):
        super().__init__(path, attributes, security_descriptor)
        self.data = bytearray(allocation_size)
        self.attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE
        assert not self.attributes & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY

    @property
    def allocation_size(self):
        return len(self.data)

    def set_allocation_size(self, allocation_size):
        if allocation_size < self.allocation_size:
            self.data = self.data[:allocation_size]
        if allocation_size > self.allocation_size:
            self.data += bytearray(allocation_size - self.allocation_size)
        assert self.allocation_size == allocation_size
        self.file_size = min(self.file_size, allocation_size)

    def adapt_allocation_size(self, file_size):
        units = (file_size + self.allocation_unit - 1) // self.allocation_unit
        self.set_allocation_size(units * self.allocation_unit)

    def set_file_size(self, file_size):
        if file_size < self.file_size:
            zeros = bytearray(self.file_size - file_size)
            self.data[file_size : self.file_size] = zeros
        if file_size > self.allocation_size:
            self.adapt_allocation_size(file_size)
        self.file_size = file_size

    def read(self, offset, length):
        if offset >= self.file_size:
            raise NTStatusEndOfFile()
        end_offset = min(self.file_size, offset + length)
        return self.data[offset:end_offset]

    def write(self, buffer, offset, write_to_end_of_file):
        if write_to_end_of_file:
            offset = self.file_size
        end_offset = offset + len(buffer)
        if end_offset > self.file_size:
            self.set_file_size(end_offset)
        self.data[offset:end_offset] = buffer
        return len(buffer)

    def constrained_write(self, buffer, offset):
        if offset >= self.file_size:
            return 0
        end_offset = min(self.file_size, offset + len(buffer))
        transferred_length = end_offset - offset
        self.data[offset:end_offset] = buffer[:transferred_length]
        return transferred_length


class FolderObj(BaseFileObj):
    def __init__(self, path, attributes, security_descriptor):
        super().__init__(path, attributes, security_descriptor)
        self.allocation_size = 0
        assert self.attributes & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY


class OpenedObj:
    def __init__(self, file_obj):
        self.file_obj = file_obj


class SplitFileObj(BaseFileObj):
    def __init__(
        self, path, security_descriptor, index, xypsa_generator: XYpsaGenerator
    ):
        """分卷文件对象,index为从0开始的分卷号"""
        super().__init__(
            path, FILE_ATTRIBUTE.FILE_ATTRIBUTE_NORMAL, security_descriptor
        )
        self.allocation_size = 0

        self.xypsa_generator = xypsa_generator
        assert xypsa_generator.split_size is not None
        self.split_index = index

        if (index + 1) == xypsa_generator.split_count:
            self.file_size = xypsa_generator.last_split_size
        else:
            self.file_size = xypsa_generator.split_size
        self.xypsafile = True

    def read(self, offset, length):
        if offset >= self.file_size:
            raise NTStatusEndOfFile()
        if offset + length > self.file_size:
            length = self.file_size - offset  # 需要截断掉超出文件大小的部分
        return self.xypsa_generator.read_split_chunk(self.split_index, offset, length)


class FileObj(BaseFileObj):
    def __init__(self, path, security_descriptor, xypsa_generator: XYpsaGenerator):
        super().__init__(
            path, FILE_ATTRIBUTE.FILE_ATTRIBUTE_NORMAL, security_descriptor
        )
        self.allocation_size = 0

        self.xypsa_generator = xypsa_generator
        assert xypsa_generator.split_size is None

        self.file_size = len(xypsa_generator)
        self.xypsafile = True

    def read(self, offset, length):
        if offset >= self.file_size:
            raise NTStatusEndOfFile()
        return self.xypsa_generator.read_chunk(offset, length)


class XYpsaFileSystemOperations(BaseFileSystemOperations):
    def __init__(self, xypsa_generator: XYpsaGenerator):
        super().__init__()
        self._root_path = PureWindowsPath("/")
        self._root_obj = FolderObj(
            self._root_path,
            FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
            SecurityDescriptor.from_string(
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
            ),
        )
        self._entries: dict[PureWindowsPath, BaseFileObj] = {
            self._root_path: self._root_obj
        }

        if xypsa_generator.split_size is None or xypsa_generator.split_count is None:
            # 创建归档文件
            xypsa_path = self._root_path / f"{xypsa_generator.filename}.xypsa"
            self._entries[xypsa_path] = FileObj(
                xypsa_path, self._root_obj.security_descriptor, xypsa_generator
            )
        else:
            # 创建分卷归档文件
            head_str = xypsa_generator.filename + "."
            end_str = "." + str(xypsa_generator.split_count) + ".part.xypsa"
            for i in range(xypsa_generator.split_count):
                file_name = head_str + str(i + 1) + end_str
                split_path = self._root_path / file_name
                self._entries[split_path] = SplitFileObj(
                    split_path, self._root_obj.security_descriptor, i, xypsa_generator
                )

        self._thread_lock = threading.Lock()
        self._volume_info = {
            "total_size": len(xypsa_generator) * 3 + 1024 * 1024 * 1024,
            "free_size": len(xypsa_generator) * 2 + 1024 * 1024 * 1024,
            "volume_label": "XYpsaFS",
        }

    @operation
    def get_volume_info(self):
        return self._volume_info

    @operation
    def set_volume_label(self, volume_label):
        self._volume_info["volume_label"] = volume_label

    @operation
    def get_security_by_name(self, file_name):
        file_name = PureWindowsPath(file_name)
        try:
            file_obj = self._entries[file_name]
        except KeyError:
            raise NTStatusObjectNameNotFound()
        return (
            file_obj.attributes,
            file_obj.security_descriptor.handle,
            file_obj.security_descriptor.size,
        )

    @operation
    def create(
        self,
        file_name,
        create_options,
        granted_access,
        file_attributes,
        security_descriptor,
        allocation_size,
    ):
        file_name = PureWindowsPath(file_name)

        # `granted_access` is already handle by winfsp
        # `allocation_size` useless for us

        # Retrieve file
        try:
            parent_file_obj = self._entries[file_name.parent]
            if not isinstance(parent_file_obj, FolderObj):
                raise NTStatusNotADirectory()
        except KeyError:
            raise NTStatusObjectNameNotFound()

        # File/Folder already exists
        if file_name in self._entries:
            raise NTStatusObjectNameCollision()

        if create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE:
            file_obj = FolderObj(file_name, file_attributes, security_descriptor)
        else:
            file_obj = memFileObj(
                file_name,
                file_attributes,
                security_descriptor,
                allocation_size,
            )
        self._entries[file_name] = file_obj
        return OpenedObj(file_obj)

    @operation
    def get_security(self, file_context):
        return file_context.file_obj.security_descriptor

    @operation
    def set_security(self, file_context, security_information, modification_descriptor):
        if hasattr(file_context.file_obj, "xypsafile"):
            # 阻止篡改xypsa文件
            raise NTStatusAccessDenied()
        new_descriptor = file_context.file_obj.security_descriptor.evolve(
            security_information, modification_descriptor
        )
        file_context.file_obj.security_descriptor = new_descriptor

    @operation
    def rename(self, file_context, file_name, new_file_name, replace_if_exists):
        file_name = PureWindowsPath(file_name)
        new_file_name = PureWindowsPath(new_file_name)

        # Retrieve file
        try:
            file_obj = self._entries[file_name]
        except KeyError:
            raise NTStatusObjectNameNotFound()

        if hasattr(file_obj, "xypsafile"):
            raise NTStatusAccessDenied()

        if new_file_name in self._entries:
            # Case-sensitive comparison
            if new_file_name.name != self._entries[new_file_name].path.name:
                pass
            elif not replace_if_exists:
                raise NTStatusObjectNameCollision()

        for entry_path in list(self._entries):
            try:
                relative = entry_path.relative_to(file_name)
                new_entry_path = new_file_name / relative
                entry = self._entries.pop(entry_path)
                entry.path = new_entry_path
                self._entries[new_entry_path] = entry
            except ValueError:
                continue

    @operation
    def open(self, file_name, create_options, granted_access):
        file_name = PureWindowsPath(file_name)
        try:
            file_obj = self._entries[file_name]
        except KeyError:
            raise NTStatusObjectNameNotFound()
        return OpenedObj(file_obj)

    @operation
    def close(self, file_context):
        pass

    @operation
    def get_file_info(self, file_context):
        return file_context.file_obj.get_file_info()

    @operation
    def set_basic_info(
        self,
        file_context,
        file_attributes,
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
        file_info,
    ) -> dict:
        file_obj = file_context.file_obj
        if hasattr(file_obj, "xypsafile"):
            # 阻止篡改xypsa文件
            raise NTStatusAccessDenied()
        if file_attributes != FILE_ATTRIBUTE.INVALID_FILE_ATTRIBUTES:
            file_obj.attributes = file_attributes
        if creation_time:
            file_obj.creation_time = creation_time
        if last_access_time:
            file_obj.last_access_time = last_access_time
        if last_write_time:
            file_obj.last_write_time = last_write_time
        if change_time:
            file_obj.change_time = change_time

        return file_obj.get_file_info()

    @operation
    def set_file_size(self, file_context, new_size, set_allocation_size):
        if not isinstance(file_context.file_obj, memFileObj):
            raise NTStatusAccessDenied()
        if set_allocation_size:
            file_context.file_obj.set_allocation_size(new_size)
        else:
            file_context.file_obj.set_file_size(new_size)

    @operation
    def can_delete(self, file_context, file_name: str) -> None:
        file_path = PureWindowsPath(file_name)
        try:
            file_obj = self._entries[file_path]
        except KeyError:
            raise NTStatusObjectNameNotFound

        if isinstance(file_obj, FolderObj):
            for entry in self._entries.keys():
                try:
                    if entry.relative_to(file_path).parts:
                        raise NTStatusDirectoryNotEmpty()
                except ValueError:
                    continue

    @operation
    def read_directory(self, file_context, marker):
        entries = []
        file_obj = file_context.file_obj
        if isinstance(file_obj, FileObj):
            raise NTStatusNotADirectory()
        if file_obj.path != self._root_path:
            parent_obj = self._entries[file_obj.path.parent]
            entries.append({"file_name": ".", **file_obj.get_file_info()})
            entries.append({"file_name": "..", **parent_obj.get_file_info()})
        for entry_path, entry_obj in self._entries.items():
            try:
                relative = entry_path.relative_to(file_obj.path)
            except ValueError:
                continue
            if len(relative.parts) != 1:
                continue
            entries.append({"file_name": entry_path.name, **entry_obj.get_file_info()})
        entries = sorted(entries, key=lambda x: x["file_name"])
        if marker is None:
            return entries
        for i, entry in enumerate(entries):
            if entry["file_name"] == marker:
                return entries[i + 1 :]

    @operation
    def get_dir_info_by_name(self, file_context, file_name):
        path = file_context.file_obj.path / file_name
        try:
            entry_obj = self._entries[path]
        except KeyError:
            raise NTStatusObjectNameNotFound()
        return {"file_name": file_name, **entry_obj.get_file_info()}

    @operation
    def read(self, file_context, offset, length):
        return file_context.file_obj.read(offset, length)

    @operation
    def write(self, file_context, buffer, offset, write_to_end_of_file, constrained_io):
        if hasattr(file_context.file_obj, "xypsafile"):
            # 阻止篡改xypsa文件
            raise NTStatusAccessDenied()
        if constrained_io:
            return file_context.file_obj.constrained_write(buffer, offset)
        else:
            return file_context.file_obj.write(buffer, offset, write_to_end_of_file)

    @operation
    def cleanup(self, file_context, file_name, flags):
        if hasattr(file_context.file_obj, "xypsafile"):
            # 阻止篡改xypsa文件
            raise NTStatusAccessDenied()

        file_obj = file_context.file_obj

        # Delete
        if flags & FspCleanupDelete:

            # Check for non-empty direcory
            if any(key.parent == file_obj.path for key in self._entries):
                return

            # Delete immediately
            try:
                del self._entries[file_obj.path]
            except KeyError:
                raise NTStatusObjectNameNotFound()

        # Resize
        if flags & FspCleanupSetAllocationSize:
            file_obj.adapt_allocation_size(file_obj.file_size)

        # Set archive bit
        if flags & FspCleanupSetArchiveBit and isinstance(file_obj, FileObj):
            file_obj.attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE

        # Set last access time
        if flags & FspCleanupSetLastAccessTime:
            file_obj.last_access_time = filetime_now()

        # Set last access time
        if flags & FspCleanupSetLastWriteTime:
            file_obj.last_write_time = filetime_now()

        # Set last access time
        if flags & FspCleanupSetChangeTime:
            file_obj.change_time = filetime_now()

    @operation
    def overwrite(
        self,
        file_context,
        file_attributes,
        replace_file_attributes: bool,
        allocation_size: int,
    ):
        file_obj = file_context.file_obj
        if hasattr(file_obj, "xypsafile"):
            # 阻止篡改xypsa文件
            raise NTStatusAccessDenied()

        # File attributes
        file_attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE
        if replace_file_attributes:
            file_obj.attributes = file_attributes
        else:
            file_obj.attributes |= file_attributes

        # Allocation size
        file_obj.set_allocation_size(allocation_size)

        # Set times
        now = filetime_now()
        file_obj.last_access_time = now
        file_obj.last_write_time = now
        file_obj.change_time = now

    @operation
    def flush(self, file_context):
        pass


class VirtualFileSystem:
    def __init__(self, mountpoint: str, xypsa_generator: XYpsaGenerator):
        self.xypsa_generator = xypsa_generator
        self.fs = FileSystem(
            mountpoint,
            XYpsaFileSystemOperations(xypsa_generator),
            sector_size=512,
            sectors_per_allocation_unit=1,
            volume_creation_time=filetime_now(),
            volume_serial_number=0,
            file_info_timeout=1000,
            case_sensitive_search=1,
            case_preserved_names=1,
            unicode_on_disk=1,
            persistent_acls=1,
            post_cleanup_when_modified_only=1,
            um_file_context_is_user_context2=1,
            file_system_name=mountpoint,
        )

    def start(self):
        self.fs.start()

    def stop(self):
        self.fs.stop()
