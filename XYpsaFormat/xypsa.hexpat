#pragma author XY0797
#pragma description XY predictable size archive
struct Metadata {
    // 魔数
    char magicNumber[4];
    // 版本
    be u64 version;
    // 加密类型
    be u8 encryptionType;
    // 文件备注文本长度
    be u16 commentTextLength;
    // 文件备注文本
    char commentText[commentTextLength];
    // 索引区大小
    be u64 indexSize;
    // 文件项总大小
    be u64 dataItemsSize;
    // 初始化向量
    if (encryptionType == 1 || encryptionType == 2) {
        u8 iv[16];
    }
    // 元数据区校验码
    char metadataCheckCode[32];
};
Metadata metadata @ 0x00;
if (metadata.encryptionType == 1 || metadata.encryptionType == 2) {
   return;
}
struct IndexItem {
    // 实体 ID
    be u64 id;
    // 实体父 ID
    be u64 parentId;
    // 实体类型 - 0:文件,1:文件夹
    be u8 type;
    // 修改时间
    be u64 modifyTime;
    // 实体名长度
    be u16 nameLength;
    // 实体名
    char name[nameLength];
    // 文件大小
    if (type == 0) {
        be u64 size;
    }
};
u64 indexItemStartAddress = sizeof(metadata);
u64 indexItemEndAddress = sizeof(metadata) + metadata.indexSize - 32;
IndexItem indexItems[while($ != indexItemEndAddress)] @ indexItemStartAddress;
u8 indexCheckCode[32] @ indexItemEndAddress;
import std.core;
fn getFileItemSize(u64 id) {
   u64 len = std::core::member_count(indexItems);
   for (u64 i = 0, i < len, i += 1) {
       if (indexItems[i].id == id && indexItems[i].type == 0) {
           return indexItems[i].size;
       }
   }
   return 0;
};
struct FileItem {
    // 实体 ID
    be u64 id;
    // 文件数据
    char data[getFileItemSize(id)];
    // 实体 ID+文件数据校验码
    char checkCode[32];
};
u64 fileItemStartAddress = sizeof(metadata) + metadata.indexSize;
u64 fileItemEndAddress = fileItemStartAddress + metadata.dataItemsSize;
FileItem fileItems[while($ != fileItemEndAddress)] @ fileItemStartAddress;
u8 globalCheckCode[32] @ fileItemEndAddress;
