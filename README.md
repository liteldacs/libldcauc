# Libldcauc SNF / SNP-Sub 层接口文档 V1.1.0

[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 概述

本项目提供网络功能层(SNF)的核心接口，用于不同角色（AS/GS/SGW）的初始化、安全通信及数据处理。主要功能包括SNF层初始化、认证流程、数据加密/解密、完整性校验等。

其中，库中所定义的安全网关角色（SGW）仅作测试用，测试过程中使用的安全网关详见ldacs-combine项目。

---

## 功能特性

- 多角色支持：初始化和管理AS、GS、SGW实体的SNF层。
- 安全协议：支持AES加密/解密及多种HMAC算法（MAC长度64/96/128/256位）。
- 切换处理：实现基站间切换（Handover）的协调与响应。
- 回调机制：通过回调函数处理认证完成、数据传输、注册失败等事件。
- 随机数生成：生成至多64位的安全随机数。

---

## 安装

⚠️ **注意**：本项目要求 CMake 最低版本为 **3.20**。如果构建失败，请先检查 CMake 版本！

⚠️ **注意**：在执行apt upgrade之前需要评估其他项目依赖升级的影响，否则手动安装本项目依赖！

### 依赖安装

本项目依赖多个外部库以及内部项目，须按如下顺序安装依赖。

#### 1. 安装libyaml、libevent、uthash、libsqlite3 (Ubuntu)

```shell
sudo apt update && sudo apt upgrade
sudo apt install libyaml-dev libevent-dev uthash-dev libsqlite3-dev
```

#### 2. 拉取并安装base64 及 cjson

```shell
#base64
git clone https://github.com/aklomp/base64.git
cd base64 && mkdir build && cd build
cmake ..
make -j12 && sudo make install

#cjson
git clone https://github.com/DaveGamble/cJSON
cd base64 && mkdir build && cd build
cmake ..
make -j12 && sudo make install
```

#### 3. 安装密码卡驱动和库文件

- **对于尚未使用密码卡的环境**

```shell
git clone https://github.com/thirdxiaozhu/GmSSL-liteldacs
cd GmSSL && mkdir build && cd build
cmake .. 
&& make -j12 && sudo make install
```

- **对于AS、GS设备**

使用piico-manager密码卡工具安装驱动及依赖库

```shell
git clone xxxx
```

- **对于SGW设备**

请直接使用提供的网关工控机

#### 4. 安装libliteldacscrypto

```shell
git clone https://github.com/liteldacs/liteldacscrypto.git
cd liteldacscrypto && mkdir build && cd build
```

根据环境设置选项

- **对于尚未使用密码卡的设备**

```shell
cmake ..
```

- **对于AS设备**

```shell
cmake .. -DAS_DEVICE=ON
```

- **对于GS设备**

```shell
cmake .. -DGS_DEVICE=ON
```

- **对于SGW设备**

```shell
cmake .. -DSGW_DEVICE=ON
```

编译并安装

```shell
make -j12 & sudo make install
```

#### 5. 安装libliteldacssdk

```shell
git clone https://github.com/liteldacs/liteldacssdk.git
cd liteldacssdk && mkdir build && cd build
cmake ..
make -j12 && sudo make install
```

### 安装本项目

```shell
git clone https://github.com/liteldacs/libldcauc.git
cd libldcauc && mkdir build && cd build
cmake ..  //这里需要添加和libliteldacscrypto中一致的选项
make -j12 && sudo make install
```

---

## 返回码定义

| 宏定义                     | 值  | 说明     |
|-------------------------|----|--------|
| `LDCAUC_OK`             | 0  | 操作成功   |
| `LDCAUC_FAIL`           | -1 | 通用失败   |
| `LDCAUC_WRONG_PARA`     | -2 | 参数错误   |
| `LDCAUC_NULL`           | -3 | 空指针异常  |
| `LDCAUC_INTERNAL_ERROR` | -4 | 内部逻辑错误 |

---

## 角色定义

| 角色宏        | 值 | 说明             |
|------------|---|----------------|
| `ROLE_AS`  | 1 | 飞机站 (Aircraft) |
| `ROLE_GS`  | 2 | 地面站 (Ground)   |
| `ROLE_SGW` | 4 | 安全网关 (Gateway) |

---

## 安全算法配置

### MAC 长度枚举（SNP SEC字段）

```c
enum SEC_ALG_MACLEN {
    SEC_MACLEN_INVAILD = 0x0,  // 无效长度
    SEC_MACLEN_96      = 0x1,  // 96 位 (12 字节)
    SEC_MACLEN_128     = 0x2,  // 128 位 (16 字节)
    SEC_MACLEN_64      = 0x3,  // 64 位 (8 字节)
    SEC_MACLEN_256     = 0x4   // 256 位 (32 字节)
};
```

### MAC 长度转换宏

```c
// 根据枚举值返回实际字节长度，无效值返回0
int maclen = get_sec_maclen(SEC_MACLEN_96); // 返回12
```

---

## 回调函数

### 1. `finish_auth` - 认证完成回调

```c
int8_t (*finish_auth)();
```

#### 功能描述

- **用途**：由 **AS** 调用，标识认证流程完成。
- **需包含功能**：
    - 将 LME状态更新为 `LME_OPEN`。

#### 调用时机

- 当 AS 完成认证后触发。

### 2. `trans_snp` - SNP 数据传输回调

```c
int8_t (*trans_snp)(uint16_t AS_SAC, uint16_t GS_SAC, uint8_t *buf, size_t buf_len);
```

#### 功能描述

- **用途**：由 **AS/GS ** 调用，向 SNP 层传递数据。
- **参数说明**：
    - `AS_SAC`：发送/接收数据的 AS 对应的 SAC。
    - `GS_SAC`：关联的 GS 对应的SAC。
    - `buf`：待传输的数据缓冲区指针。
    - `buf_len`：数据长度（字节数）。

#### 调用场景

- AS/GS SNF 需将协议数据单元（PDU）传递至 SNP 层时调用。

### 3. `register_snf_fail` - 注册失败回调

```c
int8_t (*register_snf_fail)(uint16_t AS_SAC);
```

#### 功能描述

- **用途**：由 **AS/GS ** 调用，处理服务注册失败事件。
- **应包含功能**：
    - 清理与失败 AS 关联的 LME 和 DLS 实体资源。
- **参数说明**：
    - `AS_SAC`：注册失败的 AS 服务接入点标识符。

#### 调用场景

- SNF注册失败时触发。

### 4. `finish_handover` - 切换完成回调

```c
int8_t (*gst_ho_complete_key)(uint16_t AS_SAC, uint32_t AS_UA, uint16_t GSS_SAC);
```

#### 功能描述

- **用途**：由 **GS ** 调用，标识切换流程完成。
- **应包含功能**：
    - 向源基站（GS Source）发送切换确认（ACK）。
- **参数说明**：
    - `AS_SAC`：发生切换的 AS SAC。
    - `AS_UA`：发生切换的 AS GS。
    - `GSS_SAC`：切换前的源 GS SAC。

#### 调用场景

- 当目标 GS 确认切换完成并需通知源基站时触发。

---

## 核心接口

### 1. 初始化函数

#### AS 初始化

```c
void init_as_snf_layer(finish_auth finish_auth, trans_snp trans_snp, register_snf_fail register_fail);
```

- **参数**: (见“回调函数”部分)

#### GS 初始化

```c
void init_gs_snf_layer_unmerged(uint16_t GS_SAC, const char *gsnf_addr, uint16_t gsnf_port, trans_snp trans_snp,
                                register_snf_fail register_fail);
```

- **参数**:
    - `GS_SAC`:    地面站 SAC 标识
    - `gsnf_addr`: GSC/网关的 IPv6 地址
    - `gsnf_port`: 网关端口
    - (见“回调函数”部分)

### 2. 资源释放

```c
int8_t destory_snf_layer(); // 返回操作结果（见返回码定义）
```

- **调用场景**：
  程序结束时

### 3. 安全认证流程

#### 触发 AS 认证

```c
int8_t snf_LME_AUTH(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC);
```

- **调用场景**：
  AS LME進入LME_AUTH状态后
- **参数**:
    - `role`:   角色（需为 `ROLE_AS`）
    - `AS_SAC`: 飞机 SAC
    - `AS_UA`:  飞机 UA
    - `GS_SAC`: 目标地面站 SAC

### 4. 注册SNF实体

```c
int8_t register_snf_en(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC);
```

- **调用场景**：
  在GS从RA信道接收到Cell Response后注册AS实体

- **参数**:
    - `role`:   角色（需为 `ROLE_GS`）
    - `AS_SAC`: 飞机 SAC
    - `AS_UA`:  飞机 UA
    - `GS_SAC`: 目标地面站 SAC

### 5. 注销SNF实体

```c
int8_t unregister_snf_en(uint16_t AS_SAC);
```

- **调用场景**：
  AS注销时

- **参数**:
    - `role`:   角色（需为 `ROLE_GS`）
    - `AS_SAC`: 飞机 SAC

### 6. 上传SNF报文

```c
int8_t upload_snf(bool is_valid, uint16_t AS_SAC, uint16_t GS_SAC, uint8_t *snp_buf, size_t buf_len);
```

- **调用场景**：
  SNP上传控制报文时

- **参数**:
    - `is_valid`:   是否是合法报文
    - `AS_SAC`: 飞机 SAC
    - `GS_SAC`: 地面站 SAC
    - `snp_buf`: 上传SNF数据
    - `buf_len`: 数据长度

### 7. 目标GS切换响应

```c
int8_t handover_response(uint16_t AS_SAC, uint32_t AS_UA, uint16_t GSS_SAC, uint16_t GST_SAC);
```

- **调用场景**：
  在目标GS接收到源GS的切换提醒时

- **参数**:
    - `AS_SAC`: 飞机 SAC
    - `AS_UA`: 飞机 UA
    - `GSS_SAC`: 源地面站 SAC
    - `GST_SAC`: 目标地面站 SAC

### 8. 生成随机数

```c
uint64_t generate_urand(size_t rand_bits_sz);
```

- **参数**:
    - `rand_bits_sz`: 生成随机数的比特长度，至多64位

### 9. 数据加密/解密

加密前对原始数据使用PKCS7进行填充，并在解密后取消填充

```c
int8_t snpsub_crypto(uint16_t AS_SAC, uint8_t *in, size_t in_len, 
                    uint8_t *out, size_t *out_len, bool is_encrypt);
```

- **方向**:
    - `is_encrypt=true`: 加密 `in` 到 `out`
    - `is_encrypt=false`: 解密 `in` 到 `out`
- **注意**:
    - `out` 缓冲区需由调用者预先分配

### 10. HMAC 计算与验证

```c
// 计算 HMAC
int8_t snpsub_calc_hmac(uint16_t AS_SAC, uint8_t SEC, 
                        uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

// 验证 HMAC
int8_t snpsub_vfy_hmac(uint16_t AS_SAC, uint8_t SEC, uint8_t *snp_pdu, size_t pdu_len);
```

---

## 使用示例

### AS 初始化示例

```c
// 定义回调
int8_t on_auth_finish() { /* 处理认证完成 */ }
int8_t on_trans_snp(uint16_t as_sac, uint16_t gs_sac, uint8_t *buf, size_t len) { /* 转发数据 */ }

// 初始化
init_as_snf_layer(on_auth_finish, on_trans_snp);
snf_LME_AUTH(ROLE_AS, 0x1234, 0xABCD, 0x5678);
```

### 数据加密示例

```c
uint8_t plain[64], cipher[128];
size_t cipher_len;
snpsub_crypto(0x1234, plain, 64, cipher, &cipher_len, true);
```

---

## 注意事项

1. **线程安全**: 接口未保证线程安全，需由调用者同步。
2. **内存管理**: `snp_buf`、`out` 等缓冲区需由调用者分配/释放。
3. **错误处理**: 需检查返回值，特别是 `LDCAUC_NULL` 和 `LDCAUC_WRONG_PARA`。
4. **角色限制**: `snf_LME_AUTH` 仅限 `ROLE_AS` 调用。

---

## 版本

- **保护版本**: `PROTECT_VERSION 1`
- **最后更新**: 2025/4/30

---

## 作者

中国民航大学新航行系统研究所


