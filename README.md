# Libldcauc SNF / SNP-Sub 层接口文档 V1.0.0

[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 概述

本库提供网络功能层(SNF)的核心接口，用于不同角色（AS/GS/SGW）的初始化、安全通信及数据处理。主要功能包括SNF层初始化、认证流程、数据加密/解密、完整性校验等。

其中，安全网关角色（SGW）仅用作测试用，详见ldacs-combine项目

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

## 核心 API 详解

### 1. 初始化函数

#### AS 初始化

```c
void init_as_snf_layer(finish_auth auth_cb, trans_snp snp_cb);
```

- **参数**:
    - `auth_cb`: 认证完成回调，类型为 `int8_t (*finish_auth)()`
    - `snp_cb`:  数据转发回调，类型为 `int8_t (*trans_snp)(uint16_t, uint16_t, uint8_t*, size_t)`

#### GS 初始化(使用)

```c
void init_gs_snf_layer_unmerged(uint16_t GS_SAC, const char *gsnf_addr, uint16_t gsnf_port, trans_snp trans_snp,
                                register_snf_fail register_fail);
```

- **参数**:
    - `GS_SAC`:    地面站 SAC 标识
    - `gsnf_addr`: GSC/网关的 IPv6 地址
    - `gsnf_port`: 网关端口
    - `snp_cb`:    数据转发回调

### 2. 资源释放

```c
int8_t destory_snf_layer(); // 返回操作结果（见返回码定义）
```

### 3. 安全认证流程

#### 触发 AS 认证

```c
int8_t snf_LME_AUTH(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC);
```

- **参数**:
    - `role`:   角色（需为 `ROLE_AS`）
    - `AS_SAC`: 飞机 SAC
    - `AS_UA`:  飞机 UA
    - `GS_SAC`: 目标地面站 SAC

### 4. 数据加密/解密

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

### 5. HMAC 计算与验证

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
- **最后更新**: 2025/4/15

---

## 作者

中国民航大学新航行系统研究所


