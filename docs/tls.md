# TLS

TLS 由**记录协议**、**握手协议**、**警告协议**、**变更密码规范协议**、**扩展协议**等几个子协议组成，综合使用了对称加密、非对称加密、身份认证等许多密码学前沿技术。

## 协议组成

1. **记录协议**（Record Protocol）规定了 TLS 收发数据的基本单位：**记录**（`record`）。类似 TCP 协议中的 `segment`，**其他所有的子协议都需要通过记录协议发出**。但多个记录数据可以在一个 TCP 包里一次性发出，也并不需要像 TCP 那样返回 ACK。
2. **警报协议**（Alert Protocol）的职责是向对方发出警报信息，类似 HTTP 协议里的状态码，，收到警报后另一方可以选择继续，也可以立即终止连接，如：
   - `protocol_version`：不支持旧版本
   - `bad_certificate` ：证书有问题
3. **握手协议**（Handshake Protocol）是 TLS 里最复杂的子协议，比 TCP 的 SYN/ACK 复杂，浏览器和服务器会在握手过程中协商 **TLS 版本号**、**随机数**、**密码套件**等信息，然后**交换证书**和**密钥参数**，最终双方协商得到**会话密钥**，用于后续的混合加密系统。
4. **变更密码规范协议**（Change Cipher Spec Protocol），是一个“通知”，告诉对方后续的数据都将使用加密保护，客户端和服务端在握手完成后都会发送，所以在发送`Change Ciper Spec`之前，数据都是明文的。

### 密码套件

浏览器和服务器在使用 TLS 建立连接时需要选择一组恰当的加密算法来实现安全通信，这些算法的组合被称为“**密码套件**”（cipher suite，也叫加密套件）。
TLS 的密码套件命名非常规范，格式很固定。基本的形式是“**密钥交换算法** + **签名算法** + **对称加密算法** + **摘要算法”**。
比如 “ECDHE-RSA-AES256-GCM-SHA384” 密码套件的意思就是：

1. 握手时使用 ECDHE 非对称加密算法进行密钥交换
2. 用 RSA 非对称加密算法签名和身份认证
3. 握手后的通信使用 AES 对称加密算法，密钥长度 256 位
4. 分组模式是 GCM
5. 摘要算法 SHA384 用于消息认证和产生随机数

## TLS1.2 握手

下面的这张图描述了 TLS 的握手过程，其中每一个“框”都是一个记录（`record`），多个记录组合成一个 TCP 包（**segment**）发送。所以，最多经过两次消息往返（4 个消息）就可以完成握手，然后就可以在安全的通信环境里发送 HTTP 报文，实现 HTTPS 协议。

![tls1.2](/resources/tls-1-2.png)

### Client Hello

在 TCP 建立连接之后，浏览器会首先发一个“`Client Hello`”消息，里面有客户端的版本号、支持的密码套件，还有一个随机数（`Client Random`），用于后续生成会话密钥。

```
Handshake Protocol: Client Hello
    Version: TLS 1.2 (0x0303)
    Random: 1cbf803321fd2623408dfe…
    Cipher Suites (17 suites)
        Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
        Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
```

### Server Hello

服务器收到“`Client Hello`”后，返回一个“`Server Hello`”消息。把版本号对一下，也给出一个随机数（`Server Random`），然后从客户端的列表里选一个作为本次通信使用的密码套件，如下所示选择了“`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`”。

```
Handshake Protocol: Server Hello
    Version: TLS 1.2 (0x0303)
    Random: 0e6320f21bae50842e96…
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
```

### Server Certificate

服务器为了证明自己的身份，就把服务端公钥证书发给客户端（`Server Certificate`）。

### Server Key Exchange

服务器选择了 ECDHE 算法，所以在发送证书后，发送“`Server Key Exchange`”消息，里面包含非对称加密的公钥（`Server Params`），用来实现密钥交换算法，并用自己的私钥签名认证。

```
Handshake Protocol: Server Key Exchange
    EC Diffie-Hellman Server Params
        Curve Type: named_curve (0x03)
        Named Curve: x25519 (0x001d)
        Pubkey: 3b39deaf00217894e...
        Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
        Signature: 37141adac38ea4...
```

### Server Hello Done

发送“`Server Hello Done`”消息，表示第一个消息往返结束（两个 TCP 包），结果是客户端和服务器通过明文共享了三个信息：`Client Random`、`Server Random` 和 `Server Params`。

### Client Certificate

通常“**单向认证”**（只认证服务器的证书）通过后已经建立了安全通信，用账号、密码等简单的手段就能够确认用户的真实身份。
为了防止账号密码被盗，会使用 U 盾（网上银行）给用户颁发客户端证书，实现“**双向认证**”。
双向认证时，在“**Server Hello Done**”消息之后，“**Client Key Exchange**”消息之前，客户端要发送“**Client Certificate**”消息，服务器收到后也把证书链走一遍，验证客户端的身份。

### Client Key Exchange

1. 客户端开始走证书链逐级验证，确认证书的真实性，再用公钥验证签名，确认服务器的身份。
2. 根据服务器选择的密码套件生成非对称加密的公钥（`Client Params`），并通过 “`Client Key Exchange`” 消息发送给服务器。

```
Handshake Protocol: Client Key Exchange
    EC Diffie-Hellman Client Params
        Pubkey: 8c674d0e08dc27b5eaa…
```

### Pre-Master

客户端和服务器都拿到了密钥交换算法的两个参数（`Client Params`、`Server Params`），用 ECDHE 算法计算出“`Pre-Master`”，也是一个随机数。

### Master Secret

客户端和服务器有了三个随机数：`Client Random`、`Server Random` 和 `Pre-Master`。用这三个作为原始材料，就可以生成用于加密会话的**主密钥**，叫“`Master Secret`”。

```c
master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)
// PRF 是伪随机数函数，基于密码套件里的最后一个参数 SHA384，通过摘要算法来再一次强化 “Master Secret” 的随机性
```

主密钥有 48 字节，但它也不是最终用于通信的会话密钥，还会再用 `PRF()` 扩展出更多的密钥，比如客户端发送用的会话密钥（`client_write_key`）、服务器发送用的会话密钥（`server_write_key`）等等，避免只用一个密钥带来的安全隐患。

### Change Cipher Spec & Finished

有了主密钥和派生的会话密钥，握手就快结束了。

- 客户端发“`Change Cipher Spec`”和“`Finished`”消息，把之前所有发送的数据做个摘要，再加密一下，让服务器做个验证，判断协商的密钥是否成功。
- 服务器也发“`Change Cipher Spec`”和“`Finished`”消息，把之前所有发送的数据做个摘要，再加密一下，让客户端做个验证，判断协商的密钥是否成功。

双方都验证加密解密成功，那么握手正式结束，后面就收发被**加密的** HTTP 请求和响应。

## TLS1.3

### 兼容性

TLS1.3 协议中新增**扩展协议**（Extension Protocol），类似“补充条款”。通过在记录末尾添加一系列的“扩展字段”来增加新的功能，老版本的 TLS 不认识它可以直接忽略，这就实现了“**后向兼容**”。
在记录头的 Version 字段被兼容性“固定”的情况下，只要是 TLS1.3 协议，握手的“Hello”消息后面就必须有“`supported_versions`”扩展，它标记了 TLS 的版本号，使用它就能区分新旧协议。

```c
Handshake Protocol: Client Hello
    Version: TLS 1.2 (0x0303)
    Extension: supported_versions (len=11)
        Supported Version: TLS 1.3 (0x0304)
        Supported Version: TLS 1.2 (0x0303)
```

### 强化安全

1. 伪随机数函数由 PRF 升级为 HKDF（HMAC-based Extract-and-Expand Key Derivation Function）；
2. 明确禁止在记录协议里使用压缩；
3. 废除了 RC4、DES 对称加密算法；
4. 废除了 ECB、CBC 等传统分组模式；
5. 废除了 MD5、SHA1、SHA-224 摘要算法；
6. 废除了 RSA、DH 密钥交换算法和许多命名曲线。

TLS1.3 里只保留了：

- 对称加密算法：AES、ChaCha20
- 分组模式：AEAD 的 GCM、CCM 和 Poly1305
- 摘要算法： SHA256、SHA384，
- 密钥交换算法： ECDHE 和 DHE
- 椭圆曲线：P-256 和 x25519 等 5 种

> RSA 做密钥交换，它不具有“前向安全”（Forward Secrecy）,而 ECDHE 算法在每次握手时都会生成一对临时的公钥和私钥，每次通信的密钥对都是不同的，也就是“**一次一密**”，即使黑客花大力气破解了这一次的会话密钥，也只是这次通信被攻击，之前的历史消息不会受到影响，仍然是安全的。

只剩下 5 个密码套件：

1. TLS-AES-128-GCM-SHA256
2. TLS-AES-256-GCM-SHA384
3. TLS-CHACHA20-POLY1305-SHA256
4. TLS-AES-128-CCM-SHA256
5. TLS-AES-128-CCM-8-SHA256

### 提升性能

HTTPS 建立连接时除了要做 TCP 握手，还要做 TLS 握手，在 TLS1.2 中会多花两个消息往返（`2-RTT`），可能导致几十毫秒甚至上百毫秒的延迟，在移动网络中延迟还会更严重。
TLS1.3 因为密码套件大幅度简化，也就没有必要再走复杂的协商流程，压缩了以前的“Hello”协商过程，删除了“`Key Exchange`”消息，把握手时间减少到了“`1-RTT`”，效率提高了一倍。

![tls1.3](/resources/tls-1-3.png)

具体的做法是利用扩展协议。
客户端在“`Client Hello`”消息里：

- 用“`supported_groups`”带上支持的曲线，比如 P-256、x25519，
- 用“`key_share`”带上曲线对应的客户端公钥参数，
- 用“`signature_algorithms`”带上签名算法。

服务器收到后在这些扩展里选定一个曲线和参数，再用“`key_share`”扩展返回服务器这边的公钥参数，就实现了双方的密钥交换，后面的流程就和 1.2 基本一样。

```
Handshake Protocol: Client Hello
    Version: TLS 1.2 (0x0303)
    Random: cebeb6c05403654d66c2329…
    Cipher Suites (18 suites)
        Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
        Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
    Extension: supported_versions (len=9)
        Supported Version: TLS 1.3 (0x0304)
        Supported Version: TLS 1.2 (0x0303)
    Extension: supported_groups (len=14)
        Supported Groups (6 groups)
            Supported Group: x25519 (0x001d)
            Supported Group: secp256r1 (0x0017)
    Extension: key_share (len=107)
        Key Share extension
            Client Key Share Length: 105
            Key Share Entry: Group: x25519
            Key Share Entry: Group: secp256r1
```

```
Handshake Protocol: Server Hello
    Version: TLS 1.2 (0x0303)
    Random: 12d2bce6568b063d3dee2…
    Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
    Extension: supported_versions (len=2)
        Supported Version: TLS 1.3 (0x0304)
    Extension: key_share (len=36)
        Key Share extension
            Key Share Entry: Group: x25519, Key Exchange length: 32
```
