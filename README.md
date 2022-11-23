# cert

Generate certificates.

## OpenSSL

著名的开源密码学程序库和工具包，几乎支持所有公开的加密算法和协议，已经成为了事实上的标准，许多应用软件都会使用它作为底层库来实现 TLS 功能，包括常用的 Web 服务器 Apache、Nginx 等。

```shell
# 生成服务端私钥
openssl genrsa -out server.key 2048
# 2048 表示私钥长度

# 根据服务端私钥生成服务端公钥
openssl rsa -in server.key -out server.key.public

# 根据服务端私钥生成自签名证书
openssl req -new -x509 -key server.key  -days 365 -out server.crt 
```

```shell
--- CA ---
# 生成 CA 的私钥
openssl genrsa -out rootCA.key 2048

# 根据 CA 的私钥生成自签名的证书，证书中包含 CA 的公钥
openssl req -new -x509 -nodes -key rootCA.key -subj "/CN=*.ca.com" -out rootCA.pem -days 5000

--- Server ---
# 生成服务端私钥
openssl genrsa -out server.key 2048

# 根据服务端私钥生成证书签名请求（CSR，Certificate Sign Request）
openssl req -new -key server.key -subj "/CN=*.xxx.yyy.com" -out server.csr

# 用 CA 的私钥对服务端提交的 CSR 进行签名，生成服务端证书
openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out server.crt -days 5000

--- Client ---
# 生成客户端私钥
openssl genrsa -out client.key 2048

# 根据客户端私钥生成证书签名请求
openssl req -new -key client.key -subj "/CN=*.aaa.bbb.com" -out client.csr

# 用 CA 的私钥对客户端提交的 CSR 进行签名， 生成客户端证书
openssl x509 -req -in client.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out client.crt -days 5000

# 查公钥证书的内容
openssl x509 -in client.crt -noout -text

# 验证公钥证书
openssl verify -CAfile ca.crt server.crt
server.crt: OK
```

使用 OpenSSL 模拟证书验证过程，公钥证书中的签名信息就是使用 `ca.key` 对证书中公钥信息与证书属性信息的摘要信息进行加密而得来的。

```shell
# 生成待签名文件
echo "hello,world" > hello.txt

# 对文件进行签名
openssl rsautl -sign -in hello.txt -inkey ca.key -out hello.signed

# 对文件进行验证
openssl rsautl -verify -in hello.signed -inkey ca.crt -certin -out hello.verify

# 查看验证后的内容
cat hello.verify
hello,world

# 验证后的内容与签名前内容一致，证书验证通过
```
