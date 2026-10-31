# jenkins-atom-azure-blob

把构建产物传到 Azure Blob。

用的是 SharedKey 签名：Azure 要求按固定顺序拼一段 canonical string 再 HMAC-SHA256，拼错只回一个没有信息的 403。签名在这里集中实现一次，smoke 的假服务会**按收到的请求重算签名**——canonical string 写错，测试当场红，而不是到生产才发现。

`endpoint` 可指向本地（Azurite 或假服务），`blobPrefix` 决定路径，`overwrite=false` 时带 `If-None-Match: *`。

```bash
./build.sh && ./tools/smoke.sh
```
