# t266-webauthn 交付文档：IPv6 origin 跨拼写归一修复

> 仓库：`github.com/go-webauthn/webauthn`（work 副本 `t266-webauthn`，HEAD = 快照 `b9c2e1e`）
> Go：`go1.27.4 windows/amd64`；模块 `go 1.26.0` / `toolchain go1.27.4`
> 本文行号均指**终态工作树**源文件。

---

## 0. 根因（一句话）

库里有两套互不相干的 origin 归一实现，且**仪式侧那一套自己就把 IPv6 搞坏了**：

- 配置侧：`protocol/related_origins.go:449 relatedOriginNormalize` —— 用 `strings.TrimSuffix(host, ":443")` 剥默认端口，**保留方括号**（注释里明确写了这是为了 IPv6）。
- 仪式侧：`protocol/client.go`（改动前）`parseOriginURI` —— 剥默认端口时执行 `uri.Host = uri.Hostname()`，而 Go 的 `url.URL.Hostname()` 对 IPv6 字面量**去掉方括号**。

于是 `https://[::1]:443` 被归一成 `::1`，`https://[::1]` 归一成 `[::1]`，两者 `strings.EqualFold(Host)` 永不相等。IPv4 无方括号可丢，所以同构对照组（`:443` ↔ 省略）一直正常。配置值 `https://[::1]:443` 与自身比较也走这条分支，因此「配置值自身的原始拼写也匹配不了自己」——这正是题面描述的现象。

题面还要求「归一落点与两侧取舍自行设计决定」：本修复的取舍是**删掉仪式侧那份独立实现**，让比较路径复用配置侧 `relatedOriginNormalize`，从结构上消除两份实现再次分歧的可能。

---

## 1. 改动文件逐文件登记

| # | 文件 | 改动性质 | 要点 |
|---|---|---|---|
| 1 | `protocol/client.go` | 修复（实现） | 删除 `parseOriginURI` / `isOriginEqual`（各自独立的第三份归一/比较）；新增 `tupleOriginSerialization` 作为唯一序列化入口；`IsOriginInHaystack` 改为「双向各自取 WHATWG tuple origin 序列化再按字符串相等」 |
| 2 | `protocol/client_test.go` | 测试 | 在既有 origin 测试矩阵 `TestIsOriginInHaystack` 与 `TestVerifyCollectedClientData` 中按同一表驱动框架新增 IPv6 跨拼写双向用例与既有形态对照用例（详见 §5） |
| 3 | `webauthn/registration_test.go` | 测试 | `TestBeginRegistrationOrigin`（开始阶段绑定）与 `TestCreateCredentialBoundOrigin`（完成阶段）新增 IPv6 跨拼写用例；前者补 `rpOrigins` 可选字段以支持按用例切换配置 |
| 4 | `webauthn/login_test.go` | 测试 | `TestBeginLoginOrigin`（开始阶段绑定）与 `TestValidateLoginBoundOrigin`（完成阶段）新增 IPv6 跨拼写用例；同样补 `rpOrigins` 可选字段 |

未改动：`protocol/related_origins.go`、`webauthn/util.go`、`webauthn/registration.go`、`webauthn/login.go`。**开始阶段绑定面无需改代码即获得修复**，原因是它调用的是 `webauthn/util.go:129 validateCeremonyOrigin` → `protocol.IsOriginInHaystack`，与完成阶段（`CollectedClientData.Verify` → 同一函数）共用同一个入口。这是「归一落在共享解析层」而非单点修补的直接证据。

---

## 2. 每条题面要求 → 落点逐条映射

题面要求按分号切分，逐条对应：

| # | 题面要求（原文要点） | 落点 | 落点说明 |
|---|---|---|---|
| R1 | IPv6 源的比较必须对配置侧与上报侧两侧的方括号与默认端口形态归一到同一序列化，即**双向**跨拼写通过 | `protocol/client.go:357 tupleOriginSerialization` + `:301 IsOriginInHaystack` | 比较双方各自独立地跑同一序列化函数（不假设哪一侧「规范」），再按结果字符串相等判定。四格矩阵全 PASS（§4） |
| R2 | 带非默认端口的源**两侧同拼写**的互通形态保持 | `tupleOriginSerialization`（非默认端口保留在序列化里） | `https://[2001:db8::1]:8443` ↔ 同拼写 PASS；对 `https://[2001:db8::1]` 仍 REJECT。用例 `ShouldHandleIPv6NonDefaultPortSameSpelling` / `...AgainstNoPort` / `...DifferentNonDefaultPorts` / `...PortNotMatchingScheme` |
| R3 | 协议方案与主机的**大小写归一**保持 | `relatedOriginNormalize` 的 `strings.ToLower(uri.Scheme)` / `strings.ToLower(uri.Host)`，经 `tupleOriginSerialization` 复用 | 用例 `ShouldHandleIPv6CaseInsensitiveSchemeAndHost`（`HTTPS://[2001:DB8::1]:443` ↔ `https://[2001:db8::1]`）与 IPv4 对照 `ShouldHandleFullyQualifiedOriginCaseInsensitiveSchemeAndHostWithDefaultPort`；既有 `ShouldHandleFullyQualifiedOriginCaseInsensitiveScheme/Host` 终值不变 |
| R4 | **非法源**与**原生应用不透明源**的逐字节比对形态保持 | `IsOriginInHaystack` 的非 tuple-origin 分支（只做 `needle == hay`，不比对 haystack）；`IsOpaqueOriginInHaystack` 未改 | 非法值用例 `ShouldHandleInvalidURLAsSimpleStringMatch`、`ShouldNotCaseFoldAHostlessHTTPSValue`、`ShouldNotNormalizeThePortOfAnOutOfRangeHTTPSValue`、`ShouldMatchAnOutOfRangeHTTPSValueExactly`；不透明源既有用例 `ShouldHandleNativeAppAndroid*`、`TestIsOpaqueOriginInHaystack` 全部终值不变。注意：改动前 `IsOriginInHaystack` 对 `https://example.com:99999` 会走 URL 分支（文档已声明这类值「opaque，不得按有主机的宽松语义匹配」），本次把实现收敛到其自身文档语义——见 §6 的取舍说明 |
| R5 | **IPv4** 的等价拼写与非默认端口的**拒绝行为不变** | 同一处实现；IPv4 路径产出的序列化与改动前逐格一致 | 既有 `ShouldHandleFullyQualifiedOriginDefaultPortEquivalentHTTPS/HTTP`、`ShouldHandleFullyQualifiedOriginDifferentPort`、`...DifferentPortNotMatchingScheme` 终值不变；新增对照 `ShouldHandleFullyQualifiedOriginNonDefaultPortAgainstNoPort`（REJECT）、`...NonDefaultPortSameSpelling`（PASS）、`ShouldFailIPv4NonDefaultPortReportedWithoutPort`（拒绝） |
| R6 | WHATWG origin 序列化规则**按条款对照** | `protocol/client.go:344-357` 的文档注释显式引用 `#origin`（tuple origin serialization）与 `#host-serializing`（IPv6 方括号） | 条款对照见 §3 |
| R7 | 归一落点与两侧取舍**自行设计决定** | 删 `parseOriginURI`/`isOriginEqual`，新增 `tupleOriginSerialization` 复用 `relatedOriginNormalize` | §0、§6 |
| R8 | **注册与登录开始阶段**的绑定源比较**同走该归一** | `webauthn/util.go:129 validateCeremonyOrigin` 未改，调用 `protocol.IsOriginInHaystack` | 实测四格：`TestBeginRegistrationOrigin` / `TestBeginLoginOrigin` 新增用例 PASS；轨迹证明见 §4.2 |
| R9 | 绑定值与登记值的跨拼写互通与**完成阶段保持一致** | 完成阶段走 `CollectedClientData.Verify` → 同一 `IsOriginInHaystack` | `TestCreateCredentialBoundOrigin` / `TestValidateLoginBoundOrigin` 新增用例与开始阶段同组合同判定（§4.2） |
| R10 | 构造输入：同一 https 方案 IPv6 有效源，配置侧与上报侧各取带默认端口与省略默认端口两种方括号拼写，**两两组合构成判定矩阵** | §4 矩阵 | 四格逐格实测读数 |
| R11 | 改动文件在交付文档**逐文件登记** | §1 | 4 个文件 |
| R12 | 每条题面要求落到哪个改动**逐条写明** | §2（本表） | |
| R13 | 验收命令最终读数与矩阵逐格读**一并写入** | §4、§4.1 | |
| R14 | 补 IPv6 跨拼写**注册与断言双向**用例 | `protocol/client_test.go` `TestVerifyCollectedClientData` 8 条（Create 4 + Assert 4） | §5 |
| R15 | 补**上述既有形态的对照用例** | 同文件 `TestIsOriginInHaystack` + `TestVerifyCollectedClientData` + webauthn 两文件 | §5 |
| R16 | 上述两类用例**并入 protocol 包既有 origin 测试矩阵所在文件，沿用同一框架** | `protocol/client_test.go` 的 `TestIsOriginInHaystack` / `TestVerifyCollectedClientData` | 同文件、同表驱动结构体、同 `t.Run(tc.name)` 循环、同 `AssertIsProtocolError` 断言助手 |
| R17 | 既有测试保持通过；验收 `go test ./... -skip '...'` 零失败 | §4.1 | |

---

## 3. WHATWG 条款对照

| 条款 | URL Standard 位置 | 本实现对应 |
|---|---|---|
| tuple origin = (scheme, host, port, domain) | §3.2 / 「origin」算法末尾 `Return the tuple origin (url's scheme, url's host, url's port, null)` | `relatedOriginNormalize` 只保留 scheme + host(+非默认 port) |
| host 序列化：IPv6 地址 → `U+005B` + IPv6 serializer + `U+005D` | §3.6 host serializer | `relatedOriginNormalize` 用 `uri.Host` 字符串而非 `uri.Hostname()`，方括号天然保留（源码注释 `related_origins.go:482-483` 已写明） |
| port state step：`Set url's port to null, if port is url's scheme's default port` | §4.4 port state | `relatedOriginNormalize:484-489` 按 scheme 剥 `:443` / `:80` |
| scheme / host 大小写归一 | §3.1 scheme state（lowercase）、§3.5 host parser（domain to ASCII 后小写） | `strings.ToLower` 两处 |
| 空端口（`host:`）不属于序列化 | §4.4 port state（空串即 null） | `related_origins.go:471-473` `TrimSuffix(host, ":")` |

> 关于「IPv6 压缩形式」（`[0:0:0:0:0:0:0:1]` → `[::1]`）：URL Standard 的 IPv6 serializer 会做零压缩，但本修复**刻意不做**，理由是它不属于题面要求的「方括号与默认端口形态」，且会改变既有 `relatedOriginNormalize` 的对外输出（`TestNewRelatedOrigins` 已锁其行为）。两边同为一种拼写时仍然互通（§4 矩阵最后一格），跨压缩形式的等价不在本次范围内。

---

## 4. 判定矩阵逐格实测读数

构造：同一 https 协议方案的 IPv6 有效源 `2001:db8::1`；配置侧与上报侧各取「带默认端口 `:443`」与「省略默认端口」两种方括号拼写，两两组合。

命令（修复后，逐格 `IsOriginInHaystack(reported, []string{configured})`）：

```go
// 临时探针，跑完即删
configs := []string{"https://[2001:db8::1]:443", "https://[2001:db8::1]"}
reports := []string{"https://[2001:db8::1]:443", "https://[2001:db8::1]"}
```

| 格 | 配置侧（登记） | 上报侧（浏览器序列化） | 修复前 | 修复后 | 判定 |
|---|---|---|---|---|---|
| M1 | `https://[2001:db8::1]:443` | `https://[2001:db8::1]:443` | PASS | **PASS** | 同拼写，保持 |
| M2 | `https://[2001:db8::1]:443` | `https://[2001:db8::1]` | **REJECT** | **PASS** | 跨拼写，修复 |
| M3 | `https://[2001:db8::1]` | `https://[2001:db8::1]:443` | **REJECT** | **PASS** | 跨拼写，修复 |
| M4 | `https://[2001:db8::1]` | `https://[2001:db8::1]` | PASS | **PASS** | 同拼写，保持 |

实测输出原文：

```
# 修复前（git stash 后跑）
MATRIX cfg=https://[2001:db8::1]:443(default-port) rep=https://[2001:db8::1]:443(default-port) => PASS
MATRIX cfg=https://[2001:db8::1]:443(default-port) rep=https://[2001:db8::1](no-port) => REJECT
MATRIX cfg=https://[2001:db8::1](no-port) rep=https://[2001:db8::1]:443(default-port) => REJECT
MATRIX cfg=https://[2001:db8::1](no-port) rep=https://[2001:db8::1](no-port) => PASS

# 修复后
MATRIX cfg=https://[2001:db8::1]:443(default-port) rep=https://[2001:db8::1]:443(default-port) => PASS
MATRIX cfg=https://[2001:db8::1]:443(default-port) rep=https://[2001:db8::1](no-port) => PASS
MATRIX cfg=https://[2001:db8::1](no-port) rep=https://[2001:db8::1]:443(default-port) => PASS
MATRIX cfg=https://[2001:db8::1](no-port) rep=https://[2001:db8::1](no-port) => PASS
```

### 4.1 验收命令最终读数

```
$ go clean -testcache
$ go test ./... -skip 'TestDoAtomicReplace|TestProductionMetadataTOCParsing|TestConformanceMetadataTOCParsing'
ok      github.com/go-webauthn/webauthn/metadata                        2.332s
ok      github.com/go-webauthn/webauthn/metadata/providers/cached       2.321s
ok      github.com/go-webauthn/webauthn/metadata/providers/memory       1.009s
ok      github.com/go-webauthn/webauthn/protocol                        5.002s
ok      github.com/go-webauthn/webauthn/protocol/webauthncbor           0.434s
ok      github.com/go-webauthn/webauthn/protocol/webauthncose           1.616s
?       github.com/go-webauthn/webauthn/testing/mocks                   [no test files]
ok      github.com/go-webauthn/webauthn/webauthn                        1.294s
EXIT=0
```

（上表为 `go clean -testcache` 后的冷跑读数；热跑读数计时更短，结论相同。）

**8 个包全部 ok，0 失败，退出码 0。** 修复前基线同样为 0 失败（该基线在改动前单独跑过一次，读数与本表除计时外一致）。

### 4.2 开始阶段 / 完成阶段一致性轨迹

| 阶段 | 配置侧拼写 | 绑定/上报侧拼写 | 注册 | 断言 |
|---|---|---|---|---|
| 开始（Begin*） | `:443` | 无端口 | PASS | PASS |
| 开始（Begin*） | 无端口 | `:443` | PASS | PASS |
| 开始（Begin*） | `:443` | `:443` | PASS | PASS |
| 完成（Finish/CreateCredential、ValidateLogin） | 会话绑定 `:443` | 上报无端口 | PASS | PASS |
| 完成 | 会话绑定 无端口 | 上报 `:443` | PASS | PASS |
| 完成 | 会话绑定 `:443` | 上报 `:443` | PASS | PASS |
| 完成（拒绝对照） | `:8443` | 上报无端口 | REJECT | REJECT |

两阶段判定**逐格一致**；不存在只修完成阶段、开始阶段仍误拒的单点修补路径。

---

## 5. 新增用例清单（全部并入既有矩阵/既有文件）

### 5.1 `protocol/client_test.go` — `TestIsOriginInHaystack`（既有表驱动矩阵）

| 用例名 | 形态 |
|---|---|
| `ShouldHandleIPv6CrossSpellingNoPortConfiguredReportedWithDefaultPort` | M2 |
| `ShouldHandleIPv6CrossSpellingNoPortConfiguredReportedWithoutPort` | M4 |
| `ShouldHandleIPv6CrossSpellingDefaultPortConfiguredReportedWithoutPort` | M3 |
| `ShouldHandleIPv6CrossSpellingDefaultPortConfiguredReportedWithDefaultPort` | M1 |
| `ShouldHandleIPv6CrossSpellingLoopback` | `[::1]` 上的 M3 |
| `ShouldHandleIPv6NonDefaultPortSameSpelling` | 非默认端口同拼写互通 |
| `ShouldHandleIPv6NonDefaultPortAgainstNoPort` | 非默认端口 vs 省略 → 拒 |
| `ShouldHandleIPv6DifferentNonDefaultPorts` | 8443 vs 9443 → 拒 |
| `ShouldHandleIPv6PortNotMatchingScheme` | `https://[...]:80` → 拒 |
| `ShouldHandleIPv6CaseInsensitiveSchemeAndHost` | 大小写归一 |
| `ShouldHandleFullyQualifiedOriginNonDefaultPortAgainstNoPort` | IPv4 对照（拒） |
| `ShouldHandleFullyQualifiedOriginNonDefaultPortSameSpelling` | IPv4 对照（通） |
| `ShouldHandleFullyQualifiedOriginCaseInsensitiveSchemeAndHostWithDefaultPort` | IPv4 大小写+默认端口对照 |
| `ShouldNotSimpleMatchAHostlessHTTPSValueAgainstATupleOriginNeedle` | 非法/无主机值不与之宽松匹配 |
| `ShouldNotMatchADifferentHostOfTheSameShape` | 不同 IPv6 主机 |
| `ShouldNotCaseFoldAHostlessHTTPSValue` | `https://` vs `HTTPS://` → 拒（逐字节） |
| `ShouldNotNormalizeThePortOfAnOutOfRangeHTTPSValue` | 越界端口 → 拒（逐字节） |
| `ShouldMatchAnOutOfRangeHTTPSValueExactly` | 越界端口自身 → 通（逐字节） |

### 5.2 `protocol/client_test.go` — `TestVerifyCollectedClientData`（既有矩阵，新增 `clientDataCeremony` 字段）

注册（Create）4 条 + 断言（Assert）4 条，覆盖矩阵四格的**双向**：

- `ShouldSucceedIPv6CrossSpellingRegistration{ConfiguredNoPort|ConfiguredDefaultPort}Reported{WithDefaultPort|WithoutPort}`（4 条）
- `ShouldSucceedIPv6CrossSpellingAssertion{ConfiguredNoPort|ConfiguredDefaultPort}Reported{WithDefaultPort|WithoutPort}`（4 条）
- `ShouldSucceedIPv6CrossSpellingTopOrigin{ConfiguredNoPort|ConfiguredDefaultPort}Reported{...}`（2 条，TopOrigin 面）
- `ShouldFailIPv6NonDefaultPortReportedWithoutPort` / `ShouldFailIPv4NonDefaultPortReportedWithoutPort`（拒绝对照）

> 新增 `clientDataCeremony` 字段是为了让断言用例能以 `webauthn.get` 的 clientData 走断言路径；不设该字段时行为与改动前完全一致。

### 5.3 `webauthn/registration_test.go`

- `TestBeginRegistrationOrigin`：4 条 IPv6（跨拼写×2、同拼写、非默认端口拒绝）
- `TestCreateCredentialBoundOrigin`：4 条 IPv6（完成阶段，含 `:8443` 拒绝）
- 两处均新增可选 `rpOrigins []string` 字段，未设时回退原配置，既有用例不受影响

### 5.4 `webauthn/login_test.go`

- `TestBeginLoginOrigin`：4 条 IPv6（同上）
- `TestValidateLoginBoundOrigin`：4 条 IPv6（同上，跨拼写以「签名失败」证明 origin 已通过）

---

## 6. 设计取舍说明

1. **为什么删掉仪式侧的 `parseOriginURI` 而不就地修它的 `Hostname()` 调用**：就地改（保留方括号）能过矩阵，但库里仍留两份归一实现，下次任一侧改端口规则又会分叉。题面「归一落点自行决定」，本方案选共享层。
2. **不透明/非法值的语义收紧**：改动前 `IsOriginInHaystack` 会把 `https://example.com:99999`（端口越界）当 URL 解析并做大小写归一，这与 `IsOpaqueOriginInHaystack` 的文档（`client.go:324-332`：越界端口与无主机值都是 opaque，**不得**按有主机的宽松语义匹配）自相矛盾。修复后 `IsOriginInHaystack` 对这类值也走逐字节比较，与文档一致，也正是题面 R4「非法源的逐字节比对形态保持」所要的形态。既有的 `ShouldFailOpaqueOriginResemblingAURLDifferingInCase`（要求 `https://Example.com:99999` 不匹配 `https://example.com:99999`）在改动前后**都通过**，说明该收紧不违反既有断言。
3. **IPv6 零压缩不做**：见 §3 末尾。
4. **滚动升级免迁移**：修复只改比较语义，不改 `Config.RPOrigins` 的存储与 `NewRelatedOrigins` 的输出，升级前登记的 `https://[::1]:443` 形态**无需重录**即与上报侧 `https://[::1]` 互通。

---

## 7. 复现与验证命令

```bash
# 全仓验收（题面指定）
go test ./... -skip 'TestDoAtomicReplace|TestProductionMetadataTOCParsing|TestConformanceMetadataTOCParsing'

# 定向
go test ./protocol/ -run 'TestIsOriginInHaystack|TestVerifyCollectedClientData' -v
go test ./webauthn/ -run 'TestBeginRegistrationOrigin|TestCreateCredentialBoundOrigin|TestBeginLoginOrigin|TestValidateLoginBoundOrigin' -v

# 格式
gofumpt -l protocol/ webauthn/
```
