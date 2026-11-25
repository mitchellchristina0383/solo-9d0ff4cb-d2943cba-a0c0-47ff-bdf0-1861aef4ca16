# 内网 HTTPS 根证书更换顺序规划器

值班员更换内网 HTTPS 根证书时，用本工具先排好变更顺序：录入服务副本的新旧
PEM 证书链与终端批次的新旧 PEM 根证书包，工具用真实的 `openssl verify` 核验，
给出“每一步只换一个副本的链、或更新一批终端根包”的可行顺序；无解时区分
**证书材料无法通过验证** 与 **过渡名额不足** 两类原因并给出明细。

## 1. 模型与规则

| 对象 | 状态 | 单步动作 |
| --- | --- | --- |
| 服务副本（1~4 个） | 旧链 / 新链 | 一次只把一个副本从旧链切到新链 |
| 终端批次（1~4 批） | 旧包 / 过渡包（新旧并集）/ 新包 | 一批终端可旧包直跳新包，也可先切并集过渡，再切新包 |

- 页面可设置**同时处于过渡态的批次上限** L（0 表示禁止并集过渡，只能直跳）。
- 任一核验时刻（初始态及每步动作之后），每批终端都必须只用**当时持有的根
  证书包**，按域名验证每个副本**当时出示的证书链**；全部 “批次 × 副本”
  组合通过，该状态才合法。
- 核验调用本机 `openssl verify -no-CAfile -CAfile <根包> -untrusted <中间证书>
  -verify_hostname <域名>`：信任锚仅来自录入的根包（不加载系统默认 CA），
  同时完成链签名/有效期校验与 SAN 主机名校验。
- 状态空间至多 2⁴ × 3⁴ = 1296，BFS 求步数最少的方案，动作顺序固定
  （开过渡 → 换副本链 → 收过渡/直跳），方案可复现。
- 无解诊断：
  - **硬无解**：现状（旧链×旧包）或目标态（新链×新包）本身核验失败，或放开
    名额到全部批次仍走不通；页面列出每个失败的“批次 × 副本”在全部 6 种
    链/包组合下的 openssl 失败原因（含主机名不匹配时叶子实际 SAN）。
  - **过渡名额不足**：放开上限可解、按当前 L 不可解时，二分求出最小所需名额，
    提示调大上限后重算。

## 2. 目录结构

```
app/
  certutil.py     # PEM 解析、并集合并、openssl verify 封装
  planner.py      # 状态建模、BFS 求解、无解诊断
  preparation.py  # 启动样例准备：沿用/对齐、缺失重建、失败标记与健康判定
  app.py          # Flask 路由（/、/api/plan、/api/sample、/api/health、/api/summaries）
  templates/      # 单页界面（原生 JS，无前端构建）
  static/         # 样式
scripts/
  generate_samples.py  # 强制重新生成两套独立 PKI 的演示证书（支持 --ensure）
  prepare_samples.py   # 启动入口：按“能沿用则不重签”的规则准备样例
  entrypoint.sh        # 容器入口：准备样例后启动 gunicorn（失败也起服务以暴露健康 503）
samples/          # 已生成的样例（根/中间/各副本链/根包/sample.json，挂载卷）
tests/            # pytest：求解器 12 项 + API 7 项 + 样例准备 10 项
Dockerfile, docker-compose.yml
```

## 3. 启动方式

### Docker Compose（推荐）

```bash
docker compose up --build
# 浏览器打开 http://localhost:8000
```

镜像内已安装 openssl；compose 把宿主机 `./samples` 挂载到 `/app/samples`，
并通过 `/api/health` 做健康检查（约 3~30 秒内变为 healthy）。

#### 启动时的样例准备规则（本次修复重点）

旧 Dockerfile 每次启动都直接执行 `generate_samples.py`，**无条件重新签发**
全套证书并覆盖 `sample.json`，导致值班员此前复制 / 备份的旧根包与网页新载入
的证书链对不上。现在容器入口改为执行
`python scripts/prepare_samples.py /app/samples`，规则：

1. **现有 `sample.json` 能排通迁移方案**（用满过渡名额求解得到 `plan`）：
   **沿用其中全部证书，绝不重新签发、不改写 sample.json**；并以它为唯一
   事实来源，把目录里缺失或损坏的 PEM 对齐 / 补齐：
   - `replicas/<副本>/old-chain.pem`、`new-chain.pem`（逐字对齐）；
   - `bundles/old-bundle.pem`、`new-bundle.pem`、`union-bundle.pem`
     （取首批终端；各批根包不一致时另写 `batch-NN-*` 文件）；
   - 可由根包推导的 `roots/old|new-root.pem`、可由链推导的
     `intermediates/old|new-intermediate.pem`。
   写入采用“内容不同才替换 + 同目录临时文件原子 rename”，正常重启时整个
   `samples/` 目录零改动。
2. **`sample.json` 缺失，或 JSON / 材料解析失败、核验后排不出方案（硬无解）**：
   调用 `generate_samples.py` 重新签发一套确定可解的样例（`sample.json`
   原子替换，避免半截文件）。
3. **准备过程本身失败**（目录被占位文件挡住、权限 / 磁盘错误、openssl 缺失、
   环境级子进程错误等）：写入 `status=error` 状态标记、脚本以退出码 1 结束；
   入口仍启动 gunicorn，`/api/health` 与 `/healthz`、`/health` 均返回 503，
   容器健康检查不通过。第 1 步只读取 `sample.json`，因此**仍可用的
   `sample.json` 会原样保留**；排除故障后 `docker compose restart`（用原
   `./samples` 目录）即会重新准备并恢复 healthy。

相关环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `SAMPLES_DIR` | 仓库根 `samples/`（镜像内 `/app/samples`） | 样例目录 |
| `PREPARE_STATUS_FILE` | `<SAMPLES_DIR>/.prepare-status.json` | 准备状态标记；compose / Dockerfile 固定为 `/tmp/tls-plan-prepare-status.json`，保证挂载目录故障时仍能写失败标记，不可写时再退到系统临时目录 |
| `PORT` | `8000` | gunicorn 监听端口 |

也可在本机直接运行准备脚本查看 JSON 结论：

```bash
python scripts/prepare_samples.py samples
python scripts/generate_samples.py --ensure samples   # 等价的 ensure 入口
```

### 本地直接运行

```bash
pip install -r requirements.txt
python scripts/prepare_samples.py samples   # 沿用/对齐优先，必要时才生成
# 或显式强制重新签发：python scripts/generate_samples.py samples
flask --app app.app run --host 0.0.0.0 --port 8000
```

## 4. 网页试跑流程

1. 打开页面后样例自动载入（3 个副本 × 3 批终端，默认过渡上限 3）；也可点
   “载入证书样例”重新载入。每个 PEM 输入框失焦后会显示解析概要（叶子 CN、
   SAN、链长 / 根包内证书数量）。
2. 点“求解变更顺序”，得到分步方案，每步附带动作后的状态快照与
   “本步核验 9/9 个组合全部通过”的核验证据，页面下方还有 6 列核验矩阵。
3. 试无解场景：
   - 把上限改成 0 → 提示“过渡名额不足，至少需要 3 个批次同时过渡”；
   - 把某批的“新根证书包”替换成旧根包内容 → 提示硬无解并列出 9 个失败配对
     及 `unable to get local issuer certificate`；
   - 把某个副本域名改成证书 SAN 之外的名字 → 提示 `hostname mismatch`
     （并附叶子实际 SAN）。

## 5. 实测结果

### 本次修复后的自测（Python 3.11.2 + OpenSSL 3.0.22，本机无 docker CLI / daemon）

- `pytest tests/` 共 **30 项全部通过**：原有 20 项（求解器 + Flask API，
  含原 README 统计的 19 项口径之外现有的全部用例）+ 新增
  `tests/test_preparation.py` **10 项**，覆盖：
  - 空目录准备 -> 生成可解样例且 14 个预期文件齐全；
  - 连续两次准备（模拟重启）-> `mode=kept`、全部 PEM `unchanged`、
    sample.json 与全目录 SHA-256 不变；
  - 删除根包 / 整个副本目录、写坏根包与链 -> 按 sample.json 逐字节修复，
    修复后仍求出 9 步；
  - 非法 JSON、硬无解材料 -> 自动重新生成且新样例可解；
  - `replicas` 被普通文件挡住 -> 准备失败、error 标记、`/api/health` 503、
    sample.json 原字节保留；移除占位文件后原目录恢复 `kept`/200；
  - 无状态标记时健康探针的结构检查、CLI 退出码 0/1、准备后的样例经 HTTP
    `/api/plan` 求出 9 步；未设 `PREPARE_STATUS_FILE` 且显式传目录时，标记
    正确落在该目录而不是默认 `samples/`。
- 用**真实 gunicorn + 实际 `scripts/entrypoint.sh`**（PATH 垫片提供镜像里的
  `python`/`gunicorn` 命令）跑进程级 E2E，**32 项断言全部通过**，包括：
  首启 `/api/health=200`、迁移页 HTML 含样例、API 求出 9 步；重启后整个
  `samples/` 哈希不变；值班员备份的旧根包经生产 `verify_chain` 验过
  `svc-a` 旧链、错误主机名仍被 SAN 校验拒绝；缺件 / 坏件重启修复；删除
  sample.json 后 `mode=generated` 并签发新材料；占位文件导致准备失败时
  健康检查为 503、`/api/sample` 仍可读、sample.json 字节不变；排障后原目录
  重启恢复。
- 用 jsdom 驱动真实页面打完整浏览器流程：样例自动载入为 3×3 行、
  **12 个 PEM 概要全部 `ok`**、点“求解变更顺序”渲染出
  “找到可行变更顺序，共 9 步”及每步 9/9 核验证据；上限改 0 重算正确出现
  “过渡名额不足，至少需要 3 个批次同时过渡”。渲染后内联 JS 通过
  `node --check`。
- 另测三类准备失败均退出码 1 并写 error 标记：目录只读且缺件
  （`Permission denied`，sample.json 哈希不变，恢复写权限后原目录补齐）、
  PATH 中无 openssl、`sample.json` 是目录。
- `docker-compose.yml` 已用 PyYAML 解析核对；健康检查所用的 urllib 一行命令
  已分别对 200 / 503 实测退出码 0 / 1；`sh -n`、`bash -n` 通过。

### 既有求解器 / API 实测

环境：Python 3.11 + OpenSSL 3.0.22，`pytest tests/` 全部通过，覆盖：

- 旧链仅被旧根信任、新链仅被新根信任、并集同时信任两者、域名不匹配必失败；
- 合法场景求出 9 步方案并逐步回放，验证每步只动一个对象、过渡名额不超限、
  每步全部核验通过、终态全部为新；
- L=0 多批次场景判为名额不足并求出最小名额 3，调到最小名额后可解；
- 新根包错放、现状即坏、SAN 不匹配均判硬无解且明细正确；
- 非法 PEM、空字段、非法上限、空表单均返回 400/抛错。

HTTP 端到端冒烟（真实 Flask 服务）四种返回：

| 场景 | status | 关键输出 |
| --- | --- | --- |
| 默认样例（L=3） | `plan` | 9 步，每步 9/9 核验通过 |
| L=0 | `insufficient_quota` | `min_required=3` |
| 新根包错放为旧根 | `hard_infeasible` | 9 个目标态失败项，原因 `unable to get local issuer certificate` |
| 域名与 SAN 不符 | `hard_infeasible` | `hostname mismatch（叶子证书 SAN: svc-a.internal.example）` |

另用 openssl CLI 直测样例链（旧包验旧链、并集包验新链、错误主机名拒绝）均符合预期。

## 6. 约束与余项

- 本次开发沙箱内**没有 docker CLI 也没有 /var/run/docker.sock**，因此
  `docker compose up --build` 的真实镜像构建 / Docker healthy 状态未能在本机
  执行；已用与镜像相同的启动链路（`scripts/entrypoint.sh` +
  `prepare_samples.py` + gunicorn 2 workers + 真实 openssl）完成进程级自测，
  并核对了 Dockerfile / compose / 健康检查命令。请在有 Docker 的环境最终执行
  `docker compose up --build`，确认容器在 `start_period` 后转为 `(healthy)`；
  失败场景约在 15s + 3×3s 内转为 `(unhealthy)`。
- compose 默认绑定挂载 `./samples:/app/samples`：宿主机侧删除 / `chmod` /
  占位文件等操作可直接被重启后的准备脚本感知。若以 root 运行 Docker，容器
  补齐的文件属主为 root（权限 0644，不影响读取与备份）；rootless / 用户命名
  空间映射下请确保宿主机 `samples/` 对容器内用户可写。
- 证书核验通过每次请求临时文件调用 openssl 子进程完成；输入规模上限
  4×4、缓存按 PEM 组合去重，单次求解最多 96 次核验，实测秒级返回，未做
  高并发压测。启动准备会在满配额下额外求解一次（本机约 0.7~1s）。
- 工具只做离线顺序规划与核验，不连接任何真实服务、不保存录入内容
  （浏览器表单数据仅存在于浏览器与单次请求内存中；启动准备状态只写
  `.prepare-status.json` / `/tmp` 标记，不含私钥）。
- 样例私钥仅用于本地生成演示证书，密钥只在生成进程内存中使用，不落盘；
  请勿把样例证书用于任何真实环境。
- 证书链约定：叶子证书在前、中间 CA 依次在后的 PEM 拼接；根证书不放链文件，
  只放终端根包。
