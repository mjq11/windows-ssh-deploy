# Windows SSH 远程部署 Skill

供 Codex 使用的 Windows SSH 连接检查与部署工作流，适用于从 Mac 管理已配置的 Windows 服务器。

公开版已去除个人路径、真实服务器地址、账号及主机名。目标通过本机 SSH 配置和命令参数指定；仓库不包含私钥、密码、API Key 或生产配置。

## 内容

- **连接检测**：验证 SSH 认证、远程命令执行，并返回主机名与当前身份供核对。
- **服务检查**：可选只读检测 CodexRelay 计划任务、部署文件、配置端口和健康接口。
- **部署指导**：备份、上传与运行副本核对、服务验收、失败恢复。
- **排障经验**：区分连接错误与首次安装，处理 Windows 命令转义和计划任务登录条件。

探测脚本不会部署、重启服务或修改服务器配置。实际部署使用目标项目已有的部署入口，按当前用户授权执行。

## 安装

克隆本仓库：

```sh
git clone https://github.com/mjq11/windows-ssh-deploy.git
```

将仓库的 `SKILL.md`、`agents/`、`references/` 和 `scripts/` 放入 `~/.codex/skills/windows-ssh-deploy/`。如果设置了 `CODEX_HOME`，则使用其 `skills/windows-ssh-deploy/` 目录。已有同名 skill 时先对比内容再更新。

在 Codex 中使用：

- `使用 $windows-ssh-deploy 检查我的 Windows 服务器连接`
- `使用 $windows-ssh-deploy 检查中转服务状态`
- `使用 $windows-ssh-deploy 部署当前项目到指定 Windows 服务器`

## 独立运行只读检测

需要本机 Python 3.9+、OpenSSH、已配置的 SSH 目标与密钥，以及远端 Windows PowerShell。Python 脚本仅使用标准库。

先用自己配置的 SSH 别名替换示例 `windows-server`：

```sh
python3 scripts/probe.py --host windows-server
```

CodexRelay 服务检查还需明确根目录、任务名和端口；以下值均为示例：

```sh
python3 scripts/probe.py --host windows-server --relay \
  --root 'C:\Apps\CodexRelay' --task-name ExampleRelay --port 12345
```

`--timeout` 为总超时秒数，默认 30，可设 5–120。`--relay` 预期的目录布局与接口见 [部署参考](references/deployment.md)。

| 退出码 | 含义 |
| --- | --- |
| 0 | 所请求检查通过，输出 JSON |
| 1 | SSH 连接或探测失败，输出 JSON |
| 2 | SSH 成功但服务检查未通过，输出 JSON；或者参数错误，仅输出参数帮助 |

健康检查不验证实际模型生成或每个客户端的权限。部署验收应覆盖本次变更涉及的真实调用。

## 验证

发布前检查 skill 结构、相对引用、参数校验、异常结果处理及输出脱敏，并对参数化探测进行了实际 Windows SSH 与服务健康验证。真实目标和检测输出不随仓库发布。

完整操作说明见 [SKILL.md](SKILL.md)。
