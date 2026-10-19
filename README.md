# 用 ChatGPT Plus 套餐发起 Responses API 请求

这是一个只在本机运行的单账号示例。它使用 OpenAI 官方的 **Sign in with ChatGPT / ChatGPT plan usage** OAuth 流程。登录后，`ask` 命令调用公开的 `https://api.openai.com/v1/responses`，使用你的 ChatGPT 套餐用量。它不会创建 API 平台的通用 API Key。

## 在 Git Bash 中运行

```bash
cd /c/Users/15770/Documents/work_space/AItest
python -m pip install -r requirements.txt
python plus_api.py login
python plus_api.py models
python plus_api.py ask --model gpt-6.1-sol '你好，请回复一句话。'
python plus_api.py status
```

本机 Git Bash 中已找到 Python 3.14，以及所需三个库，因此通常可以跳过安装命令。`login` 会打开浏览器；你需要亲自登录 ChatGPT，选择账号，并**明确批准此应用使用 ChatGPT 套餐**。浏览器返回本机回调页后，再执行 `models`。上面的模型名只是官方文档示例；请使用 `models` 实际列出的 slug。`ask` 省略 `--model` 时会选择列表中的第一个模型。

如果浏览器没有自动弹出，运行 `python plus_api.py login --manual`，复制 Git Bash 中打印的链接到浏览器。默认等待授权回调 10 分钟，可用 `--timeout 900` 调整。

## 在本机脚本中使用 OAuth Bearer token

如果你信任一个本机脚本，且它从 `OPENAI_API_KEY` 读取 Bearer 凭据，可以通过本工具启动它：

```bash
python plus_api.py run -- python third_party.py
```

`run` 会先按需刷新 OAuth access token，然后仅在子进程环境变量 `OPENAI_API_KEY` 中传入；不会在终端打印 token，也不会修改当前 Git Bash 会话的环境变量。把示例中的 `python third_party.py` 换成实际启动命令。子进程退出码会原样返回。此命令适合本机可信脚本；该脚本仍然能读取完整 access token。

这个 token 有效期约一小时；`run` 只在**启动时**刷新，长期运行的第三方脚本还需要自行续期或重新启动。第三方脚本必须调用 `POST https://api.openai.com/v1/responses`，使用账号模型列表中的 slug，并在请求中设置 `store: false`、`stream: true`。它若调用 Chat Completions、图像生成等其他 API，或发送预览期不支持的参数，仅设置 `OPENAI_API_KEY` 无法让它使用 Plus 套餐。`api_key` 是部分 SDK 的参数名，在这里传入的仍是 OAuth token，不是 API 平台密钥。

## 雨课堂 Tampermonkey 脚本

[雨课堂刷课助手 3.0.6](https://greasyfork.org/zh-CN/scripts/466651-%E9%9B%A8%E8%AF%BE%E5%A0%82%E5%88%B7%E8%AF%BE%E5%8A%A9%E6%89%8B/code) 的 AI 配置使用非流式 Chat Completions 格式，并在网页 `localStorage` 保存填写的密钥。不要把 Plus OAuth token 或 API 平台的正式 Key 填进去。本机转换入口提供一个可见的**本地密钥**，只接受 `127.0.0.1` 上的请求；它自动刷新已授权的 Plus token，向 OpenAI 发送符合要求的 Responses 请求，再把文字结果转换为该脚本能读取的 `choices[0].message.content`。

在 Git Bash 中保持以下命令运行：

```bash
cd /c/Users/15770/Documents/work_space/AItest
python plus_api.py serve
```

终端会显示 `Local API KEY`。把雨课堂脚本的 **AI配置** 填成：

| 字段 | 填写内容 |
| --- | --- |
| API URL | `http://127.0.0.1:8765/v1/chat/completions` |
| API KEY | Git Bash 终端显示的 `Local API KEY`，只复制密钥本身 |
| Model Name | `gpt-6-luna`（或 `python plus_api.py models` 列出的其他模型） |
| API Format | `OpenAI Format (Chat Completions)` |
| Auth Method | `Bearer Token (Authorization: Bearer)` |

这个本地密钥保存在 Windows 当前用户的凭据管理器中，重启入口后保持不变。入口只支持该脚本所需的文本请求；它会忽略脚本发送的 `temperature: 0.1`，因为 Plus OAuth 的 Responses 路径不支持该参数。请求上游时仍使用 `store: false`、`stream: true`，并等待 `response.completed` 后才返回。终端关闭后，脚本无法访问本机入口。注意本地密钥仍允许能访问本机入口的程序消耗你的 Plus 用量，勿发给他人。

退出并撤销可续期会话：

```bash
python plus_api.py logout
```

完整凭据加密保存在 `%LOCALAPPDATA%/plus-responses-local/session.enc`，加密密钥存于 Windows 当前用户的凭据管理器；命令不会打印 access token 或 refresh token。本机标识保存在同目录的 `config.json`。此工具只管理一个 ChatGPT 账号；要换账号，需先在 ChatGPT 设置中断开此应用的连接，再清理本机旧注册资料。

## 用量与适用范围

在 ChatGPT **设置 → 用量** 中查看应用限额和消耗。Plus 的套餐用量由支持该功能的应用共享；达到套餐上限后，应用只有在你允许使用 ChatGPT credits 时才可能继续消耗额度。API 平台 Key 的计费独立。

这个授权流程当前要求 Responses 请求使用 `store: false` 和 `stream: true`，且只有收到 `response.completed` 才算成功。支持的模型和功能以授权账号返回的信息及官方预览限制为准。

## 官方文档

- [OAuth 注册与登录](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [模型查询与 Responses 请求](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- [账号、续期与登出](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
- [预览期功能限制](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
- [ChatGPT 应用用量管理](https://help.openai.com/en/articles/20001542-using-your-chatgpt-plan-in-other-apps-and-sites)
