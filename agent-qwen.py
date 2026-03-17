# agent.py (千问 Qwen 版本)
import os
import asyncio
import json
from dotenv import load_dotenv
from openai import AsyncOpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 加载环境变量
load_dotenv()
api_key = os.environ.get("DASHSCOPE_API_KEY")
if not api_key:
    raise ValueError("请在 .env 文件中设置 DASHSCOPE_API_KEY")

# 初始化 OpenAI 客户端，指向阿里云千问的 API 地址
client = AsyncOpenAI(
    api_key=api_key,
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)

SYSTEM_PROMPT = """
# Role
你是一个顶级的 Android 安全逆向工程师，专注于 WebView 任意 URL 加载漏洞的挖掘与利用链分析。

# Tool Selection Guidelines
1. `search_code`: 广度扫描关键字，易受混淆影响。
2. `search_vulnerable_method_call`: 精准 AST 定位方法调用，无视混淆，优先使用。
3. `get_method_body`: 获取方法完整源码，确认漏洞逻辑。
4. `get_method_callees`: 分析方法内部调用链，追踪数据流向。
5. `get_method_xrefs`: 追踪谁调用了某个敏感函数。

# Vulnerability Checklist — WebView 任意 URL 加载
- [ ] WebView 初始化配置 (setJavaScriptEnabled, setAllowFileAccess, setAllowUniversalAccessFromFileURLs)
- [ ] loadUrl / loadDataWithBaseURL 的参数来源 (是否来自外部 Intent / 用户输入)
- [ ] shouldOverrideUrlLoading 是否存在或是否放行任意 scheme
- [ ] addJavascriptInterface 注入 (JS 桥接口暴露 Java 方法)
- [ ] exported Activity/Service 中是否持有 WebView 且接受外部 Intent 控制 URL
- [ ] DeepLink / 自定义 scheme 处理逻辑是否将 URL 直接传给 WebView
- [ ] file:// scheme 访问本地文件 / 跨域读取 (UXSS)

# Standard Operating Procedure
1. 【解包准备】：如未反编译，先调用 `decompile_apk`。
2. 【配置侦察】：调用 `analyze_manifest`，重点找 exported=true 且含 intent-filter (VIEW/BROWSABLE) 的 Activity/Service。
3. 【WebView 配置扫描】：用 `search_vulnerable_method_call` 搜索 setJavaScriptEnabled、setAllowFileAccess、setAllowUniversalAccessFromFileURLs。
4. 【URL 加载点定位】：用 `search_vulnerable_method_call` 搜索 loadUrl、loadDataWithBaseURL。
5. 【数据流追踪】：对每个 loadUrl 调用，用 `get_method_body` 和 `get_method_callees` 追踪 URL 参数来源，确认是否可由外部控制。
6. 【JS 桥审计】：用 `search_vulnerable_method_call` 搜索 addJavascriptInterface，获取接口方法体，确认暴露的 Java 方法。
7. 【scheme 处理审计】：搜索 shouldOverrideUrlLoading、getIntent、getDataString，确认是否存在任意跳转。
8. 【结论输出】：对每个确认漏洞，输出：漏洞类型、受影响类/方法、外部触发路径、可能的攻击影响、关键代码片段。未完成全部 Checklist 前不得输出最终报告。

# Important Rules
- 专注业务代码，android.support / androidx / com.google / aosp 框架代码可忽略。
- 调用工具前必须说明目的和预期。
- 发现一个漏洞后继续分析，直到所有 Checklist 项目均已检查完毕。
"""

# 千问 (OpenAI 格式) 的工具定义 Schema
tools = [
    {
        "type": "function",
        "function": {
            "name": "decompile_apk",
            "description": "将 APK 文件反编译为 Java 源代码，保存到指定目录",
            "parameters": {
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string"},
                    "output_dir": {"type": "string"},
                },
                "required": ["apk_path", "output_dir"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "在源码目录中纯文本/正则搜索关键字",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory_path": {"type": "string"},
                    "pattern": {"type": "string"},
                    "is_regex": {"type": "boolean"},
                    "max_results": {"type": "integer"}
                },
                "required": ["directory_path", "pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_vulnerable_method_call",
            "description": "使用 AST 语义搜索特定方法调用，无视混淆",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory_path": {"type": "string"},
                    "target_method_name": {"type": "string"}
                },
                "required": ["directory_path", "target_method_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_method_xrefs",
            "description": "获取指定类中指定方法的交叉引用 (谁调用了它)",
            "parameters": {
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string"},
                    "target_class": {"type": "string"},
                    "target_method": {"type": "string"}
                },
                "required": ["apk_path", "target_class", "target_method"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_class_structure",
            "description": "获取类的结构 (字段与方法签名)",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"}
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_method_body",
            "description": "获取特定方法的完整源代码;专注业务代码，aosp代码可忽略",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "method_name": {"type": "string"},
                },
                "required": ["file_path", "method_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_manifest",
            "description": "解析 AndroidManifest.xml 组件，Manifest文件一般在resources目录下",
            "parameters": {
                "type": "object",
                "properties": {
                    "manifest_path": {"type": "string"}
                },
                "required": ["manifest_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_hardcoded_secrets",
            "description": "硬编码敏感信息扫描 (Secrets Scanner)，专注业务代码，aosp代码可忽略",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory_path": {"type": "string"}
                },
                "required": ["directory_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_sensitive_apis",
            "description": "敏感 API 使用情况审计 (Risk API Audit);专注业务代码，aosp代码可忽略",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory_path": {"type": "string"}
                },
                "required": ["directory_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_method_callees",
            "description": "分析一个方法内部调用的所有其他方法，用于追踪数据流和调用链",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "method_name": {"type": "string"}
                },
                "required": ["file_path", "method_name"]
            }
        }
    }
]


# Checklist items that must all be covered before the agent can terminate
CHECKLIST = [
    "WebView配置",
    "loadUrl参数来源",
    "shouldOverrideUrlLoading",
    "addJavascriptInterface",
    "exported组件+WebView",
    "DeepLink/自定义scheme",
    "file://跨域",
]

# Keywords used to detect whether a checklist item has been investigated
CHECKLIST_KEYWORDS = {
    "WebView配置":             ["setJavaScriptEnabled", "setAllowFileAccess", "setAllowUniversalAccessFromFileURLs", "WebSettings"],
    "loadUrl参数来源":          ["loadUrl", "loadDataWithBaseURL"],
    "shouldOverrideUrlLoading": ["shouldOverrideUrlLoading", "shouldOverrideUrlLoading"],
    "addJavascriptInterface":  ["addJavascriptInterface"],
    "exported组件+WebView":    ["exported", "intent-filter", "BROWSABLE", "VIEW"],
    "DeepLink/自定义scheme":   ["getDataString", "getIntent", "getData", "scheme"],
    "file://跨域":             ["file://", "UXSS", "setAllowUniversalAccessFromFileURLs"],
}


def get_unchecked_items(messages: list) -> list[str]:
    """Scan conversation history to determine which checklist items haven't been investigated yet."""
    # Collect all text from assistant reasoning and tool results
    covered_text = ""
    for msg in messages:
        if msg.get("role") in ("assistant", "tool"):
            content = msg.get("content") or ""
            covered_text += content
        # Also scan tool call names/arguments
        for tc in msg.get("tool_calls") or []:
            covered_text += tc.get("function", {}).get("arguments", "")

    unchecked = []
    for item, keywords in CHECKLIST_KEYWORDS.items():
        if not any(kw in covered_text for kw in keywords):
            unchecked.append(item)
    return unchecked


async def run_agent(task_prompt: str):
    server_params = StdioServerParameters(command="python", args=["jadxmcpserver.py"])
    print("🔌 正在启动并连接 Android Sec MCP Server...")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ MCP Server 连接成功！")

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task_prompt}
            ]

            print(f"\n👨\u200d💻 任务指令: {task_prompt}")

            for step in range(200):
                print(f"\n{'='*60}\n🔄 【第 {step + 1} 轮】")

                # 1. 调用千问大模型
                response = await client.chat.completions.create(
                    model="qwen3.5-plus",
                    messages=messages,
                    tools=tools,
                    temperature=0.1,
                )

                choice = response.choices[0]
                assistant_message = choice.message
                finish_reason = choice.finish_reason

                if assistant_message.content:
                    print(f"\n🧠 【千问 思考】:\n{assistant_message.content}")

                # 将助手回复加入历史记录。tool_calls 必须为列表或不存在，不能为 null
                tool_calls_serialized = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments
                        }
                    }
                    for tc in (assistant_message.tool_calls or [])
                ]
                assistant_record = {
                    "role": "assistant",
                    "content": assistant_message.content,
                }
                if tool_calls_serialized:
                    assistant_record["tool_calls"] = tool_calls_serialized
                messages.append(assistant_record)

                # finish_reason == "length" => token 超限，提示继续
                if finish_reason == "length":
                    print("⚠️  【警告】Token 上限截断，尝试继续...")
                    messages.append({"role": "user", "content": "你的回复被截断了，请继续完成分析。"})
                    continue

                # 模型没有调用工具 => 检查 Checklist 是否全部覆盖
                if not assistant_message.tool_calls:
                    unchecked = get_unchecked_items(messages)
                    if unchecked:
                        reminder = (
                            f"你还没有检查以下漏洞类型，请继续分析，不要输出最终报告：\n"
                            + "\n".join(f"- {item}" for item in unchecked)
                            + "\n\n请按照 Vulnerability Checklist 逐一排查这些项目。"
                        )
                        print(f"\n⚠️  【强制继续】未覆盖项: {unchecked}")
                        messages.append({"role": "user", "content": reminder})
                        continue  # 强制 LLM 继续

                    # 所有项目已覆盖，允许结束
                    print(f"\n✅ 所有 Checklist 项目已覆盖，分析完成。")
                    print(f"\n✨ 【千问 最终报告】:\n{assistant_message.content}")
                    break

                # 接近步数上限时提醒模型抓紧总结
                if step == 180:
                    messages.append({"role": "user", "content": "注意：分析步骤即将到达上限，请尽快完成所有未检查的 Checklist 项目并输出最终报告。"})

                # 2. 执行工具调用
                for tool_call in assistant_message.tool_calls:
                    func_name = tool_call.function.name
                    func_args = json.loads(tool_call.function.arguments)

                    print(f"\n🤖 【执行行动】: 决定调用 -> {func_name}({func_args})")

                    try:
                        tool_result = await session.call_tool(func_name, arguments=func_args)
                        if tool_result.content:
                            result_text = tool_result.content[0].text
                        else:
                            result_text = "(工具返回了空结果)"
                    except Exception as e:
                        result_text = f"Tool execution failed: {str(e)}"

                    print(f"🛠️  【工具返回结果 (截断预览)】: {result_text[:500]}...")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": func_name,
                        "content": result_text
                    })

                # 循环会继续，带着工具的结果再次请求千问...


if __name__ == "__main__":
    task = """
    我这里有一个 APK 文件：'./test_target/shealth.apk'。
    请你帮我把它反编译到 './test_target/src' 目录下，然后对它进行全面的安全审计。
    请按照安全检查清单逐一排查所有漏洞类型，并给出最终的完整安全报告。
    """
    asyncio.run(run_agent(task))