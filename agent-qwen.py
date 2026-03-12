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
你是一个顶级的 Android 安全逆向工程师和代码审计专家。你的任务是利用提供给你的分析工具，深度挖掘给定 APK 中的安全漏洞。

# Tool Selection Guidelines
1. `search_code`: 适用广度扫描 (找硬编码, 查 Manifest)。易受混淆影响。
2. `search_vulnerable_method_call`: 适用精准定位高危 API 调用 (如 addJavascriptInterface, exec)。无视混淆。
3. `get_method_xrefs`: 适用追踪调用链，看某个敏感函数被谁调用。

# Standard Operating Procedure
1. 【解包准备】：如果用户只提供了 APK 文件且尚未反编译，必须先调用 `decompile_apk` 工具将其反编译到指定目录。
2. 【配置侦察】：先用 search_code 查看 Manifest 或硬编码。
3. 【特征扫描】：结合漏洞模式，决定使用文本还是 AST 搜索。
4. 【深度溯源】：一旦发现可疑点，立即使用 get_method_xrefs 追踪。
5. 【结论输出】：指明漏洞所在的类名、方法名及逻辑。调用工具前请说明思考过程。
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
    }
]


async def run_agent(task_prompt: str):
    server_params = StdioServerParameters(command="python", args=["jadxmcpserver.py"])
    print("🔌 正在启动并连接 Android Sec MCP Server...")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ MCP Server 连接成功！")

            # 维护对话历史记录 (千问/OpenAI 需要手动管理上下文)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task_prompt}
            ]

            print(f"\n👨‍💻 任务指令: {task_prompt}")

            # 开启自动交互循环
            for step in range(100):
                # 1. 调用千问大模型 (推荐使用 qwen-max 获得最强代码推理能力)
                response = await client.chat.completions.create(
                    model="qwen3.5-flash-2026-02-23",
                    messages=messages,
                    tools=tools,
                    temperature=0.1,
                )

                assistant_message = response.choices[0].message

                # 如果模型没有调用工具，说明它得出了最终结论
                if not assistant_message.tool_calls:
                    print(f"\n✨ 【千问 最终报告】:\n{assistant_message.content}")
                    break

                # 打印模型的思考过程 (如果有)
                if assistant_message.content:
                    print(f"\n🧠 【千问 思考】:\n{assistant_message.content}")

                # 将助手的回复 (包含工具调用指令) 加入历史记录
                messages.append(assistant_message)

                # 2. 遍历并执行模型请求调用的工具
                for tool_call in assistant_message.tool_calls:
                    func_name = tool_call.function.name
                    # 解析千问传过来的 JSON 格式参数
                    func_args = json.loads(tool_call.function.arguments)

                    print(f"\n🤖 【执行行动】: 决定调用 -> {func_name}({func_args})")

                    # 执行 MCP Server 中的工具
                    try:
                        tool_result = await session.call_tool(func_name, arguments=func_args)
                        result_text = tool_result.content[0].text
                    except Exception as e:
                        result_text = f"Tool execution failed: {str(e)}"

                    print(f"🛠️  【工具返回结果 (截断预览)】: {result_text[:200]}...")

                    # 3. 将工具的执行结果封装成 'tool' 角色的消息，加回历史记录
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": func_name,
                        "content": result_text
                    })

                # 循环会继续，带着工具的结果再次请求千问...


if __name__ == "__main__":
    task = """
    我这里有一个 APK 文件：'./test_target/VexScanner.apk'。
    请你帮我把它反编译到 './test_target/src' 目录下，然后分析里面是否有Intent重定向类型的安全问题。
    请一步步查证，并告诉我最终的攻击链路。
    """
    asyncio.run(run_agent(task))