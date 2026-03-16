# agent-gemini.py
import os
import asyncio
from dotenv import load_dotenv
from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 加载 .env 文件中的 GEMINI_API_KEY
load_dotenv()
if "GEMINI_API_KEY" not in os.environ:
    raise ValueError("请在 .env 文件中设置 GEMINI_API_KEY")

gemini_client = genai.Client()

SYSTEM_PROMPT = """
# Role
你是一个顶级的 Android 安全逆向工程师和代码审计专家。你的任务是利用提供给你的分析工具，深度挖掘给定 APK 中的安全漏洞。

# Tool Selection Guidelines (核心工具切换指南)
你有三个强大的代码搜索与分析工具。请务必严格按照以下场景选择工具：
1. `search_code`: 适用场景：信息收集、广度扫描 (如找硬编码的 "secret", "http://", 或查 Manifest)。容易受代码混淆影响。
2. `search_vulnerable_method_call`: 适用场景：精准定位高危 API 调用 (如 `addJavascriptInterface`, `exec`)。只查真正的代码逻辑，零误报。
3. `get_method_xrefs`: 适用场景：污点分析、追踪调用链。当你需要知道某个敏感函数是被谁调用时使用。

# Standard Operating Procedure (分析工作流)
1. 【解包准备】：如果用户只提供了 APK 文件且尚未反编译，必须先调用 `decompile_apk` 工具将其反编译到指定目录。
2. 【配置侦察】：先用 search_code 查看 Manifest 或硬编码信息。
3. 【特征扫描】：结合漏洞模式，决定是使用纯文本搜索还是 AST 语义搜索找高危函数。
4. 【深度溯源】：一旦发现可疑点，立即使用 get_method_xrefs 追踪调用链。
5. 【结论输出】：指明漏洞所在的类名、方法名及逻辑。在调用工具前，先说明你的思考过程。
"""

# 手动定义 Gemini Tool Schema (映射 Server 中的功能)
tools = [
    types.Tool(
        function_declarations=[
            types.FunctionDeclaration(
                name="decompile_apk",
                description="将 APK 文件反编译为 Java 源代码，保存到指定目录",
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "apk_path": types.Schema(type=types.Type.STRING),
                        "output_dir": types.Schema(type=types.Type.STRING)
                    },
                    required=["apk_path", "output_dir"]
                )
            ),
            types.FunctionDeclaration(
                name="search_code",
                description="在源码目录中纯文本/正则搜索关键字",
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "directory_path": types.Schema(type=types.Type.STRING),
                        "pattern": types.Schema(type=types.Type.STRING),
                        "is_regex": types.Schema(type=types.Type.BOOLEAN),
                        "max_results": types.Schema(type=types.Type.INTEGER)
                    },
                    required=["directory_path", "pattern"]
                )
            ),
            types.FunctionDeclaration(
                name="search_vulnerable_method_call",
                description="使用 AST 语义搜索特定方法调用，无视混淆",
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "directory_path": types.Schema(type=types.Type.STRING),
                        "target_method_name": types.Schema(type=types.Type.STRING)
                    },
                    required=["directory_path", "target_method_name"]
                )
            ),
            types.FunctionDeclaration(
                name="get_method_xrefs",
                description="获取指定类中指定方法的交叉引用 (谁调用了它)",
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "apk_path": types.Schema(type=types.Type.STRING),
                        "target_class": types.Schema(type=types.Type.STRING),
                        "target_method": types.Schema(type=types.Type.STRING)
                    },
                    required=["apk_path", "target_class", "target_method"]
                )
            )
        ]
    )
]


async def run_agent(task_prompt: str):
    server_params = StdioServerParameters(command="python", args=["jadxmcpserver.py"])
    print("🔌 正在启动并连接 Android Sec MCP Server...")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ MCP Server 连接成功！")

            chat = gemini_client.chats.create(
                model="gemini-3-flash-preview",  # 这里可以换成 gemini-2.5-pro 获取更强推理
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    tools=tools,
                    temperature=0.1,
                )
            )

            print(f"\n👨‍💻 任务指令: {task_prompt}")
            response = chat.send_message(task_prompt)

            # 开启自动交互循环 (最多允许 Agent 执行 5 步，防止死循环)
            for step in range(100):
                if not response.function_calls:
                    print(f"\n✨ 【Agent 最终报告】:\n{response.text}")
                    break

                for call in response.function_calls:
                    print(f"\n🤖 【Agent 思考与行动】: 决定调用 -> {call.name}({call.args})")

                    # 执行对应的 MCP 工具
                    try:
                        tool_result = await session.call_tool(call.name, arguments=call.args)
                        result_text = tool_result.content[0].text
                    except Exception as e:
                        result_text = f"Tool execution failed: {str(e)}"

                    print(f"🛠️  【工具返回结果 (截断预览)】: {result_text[:200]}...")

                    # 将结果送回给 Gemini 继续思考
                    response = chat.send_message(
                        types.Part.from_function_response(
                            name=call.name,
                            response={"result": result_text}
                        )
                    )


if __name__ == "__main__":
    task = """
    我这里有一个 APK 文件：'./test_target/shealth.apk'。
    请你帮我把它反编译到 './test_target/src' 目录下，然后分析webview组件是否有加载任意url的风险 。
    请一步步查证，并告诉我详细攻击路径，如何从入口一步步跳转到任意url加载。
    """
    asyncio.run(run_agent(task))