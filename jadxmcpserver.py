# server.py
import os
import re
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from tree_sitter import Language, Parser
import tree_sitter_java as tsjava
import jpype
import jpype.imports

# 初始化 MCP Server
mcp = FastMCP("AndroidSecServer")

import subprocess


# ==========================================
# 工具 0：全自动反编译 APK
# ==========================================
@mcp.tool()
def decompile_apk(apk_path: str, output_dir: str) -> str:
    # --- 新增判断逻辑 ---
    # 检查输出目录是否存在且不是空的
    if os.path.exists(output_dir) and any(os.scandir(output_dir)):
        # 简单校验：如果目录下已经有 com 或 android 文件夹，基本确定已成功反编译过
        print(f"♻️  检测到已存在的反编译源码: {output_dir}，跳过重复操作。")
        return f"✅ 检测到该 APK 已经反编译过了，源码位于: {output_dir}。你可以直接开始分析了。"
    # ------------------
    """
    将目标 APK 文件反编译为 Java 源代码，并保存到指定的输出目录。
    这是进行静态代码分析的第一步。
    """
    if not os.path.exists(apk_path):
        return f"❌ 找不到 APK 文件: {apk_path}"

    print(f"📦 正在反编译 {apk_path} 到 {output_dir} ... 这可能需要一两分钟。")

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 构建 Jadx 命令 (这里假设你已经把 jadx 加入了系统环境变量)
    # 如果你是直接下载的压缩包，请把 "jadx" 替换为绝对路径，比如 "./jadx-1.5.5/bin/jadx" (Mac/Linux) 或 "./jadx-1.5.5/bin/jadx.bat" (Windows)
    command = [
        "./jadx-1.5.5/bin/jadx",
        "-d", output_dir,
        apk_path
    ]

    try:
        # 执行命令，设置超时时间防止卡死
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)

        # 优化后的判断逻辑：
        # 只要源码目录里产生了文件，我们就认为初步成功了，即使 Jadx 报了错
        if os.path.exists(output_dir) and any(os.scandir(output_dir)):
            error_msg = f" (注意：Jadx 报告了 {result.stderr.count('ERROR')} 个解析错误，但不影响整体分析)" if "ERROR" in result.stderr else ""
            return f"✅ 反编译初步完成！源码已保存至: {output_dir}{error_msg}\n现在你可以调用 search_code 开始分析了。"
        else:
            return f"❌ 反编译彻底失败，错误日志:\n{result.stderr}"

    except FileNotFoundError:
        return "❌ 找不到 jadx 命令！请确保 jadx 已安装并配置在系统的 PATH 环境变量中，或者在代码中写死 jadx 的绝对路径。"
    except subprocess.TimeoutExpired:
        return "❌ 反编译超时 (超过 5 分钟)，APK 可能过大或被严重混淆。"

# ==========================================
# 工具 1：纯文本 / 正则搜索
# ==========================================
@mcp.tool()
def search_code(directory_path: str, pattern: str, is_regex: bool = False, max_results: int = 50) -> str:
    """在指定目录下的源码文件（Java, Kotlin, XML）中搜索关键字或正则表达式。"""
    if not os.path.exists(directory_path):
        return f"Error: 目录不存在 {directory_path}"

    target_extensions = {".java", ".kt", ".xml", ".properties"}
    results = []
    match_count = 0

    if is_regex:
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return f"Error: 无效的正则表达式 - {e}"
    else:
        pattern_lower = pattern.lower()

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() not in target_extensions:
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_number, line in enumerate(f, 1):
                        matched = False
                        if is_regex:
                            if compiled_pattern.search(line): matched = True
                        else:
                            if pattern_lower in line.lower(): matched = True

                        if matched:
                            clean_line = line.strip()
                            rel_path = os.path.relpath(file_path, directory_path)
                            results.append(f"[{rel_path}:{line_number}] {clean_line}")
                            match_count += 1
                            if match_count >= max_results:
                                results.append(f"\n⚠️ 警告: 匹配结果超过 {max_results} 条，已截断。")
                                return "\n".join(results)
            except Exception:
                continue

    return "\n".join(results) if results else f"未找到 '{pattern}' 的匹配项。"


# ==========================================
# 工具 2：基于 Tree-sitter 的 AST 语义搜索 (适配新版 API)
# ==========================================
from tree_sitter import Language, Parser, Query  # 确保导入了 Query

JAVA_LANGUAGE = Language(tsjava.language())
parser = Parser(JAVA_LANGUAGE)


@mcp.tool()
def search_vulnerable_method_call(directory_path: str, target_method_name: str) -> str:
    """使用 AST (抽象语法树) 精准搜索特定方法名的调用，无视代码混淆和注释。"""
    if not os.path.exists(directory_path):
        return "Error: 目录不存在"

    # 新版本推荐的查询语法定义方式
    query_string = f"""
    (method_invocation
      name: (identifier) @method_name
      (#eq? @method_name "{target_method_name}")
    ) @call_expression
    """

    # 适配新版 API：使用 Query 构造函数
    try:
        query = Query(JAVA_LANGUAGE, query_string)
    except Exception as e:
        return f"Error building AST query: {str(e)}"

    results = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        source_bytes = f.read()

                    tree = parser.parse(source_bytes)

                    # 适配新版 API：使用 query.captures() 并在循环中处理
                    # 注意：新版返回的是一个字典或特定的迭代器格式
                    captures = query.captures(tree.root_node)

                    # 在新版 tree-sitter 中，captures 返回的是一个字典
                    # 键是 capture 名 (比如 'call_expression')，值是节点列表
                    if "call_expression" in captures:
                        for node in captures["call_expression"]:
                            line_number = node.start_point[0] + 1
                            code_snippet = source_bytes[node.start_byte:node.end_byte].decode('utf8', 'ignore')
                            rel_path = os.path.relpath(file_path, directory_path)
                            results.append(f"🎯 发现调用 [{rel_path}:{line_number}]: \n{code_snippet}")
                except Exception:
                    continue

    return "\n---\n".join(results) if results else f"未在 AST 中找到对方法 '{target_method_name}' 的调用。"


# ==========================================
# 工具 3：基于 Jadx/JPype 的交叉引用 (Xref)
# ==========================================
@mcp.tool()
def get_method_xrefs(apk_path: str, target_class: str, target_method: str) -> str:
    """获取指定方法的交叉引用。找出是哪些类和方法调用了目标方法。"""
    # 动态启动 JVM
    if not jpype.isJVMStarted():
        # 请确保 jadx-core.jar 在项目根目录
        jar_path = os.path.abspath("jadx-1.5.5-all.jar")
        if not os.path.exists(jar_path):
            return f"❌ 找不到 {jar_path}。请先下载并放入项目根目录。"
        jpype.startJVM(classpath=[jar_path])

    try:
        from jadx.api import JadxArgs, JadxDecompiler
        from jadx.api.plugins.utils import CommonFileUtils

        args = JadxArgs()
        args.getInputFiles().add(CommonFileUtils.createFile(apk_path))
        args.setSkipResources(True)

        decompiler = JadxDecompiler(args)
        decompiler.load()

        classes = decompiler.getClasses()
        found_method = None

        for cls in classes:
            if cls.getFullName() == target_class:
                for mth in cls.getMethods():
                    if mth.getName() == target_method:
                        found_method = mth
                        break
                break

        if not found_method:
            decompiler.close()
            return f"❌ 未在 APK 中找到 {target_class}.{target_method}"

        usage_list = found_method.getUseIn()
        results = [f"🔗 发现 {len(usage_list)} 处调用了 {target_class}.{target_method}:"]

        for usage_node in usage_list:
            caller_class = usage_node.getTopParentClass().getFullName()
            line_num = usage_node.getSourceLine()
            results.append(f"  -> 被调用方: {caller_class} (在第 {line_num} 行附近)")

        decompiler.close()
        return "\n".join(results)
    except Exception as e:
        return f"❌ Jadx API 执行报错: {str(e)}"


if __name__ == "__main__":
    mcp.run()