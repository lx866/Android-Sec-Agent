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
# 工具 2：基于 Tree-sitter 的 AST 语义搜索
# ==========================================
JAVA_LANGUAGE = Language(tsjava.language())
parser = Parser(JAVA_LANGUAGE)


@mcp.tool()
def search_vulnerable_method_call(directory_path: str, target_method_name: str) -> str:
    """使用 AST (抽象语法树) 精准搜索特定方法名的调用，无视代码混淆和注释。"""
    if not os.path.exists(directory_path):
        return "Error: 目录不存在"

    query_string = f"""
    (method_invocation
      name: (identifier) @method_name
      (#eq? @method_name "{target_method_name}")
    ) @call_expression
    """
    query = JAVA_LANGUAGE.query(query_string)
    results = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    source_bytes = f.read()

                tree = parser.parse(source_bytes)
                captures = query.captures(tree.root_node)
                for node, capture_name in captures:
                    if capture_name == "call_expression":
                        line_number = node.start_point[0] + 1
                        code_snippet = source_bytes[node.start_byte:node.end_byte].decode('utf8', 'ignore')
                        rel_path = os.path.relpath(file_path, directory_path)
                        results.append(f"🎯 调用 [{rel_path}:{line_number}]: \n{code_snippet}")

    return "\n---\n".join(results) if results else f"未找到 '{target_method_name}' 的调用。"


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