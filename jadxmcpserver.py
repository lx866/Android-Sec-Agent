# server.py
import os
import re
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from tree_sitter import Language, Parser, Query, QueryCursor
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
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)

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
        return "❌ 反编译超时 (超过 10 分钟)，APK 可能过大或被严重混淆。"

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
                    cursor = QueryCursor(query)
                    captures = cursor.captures(tree.root_node)

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
    import os
    import jpype

    # 动态启动 JVM
    if not jpype.isJVMStarted():
        jar_path = os.path.abspath("jadx-1.5.5/lib/jadx-1.5.5-all.jar")
        if not os.path.exists(jar_path):
            return f"❌ 找不到 {jar_path}。请先下载并放入项目根目录。"
        # 增加 convertStrings=True 可以让 Java 字符串自动转为 Python 字符串，方便后续处理
        jpype.startJVM(classpath=[jar_path], convertStrings=True)

    decompiler = None
    try:
        # 1. 引用 Java 原生文件类，避开 Jadx 不稳定的 Utils 插件
        JavaFile = jpype.JClass("java.io.File")
        from jadx.api import JadxArgs, JadxDecompiler

        args = JadxArgs()
        args.getInputFiles().add(JavaFile(apk_path))
        args.setSkipResources(True)

        decompiler = JadxDecompiler(args)
        decompiler.load()

        classes = decompiler.getClasses()
        found_method = None

        # 查找目标类和方法
        for cls in classes:
            if cls.getFullName() == target_class:
                for mth in cls.getMethods():
                    if mth.getName() == target_method:
                        found_method = mth
                        break
                if found_method:
                    break

        if not found_method:
            return f"❌ 未在 APK 中找到 {target_class}.{target_method}"

        # 获取交叉引用 (XREFs)
        # getUseIn() returns a list of MethodNode (callers), not instruction nodes
        usage_list = found_method.getUseIn()

        if not usage_list or len(usage_list) == 0:
            return f"✅ 找到了方法，但没有发现任何地方调用了 {target_class}.{target_method}。"

        results = [f"🔗 发现 {len(usage_list)} 处调用了 {target_class}.{target_method}:"]

        for caller_method in usage_list:
            # usage_list entries are MethodNode objects (the calling methods)
            try:
                caller_class_name = caller_method.getDeclaringClass().getFullName()
                caller_method_name = caller_method.getName()
                results.append(f"  -> {caller_class_name}.{caller_method_name}")
            except Exception:
                results.append("  -> 发现一处调用，但无法解析具体调用者信息")

        return "\n".join(results)

    except Exception as e:
        return f"❌ Jadx API 执行报错: {str(e)}"
    finally:
        # Always close the decompiler to release JVM resources
        if decompiler is not None:
            try:
                decompiler.close()
            except Exception:
                pass


# ==========================================
# 工具 4：获取类的结构 (修正版)
# ==========================================
@mcp.tool()
def get_class_structure(file_path: str) -> str:
    """解析 Java 文件，提取并列出其中定义的所有字段和方法签名。"""
    if not os.path.exists(file_path):
        return f"❌ 找不到文件: {file_path}"

    try:
        with open(file_path, 'rb') as f:
            source_bytes = f.read()

        tree = parser.parse(source_bytes)

        # 定义查询
        query_string = """
        (field_declaration) @field
        (method_declaration) @method
        (constructor_declaration) @method
        """
        query = Query(JAVA_LANGUAGE, query_string)
        cursor = QueryCursor(query)
        captures = cursor.captures(tree.root_node)

        results = [f"📊 Class Structure: {os.path.basename(file_path)}", "---"]

        fields = []
        methods = []

        for tag, nodes in captures.items():
            for node in nodes:
                if tag == "field":
                    field_text = source_bytes[node.start_byte:node.end_byte].decode('utf-8', 'ignore').strip()
                    fields.append(f"  [FLD] {field_text}")
                elif tag == "method":
                    # 获取方法签名（去掉方法体）
                    method_full = source_bytes[node.start_byte:node.end_byte].decode('utf-8', 'ignore').split('{')[
                        0].strip()
                    line_num = node.start_point[0] + 1
                    methods.append(f"  [MTH] Line {line_num}: {method_full}")

        if fields:
            results.append(f"Found {len(fields)} Fields:")
            results.extend(fields)
            results.append("")

        if methods:
            results.append(f"Found {len(methods)} Methods:")
            results.extend(methods)

        return "\n".join(results) if (fields or methods) else "ℹ️ 未在文件中发现明显的字段或方法定义。"
    except Exception as e:
        return f"❌ 解析类结构失败: {str(e)}"


# ==========================================
# 工具 5：获取特定方法体 (修正版)
# ==========================================
@mcp.tool()
def get_method_body(file_path: str, method_name: str) -> str:
    """提取指定方法的完整源代码实现。"""
    if not os.path.exists(file_path):
        return f"❌ 找不到文件: {file_path}"

    try:
        with open(file_path, 'rb') as f:
            source_bytes = f.read()

        tree = parser.parse(source_bytes)
        # Query all method/constructor declarations, then filter by name in Python
        query_string = """
        (method_declaration name: (identifier) @name) @method
        (constructor_declaration name: (identifier) @name) @method
        """
        query = Query(JAVA_LANGUAGE, query_string)
        cursor = QueryCursor(query)
        captures = cursor.captures(tree.root_node)

        # Build a map from method node id -> node, and name node id -> name text
        method_nodes = {}  # node_id -> node
        name_for_method = {}  # method node_id -> name text

        # captures is dict: tag -> [nodes]
        method_list = captures.get("method", [])
        name_list = captures.get("name", [])

        for node in method_list:
            method_nodes[node.id] = node
        # Each name node is a direct child of a method node; match by parent id
        for name_node in name_list:
            parent = name_node.parent
            if parent and parent.id in method_nodes:
                name_for_method[parent.id] = source_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8', 'ignore')

        method_codes = []
        for node_id, node in method_nodes.items():
            if name_for_method.get(node_id) == method_name:
                code = source_bytes[node.start_byte:node.end_byte].decode('utf-8', 'ignore')
                method_codes.append(code)

        if not method_codes:
            return f"❓ 在该文件中未找到名为 '{method_name}' 的方法。"

        separator = "\n" + "=" * 40 + "\n"
        return separator.join(method_codes)
    except Exception as e:
        return f"❌ 提取方法体失败: {str(e)}"


import xml.etree.ElementTree as ET


# ==========================================
# 工具 6：解析 AndroidManifest.xml 组件
# ==========================================
@mcp.tool()
def analyze_manifest(manifest_path: str) -> str:
    """
    解析 AndroidManifest.xml 文件，提取包名、权限以及导出的四大组件。
    用于识别应用的攻击面（导出组件、敏感权限等）。
    """
    if not os.path.exists(manifest_path):
        return f"❌ 找不到 Manifest 文件: {manifest_path}"

    try:
        # 自动处理 Android XML 命名空间
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        package_name = root.attrib.get('package', 'Unknown')
        results = [f"📦 Package: {package_name}", "=" * 40]

        # 1. 提取权限
        permissions = [p.attrib.get('{http://schemas.android.com/apk/res/android}name')
                       for p in root.findall('uses-permission', ns)]
        if permissions:
            results.append(f"🔐 声明权限 ({len(permissions)} 个):")
            results.extend([f"  - {p}" for p in permissions[:10]])  # 仅列出前10个
            if len(permissions) > 10: results.append("  ... (略)")
            results.append("")

        # 2. 提取四大组件
        components = {
            "activity": "🚩 Activities",
            "service": "⚙️ Services",
            "receiver": "📡 Receivers",
            "provider": "📂 Providers"
        }

        application = root.find('application')
        if application is not None:
            for tag, label in components.items():
                found_elements = application.findall(tag, ns)
                if not found_elements:
                    continue

                results.append(f"{label}:")
                for elem in found_elements:
                    name = elem.attrib.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                    exported = elem.attrib.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                    permission = elem.attrib.get('{http://schemas.android.com/apk/res/android}permission', 'None')

                    # 标记关键风险点：已导出且无权限保护
                    risk_tag = " [!] EXPORTED" if exported.lower() == "true" else ""
                    results.append(f"  - {name}")
                    results.append(f"    Exported: {exported}{risk_tag} | Permission: {permission}")

                    # 检查 Intent-Filter
                    filters = elem.findall('intent-filter', ns)
                    if filters:
                        actions = []
                        for f in filters:
                            for action in f.findall('action', ns):
                                actions.append(
                                    action.attrib.get('{http://schemas.android.com/apk/res/android}name').split('.')[
                                        -1])
                        results.append(f"    Actions: {', '.join(actions)}")
                results.append("")

        return "\n".join(results)
    except Exception as e:
        return f"❌ 解析 Manifest 失败: {str(e)}"


# ==========================================
# 工具 7：硬编码敏感信息扫描 (Secrets Scanner)
# ==========================================
@mcp.tool()
def find_hardcoded_secrets(directory_path: str) -> str:
    """
    扫描源码中硬编码的敏感信息，如 IP 地址、API 密钥、Token 以及可疑的加密 Key。
    """
    if not os.path.exists(directory_path):
        return "❌ 目录不存在"

    patterns = {
        "IPv4_Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "API_Key/Token": r"(?i)(?:key|secret|token|auth|password|passwd)[\s:=]+['\"]([a-zA-Z0-9_\-]{16,})['\"]",
        "Common_Internal_URL": r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[1-2]))[\w\.-]+",
        "Crypto_Key_Candidate": r"(?i)(?:aes|des|rsa|key)[\s:=]+['\"]([a-zA-Z0-9+/=]{16,})['\"]"
    }

    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith(('.java', '.xml', '.properties', '.json')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for label, p in patterns.items():
                            matches = re.finditer(p, content)
                            for m in matches:
                                line_no = content.count('\n', 0, m.start()) + 1
                                rel_path = os.path.relpath(file_path, directory_path)
                                results.append(f"🚩 [{label}] 发现于 {rel_path}:{line_no} -> {m.group(0)[:50]}")
                except:
                    continue

    return "\n".join(results) if results else "✅ 未发现明显的硬编码敏感信息。"


# ==========================================
# 工具 8：敏感 API 使用情况审计 (Risk API Audit)
# ==========================================
@mcp.tool()
def audit_sensitive_apis(directory_path: str) -> str:
    """
    审计源码中调用的 Android 敏感 API，识别涉及隐私权限的操作。
    """
    # Use raw strings to avoid escape issues; patterns are proper regex
    risk_map = {
        r"getDeviceId|getImei|getMeid": "设备标识符获取 (IMEI/MEID)",
        r"getLastKnownLocation|requestLocationUpdates": "地理位置追踪",
        r"sendTextMessage|getAllMessagesFromSim": "短信/通讯录操作",
        r"\.exec\s*\(": "执行系统命令 (可能的 RCE 风险)",
        r"loadLibrary|System\.load\s*\(": "动态加载 Native 库",
        r"getDisplayOriginatingAddress": "获取短信发送方号码"
    }

    if not os.path.exists(directory_path):
        return f"❌ 目录不存在: {directory_path}"

    results = []
    for pattern, desc in risk_map.items():
        found = search_code(directory_path, pattern, is_regex=True, max_results=5)
        # search_code returns "未找到 '...' 的匹配项。" when nothing is found
        # and "Error: ..." when something goes wrong — skip both
        if found and not found.startswith("未找到") and not found.startswith("Error"):
            results.append(f"⚠️ 风险类别: {desc}\n{found}\n")

    return "\n---\n".join(results) if results else "✅ 未检测到高风险系统 API 的直接调用。"


# ==========================================
# 工具 9：方法内调用链分析 (修正版)
# ==========================================
@mcp.tool()
def get_method_callees(file_path: str, method_name: str) -> str:
    """分析一个方法内部调用的所有其他方法。"""
    if not os.path.exists(file_path):
        return "❌ 文件不存在"

    try:
        with open(file_path, 'rb') as f:
            source_bytes = f.read()

        tree = parser.parse(source_bytes)

        # Query all method/constructor declarations, filter by name in Python
        query_string = """
        (method_declaration name: (identifier) @name) @method
        (constructor_declaration name: (identifier) @name) @method
        """
        method_query = Query(JAVA_LANGUAGE, query_string)
        cursor = QueryCursor(method_query)
        captures = cursor.captures(tree.root_node)

        method_list = captures.get("method", [])
        name_list = captures.get("name", [])

        # Map method node id -> name text
        method_nodes = {node.id: node for node in method_list}
        name_for_method = {}
        for name_node in name_list:
            parent = name_node.parent
            if parent and parent.id in method_nodes:
                name_for_method[parent.id] = source_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8', 'ignore')

        target_body = None
        for node_id, node in method_nodes.items():
            if name_for_method.get(node_id) == method_name:
                # Find the body (block) child
                for child in node.children:
                    if child.type == 'block':
                        target_body = child
                        break
            if target_body:
                break

        if not target_body:
            return f"❓ 未找到方法 '{method_name}' 的实现体。"

        # 步骤 2：在方法体内寻找调用
        call_query = Query(JAVA_LANGUAGE, "(method_invocation name: (identifier) @call_name)")
        call_cursor = QueryCursor(call_query)
        call_captures = call_cursor.captures(target_body)

        calls = sorted(set(
            source_bytes[n.start_byte:n.end_byte].decode('utf-8', 'ignore')
            for n in call_captures.get("call_name", [])
        ))

        return f"🔍 方法 '{method_name}' 内部调用了:\n" + "\n".join([f"  -> {c}" for c in calls])
    except Exception as e:
        return f"❌ 分析调用链失败: {str(e)}"

if __name__ == "__main__":
    mcp.run()