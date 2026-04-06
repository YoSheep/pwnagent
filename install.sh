#!/usr/bin/env bash
# PwnAgent 一键安装脚本
# 安装 Python 依赖 + 可选的外部二进制工具

set -e
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

echo -e "${BOLD}"
echo "██████╗ ██╗    ██╗███╗   ██╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗"
echo "██╔══██╗██║    ██║████╗  ██║██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝"
echo "██████╔╝██║ █╗ ██║██╔██╗ ██║███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   "
echo "██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   "
echo "██║     ╚███╔███╔╝██║ ╚████║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   "
echo "╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝  "
echo -e "${NC}"
echo -e "${BOLD}PwnAgent 安装程序${NC}"
echo "=================================================="

# ------------------------------------------------------------------
# 检测 Python 版本
# ------------------------------------------------------------------
info "检查 Python 版本..."
if ! command -v python3 &>/dev/null; then
    error "未找到 Python 3，请先安装 Python 3.11+"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo $PY_VER | cut -d. -f1)
PY_MINOR=$(echo $PY_VER | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]); then
    error "需要 Python 3.11+，当前版本: $PY_VER"
    exit 1
fi
success "Python $PY_VER ✓"

# ------------------------------------------------------------------
# 安装 Python 依赖
# ------------------------------------------------------------------
info "安装 Python 依赖..."
pip install -q \
    anthropic \
    openai \
    "mcp[cli]" \
    rich \
    typer \
    chromadb \
    httpx \
    jinja2 \
    pyyaml \
    python-dotenv \
    pydantic \
    sqlalchemy \
    python-nmap

success "Python 依赖安装完成 ✓"

# ------------------------------------------------------------------
# Playwright（可选）
# ------------------------------------------------------------------
echo ""
read -r -p "$(echo -e ${YELLOW}安装 Playwright（用于 DOM XSS 检测，需要约 200MB）？[y/N] ${NC})" install_playwright
if [[ "$install_playwright" =~ ^[Yy]$ ]]; then
    info "安装 Playwright..."
    pip install -q playwright
    python3 -m playwright install chromium
    success "Playwright 安装完成 ✓"
else
    warn "跳过 Playwright，DOM XSS 检测将不可用"
fi

# ------------------------------------------------------------------
# nmap（可选）
# ------------------------------------------------------------------
echo ""
if command -v nmap &>/dev/null; then
    success "nmap 已安装 ✓ ($(nmap --version | head -1))"
else
    warn "nmap 未安装，将使用纯 Python 端口扫描器（速度较慢）"
    read -r -p "$(echo -e ${YELLOW}尝试自动安装 nmap？[y/N] ${NC})" install_nmap
    if [[ "$install_nmap" =~ ^[Yy]$ ]]; then
        if command -v brew &>/dev/null; then
            brew install nmap
        elif command -v apt-get &>/dev/null; then
            sudo apt-get install -y nmap
        elif command -v yum &>/dev/null; then
            sudo yum install -y nmap
        else
            warn "无法自动安装，请手动安装 nmap"
        fi
    fi
fi

# ------------------------------------------------------------------
# Go 工具（可选）
# ------------------------------------------------------------------
echo ""
if command -v go &>/dev/null; then
    GO_VER=$(go version | awk '{print $3}')
    success "Go 已安装 ($GO_VER)，可安装 ProjectDiscovery 工具"

    read -r -p "$(echo -e ${YELLOW}安装 nuclei（漏洞扫描）？[y/N] ${NC})" install_nuclei
    if [[ "$install_nuclei" =~ ^[Yy]$ ]]; then
        info "安装 nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        success "nuclei 安装完成 ✓"
    fi

    read -r -p "$(echo -e ${YELLOW}安装 httpx（Web 探测）？[y/N] ${NC})" install_httpx
    if [[ "$install_httpx" =~ ^[Yy]$ ]]; then
        info "安装 httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        success "httpx 安装完成 ✓"
    fi
else
    warn "Go 未安装，跳过 nuclei/httpx（将使用纯 Python 实现）"
fi

# ------------------------------------------------------------------
# sqlmap（可选）
# ------------------------------------------------------------------
echo ""
if command -v sqlmap &>/dev/null; then
    success "sqlmap 已安装 ✓"
else
    read -r -p "$(echo -e ${YELLOW}安装 sqlmap（SQL 注入深度扫描）？[y/N] ${NC})" install_sqlmap
    if [[ "$install_sqlmap" =~ ^[Yy]$ ]]; then
        pip install -q sqlmap
        success "sqlmap 安装完成 ✓"
    fi
fi

# ------------------------------------------------------------------
# 初始化知识库（OWASP Top 10）
# ------------------------------------------------------------------
echo ""
info "初始化知识库（导入 OWASP Top 10）..."
python3 -c "
import sys
sys.path.insert(0, '.')
from knowledge.ingest import ingest_owasp_top10
ingest_owasp_top10()
" && success "知识库初始化完成 ✓" || warn "知识库初始化失败，可稍后手动运行: python3 knowledge/ingest.py"

# ------------------------------------------------------------------
# 生成 Claude Code MCP 配置
# ------------------------------------------------------------------
echo ""
info "生成 Claude Code MCP 配置..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_CONFIG_DIR="$HOME/.claude"
MCP_CONFIG_FILE="$MCP_CONFIG_DIR/settings.json"

mkdir -p "$MCP_CONFIG_DIR"

# 读取现有配置（若存在）
if [ -f "$MCP_CONFIG_FILE" ]; then
    warn "检测到已有 Claude Code 配置: $MCP_CONFIG_FILE"
    warn "请手动添加以下内容到 mcpServers 节点："
    echo ""
    echo -e "${BOLD}--- 复制以下内容 ---${NC}"
cat << EOF
"pwnagent": {
  "command": "python3",
  "args": ["$SCRIPT_DIR/mcp_server.py"]
}
EOF
    echo -e "${BOLD}-------------------${NC}"
else
    # 创建新配置
    cat > "$MCP_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "pwnagent": {
      "command": "python3",
      "args": ["$SCRIPT_DIR/mcp_server.py"]
    }
  }
}
EOF
    success "Claude Code MCP 配置已写入: $MCP_CONFIG_FILE ✓"
fi

# ------------------------------------------------------------------
# 完成
# ------------------------------------------------------------------
echo ""
echo "=================================================="
success "PwnAgent 安装完成！"
echo ""
echo -e "${BOLD}快速启动：${NC}"
echo "  python3 main.py scan http://TARGET"
echo "  然后按需编辑 config.yaml 的 llm.provider，或在 .env / 环境变量里填写 API key"
echo ""
echo -e "${BOLD}MCP Server 独立启动：${NC}"
echo "  python3 mcp_server.py"
echo ""
echo -e "${BOLD}在 Claude Code 中使用（配置好 MCP 后）：${NC}"
echo "  使用 nmap_scan、httpx_probe、nuclei_scan 等工具直接对授权目标测试"
echo ""
echo -e "${RED}${BOLD}提醒：仅限对已获得书面授权的目标使用！${NC}"
