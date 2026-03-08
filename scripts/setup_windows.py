"""
Windows Setup Script
- Sets system-wide proxy so ALL apps route through PII proxy
- Works for: curl, browsers, Copilot, VS Code, Python, Node.js
Run as: python setup_windows.py [enable|disable|status]
"""

import sys
import subprocess
import winreg
import os
import ctypes

PROXY_HOST = "127.0.0.1"
PROXY_PORT = "8080"
PROXY_URL  = f"http://{PROXY_HOST}:{PROXY_PORT}"

# LLM domains to intercept
BYPASS_NONE = ""  # Set to "" to intercept everything
                  # Or e.g. "<local>;*.internal.com" to bypass internal

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def set_system_proxy(enable: bool):
    """Set or unset Windows system proxy via registry"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)

        if enable:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{PROXY_HOST}:{PROXY_PORT}")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, BYPASS_NONE)
            print(f"✅ System proxy ENABLED → {PROXY_URL}")
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
            print("✅ System proxy DISABLED")

        winreg.CloseKey(key)

        # Notify Windows of proxy change
        import ctypes
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)

    except Exception as e:
        print(f"❌ Registry error: {e}")
        print("   Try running as Administrator")


def set_env_variables(enable: bool):
    """Set environment variables for tools that use them"""
    vars_to_set = {
        "HTTP_PROXY":  PROXY_URL if enable else "",
        "HTTPS_PROXY": PROXY_URL if enable else "",
        "http_proxy":  PROXY_URL if enable else "",
        "https_proxy": PROXY_URL if enable else "",
        # Tell Python requests / httpx to use proxy
        "REQUESTS_CA_BUNDLE": "",
        "CURL_CA_BUNDLE": "",
    }

    for var, val in vars_to_set.items():
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                "Environment",
                0, winreg.KEY_SET_VALUE
            )
            if val:
                winreg.SetValueEx(key, var, 0, winreg.REG_EXPAND_SZ, val)
            else:
                try:
                    winreg.DeleteValue(key, var)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
        except Exception as e:
            print(f"  Warning: Could not set {var}: {e}")

    # Apply to current session too
    for var, val in vars_to_set.items():
        os.environ[var] = val

    if enable:
        print(f"✅ Environment variables set: HTTP_PROXY / HTTPS_PROXY → {PROXY_URL}")
    else:
        print("✅ Environment variables cleared")


def get_status():
    """Show current proxy status"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS)
        enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        server, _  = winreg.QueryValueEx(key, "ProxyServer")
        winreg.CloseKey(key)

        if enabled:
            print(f"🟢 System Proxy: ENABLED → {server}")
        else:
            print(f"🔴 System Proxy: DISABLED")

        # Check env vars
        http  = os.environ.get("HTTP_PROXY", "not set")
        https = os.environ.get("HTTPS_PROXY", "not set")
        print(f"   HTTP_PROXY  = {http}")
        print(f"   HTTPS_PROXY = {https}")

    except Exception as e:
        print(f"Could not read proxy settings: {e}")


def install_dependencies():
    """Install all required Python packages"""
    packages = [
        "fastapi",
        "uvicorn",
        "httpx",
        "presidio-analyzer",
        "presidio-anonymizer",
        "spacy",
    ]
    print("📦 Installing dependencies...")
    for pkg in packages:
        subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"])

    # Download spacy model for Presidio
    print("📦 Downloading spaCy English model...")
    subprocess.run([sys.executable, "-m", "spacy", "download", "en_core_web_lg"])
    print("✅ All dependencies installed!")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "status"

    print("\n" + "="*55)
    print("  🛡️  PII PROXY — Windows Setup")
    print("="*55)

    if action == "enable":
        set_system_proxy(True)
        set_env_variables(True)
        print("\n📌 Restart your terminal/apps to apply env variables")
        print("📌 Start proxy with: python proxy_server.py")

    elif action == "disable":
        set_system_proxy(False)
        set_env_variables(False)

    elif action == "install":
        install_dependencies()

    else:
        get_status()

    print("="*55 + "\n")
