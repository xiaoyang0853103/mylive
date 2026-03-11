#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TVBox 接口自动解密工具
支持：Base64、AES、URL参数提取、JSON解析
自动识别加密类型，无需手动指定
"""

import base64
import json
import re
import os
import sys
import time
from datetime import datetime
from urllib.parse import unquote, parse_qs, urlparse
import requests
import binascii

# 可选：如果安装了pycryptodome则支持AES解密
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️ 未安装 pycryptodome，AES解密功能不可用")


class TVBoxDecoder:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        self.results = []
        self.errors = []
    
    def fetch_content(self, url, retries=3):
        """获取URL内容，带重试机制"""
        for i in range(retries):
            try:
                print(f"  📥 正在获取: {url} (尝试 {i+1}/{retries})")
                response = self.session.get(url, timeout=30, allow_redirects=True)
                response.raise_for_status()
                
                # 尝试检测编码
                if response.encoding == 'ISO-8859-1':
                    response.encoding = response.apparent_encoding
                
                content = response.text
                print(f"  ✅ 获取成功，内容长度: {len(content)} 字符")
                return content
            except requests.exceptions.RequestException as e:
                print(f"  ❌ 获取失败: {e}")
                if i < retries - 1:
                    time.sleep(2 ** i)  # 指数退避
                else:
                    self.errors.append(f"{url}: {str(e)}")
                    return None
            except Exception as e:
                print(f"  ❌ 错误: {e}")
                self.errors.append(f"{url}: {str(e)}")
                return None
    
    def is_json(self, text):
        """检查是否为有效JSON"""
        try:
            json.loads(text)
            return True
        except:
            return False
    
    def is_base64(self, text):
        """检查是否为Base64编码"""
        # 清理文本
        text = text.strip()
        if not text:
            return False
        
        # 检查是否只包含Base64字符
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        if not base64_pattern.match(text):
            return False
        
        # 尝试解码
        try:
            # 填充检查
            padding = 4 - len(text) % 4
            if padding != 4:
                text += '=' * padding
            
            decoded = base64.b64decode(text)
            # 检查解码后是否为可读文本
            decoded_text = decoded.decode('utf-8')
            return len(decoded_text) > 0
        except:
            return False
    
    def try_base64_decode(self, text, depth=3):
        """尝试Base64解码（支持嵌套）"""
        results = []
        current = text.strip()
        
        for i in range(depth):
            if not self.is_base64(current):
                break
            
            try:
                # 处理填充
                padding = 4 - len(current) % 4
                if padding != 4:
                    current += '=' * padding
                
                decoded = base64.b64decode(current).decode('utf-8')
                results.append({
                    'layer': i + 1,
                    'content': decoded,
                    'is_json': self.is_json(decoded)
                })
                current = decoded
            except Exception as e:
                break
        
        return results
    
    def try_url_safe_base64(self, text):
        """尝试URL安全的Base64解码"""
        try:
            decoded = base64.urlsafe_b64decode(text + '=' * (4 - len(text) % 4))
            return decoded.decode('utf-8')
        except:
            return None
    
    def try_aes_decrypt(self, text):
        """尝试AES解密（常见密钥）"""
        if not CRYPTO_AVAILABLE:
            return []
        
        results = []
        # TVBox常见密钥列表
        common_keys = [
            b'1234567890123456',
            b'abcdefghijklmnop',
            b'0123456789abcdef',
            b'qwertyuiopasdfgh',
            b'16位自定义密钥..',
            b'your-secret-key0',
        ]
        
        # 尝试从文本中提取可能的密钥（如果有）
        key_pattern = re.search(r'key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,32})["\']', text)
        if key_pattern:
            possible_key = key_pattern.group(1).encode()
            if len(possible_key) in [16, 24, 32]:
                common_keys.insert(0, possible_key)
        
        for key in common_keys:
            if len(key) not in [16, 24, 32]:
                continue
            
            # ECB模式
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(base64.b64decode(text)), AES.block_size)
                result = decrypted.decode('utf-8')
                if self.is_valid_content(result):
                    results.append({'mode': 'AES-ECB', 'key': key.decode(), 'content': result})
            except:
                pass
            
            # CBC模式（常见IV）
            for iv in [key, b'\x00' * 16, key[:16]]:
                try:
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = unpad(cipher.decrypt(base64.b64decode(text)), AES.block_size)
                    result = decrypted.decode('utf-8')
                    if self.is_valid_content(result):
                        results.append({'mode': 'AES-CBC', 'key': key.decode(), 'iv': iv[:8].hex(), 'content': result})
                except:
                    pass
        
        return results
    
    def is_valid_content(self, text):
        """检查解密后的内容是否有效"""
        if not text or len(text) < 10:
            return False
        
        # 检查是否为可打印字符
        printable_ratio = sum(c.isprintable() or c.isspace() for c in text) / len(text)
        return printable_ratio > 0.9
    
    def extract_json_content(self, text):
        """提取和格式化JSON内容"""
        try:
            data = json.loads(text)
            
            # 如果是TVBox标准格式，提取关键信息
            if isinstance(data, dict):
                summary = []
                
                if 'sites' in data and isinstance(data['sites'], list):
                    summary.append(f"站点数: {len(data['sites'])}")
                if 'lives' in data and isinstance(data['lives'], list):
                    summary.append(f"直播源: {len(data['lives'])}")
                if 'parses' in data and isinstance(data['parses'], list):
                    summary.append(f"解析接口: {len(data['parses'])}")
                if 'spider' in data:
                    spider = data['spider']
                    if isinstance(spider, str) and len(spider) > 100:
                        summary.append(f"Spider: {spider[:50]}...")
                    else:
                        summary.append(f"Spider: {spider}")
                
                return {
                    'type': 'tvbox',
                    'summary': ' | '.join(summary) if summary else '标准JSON',
                    'content': json.dumps(data, ensure_ascii=False, indent=2)
                }
            
            return {
                'type': 'json',
                'summary': f"JSON对象 ({len(str(data))} 字符)",
                'content': json.dumps(data, ensure_ascii=False, indent=2)
            }
            
        except:
            return None
    
    def process_url(self, url):
        """处理单个URL"""
        print(f"\n{'='*70}")
        print(f"🔍 处理: {url}")
        print(f"{'='*70}")
        
        content = self.fetch_content(url)
        if not content:
            return None
        
        result = {
            'url': url,
            'original_length': len(content),
            'decrypted': False,
            'methods': [],
            'final_content': content,
            'timestamp': datetime.now().isoformat()
        }
        
        # 1. 检查是否已经是明文JSON
        if self.is_json(content):
            print("  ℹ️  内容已是明文JSON，无需解密")
            json_info = self.extract_json_content(content)
            if json_info:
                result['methods'].append({
                    'type': 'plaintext',
                    'description': '明文JSON',
                    'info': json_info['summary']
                })
                result['final_content'] = json_info['content']
                result['decrypted'] = True
                self.results.append(result)
                return result
        
        # 2. 尝试Base64解码
        print("  🔓 尝试Base64解码...")
        b64_results = self.try_base64_decode(content)
        
        if b64_results:
            best_result = None
            for r in b64_results:
                print(f"    ✓ Base64第{r['layer']}层解码成功 (JSON: {r['is_json']})")
                
                if r['is_json']:
                    json_info = self.extract_json_content(r['content'])
                    if json_info:
                        result['methods'].append({
                            'type': 'base64',
                            'layers': r['layer'],
                            'description': f'Base64({r["layer"]}层) -> JSON',
                            'info': json_info['summary']
                        })
                        result['final_content'] = json_info['content']
                        result['decrypted'] = True
                        best_result = r['content']
                        break
            
            # 如果没有找到JSON，使用最后一层解码结果
            if not result['decrypted'] and b64_results:
                last = b64_results[-1]
                result['methods'].append({
                    'type': 'base64',
                    'layers': last['layer'],
                    'description': f'Base64({last["layer"]}层)',
                    'info': f'文本长度: {len(last["content"])}'
                })
                result['final_content'] = last['content']
                result['decrypted'] = True
        
        # 3. 尝试URL安全Base64
        if not result['decrypted']:
            urlsafe_result = self.try_url_safe_base64(content)
            if urlsafe_result and self.is_valid_content(urlsafe_result):
                print("  ✓ URL安全Base64解码成功")
                is_json = self.is_json(urlsafe_result)
                result['methods'].append({
                    'type': 'base64url',
                    'description': 'URL安全Base64',
                    'info': f'JSON: {is_json}'
                })
                if is_json:
                    json_info = self.extract_json_content(urlsafe_result)
                    result['final_content'] = json_info['content'] if json_info else urlsafe_result
                else:
                    result['final_content'] = urlsafe_result
                result['decrypted'] = True
        
        # 4. 尝试AES解密
        if not result['decrypted'] and CRYPTO_AVAILABLE:
            print("  🔓 尝试AES解密...")
            aes_results = self.try_aes_decrypt(content)
            if aes_results:
                best = aes_results[0]
                print(f"    ✓ AES解密成功 ({best['mode']})")
                result['methods'].append({
                    'type': 'aes',
                    'mode': best['mode'],
                    'key': best['key'],
                    'description': f"AES-{best['mode']}",
                    'info': f'密钥: {best["key"][:8]}...'
                })
                if self.is_json(best['content']):
                    json_info = self.extract_json_content(best['content'])
                    result['final_content'] = json_info['content'] if json_info else best['content']
                else:
                    result['final_content'] = best['content']
                result['decrypted'] = True
        
        # 5. 如果都失败，保留原始内容
        if not result['decrypted']:
            print("  ⚠️  未能自动解密，保留原始内容")
            result['methods'].append({
                'type': 'unknown',
                'description': '未识别加密方式',
                'info': '保留原始数据'
            })
        
        self.results.append(result)
        return result
    
    def process_url_list(self, file_path='url.txt'):
        """处理URL列表文件"""
        if not os.path.exists(file_path):
            print(f"❌ 文件不存在: {file_path}")
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"\n📋 从 {file_path} 读取到 {len(urls)} 个URL")
        print(f"⏰ 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        for url in urls:
            self.process_url(url)
            time.sleep(1)  # 礼貌性延迟
        
        return True
    
    def generate_live_txt(self, output_file='live.txt'):
        """生成live.txt文件"""
        print(f"\n{'='*70}")
        print(f"📝 正在生成 {output_file}...")
        print(f"{'='*70}")
        
        lines = []
        lines.append(f"# TVBox 接口解密结果")
        lines.append(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"# 总计处理: {len(self.results)} 个URL")
        lines.append(f"# 成功解密: {sum(1 for r in self.results if r['decrypted'])} 个")
        lines.append(f"# {'='*70}")
        lines.append("")
        
        for i, result in enumerate(self.results, 1):
            lines.append(f"# {'='*70}")
            lines.append(f"# 源地址 {i}: {result['url']}")
            lines.append(f"# 解密方法: {', '.join(m['description'] for m in result['methods'])}")
            lines.append(f"# 处理时间: {result['timestamp']}")
            lines.append(f"# {'='*70}")
            lines.append("")
            
            # 添加解密后的内容
            content = result['final_content']
            if isinstance(content, str):
                lines.append(content)
            else:
                lines.append(json.dumps(content, ensure_ascii=False, indent=2))
            
            lines.append("")
            lines.append("")
        
        # 添加错误日志
        if self.errors:
            lines.append(f"# {'='*70}")
            lines.append(f"# 错误日志:")
            lines.append(f"# {'='*70}")
            for error in self.errors:
                lines.append(f"# ERROR: {error}")
        
        final_content = '\n'.join(lines)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(final_content)
        
        print(f"✅ 已保存到: {output_file}")
        print(f"📊 文件大小: {len(final_content)} 字符")
        
        # 同时生成一个JSON格式的详细报告
        report_file = output_file.replace('.txt', '_report.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total': len(self.results),
                'success': sum(1 for r in self.results if r['decrypted']),
                'failed': len(self.errors),
                'results': self.results,
                'errors': self.errors
            }, f, ensure_ascii=False, indent=2)
        
        print(f"📊 详细报告已保存到: {report_file}")
        
        return output_file


def main():
    decoder = TVBoxDecoder()
    
    # 处理url.txt
    if decoder.process_url_list('url.txt'):
        # 生成live.txt
        decoder.generate_live_txt('live.txt')
        
        # 打印统计
        print(f"\n{'='*70}")
        print("📈 处理统计:")
        print(f"{'='*70}")
        print(f"  总计URL: {len(decoder.results)}")
        print(f"  成功解密: {sum(1 for r in decoder.results if r['decrypted'])}")
        print(f"  失败/跳过: {len(decoder.errors)}")
        print(f"{'='*70}")
    else:
        print("❌ 处理失败")
        sys.exit(1)


if __name__ == "__main__":
    main()
