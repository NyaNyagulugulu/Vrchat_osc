#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VRChat OSC 硬件监控工具
实时采集CPU、内存、磁盘等硬件信息并通过OSC发送到VRChat
"""

import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import time
import threading
import socket
import struct
from collections import deque
import math


class OSCMessage:
    """OSC消息封装类"""
    
    def __init__(self, address, value):
        self.address = address
        self.value = value
    
    def to_bytes(self):
        """将OSC消息转换为字节格式"""
        address_bytes = self.address.encode('utf-8')
        # OSC地址需要4字节对齐
        address_bytes += b'\x00' * ((4 - len(address_bytes) % 4) % 4)
        
        # 类型标签
        if isinstance(self.value, float):
            type_tag = b',f\x00'
            value_bytes = struct.pack('>f', self.value)
        elif isinstance(self.value, int):
            type_tag = b',i\x00'
            value_bytes = struct.pack('>i', self.value)
        elif isinstance(self.value, bool):
            type_tag = b',T\x00' if self.value else b',F\x00'
            value_bytes = b''
        else:
            type_tag = b',s\x00'
            value_bytes = str(self.value).encode('utf-8')
            value_bytes += b'\x00' * ((4 - len(value_bytes) % 4) % 4)
        
        return address_bytes + type_tag + value_bytes


class OSCSender:
    """OSC发送器"""
    
    def __init__(self, host='127.0.0.1', port=9000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def send(self, address, value):
        """发送OSC消息"""
        try:
            message = OSCMessage(address, value)
            self.socket.sendto(message.to_bytes(), (self.host, self.port))
        except Exception as e:
            print(f"发送OSC消息失败: {e}")
    
    def send_chatbox(self, message):
        """发送消息到VRChat聊天框
        
        Args:
            message: 要发送的消息文本
        """
        try:
            # VRChat聊天框OSC地址
            # 使用正确的OSC协议发送消息
            # 直接发送消息，不触发虚拟键盘，不设置正在输入状态
            message_bytes = message.encode('utf-8')
            
            # 构建OSC消息：地址 + 类型标签 + 消息内容 + 是否立即发送
            address = "/chatbox/input"
            address_bytes = address.encode('utf-8')
            address_bytes += b'\x00' * ((4 - len(address_bytes) % 4) % 4)
            
            # 类型标签：两个参数，字符串和布尔值（True表示立即发送）
            type_tag = b',sT\x00'
            
            # 消息内容（字符串）
            value_bytes = message_bytes
            value_bytes += b'\x00' * ((4 - len(value_bytes) % 4) % 4)
            
            # 组合OSC消息
            osc_message = address_bytes + type_tag + value_bytes
            
            # 发送消息
            self.socket.sendto(osc_message, (self.host, self.port))
            
        except Exception as e:
            print(f"发送聊天框消息失败: {e}")
    
    def close(self):
        """关闭socket"""
        self.socket.close()


class HardwareMonitor:
    """硬件监控类"""
    
    def __init__(self):
        self.cpu_history = deque(maxlen=60)
        self.memory_history = deque(maxlen=60)
        self.prev_cpu_times = None
        self.prev_time = None
    
    def get_cpu_usage(self):
        """
        获取CPU使用率（支持多核CPU）
        返回所有核心的总使用率百分比（例如16核系统最大为1600%）
        """
        try:
            # 获取CPU核心数
            cpu_count = psutil.cpu_count(logical=True)
            
            with open('/proc/stat', 'r') as f:
                lines = f.readlines()
            
            cpu_line = lines[0].strip()
            parts = cpu_line.split()
            
            # 获取各时间值
            user = int(parts[1])
            nice = int(parts[2])
            system = int(parts[3])
            idle = int(parts[4])
            iowait = int(parts[5])
            irq = int(parts[6])
            softirq = int(parts[7])
            steal = int(parts[8]) if len(parts) > 8 else 0
            
            current_time = time.time()
            
            if self.prev_cpu_times is None:
                self.prev_cpu_times = (user, nice, system, idle, iowait, irq, softirq, steal)
                self.prev_time = current_time
                return 0.0
            
            prev_user, prev_nice, prev_system, prev_idle, prev_iowait, prev_irq, prev_softirq, prev_steal = self.prev_cpu_times
            time_delta = current_time - self.prev_time
            
            if time_delta == 0:
                return 0.0
            
            # 计算差值
            user_delta = user - prev_user
            nice_delta = nice - prev_nice
            system_delta = system - prev_system
            idle_delta = idle - prev_idle
            iowait_delta = iowait - prev_iowait
            irq_delta = irq - prev_irq
            softirq_delta = softirq - prev_softirq
            steal_delta = steal - prev_steal
            
            # 计算总时间（所有状态的总和）
            total_delta = (user_delta + nice_delta + system_delta + 
                          idle_delta + iowait_delta + irq_delta + 
                          softirq_delta + steal_delta)
            
            if total_delta == 0:
                return 0.0
            
            # 计算使用率：非空闲时间的比例（0-100）
            busy_delta = total_delta - idle_delta - iowait_delta
            cpu_usage = (busy_delta / total_delta) * 100
            
            # 乘以核心数，得到所有核心的总使用率
            total_cpu_usage = cpu_usage * cpu_count
            
            # 更新历史记录
            self.cpu_history.append(total_cpu_usage)
            self.prev_cpu_times = (user, nice, system, idle, iowait, irq, softirq, steal)
            self.prev_time = current_time
            
            return round(total_cpu_usage, 2)
        
        except Exception as e:
            print(f"获取CPU使用率失败: {e}")
            return 0.0
    
    def get_memory_usage(self):
        """获取内存使用率"""
        try:
            mem = psutil.virtual_memory()
            usage = mem.percent
            self.memory_history.append(usage)
            return {
                'percent': round(usage, 2),
                'used_gb': round(mem.used / (1024**3), 2),
                'total_gb': round(mem.total / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2)
            }
        except Exception as e:
            print(f"获取内存使用率失败: {e}")
            return {'percent': 0, 'used_gb': 0, 'total_gb': 0, 'available_gb': 0}
    
    def get_disk_usage(self):
        """获取磁盘使用率"""
        try:
            disk = psutil.disk_usage('/')
            return {
                'percent': round(disk.percent, 2),
                'used_gb': round(disk.used / (1024**3), 2),
                'total_gb': round(disk.total / (1024**3), 2),
                'free_gb': round(disk.free / (1024**3), 2)
            }
        except Exception as e:
            print(f"获取磁盘使用率失败: {e}")
            return {'percent': 0, 'used_gb': 0, 'total_gb': 0, 'free_gb': 0}
    
    def get_network_stats(self):
        """获取网络统计"""
        try:
            net = psutil.net_io_counters()
            return {
                'bytes_sent': round(net.bytes_sent / (1024**2), 2),  # MB
                'bytes_recv': round(net.bytes_recv / (1024**2), 2),  # MB
                'packets_sent': net.packets_sent,
                'packets_recv': net.packets_recv
            }
        except Exception as e:
            print(f"获取网络统计失败: {e}")
            return {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0}
    
    def get_cpu_temp(self):
        """获取CPU温度（如果可用）"""
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                # 尝试获取CPU温度
                for name, entries in temps.items():
                    if 'core' in name.lower() or 'cpu' in name.lower():
                        if entries:
                            return round(entries[0].current, 1)
            return 0.0
        except Exception as e:
            return 0.0
    
    def get_cpu_model(self):
        """获取CPU型号"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        # 提取型号名称（冒号后面的部分）
                        model = line.split(':', 1)[1].strip()
                        return model
            return "Unknown CPU"
        except Exception as e:
            return "Unknown CPU"
    
    def simplify_cpu_model(self, model):
        """简化CPU型号显示"""
        import re
        # Intel CPU简化
        if 'Intel' in model:
            # 提取 i3/i5/i7/i9 和后面的数字（包含K/KF等后缀）
            match = re.search(r'i[3579][-\s]*(\d+[A-Z]*)', model)
            if match:
                return f"i{match.group(1)}"
        # AMD CPU简化
        elif 'AMD' in model:
            # 提取 Ryzen 和数字
            match = re.search(r'Ryzen\s*\d+\s*\d+[A-Z]*', model)
            if match:
                return match.group(0).replace(' ', '')
        # 如果无法提取，返回前15个字符
        return model[:15]
    
    def simplify_gpu_model(self, model):
        """简化GPU型号显示"""
        import re
        # NVIDIA GPU简化
        if 'NVIDIA' in model or 'RTX' in model or 'GTX' in model:
            # 提取 RTX/GTX 和数字
            match = re.search(r'(RTX|GTX)\s*\d+[A-Z]*', model)
            if match:
                return match.group(0).replace(' ', '')
        # AMD GPU简化
        elif 'AMD' in model or 'RX' in model:
            match = re.search(r'RX\s*\d+[A-Z]*', model)
            if match:
                return match.group(0).replace(' ', '')
        return model[:15]  # 截断到15个字符
    
    def get_gpu_usage(self):
        """获取GPU使用率"""
        try:
            import subprocess
            result = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu', '--format=csv,noheader,nounits'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                usage = float(result.stdout.strip())
                return round(usage, 1)
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass
        return 0.0
    
    def get_vram_usage(self):
        """获取VRAM使用率"""
        try:
            import subprocess
            # 获取VRAM使用情况和总量
            result = subprocess.run(['nvidia-smi', '--query-gpu=memory.used,memory.total', '--format=csv,noheader,nounits'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                parts = result.stdout.strip().split(',')
                used_mb = float(parts[0].strip())
                total_mb = float(parts[1].strip())
                percent = (used_mb / total_mb) * 100
                return {
                    'percent': round(percent, 1),
                    'used_gb': round(used_mb / 1024, 2),
                    'total_gb': round(total_mb / 1024, 2)
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
            pass
        return {'percent': 0, 'used_gb': 0, 'total_gb': 0}
    
    def get_gpu_model(self):
        """获取GPU型号"""
        try:
            import subprocess
            result = subprocess.run(['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                model = result.stdout.strip()
                return model
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "Unknown GPU"
    
    def get_gpu_temp(self):
        """获取GPU温度"""
        try:
            import subprocess
            result = subprocess.run(['nvidia-smi', '--query-gpu=temperature.gpu', '--format=csv,noheader,nounits'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                temp = float(result.stdout.strip())
                return round(temp, 1)
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass
        return 0.0


class VRChatOSCApp:
    """VRChat OSC应用程序主界面"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("VRChat OSC 硬件监控")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        self.monitor = HardwareMonitor()
        self.osc_sender = None
        self.is_running = False
        self.monitor_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """设置UI界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # OSC配置区域
        osc_frame = ttk.LabelFrame(main_frame, text="OSC 配置", padding="10")
        osc_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(osc_frame, text="主机地址:").grid(row=0, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(osc_frame, width=15)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, padx=(5, 10))
        
        ttk.Label(osc_frame, text="端口:").grid(row=0, column=2, sticky=tk.W)
        self.port_entry = ttk.Entry(osc_frame, width=10)
        self.port_entry.insert(0, "9000")
        self.port_entry.grid(row=0, column=3, padx=(5, 10))
        
        self.connect_btn = ttk.Button(osc_frame, text="连接", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=4, padx=(10, 0))
        
        self.status_label = ttk.Label(osc_frame, text="未连接", foreground="red")
        self.status_label.grid(row=0, column=5, padx=(10, 0))
        
        # 聊天框配置区域
        chatbox_frame = ttk.LabelFrame(main_frame, text="聊天框配置", padding="10")
        chatbox_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.enable_chatbox = tk.BooleanVar(value=True)
        self.chatbox_check = ttk.Checkbutton(chatbox_frame, text="启用聊天框显示", variable=self.enable_chatbox)
        self.chatbox_check.grid(row=0, column=0, sticky=tk.W)
        
        ttk.Label(chatbox_frame, text="刷新间隔(秒):").grid(row=0, column=1, padx=(20, 5), sticky=tk.W)
        self.refresh_interval = ttk.Entry(chatbox_frame, width=8)
        self.refresh_interval.insert(0, "3")
        self.refresh_interval.grid(row=0, column=2, padx=(0, 10), sticky=tk.W)
        
        # 硬件信息显示区域
        info_frame = ttk.LabelFrame(main_frame, text="硬件信息", padding="10")
        info_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # CPU型号
        ttk.Label(info_frame, text="CPU 型号:").grid(row=0, column=0, sticky=tk.W)
        self.cpu_model_label = ttk.Label(info_frame, text="Unknown", font=('Arial', 10))
        self.cpu_model_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        # CPU信息
        ttk.Label(info_frame, text="CPU 使用率:").grid(row=1, column=0, sticky=tk.W)
        self.cpu_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 14, 'bold'))
        self.cpu_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        self.cpu_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.cpu_bar.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
        # 内存信息
        ttk.Label(info_frame, text="内存使用率:").grid(row=3, column=0, sticky=tk.W)
        self.memory_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 14, 'bold'))
        self.memory_label.grid(row=3, column=1, sticky=tk.W, padx=(10, 0))
        
        self.memory_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.memory_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
        # GPU型号
        ttk.Label(info_frame, text="GPU 型号:").grid(row=5, column=0, sticky=tk.W)
        self.gpu_model_label = ttk.Label(info_frame, text="Unknown", font=('Arial', 10))
        self.gpu_model_label.grid(row=5, column=1, sticky=tk.W, padx=(10, 0))
        
        # GPU信息
        ttk.Label(info_frame, text="GPU 使用率:").grid(row=6, column=0, sticky=tk.W)
        self.gpu_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 12, 'bold'))
        self.gpu_label.grid(row=6, column=1, sticky=tk.W, padx=(10, 0))
        
        self.gpu_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.gpu_bar.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
        # VRAM信息
        ttk.Label(info_frame, text="VRAM 使用率:").grid(row=8, column=0, sticky=tk.W)
        self.vram_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 12, 'bold'))
        self.vram_label.grid(row=8, column=1, sticky=tk.W, padx=(10, 0))
        
        self.vram_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.vram_bar.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
        # 详细信息
        detail_frame = ttk.LabelFrame(main_frame, text="详细信息", padding="10")
        detail_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self.detail_text = tk.Text(detail_frame, height=8, width=70, state='disabled')
        self.detail_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.detail_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.detail_text['yscrollcommand'] = scrollbar.set
        
        # OSC地址前缀设置
        prefix_frame = ttk.LabelFrame(main_frame, text="OSC 地址前缀", padding="10")
        prefix_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        ttk.Label(prefix_frame, text="/avatar/parameters/").grid(row=0, column=0, sticky=tk.W)
        self.prefix_entry = ttk.Entry(prefix_frame, width=20)
        self.prefix_entry.insert(0, "Hardware")
        self.prefix_entry.grid(row=0, column=1, padx=(5, 0))
        
        # 配置权重
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def toggle_connection(self):
        """切换OSC连接状态"""
        if self.is_running:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """开始监控"""
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            self.osc_sender = OSCSender(host, port)
            self.is_running = True
            self.connect_btn.config(text="断开")
            self.status_label.config(text="已连接", foreground="green")
            
            # 启动监控线程
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            # 启动UI更新
            self.update_ui()
            
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {e}")
    
    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False
        if self.osc_sender:
            self.osc_sender.close()
            self.osc_sender = None
        self.connect_btn.config(text="连接")
        self.status_label.config(text="未连接", foreground="red")
    
    def monitor_loop(self):
        """监控循环（在后台线程中运行）"""
        while self.is_running:
            self.update_hardware_info()
            time.sleep(1)
    
    def update_hardware_info(self):
        """更新硬件信息"""
        self.cpu_usage = self.monitor.get_cpu_usage()
        self.memory_info = self.monitor.get_memory_usage()
        self.gpu_usage = self.monitor.get_gpu_usage()
        self.vram_info = self.monitor.get_vram_usage()
        self.gpu_model = self.monitor.get_gpu_model()
        self.gpu_temp = self.monitor.get_gpu_temp()
        self.network_info = self.monitor.get_network_stats()
        self.cpu_temp = self.monitor.get_cpu_temp()
        self.cpu_model = self.monitor.get_cpu_model()
        
        # 发送OSC消息
        if self.osc_sender:
            # 发送到VRChat聊天框（根据刷新间隔）
            if self.enable_chatbox.get():
                try:
                    refresh_interval = int(self.refresh_interval.get())
                except ValueError:
                    refresh_interval = 3
                
                # 使用计数器控制聊天框刷新频率
                if not hasattr(self, '_chatbox_counter'):
                    self._chatbox_counter = 0
                
                self._chatbox_counter += 1
                if self._chatbox_counter >= refresh_interval:
                    self._chatbox_counter = 0
                    
                    # 获取CPU最大值
                    cpu_count = psutil.cpu_count(logical=True)
                    cpu_max = cpu_count * 100
                    
                    chatbox_message = f"CPU: {self.monitor.simplify_cpu_model(self.cpu_model)}\n"
                    chatbox_message += f"使用率: {self.cpu_usage:.1f}%/{cpu_max:.0f}%"
                    if self.cpu_temp > 0:
                        chatbox_message += f" ({self.cpu_temp}°C)"
                    chatbox_message += f"\n内存: {self.memory_info['percent']:.1f}% ({self.memory_info['used_gb']:.1f}GB/{self.memory_info['total_gb']:.1f}GB)"
                    chatbox_message += f"\nGPU: {self.monitor.simplify_gpu_model(self.gpu_model)}\n"
                    chatbox_message += f"使用率: {self.gpu_usage:.1f}%"
                    if self.gpu_temp > 0:
                        chatbox_message += f" ({self.gpu_temp}°C)"
                    chatbox_message += f"\nVRAM: {self.vram_info['percent']:.1f}% ({self.vram_info['used_gb']:.1f}GB/{self.vram_info['total_gb']:.1f}GB)"
                    
                    self.osc_sender.send_chatbox(chatbox_message)
            
            # 同时发送到avatar parameters（用于Avatar显示，每秒发送）
            prefix = self.prefix_entry.get()
            base_address = f"/avatar/parameters/{prefix}"
            
            try:
                # 发送CPU使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/CPU", self.cpu_usage / 100.0)
                # 发送内存使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/Memory", self.memory_info['percent'] / 100.0)
                # 发送GPU使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/GPU", self.gpu_usage / 100.0)
                # 发送VRAM使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/VRAM", self.vram_info['percent'] / 100.0)
                # 发送CPU温度（摄氏度）
                if self.cpu_temp > 0:
                    self.osc_sender.send(f"{base_address}/CPUTemp", self.cpu_temp)
            except Exception as e:
                print(f"发送OSC消息失败: {e}")
    
    def update_ui(self):
        """更新UI显示"""
        if self.is_running:
            # 获取CPU核心数用于计算最大值
            cpu_count = psutil.cpu_count(logical=True)
            cpu_max = cpu_count * 100
            
            # 更新CPU型号
            self.cpu_model_label.config(text=self.cpu_model)
            
            # 更新CPU
            self.cpu_label.config(text=f"{self.cpu_usage:.1f}%/{cpu_max:.0f}%")
            self.cpu_bar['value'] = self.cpu_usage
            self.cpu_bar['maximum'] = cpu_max
            
            # 根据使用率设置颜色（相对于最大值）
            usage_percent = (self.cpu_usage / cpu_max) * 100
            if usage_percent > 80:
                self.cpu_label.config(foreground="red")
            elif usage_percent > 50:
                self.cpu_label.config(foreground="orange")
            else:
                self.cpu_label.config(foreground="green")
            
            # 更新内存
            self.memory_label.config(text=f"{self.memory_info['percent']:.1f}%")
            self.memory_bar['value'] = self.memory_info['percent']
            
            if self.memory_info['percent'] > 80:
                self.memory_label.config(foreground="red")
            elif self.memory_info['percent'] > 50:
                self.memory_label.config(foreground="orange")
            else:
                self.memory_label.config(foreground="green")
            
            # 更新GPU型号
            self.gpu_model_label.config(text=self.gpu_model)
            
            # 更新GPU
            self.gpu_label.config(text=f"{self.gpu_usage:.1f}%")
            self.gpu_bar['value'] = self.gpu_usage
            
            # 更新VRAM
            self.vram_label.config(text=f"{self.vram_info['percent']:.1f}%")
            self.vram_bar['value'] = self.vram_info['percent']
            
            # 更新详细信息
            detail_text = f"""CPU 使用率: {self.cpu_usage:.1f}%
CPU 温度: {self.cpu_temp}°C
内存使用: {self.memory_info['used_gb']} GB / {self.memory_info['total_gb']} GB ({self.memory_info['percent']:.1f}%)
内存可用: {self.memory_info['available_gb']} GB
GPU 型号: {self.gpu_model}
GPU 使用率: {self.gpu_usage:.1f}%
GPU 温度: {self.gpu_temp}°C
VRAM 使用: {self.vram_info['used_gb']} GB / {self.vram_info['total_gb']} GB ({self.vram_info['percent']:.1f}%)
网络发送: {self.network_info['bytes_sent']} MB
网络接收: {self.network_info['bytes_recv']} MB"""
            
            self.detail_text.config(state='normal')
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, detail_text)
            self.detail_text.config(state='disabled')
            
            # 继续更新
            self.root.after(1000, self.update_ui)
    
    def on_close(self):
        """关闭窗口"""
        self.stop_monitoring()
        self.root.destroy()


def main():
    """主函数"""
    root = tk.Tk()
    app = VRChatOSCApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()