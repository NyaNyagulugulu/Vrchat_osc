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
        获取CPU使用率（基于/proc/stat的标准Linux计算方法）
        返回0-100之间的使用率百分比
        """
        try:
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
            
            # 计算使用率：非空闲时间的比例
            busy_delta = total_delta - idle_delta - iowait_delta
            cpu_usage = (busy_delta / total_delta) * 100
            
            # 更新历史记录
            self.cpu_history.append(cpu_usage)
            self.prev_cpu_times = (user, nice, system, idle, iowait, irq, softirq, steal)
            self.prev_time = current_time
            
            return round(cpu_usage, 2)
        
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
        
        # 硬件信息显示区域
        info_frame = ttk.LabelFrame(main_frame, text="硬件信息", padding="10")
        info_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # CPU信息
        ttk.Label(info_frame, text="CPU 使用率:").grid(row=0, column=0, sticky=tk.W)
        self.cpu_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 14, 'bold'))
        self.cpu_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        self.cpu_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.cpu_bar.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
        # 内存信息
        ttk.Label(info_frame, text="内存使用率:").grid(row=2, column=0, sticky=tk.W)
        self.memory_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 14, 'bold'))
        self.memory_label.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        self.memory_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.memory_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
        # 磁盘信息
        ttk.Label(info_frame, text="磁盘使用率:").grid(row=4, column=0, sticky=tk.W)
        self.disk_label = ttk.Label(info_frame, text="0.0%", font=('Arial', 12, 'bold'))
        self.disk_label.grid(row=4, column=1, sticky=tk.W, padx=(10, 0))
        
        self.disk_bar = ttk.Progressbar(info_frame, length=300, mode='determinate')
        self.disk_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 10))
        
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
        self.disk_info = self.monitor.get_disk_usage()
        self.network_info = self.monitor.get_network_stats()
        self.cpu_temp = self.monitor.get_cpu_temp()
        
        # 发送OSC消息
        if self.osc_sender:
            prefix = self.prefix_entry.get()
            base_address = f"/avatar/parameters/{prefix}"
            
            try:
                # 发送CPU使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/CPU", self.cpu_usage / 100.0)
                # 发送内存使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/Memory", self.memory_info['percent'] / 100.0)
                # 发送磁盘使用率（0-1范围）
                self.osc_sender.send(f"{base_address}/Disk", self.disk_info['percent'] / 100.0)
                # 发送CPU温度（摄氏度）
                if self.cpu_temp > 0:
                    self.osc_sender.send(f"{base_address}/CPUTemp", self.cpu_temp)
            except Exception as e:
                print(f"发送OSC消息失败: {e}")
    
    def update_ui(self):
        """更新UI显示"""
        if self.is_running:
            # 更新CPU
            self.cpu_label.config(text=f"{self.cpu_usage:.1f}%")
            self.cpu_bar['value'] = self.cpu_usage
            
            # 根据使用率设置颜色
            if self.cpu_usage > 80:
                self.cpu_label.config(foreground="red")
            elif self.cpu_usage > 50:
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
            
            # 更新磁盘
            self.disk_label.config(text=f"{self.disk_info['percent']:.1f}%")
            self.disk_bar['value'] = self.disk_info['percent']
            
            # 更新详细信息
            detail_text = f"""CPU 使用率: {self.cpu_usage:.1f}%
CPU 温度: {self.cpu_temp}°C
内存使用: {self.memory_info['used_gb']} GB / {self.memory_info['total_gb']} GB ({self.memory_info['percent']:.1f}%)
内存可用: {self.memory_info['available_gb']} GB
磁盘使用: {self.disk_info['used_gb']} GB / {self.disk_info['total_gb']} GB ({self.disk_info['percent']:.1f}%)
磁盘剩余: {self.disk_info['free_gb']} GB
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