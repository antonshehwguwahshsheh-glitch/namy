import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil

from scanner import scan_folder


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AV Monitor")
        self.geometry("1100x700")
        self.minsize(900, 600)

        self.cpu_history = [0] * 60
        self.ram_history = [0] * 60

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_monitor = ttk.Frame(self.notebook)
        self.tab_process = ttk.Frame(self.notebook)
        self.tab_scanner = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_monitor, text="Монитор")
        self.notebook.add(self.tab_process, text="Процессы")
        self.notebook.add(self.tab_scanner, text="Сканер")

        self.build_monitor()
        self.build_process()
        self.build_scanner()

        self.after(500, self.refresh_monitor)
        self.after(500, self.refresh_processes)

    def build_monitor(self):
        top = ttk.Frame(self.tab_monitor)
        top.pack(fill="x", padx=10, pady=10)

        self.cpu_var = tk.StringVar(value="CPU: 0%")
        self.ram_var = tk.StringVar(value="RAM: 0%")
        self.disk_var = tk.StringVar(value="Disk: 0%")

        ttk.Label(top, textvariable=self.cpu_var, font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)
        ttk.Label(top, textvariable=self.ram_var, font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)
        ttk.Label(top, textvariable=self.disk_var, font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)

        self.canvas = tk.Canvas(self.tab_monitor, bg="#111", height=260)
        self.canvas.pack(fill="both", expand=True, padx=10, pady=10)
        self.canvas.bind("<Configure>", lambda e: self.draw_graph())

    def build_process(self):
        columns = ("pid", "name", "cpu", "mem", "status")
        self.proc_tree = ttk.Treeview(self.tab_process, columns=columns, show="headings")
        for col, text, width in [
            ("pid", "PID", 80),
            ("name", "Имя", 350),
            ("cpu", "CPU %", 100),
            ("mem", "RAM %", 100),
            ("status", "Статус", 120),
        ]:
            self.proc_tree.heading(col, text=text)
            self.proc_tree.column(col, width=width, anchor="w")

        scroll = ttk.Scrollbar(self.tab_process, orient="vertical", command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=scroll.set)
        self.proc_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll.pack(side="right", fill="y", padx=(0, 10), pady=10)

    def build_scanner(self):
        top = ttk.Frame(self.tab_scanner)
        top.pack(fill="x", padx=10, pady=10)

        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(top, text="Выбрать", command=self.choose_folder).pack(side="left", padx=4)
        self.scan_btn = ttk.Button(top, text="Сканировать", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=4)

        self.progress = ttk.Progressbar(self.tab_scanner, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 8))

        self.scan_status = tk.StringVar(value="Готов.")
        ttk.Label(self.tab_scanner, textvariable=self.scan_status).pack(anchor="w", padx=10)

        columns = ("path", "size", "sha256", "reasons")
        self.scan_tree = ttk.Treeview(self.tab_scanner, columns=columns, show="headings")
        for col, text, width in [
            ("path", "Файл", 380),
            ("size", "Размер", 90),
            ("sha256", "SHA-256", 260),
            ("reasons", "Причина", 300),
        ]:
            self.scan_tree.heading(col, text=text)
            self.scan_tree.column(col, width=width, anchor="w")

        scroll = ttk.Scrollbar(self.tab_scanner, orient="vertical", command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scroll.set)
        self.scan_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll.pack(side="right", fill="y", padx=(0, 10), pady=10)

    def choose_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)

    def start_scan(self):
        root = self.path_var.get().strip()
        if not root or not os.path.isdir(root):
            messagebox.showerror("Ошибка", "Выбери существующую папку.")
            return

        self.scan_btn.config(state="disabled")
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.progress["value"] = 0
        self.scan_status.set("Сканирование...")

        def progress_cb(done, total):
            self.after(0, lambda: self._update_progress(done, total))

        def worker():
            try:
                findings = scan_folder(root, progress_cb=progress_cb)
                self.after(0, lambda: self._scan_done(findings))
            except Exception as e:
                self.after(0, lambda: self._scan_error(e))

        threading.Thread(target=worker, daemon=True).start()

    def _update_progress(self, done, total):
        self.progress["maximum"] = max(total, 1)
        self.progress["value"] = done
        self.scan_status.set(f"Проверено: {done}/{total}")

    def _scan_done(self, findings):
        for item in findings:
            self.scan_tree.insert("", "end", values=(
                item["path"],
                item["size"],
                item["sha256"],
                item["reasons"],
            ))
        self.scan_status.set(f"Готово. Найдено подозрительных: {len(findings)}")
        self.scan_btn.config(state="normal")

    def _scan_error(self, error):
        self.scan_status.set(f"Ошибка: {error}")
        self.scan_btn.config(state="normal")

    def refresh_monitor(self):
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage(os.path.abspath(os.sep)).percent

        self.cpu_var.set(f"CPU: {cpu:.1f}%")
        self.ram_var.set(f"RAM: {ram:.1f}%")
        self.disk_var.set(f"Disk: {disk:.1f}%")

        self.cpu_history.append(cpu)
        self.ram_history.append(ram)
        self.cpu_history = self.cpu_history[-60:]
        self.ram_history = self.ram_history[-60:]

        self.draw_graph()
        self.after(1000, self.refresh_monitor)

    def draw_graph(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10 or h < 10:
            return

        for i in range(0, 101, 25):
            y = h - (i / 100) * h
            self.canvas.create_line(0, y, w, y, fill="#333")
            self.canvas.create_text(4, y - 8, text=f"{i}%", fill="#777", anchor="w")

        def line(data, color):
            if len(data) < 2:
                return
            step = w / (len(data) - 1)
            points = []
            for idx, val in enumerate(data):
                x = idx * step
                y = h - (val / 100) * h
                points.extend([x, y])
            self.canvas.create_line(*points, fill=color, width=2, smooth=True)

        line(self.cpu_history, "#4fc3f7")
        line(self.ram_history, "#ffb74d")

        self.canvas.create_text(w - 10, 12, text="CPU", fill="#4fc3f7", anchor="e")
        self.canvas.create_text(w - 10, 30, text="RAM", fill="#ffb74d", anchor="e")

    def refresh_processes(self):
        self.proc_tree.delete(*self.proc_tree.get_children())
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
            try:
                info = p.info
                self.proc_tree.insert("", "end", values=(
                    info["pid"],
                    info["name"] or "",
                    f"{info['cpu_percent'] or 0:.1f}",
                    f"{info['memory_percent'] or 0:.1f}",
                    info["status"] or "",
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self.after(2000, self.refresh_processes)


if __name__ == "__main__":
    App().mainloop()
