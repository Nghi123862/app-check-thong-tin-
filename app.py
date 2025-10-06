import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

try:
    from detectors import analyze_url, analyze_text, analyze_file
except Exception:
    # Lazy import fallback paths
    from detectors.url_detector import analyze_url  # type: ignore
    from detectors.text_detector import analyze_text  # type: ignore
    from detectors.file_detector import analyze_file  # type: ignore


class App(ttk.Window):
    def __init__(self) -> None:
        # Use a modern theme from ttkbootstrap
        super().__init__(themename="superhero")
        self.title("Công Cụ Giám Sát Nội Dung Vi Phạm & Tin Giả")
        self.geometry("900x700")
        self._build_ui()

    def _build_ui(self) -> None:
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(fill=BOTH, expand=YES)

        header = ttk.Label(main_frame, text="Công Cụ Phân Tích Nội Dung", font="-size 16 -weight bold")
        header.pack(pady=(0, 15))

        notebook = ttk.Notebook(main_frame, bootstyle="primary")
        notebook.pack(fill=BOTH, expand=YES)

        # URL Tab
        url_tab = ttk.Frame(notebook, padding=15)
        notebook.add(url_tab, text="  Kiểm tra Link  ")
        self._build_url_tab(url_tab)

        # Text Tab
        text_tab = ttk.Frame(notebook, padding=15)
        notebook.add(text_tab, text="  Kiểm tra Văn bản  ")
        self._build_text_tab(text_tab)

        # File Tab
        file_tab = ttk.Frame(notebook, padding=15)
        notebook.add(file_tab, text="  Kiểm tra Tập tin  ")
        self._build_file_tab(file_tab)

    def _build_url_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Nhập đường dẫn (URL) để phân tích:", font="-size 12").pack(anchor=W, pady=(0, 5))
        self.url_var = tk.StringVar()
        entry = ttk.Entry(parent, textvariable=self.url_var, font="-size 11")
        entry.pack(fill=X, pady=(0, 10), ipady=4)

        ttk.Button(parent, text="Phân tích URL", command=self._on_check_url, bootstyle="success").pack(anchor=W, pady=5, ipady=4)
        self.url_result = ttk.Text(parent, height=16, font="-size 10", wrap="word", relief=FLAT)
        self.url_result.pack(fill=BOTH, expand=YES, pady=(5,0))
        self.url_result.configure(state='disabled') # Make it read-only initially

    def _build_text_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Dán hoặc nhập văn bản cần phân tích:", font="-size 12").pack(anchor=W, pady=(0, 5))
        self.text_input = ttk.Text(parent, height=12, font="-size 10", wrap="word", relief=FLAT)
        self.text_input.pack(fill=BOTH, expand=YES, pady=(0, 10))

        ttk.Button(parent, text="Phân tích văn bản", command=self._on_check_text, bootstyle="success").pack(anchor=W, pady=5, ipady=4)
        self.text_result = ttk.Text(parent, height=12, font="-size 10", wrap="word", relief=FLAT)
        self.text_result.pack(fill=BOTH, expand=YES, pady=(5,0))
        self.text_result.configure(state='disabled')

    def _build_file_tab(self, parent: ttk.Frame) -> None:
        btn_row = ttk.Frame(parent)
        btn_row.pack(fill=X, pady=(5, 10))
        ttk.Button(btn_row, text="Chọn tập tin...", command=self._on_pick_file, bootstyle="info").pack(side=LEFT, ipady=4)
        self.file_path_var = tk.StringVar()
        ttk.Entry(btn_row, textvariable=self.file_path_var, font="-size 11").pack(side=LEFT, fill=X, expand=YES, padx=10, ipady=4)
        ttk.Button(btn_row, text="Phân tích tập tin", command=self._on_check_file, bootstyle="success").pack(side=LEFT, ipady=4)

        self.file_result = ttk.Text(parent, height=18, font="-size 10", wrap="word", relief=FLAT)
        self.file_result.pack(fill=BOTH, expand=YES, pady=(5,0))
        self.file_result.configure(state='disabled')

    def _on_check_url(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập URL")
            return
        try:
            result = analyze_url(url)
            self._display_summary_plus_json(self.url_result, result)
        except Exception as e:
            self._display_error(self.url_result, e)

    def _on_check_text(self) -> None:
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập văn bản")
            return
        try:
            result = analyze_text(text)
            self._display_summary_plus_json(self.text_result, result)
        except Exception as e:
            self._display_error(self.text_result, e)

    def _on_pick_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Tất cả", "*.*"), ("Văn bản", "*.txt"), ("PDF", "*.pdf"), ("Word", "*.docx")])
        if path:
            self.file_path_var.set(path)

    def _on_check_file(self) -> None:
        path = self.file_path_var.get().strip()
        if not path:
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng chọn tập tin")
            return
        try:
            result = analyze_file(path)
            self._display_summary_plus_json(self.file_result, result)
        except Exception as e:
            self._display_error(self.file_result, e)

    def _display_error(self, widget: ttk.Text, error: Exception) -> None:
        widget.configure(state='normal')
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, f"Lỗi không xác định:\n{error}")
        widget.configure(state='disabled')
        messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình phân tích:\n{error}")

    def _display_summary_plus_json(self, widget: ttk.Text, payload: Any) -> None:
        import json
        widget.configure(state='normal')
        widget.delete("1.0", tk.END)

        if not isinstance(payload, dict):
            widget.insert(tk.END, str(payload))
            widget.configure(state='disabled')
            return

        # Define styles for text
        widget.tag_configure("header", font="-size 12 -weight bold", foreground=self.style.colors.primary)
        widget.tag_configure("bold", font="-weight bold")
        widget.tag_configure("risk_cao", foreground=self.style.colors.danger)
        widget.tag_configure("risk_trung bình", foreground=self.style.colors.warning)
        widget.tag_configure("risk_thấp", foreground=self.style.colors.success)
        widget.tag_configure("json_key", foreground=self.style.colors.info)
        widget.tag_configure("json_string", foreground=self.style.colors.light)
        widget.tag_configure("json_number", foreground=self.style.colors.success)

        verdict = payload.get("verdict", "")
        risk = payload.get("risk_level", "Không xác định").lower()

        risk_tag = f"risk_{risk}"

        widget.insert(tk.END, "TỔNG QUAN PHÂN TÍCH\n", "header")
        widget.insert(tk.END, "Kết luận: ", "bold")
        widget.insert(tk.END, f"{verdict}\n", risk_tag)
        widget.insert(tk.END, "Độ tin cậy: ", "bold")
        widget.insert(tk.END, f"{payload.get('confidence', 'N/A')}%\n")
        widget.insert(tk.END, "Mức rủi ro: ", "bold")
        widget.insert(tk.END, f"{payload.get('risk_level', 'N/A')}\n", risk_tag)
        widget.insert(tk.END, "Lý do: ", "bold")
        widget.insert(tk.END, f"{payload.get('rationale', 'Không có')}\n\n")

        try:
            widget.insert(tk.END, "--- Dữ liệu phân tích chi tiết ---\n", "header")
            json_str = json.dumps(payload, ensure_ascii=False, indent=2)
            widget.insert(tk.END, json_str)
        except Exception as e:
            widget.insert(tk.END, f"\nLỗi hiển thị JSON: {e}")

        widget.configure(state='disabled')


if __name__ == "__main__":
    App().mainloop()