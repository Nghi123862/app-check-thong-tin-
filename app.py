import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Any
from updater import update_rules

# Run the updater first to ensure rules are in place before detectors are loaded.
update_rules()

try:
    from detectors import analyze_url, analyze_text, analyze_file
except Exception:
    # Lazy import fallback paths
    from detectors.url_detector import analyze_url  # type: ignore
    from detectors.text_detector import analyze_text  # type: ignore
    from detectors.file_detector import analyze_file  # type: ignore


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Giám sát nội dung vi phạm & tin giả")
        self.geometry("880x600")
        self._build_ui()

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # URL Tab
        url_tab = ttk.Frame(notebook)
        notebook.add(url_tab, text="Kiểm tra Link")
        self._build_url_tab(url_tab)

        # Text Tab
        text_tab = ttk.Frame(notebook)
        notebook.add(text_tab, text="Kiểm tra Văn bản")
        self._build_text_tab(text_tab)

        # File Tab
        file_tab = ttk.Frame(notebook)
        notebook.add(file_tab, text="Kiểm tra Tập tin")
        self._build_file_tab(file_tab)

    def _build_url_tab(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Nhập đường dẫn (URL)").pack(anchor=tk.W)
        self.url_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.url_var).pack(fill=tk.X)

        ttk.Button(frame, text="Phát hiện", command=self._on_check_url).pack(pady=8, anchor=tk.W)
        self.url_result = tk.Text(frame, height=16)
        self.url_result.pack(fill=tk.BOTH, expand=True)

    def _build_text_tab(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Dán hoặc nhập văn bản").pack(anchor=tk.W)
        self.text_input = tk.Text(frame, height=12)
        self.text_input.pack(fill=tk.BOTH, expand=True)

        ttk.Button(frame, text="Phát hiện", command=self._on_check_text).pack(pady=8, anchor=tk.W)
        self.text_result = tk.Text(frame, height=12)
        self.text_result.pack(fill=tk.BOTH, expand=True)

    def _build_file_tab(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="Chọn tập tin", command=self._on_pick_file).pack(side=tk.LEFT)
        self.file_path_var = tk.StringVar()
        ttk.Entry(btn_row, textvariable=self.file_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        ttk.Button(btn_row, text="Phát hiện", command=self._on_check_file).pack(side=tk.LEFT)

        self.file_result = tk.Text(frame, height=18)
        self.file_result.pack(fill=tk.BOTH, expand=True)

    # Handlers
    def _on_check_url(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập URL")
            return
        try:
            result = analyze_url(url)
            self._display_summary_plus_json(self.url_result, result)
        except Exception as e:
            self.url_result.delete("1.0", tk.END)
            self.url_result.insert(tk.END, f"Lỗi không xác định:\n{e}")
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình phân tích:\n{e}")

    def _on_check_text(self) -> None:
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập văn bản")
            return
        try:
            result = analyze_text(text)
            self._display_summary_plus_json(self.text_result, result)
        except Exception as e:
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert(tk.END, f"Lỗi không xác định:\n{e}")
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình phân tích:\n{e}")

    def _on_pick_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[
            ("Tất cả", "*.*"),
            ("Văn bản", "*.txt"),
            ("PDF", "*.pdf"),
            ("Word", "*.docx"),
        ])
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
            self.file_result.delete("1.0", tk.END)
            self.file_result.insert(tk.END, f"Lỗi không xác định:\n{e}")
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình phân tích:\n{e}")

    def _display_summary_plus_json(self, widget: tk.Text, payload: Any) -> None:
        import json
        widget.delete("1.0", tk.END)

        if not isinstance(payload, dict):
            widget.insert(tk.END, str(payload))
            return

        verdict = payload.get("verdict", "")
        confidence = payload.get("confidence", "")
        risk = payload.get("risk_level", "")
        rationale = payload.get("rationale", "")

        if verdict:
            widget.insert(tk.END, f"Kết luận: {verdict} — Độ tin cậy: {confidence}% — Mức rủi ro: {risk}\n")
            if rationale:
                widget.insert(tk.END, f"Lý do: {rationale}\n\n")

        # Handle nested text analysis for URL results
        text_summary = payload.pop("text_analysis_summary", None)

        try:
            # Display the main payload (without the nested part)
            widget.insert(tk.END, json.dumps(payload, ensure_ascii=False, indent=2))
        except Exception:
            widget.insert(tk.END, str(payload))

        # Display the text analysis summary if it exists
        if text_summary and isinstance(text_summary, dict):
            widget.insert(tk.END, "\n\n--- Phân tích nội dung trang web ---\n")
            text_verdict = text_summary.get('verdict', 'N/A')
            text_risk = text_summary.get('risk_level', 'N/A')
            text_rationale = text_summary.get('rationale', 'N/A')
            widget.insert(tk.END, f"Kết luận nội dung: {text_verdict}\n")
            widget.insert(tk.END, f"Mức rủi ro nội dung: {text_risk}\n")
            widget.insert(tk.END, f"Lý do: {text_rationale}\n")


if __name__ == "__main__":
    # Launch the main application window.
    App().mainloop()
