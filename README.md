# Demo SSL/TLS và sự cố lộ khóa CA

Chạy `powershell -ExecutionPolicy Bypass -File .\start-demo.ps1`, mở http://127.0.0.1:8765 rồi bấm **Chạy demo thực tế**. Dùng **Bước tiếp theo** hoặc chọn từng kịch bản để thuyết trình. Dừng bằng Ctrl+C trong cửa sổ chạy server.

Nếu dùng máy khác: cài Python 3.10+ và `python -m pip install -r requirements.txt`, sau đó `python demo.py`. Có thể kiểm thử không mở giao diện bằng `python demo.py --self-test`.

## Kịch bản trình bày khoảng 3 phút

1. Root CA chưa được client tin: kết nối bị từ chối, mã 20.
2. Root CA được tin, leaf giả được ký bằng khóa Intermediate bị lộ: TLS 1.3 thành công.
3. Đổi hostname thành `other.payroll.test`: từ chối, mã 62.
4. Root ký CRL thu hồi Intermediate với lý do `cACompromise`; client bật kiểm tra cả chuỗi: từ chối, mã 23.
5. Dùng chính bundle có CRL nhưng tắt kiểm tra thu hồi: kết nối vẫn thành công.
6. Thay Intermediate bằng khóa mới và cấp lại leaf, giữ CRL của CA cũ: thành công.

Chứng chỉ, CRL và bằng chứng của mỗi lần chạy nằm trong `runs/<id>/`; kết quả gần nhất nằm trong `latest-results.json`. Private key trong các thư mục này chỉ dùng cho lab. Root key không ghi ra ổ đĩa và không đưa vào phần giả lập kẻ tấn công. Không cài chứng chỉ vào kho tin cậy thật. Các kết nối chỉ dùng loopback và tên miền `.test`.

Demo thực hiện xác minh chứng chỉ và bắt tay bằng Python `ssl` dựa trên OpenSSL. Không mô phỏng chiếm DNS hay đường truyền thật. Có CRL sẵn trong bundle là điều kiện của thử nghiệm, không phải tự tải CRL/OCSP từ mạng. Chính sách của trình duyệt có thể khác client trong lab. Lộ khóa CA không tự suy ra khóa phiên TLS 1.3 lịch sử.

Nguồn: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [OpenSSL verification options](https://docs.openssl.org/3.6/man1/openssl-verification-options/).
