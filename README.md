# Demo SSL/TLS và sự cố lộ khóa CA trung gian

Demo sự cố trong môi trường Docker cô lập: khóa ký của Intermediate CA bị lộ, kẻ giả mạo cấp chứng chỉ cho `login.payroll.test`, resolver lab chuyển hướng DNS, sau đó CA thu hồi qua Bash và cấp lại CA trung gian mới.

Yêu cầu: Docker Engine/Desktop có Compose, Python 3.10+ trên host. Không cần `pip install` trên host, không cần OpenSSL trên host, không đổi DNS hay kho tin cậy của máy. Mọi lệnh Bash/OpenSSL chạy trong container Linux.

## Chạy

```bash
bash start-demo.sh                     # hoặc: python3 demo.py
```

Mặc định là trình diễn terminal gồm 7 bước: chờ setup/build và dịch vụ sẵn sàng, sau đó nhấn Enter trước mỗi quan sát. Mỗi bước in PASS/FAIL của kịch bản riêng với kết quả TLS chấp nhận/từ chối và bằng chứng DNS/TCP/TLS/HTTP; từ chối TLS đúng kỳ vọng vẫn là PASS. Cuối phiên có tổng kết 7 kịch bản, 5 bất biến chứng chỉ và đường dẫn bằng chứng. Không mở trình duyệt hay HTTP server trên host.

Windows: `run-demo.cmd` (gọi `start-demo.ps1`). Các launcher chuyển tiếp tham số và mã thoát; `run-demo.cmd` chỉ pause khi chạy không có tham số. Chế độ mặc định cần terminal tương tác; stdin chuyển hướng bị từ chối trước khi tạo deployment.

Tự động hóa không có prompt: `python3 demo.py --self-test`, stdout là JSON (mã thoát 0 chỉ khi cả 7 quan sát và bất biến đạt, 1 khi thất bại). Ctrl+C, EOF tại prompt hoặc SIGTERM dừng phiên đầy đủ với mã 130, giữ bằng chứng và dọn project Docker; `failure.txt` ghi `Interrupted`. DNS và kho tin cậy của host không thay đổi.

## Các lệnh độc lập (giữ deployment để trình diễn)

```bash
python3 demo.py --action setup
python3 demo.py --action attack   --run-id ID
python3 demo.py --action probe    --run-id ID
python3 demo.py --action revoke   --run-id ID
python3 demo.py --action probe    --run-id ID --check-crl
python3 demo.py --action recover  --run-id ID
python3 demo.py --action down     --run-id ID
```

Thay mọi `ID` bằng `run_id` do `setup` in ra. Mỗi action in JSON; deployment được giữ đến khi gọi `down`. Action `revoke` chạy Bash trong container CA.

## Bảy quan sát

| ID | DNS trỏ đến | Trust / CRL | Kết quả thực tế |
|---|---|---|---|
| `baseline` | legitimate | bundle, kiểm tra CRL toàn chuỗi | TLS 1.3, HTTP 200, `LEGITIMATE PAYROLL LAB` |
| `untrusted` | attacker | root không liên quan | từ chối, mã 20 |
| `forged` | attacker | root, không CRL | TLS 1.3, HTTP 200, `ATTACKER PAYROLL LAB` với hostname không đổi |
| `hostname` | attacker (`other.payroll.test`) | root | sai hostname, mã 62 |
| `revoked` | attacker | bundle mới, kiểm tra CRL | chứng chỉ bị thu hồi, mã 23 |
| `unchecked` | attacker | bundle mới, không CRL | HTTP 200, attacker |
| `recovery` | legitimate | bundle mới, kiểm tra CRL | HTTP 200, legitimate dưới CA trung gian mới |

Đúng thứ tự: setup → baseline → attack → untrusted/forged/hostname → thu hồi Bash → revoked/unchecked → recover → recovery.

## Mô hình mạng và khóa

Năm service trên một network `internal`, không publish cổng, không host networking, không Docker socket:

- `ca`: image tools, `network_mode: none`, chỉ nơi này nhận khóa private của Root và CA trung gian. Root key được lưu trong `runs/<id>/ca-private/` (chỉ trên host và trong container CA) để lệnh thu hồi độc lập ký CRL sau này; không bao giờ đưa vào JSON/log.
- `legitimate`: Nginx chỉ mount `legitimate/` (leaf + chain) read-only.
- `attacker`: image riêng, chỉ nhận `leak/` (chứng chỉ + khóa CA trung gian bị lộ) read-only và `attacker/` ghi được; không có khóa CA-private hay khóa leaf hợp lệ.
- `dns`: dnsmasq với `no-resolv`, `local=/test/`, `cache-size=0`, không chuyển tiếp ra ngoài.
- `victim`: không mount khóa nào; chỉ `public/` (chứng chỉ/CRL công khai) và `dns/resolv.conf` trỏ thẳng địa chỉ DNS của lab. Mỗi quan sát là một process mới.

Attack = resolver lab đổi bản ghi `login.payroll.test` sang Nginx giả rồi SIGHUP dnsmasq; recovery đổi lại. Đây là chuyển hướng DNS/resolver bị chiếm, không phải giả gói tin hay đầu độc cache. Không nhắm mục tiêu ngoài lab, không thu credential.

Bằng chứng mỗi lần chạy nằm trong `runs/<id>/`: `results.json`, `revocation.txt`, `state.json`, `docker.log` (log DNS/Nginx có timestamp) và chứng chỉ/CRL công khai. `latest-results.json` chỉ được cập nhật bởi lần chạy thật hoàn tất.

## Giới hạn

Revocation chỉ có hiệu lực khi client bật kiểm tra CRL (mã 23); đây chính là bài học của bước `unchecked`. Client trong lab dùng bundle cục bộ, không tự tải CRL/OCSP. Trình duyệt trên host không bị chuyển hướng và không tin CA lab; chính sách trust/thu hồi của trình duyệt khác victim. Lộ khóa CA không suy ra khóa phiên TLS 1.3 lịch sử. Khóa trong `runs/` là dữ liệu lab dùng một lần: quản trị viên host vẫn đọc được, ranh giới cô lập là giữa các container, không phải chống host.

Nguồn: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [OpenSSL verification options](https://docs.openssl.org/3.6/man1/openssl-verification-options/), [OpenSSL ca](https://docs.openssl.org/3.6/man1/openssl-ca/).
