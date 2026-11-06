# Demo SSL/TLS và sự cố lộ khóa CA trung gian

Demo sự cố trong môi trường Docker cô lập: khóa ký của Intermediate CA bị lộ, kẻ giả mạo cấp chứng chỉ cho `login.payroll.test`, resolver lab chuyển hướng DNS, sau đó CA thu hồi qua Bash và cấp lại CA trung gian mới.

Yêu cầu: Docker Engine/Desktop có Compose, Python 3.10+ trên host. Không cần `pip install` trên host, không cần OpenSSL trên host, không đổi DNS hay kho tin cậy của máy. Mọi lệnh Bash/OpenSSL chạy trong container Linux.

## Chạy

```bash
bash start-demo.sh                     # hoặc: python3 demo.py
```

Mặc định là trình diễn terminal gồm 7 bước: chờ setup/build và dịch vụ sẵn sàng, sau đó nhấn Enter trước mỗi quan sát. Mỗi bước in PASS/FAIL của kịch bản riêng với kết quả TLS chấp nhận/từ chối và bằng chứng DNS/TCP/TLS/HTTP (các bước `baseline`, `revoked`, `recovery` in thêm trạng thái OCSP của CA trung gian); từ chối TLS đúng kỳ vọng vẫn là PASS. Cuối phiên có tổng kết 7 kịch bản, 8 bất biến (5 về chứng chỉ, 3 về OCSP: GOOD trước thu hồi, REVOKED/`ca_compromise` sau thu hồi, CA thay thế GOOD) và đường dẫn bằng chứng. Không mở trình duyệt hay HTTP server trên host.

Windows: `run-demo.cmd` (gọi `start-demo.ps1`). Các launcher chuyển tiếp tham số và mã thoát; `run-demo.cmd` chỉ pause khi chạy không có tham số. Chế độ mặc định cần terminal tương tác; stdin chuyển hướng bị từ chối trước khi tạo deployment.

Output Docker được giải mã UTF-8 tường minh, không dùng code page mặc định của Windows (tránh lỗi `UnicodeDecodeError` với `cp1252`). Mỗi lần chờ readiness có tối đa 120 giây, gồm cả thời gian tạo container probe trên Docker Desktop; hết hạn vẫn báo lỗi kèm log và không bỏ qua xác minh TLS/HTTP.

Kiểm tra hồi quy giải mã stdout/stderr: `python -m unittest discover -s tests -v`.

Tự động hóa không có prompt: `python3 demo.py --self-test`, stdout là JSON (mã thoát 0 chỉ khi cả 7 quan sát và bất biến đạt, 1 khi thất bại). Ctrl+C, EOF tại prompt hoặc SIGTERM dừng phiên đầy đủ với mã 130, giữ bằng chứng và dọn project Docker; `failure.txt` ghi `Interrupted`. DNS và kho tin cậy của host không thay đổi.

## Các lệnh độc lập (giữ deployment để trình diễn)

```bash
python3 demo.py --action setup
python3 demo.py --action attack   --run-id ID
python3 demo.py --action probe    --run-id ID
python3 demo.py --action revoke   --run-id ID
python3 demo.py --action probe    --run-id ID --check-crl
python3 demo.py --action ocsp     --run-id ID                     # hỏi OCSP cho CA trung gian
python3 demo.py --action recover  --run-id ID
python3 demo.py --action ocsp     --run-id ID --ocsp-cert replacement-intermediate
python3 demo.py --action down     --run-id ID
```

Thay mọi `ID` bằng `run_id` do `setup` in ra. Mỗi action in JSON; deployment được giữ đến khi gọi `down`. Action `revoke` chạy Bash trong container CA. Action `ocsp` gửi yêu cầu OCSP đến URL trong chứng chỉ CA (`http://ocsp.payroll.test`), xác minh chữ ký phản hồi và in `cert_status` (`GOOD`/`REVOKED`/`UNKNOWN`) cùng lý do thu hồi; `replacement-intermediate` chỉ tồn tại sau `recover`.

## Trình diễn trên trình duyệt thật (ví dụ qua Tailscale)

Action `browser` bật service tùy chọn `browser` (Compose profile `browser`), publish cổng 443 và 80 chỉ trên địa chỉ chỉ định:

- `:443` chuyển tiếp TCP thẳng (không giải mã TLS) đến nơi resolver lab đang trỏ `login.payroll.test`, nên trình duyệt thấy đúng chứng chỉ của Nginx hợp lệ/attacker và đi theo cả attack lẫn recover.
- `:80` với `crl.payroll.test` phục vụ CRL dạng DER (`root.crl`, `intermediate.crl`, `replacement-intermediate.crl`, `Cache-Control: no-store`) và `root.crt` công khai. Mọi chứng chỉ không phải root đều có CRL Distribution Point trỏ về đây.
- `:80` với `ocsp.payroll.test` chuyển tiếp nguyên vẹn đến responder `ocsp` của lab. Chỉ CA trung gian (cũ và thay thế) có URL OCSP (Authority Information Access); leaf chỉ dùng CRL. Chrome/Edge hỏi OCSP trước: `GOOD`/`REVOKED` là kết luận, responder lỗi hoặc `UNKNOWN` thì quay về CRL.

```bash
python3 demo.py --action setup                                    # ghi lại run_id
python3 demo.py --action browser --run-id ID --bind 100.x.y.z     # IP Tailscale của host
```

Trên máy trình chiếu (phải nằm trong tailnet):

1. Thêm vào file hosts (`C:\Windows\System32\drivers\etc\hosts` hoặc `/etc/hosts`) dòng `hosts_entry` mà action in ra: `100.x.y.z login.payroll.test crl.payroll.test ocsp.payroll.test`.
2. Tải `http://crl.payroll.test/root.crt`, so SHA-256 với `root_sha256`, import vào kho root tin cậy (Windows: `certutil -user -addstore Root root.crt`). Root đổi theo mỗi `setup`; xóa sau buổi demo.
3. Bật kiểm tra thu hồi bắt buộc (hard-fail) cho root cục bộ trên Chrome/Edge bằng policy `RequireOnlineRevocationChecksForLocalAnchors`. Windows (PowerShell admin): `reg add HKLM\SOFTWARE\Policies\Google\Chrome /v RequireOnlineRevocationChecksForLocalAnchors /t REG_DWORD /d 1 /f` (Edge: `...\Policies\Microsoft\Edge`); Linux Chrome: file JSON trong `/etc/opt/chrome/policies/managed/`. Kiểm tra tại `chrome://policy`. Edge trên macOS không hỗ trợ policy này. Thiếu policy, Chrome/Edge không hỏi OCSP/CRL cho CA cục bộ và vẫn chấp nhận chứng chỉ bị thu hồi — chính là kịch bản `unchecked`; Firefox không tải CRL.

Chạy lần lượt `attack`, `revoke`, `recover` (cùng `--run-id`) và mở `https://login.payroll.test/` sau mỗi bước: `LEGITIMATE PAYROLL LAB` → `ATTACKER PAYROLL LAB` (khóa xanh) → `NET::ERR_CERT_REVOKED` → `LEGITIMATE PAYROLL LAB` dưới CA trung gian mới. Trình duyệt giữ kết nối và cache kết quả xác minh: trước mỗi lần mở, đóng mọi cửa sổ ẩn danh và mở cửa sổ ẩn danh mới. `docker logs pki-lab-ID-browser-1` cho thấy upstream được chọn, các yêu cầu OCSP (`ocsp.payroll.test "GET /MF...`) và các lần trình duyệt tải CRL. `down` gỡ cả gateway.

Trình diễn CRL dự phòng: `docker compose -p pki-lab-ID stop ocsp`, mở cửa sổ ẩn danh mới — vẫn `NET::ERR_CERT_REVOKED`, log gateway cho thấy OCSP `status=502` rồi `GET /root.crl`. Bật lại bằng `docker compose -p pki-lab-ID start ocsp`.

## Bảy quan sát

| ID | DNS trỏ đến | Trust / CRL | Kết quả thực tế |
|---|---|---|---|
| `baseline` | legitimate | bundle, kiểm tra CRL toàn chuỗi | TLS 1.3, HTTP 200, `LEGITIMATE PAYROLL LAB`; OCSP CA trung gian `GOOD` |
| `untrusted` | attacker | root không liên quan | từ chối, mã 20 |
| `forged` | attacker | root, không CRL | TLS 1.3, HTTP 200, `ATTACKER PAYROLL LAB` với hostname không đổi |
| `hostname` | attacker (`other.payroll.test`) | root | sai hostname, mã 62 |
| `revoked` | attacker | bundle mới, kiểm tra CRL | chứng chỉ bị thu hồi, mã 23; OCSP CA trung gian `REVOKED` (`ca_compromise`) |
| `unchecked` | attacker | bundle mới, không CRL | HTTP 200, attacker |
| `recovery` | legitimate | bundle mới, kiểm tra CRL | HTTP 200, legitimate dưới CA trung gian mới; OCSP CA thay thế `GOOD` |

Đúng thứ tự: setup → baseline → attack → untrusted/forged/hostname → thu hồi Bash → revoked/unchecked → recover → recovery.

## Mô hình mạng và khóa

Sáu service trên một network `internal`, không publish cổng, không host networking, không Docker socket (ngoại lệ duy nhất: gateway tùy chọn `browser` ở trên, nối thêm network `edge` để publish cổng):

- `ca`: image tools, `network_mode: none`, chỉ nơi này nhận khóa private của Root và CA trung gian. Root key được lưu trong `runs/<id>/ca-private/` (chỉ trên host và trong container CA) để lệnh thu hồi độc lập ký CRL sau này; không bao giờ đưa vào JSON/log.
- `legitimate`: Nginx chỉ mount `legitimate/` (leaf + chain) read-only.
- `attacker`: image riêng, chỉ nhận `leak/` (chứng chỉ + khóa CA trung gian bị lộ) read-only và `attacker/` ghi được; không có khóa CA-private hay khóa leaf hợp lệ.
- `dns`: dnsmasq với `no-resolv`, `local=/test/`, `cache-size=0`, không chuyển tiếp ra ngoài.
- `ocsp`: `openssl ocsp` (GET và POST) đọc bản sao công khai `ocsp/index.txt` của cơ sở dữ liệu Root CA, ký bằng chứng chỉ responder ủy quyền (Root cấp, EKU OCSPSigning, OCSPNoCheck); chỉ mount `ocsp/` read-only, không nhận `root.key`. Mỗi lần CA đổi trạng thái thu hồi, `publish-trust` cập nhật `ocsp/index.txt` và `demo.py` khởi động lại responder (`openssl ocsp` chỉ kiểm tra index trước khi chờ kết nối kế tiếp nên câu trả lời đầu tiên sau thay đổi sẽ cũ). Gọi `revoke-cert.sh` thủ công thì cần `docker compose -p pki-lab-ID restart ocsp`.
- `victim`: không mount khóa nào; chỉ `public/` (chứng chỉ/CRL công khai) và `dns/resolv.conf` trỏ thẳng địa chỉ DNS của lab. Mỗi quan sát là một process mới; truy vấn OCSP cũng chạy trong `victim` (POST đến địa chỉ container `ocsp` với `Host` lấy từ URL trong chứng chỉ).

Attack = resolver lab đổi bản ghi `login.payroll.test` sang Nginx giả rồi SIGHUP dnsmasq; recovery đổi lại. Đây là chuyển hướng DNS/resolver bị chiếm, không phải giả gói tin hay đầu độc cache. Không nhắm mục tiêu ngoài lab, không thu credential.

Bằng chứng mỗi lần chạy nằm trong `runs/<id>/`: `results.json` (gồm trường `ocsp` của các bước có hỏi OCSP), `revocation.txt`, `state.json`, `docker.log` (log DNS/OCSP/Nginx có timestamp) và chứng chỉ/CRL công khai. `latest-results.json` chỉ được cập nhật bởi lần chạy thật hoàn tất.

## Giới hạn

Revocation chỉ có hiệu lực khi client bật kiểm tra CRL (mã 23); đây chính là bài học của bước `unchecked`. Client TLS trong lab dùng bundle cục bộ, không tự tải CRL/OCSP; trạng thái OCSP là truy vấn riêng, không chặn kết nối TLS. OCSP chỉ phủ cấp CA (CA trung gian cũ và thay thế); leaf, kể cả leaf của attacker, chỉ có CRL. Trình duyệt trên host không bị chuyển hướng và không tin CA lab; chính sách trust/thu hồi của trình duyệt khác victim. Lộ khóa CA không suy ra khóa phiên TLS 1.3 lịch sử. Khóa trong `runs/` là dữ liệu lab dùng một lần: quản trị viên host vẫn đọc được, ranh giới cô lập là giữa các container, không phải chống host.

Nguồn: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [OpenSSL verification options](https://docs.openssl.org/3.6/man1/openssl-verification-options/), [OpenSSL ca](https://docs.openssl.org/3.6/man1/openssl-ca/), [OpenSSL ocsp](https://docs.openssl.org/3.0/man1/openssl-ocsp/).
