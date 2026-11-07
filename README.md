# Demo SSL/TLS và sự cố lộ khóa CA trung gian

Demo sự cố trong môi trường Docker cô lập: khóa ký của Intermediate CA bị lộ, kẻ giả mạo cấp chứng chỉ cho `login.payroll.test`, resolver lab chuyển hướng DNS, sau đó CA thu hồi qua Bash và cấp lại CA trung gian mới.

Yêu cầu: Docker Engine/Desktop có Compose, Python 3.10+ trên host. Không cần `pip install` hay OpenSSL trên host; công cụ Bash/OpenSSL của lab chạy trong container Linux. Script không tự sửa DNS, cài CA, cấu hình policy, gọi sudo hay mở trình duyệt. Chế độ browser yêu cầu bạn cấu hình thủ công trên máy trình duyệt dùng một lần.

## Dashboard Chrome trực quan (Windows + Docker host từ xa)

Đây là extension thật, không phải trình giả lập lỗi TLS. **Chrome thực tế** là event do extension tin cậy báo từ `chrome.webRequest` (không được chứng thực mật mã); **Tham chiếu OpenSSL** là probe Python/OpenSSL độc lập. Kỳ vọng không phải quan sát. Log gateway, CRL được tải và OpenSSL PASS không chứng minh Chrome PASS.

1. Dùng Windows VM/tài khoản demo dùng một lần, có quyền quản trị thủ công. Nạp thư mục `extension/` tại `chrome://extensions` → Developer mode → Load unpacked. Giữ nguyên đường dẫn Windows. ID ổn định của bản này: **`kgjbbjnbmkjhhmohcdanodfimemkbijg`**. Manifest chỉ giữ public key định danh extension, không giữ private key.
2. Trên Docker host, dừng **đúng run lab cũ đã biết** nếu nó đang chiếm 80/443 (`python3 demo.py --action down --run-id ID`). Không dừng dịch vụ không liên quan. Khởi động controller:

   ```bash
   python3 visual_demo.py --lab-ip REAL_ASSIGNED_DOCKER_HOST_IP --extension-id kgjbbjnbmkjhhmohcdanodfimemkbijg
   ```

   Phải dùng IP IPv4/IPv6 thật đã gán cho host. Không tự fallback địa chỉ/cổng. Controller chỉ nghe `127.0.0.1:8765`, in token trên console; chưa tạo deployment cho đến khi Start. Không chụp/chia sẻ token, không đưa token vào URL.
3. Trên Windows mở tunnel, giữ nó hoạt động:

   ```powershell
   ssh -N -L 127.0.0.1:8765:127.0.0.1:8765 USER@DOCKER_HOST
   ```

   Nếu thiếu Windows OpenSSH Client, cài/bật capability đó thủ công. Tunnel chỉ mang control. Site/CRL/OCSP vẫn đi trực tiếp đến IP Docker host cổng 80/443; cần firewall/tailnet ACL tương ứng.
4. Mở dashboard bằng toolbar extension, nhập token, Connect → Start. Dashboard cung cấp dòng hosts thật, SHA-256 DER và SHA-1 thumbprint root cùng lệnh Windows có thể sao chép. Thêm hosts tại `C:\Windows\System32\drivers\etc\hosts`: `REAL_IP login.payroll.test other.payroll.test crl.payroll.test ocsp.payroll.test`. Không dùng `0.0.0.0` hay loopback tunnel cho site. Tải root công khai, `certutil -decode root.crt root.der`, `certutil -hashfile root.der SHA256`; so với fingerprint từ control **trước** khi trust.
5. Ghi lại trust lab trong **cả** CurrentUser/LocalMachine Root và giá trị/absence của **từng** `RequireOnlineRevocationChecksForLocalAnchors`, `EnableOnlineRevocationChecks` tại `HKLM\SOFTWARE\Policies\Google\Chrome`. Dashboard có lệnh truy vấn, strict `/d 1`, unchecked `/d 0`, tìm root theo thumbprint chính xác và gỡ/import. Xem `chrome://policy`: cả hai policy phải có giá trị hiệu lực, không ignored/error/nguồn ghi đè. Checkbox chỉ xác nhận người trình diễn đã xem, không phải extension kiểm tra Windows.
6. **Prepare step** thực hiện một thay đổi backend theo thứ tự; **Next** chỉ chọn/xem trước card kế tiếp. Xác nhận checklist rồi **Open in Chrome**. **Reobserve** tạo navigation mới, không chạy lại revoke/recover. Phải có event HTTP/error thật trước khi Prepare bước tiếp; `unobserved` không đủ. Sai khác cần hành động `Tiếp tục với sai khác đã ghi nhận`, không bị đổi thành PASS. Tự xem chain bằng certificate viewer của Chrome; WebRequest không cung cấp fingerprint/issuer/OCSP của Chrome.

| Bước | Cấu hình Windows thủ công trước Open | Kỳ vọng Chrome (không phải kết quả đã đo) |
|---|---|---|
| baseline | Root đã xác minh; hai policy 1; profile strict | HTTP 200 / legitimate |
| untrusted | Gỡ đúng thumbprint khỏi cả hai Root store nếu có; thoát toàn bộ Chrome | `NET::ERR_CERT_AUTHORITY_INVALID` |
| forged | Import lại cùng root đã xác minh; khởi động lại Chrome | HTTP 200 / attacker |
| hostname | Giữ root được tin; hosts có `other.payroll.test`; mở đúng URL | `NET::ERR_CERT_COMMON_NAME_INVALID` |
| revoked | Hai policy 1; thoát toàn bộ Chrome; profile revoked **mới** | `NET::ERR_CERT_REVOKED` |
| unchecked | Hai policy 0; thoát toàn bộ Chrome; profile unchecked **mới** | HTTP 200 / cùng attacker |
| recovery | Hai policy trở lại 1; root cũ được tin; quay lại strict/revoked | HTTP 200 / legitimate, issuer mới |

Lưu công việc trước khi thoát mọi tiến trình Chrome. Profile ở `$env:LOCALAPPDATA\PKILab\RUN_ID\strict`, `revoked`, `unchecked`; stage đã dùng phải đổi sibling attempt-specific mới. Chỉ dùng `--user-data-dir=ABSOLUTE_PATH --no-first-run`, không cờ bỏ kiểm tra chứng chỉ. Nạp cùng extension và nhập lại token ở profile mới; Connect lấy run hiện tại, không Start lại. Profile/Incognito không cô lập Windows trust/policy hoặc mọi cache OS. Nếu Chrome vẫn khác kỳ vọng, giữ raw event, kiểm tra trust copies, policy precedence, hosts, reachability, hạn/cache; không bypass interstitial, đổi chứng chỉ attacker hoặc giả lỗi.

Đóng dashboard/Chrome hay mất tunnel **không dọn Docker**. Evidence chưa đồng bộ được giữ local; Connect tường minh gửi lại idempotently. Không tự replay `/start`, `/next`, `/stop` khi response không chắc chắn: lấy state trước. Cuối bước 7 website vẫn chạy đến **Stop**. Stop bị khóa khi busy, lưu log và chỉ dọn project thuộc controller; dữ liệu/root giữ nguyên. `runs/ID/browser-results.json` chứa Chrome comparisons riêng với `results.json`/`latest-results.json` tham chiếu. Không có “all browsers passed” suy ra từ `all_passed` của OpenSSL.

Stop nhắc bạn xóa **chỉ** hosts vừa thêm, phục hồi **chỉ** hai policy về DWORD gốc (xóa từng value nếu ban đầu absent), và phục hồi trust lab trước demo ở từng store. Extension không tự sửa OS; không xóa cả policy key, CA khác, `.lab-ca` hay profile khác. Forget connection chỉ gỡ token, không dừng Docker.

SIGINT/SIGTERM controller chờ operation hiện tại trong timeout lệnh, rồi dọn run nó sở hữu. Controller restart **không resume mutation**: dùng run ID trong evidence để `demo.py --action down --run-id ID` cho project cũ, rồi Start run mới. CLI terminal bên dưới vẫn giữ lifecycle cũ và trust browser cố định; checklist thay đổi trust/policy từng bước thuộc riêng dashboard này.

Kiểm tra observer: `node --test tests/extension-observer.test.mjs` (Node 18+). Kiểm tra controller/PKI: `python3 -m unittest discover -s tests -v`. Chấp nhận đủ bảy bước Windows cần Chrome Windows thật, quyền admin và SSH/80/443 thật; unit tests/Linux/OpenSSL không thay thế acceptance này.

### Kiểm chứng bản dashboard

- `python3 demo.py --self-test`: Docker thật, run `04aa3212375e`, 7/7 reference cases và 8/8 invariants đạt; CLI teardown hoàn tất.
- `python3 -m unittest discover -s tests -v`: 30 tests đạt, không skip PKI; `node --test tests/extension-observer.test.mjs`: 9 tests đạt. Disk-failure regression kiểm tra duplicate observation không được báo đồng bộ thành công trước khi ghi evidence thành công.
- Smoke extension thật bằng **Chrome for Testing 153 trên Linux**, run `defaf0193140`: root trust trong NSS HOME tạm riêng, không bỏ xác minh TLS; DNS test trỏ tới gateway trên IP thật. Đã thấy HTTP legitimate/attacker, native authority-invalid sau khi gỡ root test và native common-name-invalid trên hostname thật. Controller giữ nguyên run qua đóng/restart Chrome và gián đoạn control; event chưa sync tồn tại qua restart và không bị nhân đôi khi Connect. Timeout thật được giữ `extension.lifecycle/unobserved`, không mở khóa Next. Hai profile thật kiểm tra pending evidence của bước cũ không chặn recovery và primary card hiển thị observation mới nhất từ server.
- Linux smoke **không cấu hình policy Windows**: bước revoked thực tế nhận HTTP 200 / attacker, được lưu **mismatch** và chỉ đi tiếp sau explicit acknowledgement; không có screenshot `ERR_CERT_REVOKED` được giả tạo. Các checkbox Windows trong smoke chỉ kiểm tra UI gating, không chứng minh cấu hình OS. Final website thực tế là `LEGITIMATE PAYROLL LAB`, vẫn hoạt động trước Stop; Stop xóa đúng project và giữ evidence/root.
- Evidence: `runs/defaf0193140/browser-results.json` (12 observations, gồm lifecycle và sai khác), `results.json` (reference), `chrome-authority-invalid.png`, `chrome-common-name-invalid.png`, `chrome-final-dashboard.png`, `chrome-recovery-website.png`. Token không có trong browser evidence. Những artifact trong `runs/` là dữ liệu local, không phải dữ liệu mẫu hay cam kết parity.

**Windows-specific trust/policy acceptance not exercised.** Chưa có Windows VM/admin/SSH client từ execution environment. Phần còn lại là chạy tuần tự bảy hàng trong bảng dashboard ở trên trên Windows thật: hosts/80/443/SSH → xác minh root DER → ghi cấu hình gốc → strict/trusted baseline → gỡ đúng root ở cả hai store và restart → import lại và restart → hostname thật → revoke với hai policy 1 hiệu lực và profile revoked mới → hai policy 0 và profile unchecked mới → khôi phục hai policy 1/root ban đầu rồi recovery → Stop/hoàn tác OS. Giữ raw event và screenshot native cho từng lỗi; nếu strict/unchecked khác kỳ vọng thì giữ mismatch, không suy diễn từ OpenSSL. Gián đoạn control trong smoke được tạo bằng tạm dừng tiến trình controller; tunnel SSH Windows thật chưa được kiểm chứng.


## Chạy

```bash
bash start-demo.sh
```

Trên Linux, `bash start-demo.sh` không có tham số chạy trình diễn từng bước kèm browser gateway trên `0.0.0.0:80/443` (mọi interface IPv4, không chỉ Tailscale). Sau setup/build, script in hướng dẫn hosts, xác minh fingerprint Root CA, trust và policy Chrome/Edge rồi chờ Enter xác nhận trang ban đầu. Trên máy trình duyệt trong tailnet, thay placeholder trong dòng hosts bằng IP Tailscale thật của Docker host, KHÔNG dùng `0.0.0.0`, và cho phép truy cập cổng 80/443 qua firewall/tailnet ACL. Muốn chỉ mở trong tailnet: `bash start-demo.sh --bind <IP-Tailscale-đã-gán-cho-Docker-host>`; chỉ dùng cùng máy: `bash start-demo.sh --bind 127.0.0.1`. Script không tự chọn IP/cổng khác nếu địa chỉ không khả dụng hoặc cổng bị chiếm.

Mỗi bước chờ Enter trước probe/thay đổi trạng thái, in PASS/FAIL và bằng chứng DNS/TCP/TLS/HTTP, rồi chờ thêm Enter để bạn quan sát browser. Đóng tất cả cửa sổ ẩn danh và mở cửa sổ ẩn danh mới trước mỗi lần quan sát. Riêng recovery được giữ đến khi bạn nhấn Enter cuối cùng; Enter này kết thúc demo và gỡ gateway. Cuối phiên có tổng kết 7 kịch bản, 8 bất biến (5 về chứng chỉ, 3 về OCSP) và đường dẫn bằng chứng; từ chối TLS đúng kỳ vọng vẫn là PASS.

`python3 demo.py` không có `--bind` vẫn chỉ trình diễn terminal, chỉ chờ Enter trước mỗi probe và không publish gateway. `python3 demo.py --bind 0.0.0.0` bật cùng hướng dẫn browser như Bash mặc định. Các launcher giữ nguyên mọi tham số tường minh; `bash start-demo.sh --self-test` vẫn chạy unattended, không có gateway.

Windows: `run-demo.cmd` (gọi `start-demo.ps1`) vẫn mặc định chạy trình diễn terminal. Các launcher chuyển tiếp tham số tường minh và mã thoát; `run-demo.cmd` chỉ pause khi chạy không có tham số. Chế độ terminal cần terminal tương tác; stdin chuyển hướng bị từ chối trước khi tạo deployment.

Output Docker được giải mã UTF-8 tường minh, không dùng code page mặc định của Windows (tránh lỗi `UnicodeDecodeError` với `cp1252`). Mỗi lần chờ readiness có tối đa 120 giây, gồm cả thời gian tạo container probe trên Docker Desktop; hết hạn vẫn báo lỗi kèm log và không bỏ qua xác minh TLS/HTTP.

Kiểm tra hồi quy UTF-8 và CLI (IP không hợp lệ, self-test kèm bind, stdin không phải terminal): `python -m unittest discover -s tests -v`. Bộ kiểm tra PKI bổ sung kiểm tra tái sử dụng root, khởi tạo đồng thời và từ chối root thiếu/hết hạn/sai khóa; tự skip nếu host thiếu `cryptography` hoặc `fcntl`. Để chạy đủ trong container tools sau khi setup đã build image: `docker run --rm -v "$PWD:/workspace:ro" -w /workspace pki-lab-tools:local python -m unittest discover -s tests -v`.

Tự động hóa không có prompt: `python3 demo.py --self-test`, stdout là JSON (mã thoát 0 chỉ khi cả 7 quan sát và bất biến đạt, 1 khi thất bại). `--self-test --bind` và `--bind` với action ngoài `setup`/`browser` bị từ chối, IP được xác minh trước khi tạo deployment. Ctrl+C, EOF tại mọi prompt (kể cả setup/quan sát browser) hoặc SIGTERM dừng phiên đầy đủ với mã 130, giữ bằng chứng và dọn project Docker; `failure.txt` ghi `Interrupted`. Docker teardown không hoàn tác hosts/trust/policy do bạn tự sửa: tự gỡ chúng sau buổi demo.

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

### Root CA dùng lại giữa các phiên

Lần setup đầu tiên tạo `.lab-ca/root.crt` và `.lab-ca/root.key`; mọi setup sau trong cùng checkout dùng lại đúng cặp này. Root có hạn 10 năm (3650 ngày), không tự gia hạn hay đổi khóa. Intermediate, leaf và OCSP responder vẫn được cấp mới cho từng run, tối đa 30 ngày và không vượt hạn issuer; database thu hồi và CRL vẫn riêng trong `runs/ID/`. `recover` chỉ thay intermediate, không thay root.

Thư mục `.lab-ca/` có quyền `0700`, khóa private `0600`, bị Git ignore và không nằm trong Docker build context. Chỉ container `ca` mount nó; `down`, kết thúc demo và xóa dữ liệu `runs/` không xóa root dùng chung. Khởi tạo đầu tiên được khóa để các setup đồng thời không tạo root khác nhau. Nếu cặp root thiếu một file, sai khóa hoặc hết hạn, setup báo lỗi thay vì âm thầm tạo root mới.

Chuyển từ phiên bản root-per-run: xóa root lab cũ trong profile trình duyệt dùng một lần, xác minh fingerprint rồi import `.lab-ca/root.crt` một lần. Run cũ không bị đổi chứng chỉ. Những setup mới giữ nguyên fingerprint, nên không cần import lại khi tiếp tục dùng profile lab đó; vẫn gỡ trust khi kết thúc sử dụng lab.

Muốn chủ động đổi root: dừng mọi run, giữ bản sao `.lab-ca/` ở nơi riêng tư rồi chuyển thư mục đó ra khỏi đường dẫn này trước lần setup kế tiếp. Root mới yêu cầu xác minh fingerprint và cập nhật trust trình duyệt. Không đưa `.lab-ca/root.key` lên máy trình duyệt và không dùng CA này cho hệ thống thật.


## Trình diễn trên trình duyệt thật (ví dụ qua Tailscale)

Trong phiên Bash hướng dẫn ở trên, gateway được bật và gỡ trong cùng lifecycle. Muốn tự điều khiển từng action và giữ deployment sau khi script thoát, dùng action `setup --bind` hoặc `browser`. Gateway là service tùy chọn `browser` (Compose profile `browser`), publish cổng 443 và 80 chỉ trên địa chỉ chỉ định:

- `:443` chuyển tiếp TCP thẳng (không giải mã TLS) đến nơi resolver lab đang trỏ `login.payroll.test`, nên trình duyệt thấy đúng chứng chỉ của Nginx hợp lệ/attacker và đi theo cả attack lẫn recover.
- `:80` với `crl.payroll.test` phục vụ CRL dạng DER (`root.crl`, `intermediate.crl`, `replacement-intermediate.crl`, `Cache-Control: no-store`) và `root.crt` công khai. Mọi chứng chỉ không phải root đều có CRL Distribution Point trỏ về đây.
- `:80` với `ocsp.payroll.test` chuyển tiếp nguyên vẹn đến responder `ocsp` của lab. Chỉ CA trung gian (cũ và thay thế) có URL OCSP (Authority Information Access); leaf chỉ dùng CRL. Chrome/Edge hỏi OCSP trước: `GOOD`/`REVOKED` là kết luận, responder lỗi hoặc `UNKNOWN` thì quay về CRL.

```bash
bash start-demo.sh --action setup --bind "$(tailscale ip -4)"     # setup + browser qua Tailscale
# Hoặc chỉ định IP thủ công (không cần Tailscale CLI):
python3 demo.py --action setup --bind 100.x.y.z
# Với deployment đã tồn tại:
python3 demo.py --action browser --run-id ID --bind 100.x.y.z
```

Lệnh setup với `--bind` in JSON gồm `run_id`, `site` (URL trình duyệt), `hosts_entry`, `root_certificate` và `root_sha256`. Lab tiếp tục chạy sau khi script thoát; dùng `bash start-demo.sh --action down --run-id ID` để dọn. Mỗi lần setup tạo lab mới nhưng tái sử dụng root trong `.lab-ca/`; dừng lab cũ trước khi chạy lại để tránh trùng cổng.

Trên máy trình chiếu dùng một lần (nếu dùng Tailscale thì phải nằm trong tailnet):

1. Thêm vào file hosts (`C:\Windows\System32\drivers\etc\hosts` hoặc `/etc/hosts`) dòng `hosts_entry` in ra: `100.x.y.z login.payroll.test crl.payroll.test ocsp.payroll.test`.
2. Tải `http://crl.payroll.test/root.crt` (hoặc lấy `.lab-ca/root.crt` hay `runs/ID/public/root.crt` trên Docker host). So **fingerprint SHA-256 của chứng chỉ DER**, không phải hash file PEM, với `root_sha256`. Linux/macOS tùy chọn: `openssl x509 -in root.crt -noout -fingerprint -sha256`; bỏ dấu hai chấm và so không phân biệt hoa/thường. Windows: `certutil -decode root.crt root.der`, sau đó `certutil -hashfile root.der SHA256`. Xác minh xong mới import vào kho root tin cậy (Windows user store: `certutil -user -addstore Root root.crt`). Chỉ dùng máy/profile lab dùng một lần. Root giữ nguyên qua các `setup` trong cùng checkout; chỉ import lại nếu đổi root hoặc tạo profile lab mới, và xóa trust khi không dùng lab nữa.
3. Bật kiểm tra thu hồi bắt buộc (hard-fail) cho root cục bộ trên Chrome/Edge bằng policy `RequireOnlineRevocationChecksForLocalAnchors`. Windows (PowerShell admin): `reg add HKLM\SOFTWARE\Policies\Google\Chrome /v RequireOnlineRevocationChecksForLocalAnchors /t REG_DWORD /d 1 /f` (Edge: `HKLM\SOFTWARE\Policies\Microsoft\Edge`); Linux Chrome: file JSON `{ "RequireOnlineRevocationChecksForLocalAnchors": true }` trong `/etc/opt/chrome/policies/managed/`. Kiểm tra tại `chrome://policy` hoặc `edge://policy`, khởi động lại browser nếu cần. Edge trên macOS không hỗ trợ policy này. Thiếu policy, Chrome/Edge có thể vẫn chấp nhận chứng chỉ bị thu hồi. Firefox không tải CRL. Tự gỡ hosts/trust/policy sau phiên lab; `down` chỉ gỡ Docker.

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

Browser là client được cấu hình riêng: ở `untrusted`, probe terminal dùng root không liên quan và từ chối, còn browser đã tin root lab có thể hiện attacker. `hostname` chỉ probe `other.payroll.test`; không thêm tên này vào hosts, site browser bình thường vẫn là attacker. Ở `unchecked`, chỉ probe terminal tắt CRL; browser giữ policy hard-fail vẫn phải từ chối. Không gỡ root, đổi policy hay bỏ qua lỗi browser để bắt chước từng probe.

## Mô hình mạng và khóa

Sáu service trên một network `internal`, không publish cổng, không host networking, không Docker socket (ngoại lệ duy nhất: gateway tùy chọn `browser` ở trên, nối thêm network `edge` để publish cổng):

- `ca`: image tools, `network_mode: none`, chỉ nơi này nhận khóa private của Root và CA trung gian. Root dùng chung được lưu trong `.lab-ca/`, với bản sao trong `runs/<id>/ca-private/` để từng run ký CRL độc lập; chỉ host và container CA đọc được, không bao giờ đưa khóa vào JSON/log.
- `legitimate`: Nginx chỉ mount `legitimate/` (leaf + chain) read-only.
- `attacker`: image riêng, chỉ nhận `leak/` (chứng chỉ + khóa CA trung gian bị lộ) read-only và `attacker/` ghi được; không có khóa CA-private hay khóa leaf hợp lệ.
- `dns`: dnsmasq với `no-resolv`, `local=/test/`, `cache-size=0`, không chuyển tiếp ra ngoài.
- `ocsp`: `openssl ocsp` (GET và POST) đọc bản sao công khai `ocsp/index.txt` của cơ sở dữ liệu Root CA, ký bằng chứng chỉ responder ủy quyền (Root cấp, EKU OCSPSigning, OCSPNoCheck); chỉ mount `ocsp/` read-only, không nhận `root.key`. Mỗi lần CA đổi trạng thái thu hồi, `publish-trust` cập nhật `ocsp/index.txt` và `demo.py` khởi động lại responder (`openssl ocsp` chỉ kiểm tra index trước khi chờ kết nối kế tiếp nên câu trả lời đầu tiên sau thay đổi sẽ cũ). Gọi `revoke-cert.sh` thủ công thì cần `docker compose -p pki-lab-ID restart ocsp`.
- `victim`: không mount khóa nào; chỉ `public/` (chứng chỉ/CRL công khai) và `dns/resolv.conf` trỏ thẳng địa chỉ DNS của lab. Mỗi quan sát là một process mới; truy vấn OCSP cũng chạy trong `victim` (POST đến địa chỉ container `ocsp` với `Host` lấy từ URL trong chứng chỉ).

Attack = resolver lab đổi bản ghi `login.payroll.test` sang Nginx giả rồi SIGHUP dnsmasq; recovery đổi lại. Đây là chuyển hướng DNS/resolver bị chiếm, không phải giả gói tin hay đầu độc cache. Không nhắm mục tiêu ngoài lab, không thu credential.

Bằng chứng mỗi lần chạy nằm trong `runs/<id>/`: `results.json` (gồm trường `ocsp` của các bước có hỏi OCSP), `revocation.txt`, `state.json`, `docker.log` (log DNS/OCSP/Nginx có timestamp) và chứng chỉ/CRL công khai. `latest-results.json` chỉ được cập nhật bởi lần chạy thật hoàn tất.

## Giới hạn

Revocation chỉ có hiệu lực khi client thực thi kiểm tra thu hồi; đây chính là bài học của bước `unchecked`. Client TLS trong lab dùng bundle cục bộ, không tự tải CRL/OCSP; trạng thái OCSP là truy vấn riêng, không chặn kết nối TLS. OCSP chỉ phủ cấp CA (CA trung gian cũ và thay thế); leaf, kể cả leaf của attacker, chỉ có CRL. Browser không tự bị chuyển hướng hay tin CA lab: cần hosts/trust/policy thủ công như trên và khác victim. Lộ khóa CA không suy ra khóa phiên TLS 1.3 lịch sử. Khóa trong `runs/` và `.lab-ca/` chỉ dùng cho lab: quản trị viên host vẫn đọc được, ranh giới cô lập là giữa các container, không phải chống host. Các run dùng chung trust anchor nhưng không chia sẻ lịch sử thu hồi; CRL/OCSP của một run chỉ mô tả run đó, không phải dịch vụ CA dùng chung cho production. Không dùng lại chứng chỉ từ run cũ trong run mới.

Nguồn: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [OpenSSL verification options](https://docs.openssl.org/3.6/man1/openssl-verification-options/), [OpenSSL ca](https://docs.openssl.org/3.6/man1/openssl-ca/), [OpenSSL ocsp](https://docs.openssl.org/3.0/man1/openssl-ocsp/).
