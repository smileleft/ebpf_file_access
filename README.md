# ebpf_file_access
file access control with eBPF

프로젝트 빌드 및 실행 (사전에 Go 설치 필요)

- 빌드

```bash
make build
```

go generate 가 bpf_file_acl.go 파일을 생성하고 go build가 실행 파일을 생성함.

제대로 빌드되면 file-access-control 이라는 바이너리 파일이 생성됨

- 실행

```bash
sudo ./file-access-control
```

프로그램이 실행되면 “eBPF program loaded and attached…” 메시지가 출력됨

- 동작테스트
    - 새로운 터미널을 열고 다음 명령어를 실행하여 /tmp/secret.txt 파일에 접근을 시도
    - (사전에) 비밀 파일 생성(루트 권한)
    
    ```bash
    sudo touch /tmp/secret.txt
    ```
    
    - 파일 읽기 시도(eBPF 가 로드된 상태에서)
    
    ```bash
    cat /tmp/secret.txt
    ```
    
    이 명령은 Permission Denied 에러와 함께 실패해야 함
    
    ```bash
    echo "test" > /tmp/secret.txt
    ```
    
    이 명령도 Premission Denied 에러와 함께 실패해야 함
    
- eBPF 로그확인
    
    ```bash
    sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "Blocking access"
    # or
    sudo bpftool prog tracelog
    ```
    
- eBPF 프로그램 종료
    
    sudo ./file-access-control 을 실행한 터미널에서 Ctrl+C 로 종료
    
- 파일 읽기 다시 시도(eBPF가 언로드된 상태에서)
    
    ```bash
    cat /tmp/secret.txt
    ```
    
    파일이 정상적으로 읽혀야 함
