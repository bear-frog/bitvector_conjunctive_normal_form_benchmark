import struct
import socket
import random
import argparse

def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

ACL_ANY_PORT = 65536

def generate_acl_mock_rules(num_rules, out_file):
    # 내부 대역(Edge case) 재현을 위한 범용 사설 IP 풀 구성
    TEST_IP_POOL = [ip_to_int(f"10.0.0.{i}") for i in range(1, 51)] + [ip_to_int(f"192.168.1.{i}") for i in range(1, 51)]
    
    # 교차 매칭(Cross-matching) 결함 유도를 위한 주요 포트 풀 축소
    TEST_PORT_POOL = [80, 443, 22, 53, 8080]

    print(f"[*] 무작위 ACL 룰 {num_rules:,}개 생성 시작...")
    
    # 시드 고정을 해제하여 매번 다른 룰이 생성되도록 함
    random.seed()

    rules = []
    for _ in range(num_rules):
        r_sip = random.choice(TEST_IP_POOL) if random.random() < 0.7 else (0 if random.random() < 0.3 else random.randint(0x01000000, 0xE0000000))
        r_dip = random.choice(TEST_IP_POOL) if random.random() < 0.7 else (0 if random.random() < 0.3 else random.randint(0x01000000, 0xE0000000))
        
        r_sp = random.choice(TEST_PORT_POOL) if random.random() < 0.45 else (ACL_ANY_PORT if random.random() < 0.82 else random.randint(1000, 60000))
        r_dp = random.choice(TEST_PORT_POOL) if random.random() < 0.45 else (ACL_ANY_PORT if random.random() < 0.82 else random.randint(1000, 60000))
        
        rules.append((r_sip, r_dip, r_sp, r_dp))

    with open(out_file, "w") as f:
        f.write("[RULES]\n")
        for r_sip, r_dip, r_sp, r_dp in rules:
            f.write(f"{r_sip},{r_dip},{r_sp},{r_dp}\n")

    print(f"[+] {out_file} 생성 완료! (룰: {num_rules:,}개)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACL Engine Mock Rule Generator")
    parser.add_argument("-r", "--rules", type=int, default=500, help="Number of rules to generate")
    parser.add_argument("-o", "--output", type=str, default="mock.rule", help="Output file name")
    args = parser.parse_args()
    
    generate_acl_mock_rules(args.rules, args.output)
