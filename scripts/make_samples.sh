#!/usr/bin/env bash
# 重新生成 samples/ 下的 PKI 样例。
#
# 样例集包含：RSA 证书、ECC 证书、3 张证书的 chain.pem、p7b。
# 本脚本一次性重建自包含的样例集：
#   root.pem/der        RSA-2048 自签根 CA
#   intermediate.pem/der RSA-2048 中间 CA（root 签发）
#   leaf.pem/der        RSA-2048 证书（intermediate 签发，带 SAN）
#   ecc.pem/der         ECC P-256 证书（root 直接签发，带 SAN）
#   chain.pem           leaf + intermediate + root 三张证书
#   certs.p7b           chain 的 PKCS#7/CMS 容器（DER，p7b 闭环用）
#   ber-indefinite.bin  手工构造样例，不重新生成（保持不变）
#
# 注意：每次运行都会生成新密钥，样例字节不同但结构相同；测试只依赖结构。
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(pwd)/samples"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

CA_ROOT_SUBJECT="/C=CN/O=asn1peek/OU=QA/CN=asn1peek Root CA"
CA_INT_SUBJECT="/C=CN/O=asn1peek/OU=QA/CN=asn1peek Intermediate CA"
LEAF_SUBJECT="/C=CN/O=asn1peek/OU=QA/CN=asn1peek Leaf"
ECC_SUBJECT="/C=CN/O=asn1peek/OU=QA/CN=asn1peek ECC Leaf"

# ---- 根 CA（自签，默认 v3_ca：basicConstraints=CA:TRUE） ----
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root.key 2>/dev/null
openssl req -x509 -new -key root.key -sha256 -days 3650 \
  -subj "$CA_ROOT_SUBJECT" -out root.pem

# ---- 中间 CA ----
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out int.key 2>/dev/null
openssl req -new -key int.key \
  -subj "$CA_INT_SUBJECT" -out int.csr
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -sha256 -days 1825 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n") \
  -out intermediate.pem

# ---- 叶子证书（RSA，intermediate 签发，带 SAN） ----
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf.key 2>/dev/null
openssl req -new -key leaf.key \
  -subj "$LEAF_SUBJECT" -out leaf.csr
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey int.key -sha256 -days 365 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nsubjectAltName=DNS:leaf.asn1peek.local\n") \
  -out leaf.pem

# ---- ECC 证书（P-256，root 直接签发，带 SAN） ----
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ecc.key 2>/dev/null
openssl req -new -key ecc.key \
  -subj "$ECC_SUBJECT" -out ecc.csr
openssl x509 -req -in ecc.csr -CA root.pem -CAkey root.key -sha256 -days 365 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectAltName=DNS:ecc.asn1peek.local\n") \
  -out ecc.pem

# ---- 证书链（3 张）与 p7b ----
cat leaf.pem intermediate.pem root.pem > chain.pem
openssl crl2pkcs7 -nocrl \
  -certfile leaf.pem -certfile intermediate.pem -certfile root.pem \
  -outform der -out certs.p7b

# ---- DER 版本 ----
openssl x509 -in leaf.pem -outform der -out leaf.der
openssl x509 -in root.pem -outform der -out root.der
openssl x509 -in ecc.pem -outform der -out ecc.der
openssl x509 -in intermediate.pem -outform der -out intermediate.der

# ---- 入库 ----
install -m 0644 root.pem root.der intermediate.pem intermediate.der \
  leaf.pem leaf.der ecc.pem ecc.der chain.pem certs.p7b "$OUT"/

# ---- 自检：链验证 + p7b 内容 ----
openssl verify -CAfile "$OUT/root.pem" -untrusted "$OUT/intermediate.pem" "$OUT/leaf.pem"
openssl pkcs7 -inform der -in "$OUT/certs.p7b" -print_certs | grep -c "BEGIN CERTIFICATE"
echo "[ok] samples 更新完成"
