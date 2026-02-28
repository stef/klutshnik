# Example session

```
% klutshnik create keyid1
KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAAAUjWZfmo4B3a3i+Ii+KMS7L5d/vMyxpMUEvUMjJPWAQM=
% echo "HELLO world" | klutshnik encrypt KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAAAUjWZfmo4B3a3i+Ii+KMS7L5d/vMyxpMUEvUMjJPWAQM= >/tmp/encrypted
% xxd /tmp/encrypted
00000000: 5e12 0ef6 0b17 7341 091a 5145 80bc 65a6  ^.....sA..QE..e.
00000010: c544 dfda 64de 0460 cca9 0f83 881b 820d  .D..d..`........
00000020: 0000 0000 fc2f 2e5b e52f 341f 0874 6771  ...../.[./4..tgq
00000030: 0174 aba4 b489 44ff dd0e f291 5502 5ee6  .t....D.....U.^.
00000040: 3de7 a93b 63f2 22c7 886d 816b b26a 8447  =..;c."..m.k.j.G
00000050: 1aa7 2b81 36e1 3329 f517 2658 3ad1 7100  ..+.6.3)..&X:.q.
00000060: e5c1 8560 395b 1957 3c00 7176            ...`9[.W<.qv

% klutshnik decrypt </tmp/encrypted
HELLO world
% klutshnik rotate "keyid1"
KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABkD+jW5DoYBln2WJQ74gySEWhtM4bxbyJkeDgTcpNLVA=
KLCDELTA-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABk4hPN4VKb6lxeZO0hXEx1e/iGWQvYAIXQvu2pbIrQQQ=
% printf "KLCDELTA-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABk4hPN4VKb6lxeZO0hXEx1e/iGWQvYAIXQvu2pbIrQQQ=\n/tmp/encrypted" | klutshnik update keyid1
% xxd /tmp/encrypted
00000000: 5e12 0ef6 0b17 7341 091a 5145 80bc 65a6  ^.....sA..QE..e.
00000010: c544 dfda 64de 0460 cca9 0f83 881b 820d  .D..d..`........
00000020: 0000 0001 bc9b 0104 283b 7aa8 2939 d0f5  ........(;z.)9..
00000030: 89a8 eda3 f665 995f 499b d895 04da 9238  .....e._I......8
00000040: 5db1 8d05 63f2 22c7 886d 816b b26a 8447  ]...c."..m.k.j.G
00000050: 1aa7 2b81 36e1 3329 f517 2658 3ad1 7100  ..+.6.3)..&X:.q.
00000060: e5c1 8560 395b 1957 3c00 7176            ...`9[.W<.qv

% klutshnik decrypt </tmp/encrypted
HELLO world
```

# File formats

Encrypted files have the following structure:

```
16 bytes keyid
4 bytes epoch
32 bytes w value
12 byte nonce-half
every 64KB
    64 kBytes ciphertext (chacha20)
    16 bytes MAC (poly1305)
```
