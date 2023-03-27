
moon-buggy:     file format elf64-x86-64


Disassembly of section .init:

0000000000007000 <_init>:
    7000:	f3 0f 1e fa          	endbr64 
    7004:	48 83 ec 08          	sub    $0x8,%rsp
    7008:	48 8b 05 d1 7f 01 00 	mov    0x17fd1(%rip),%rax        # 1efe0 <__gmon_start__>
    700f:	48 85 c0             	test   %rax,%rax
    7012:	74 02                	je     7016 <_init+0x16>
    7014:	ff d0                	callq  *%rax
    7016:	48 83 c4 08          	add    $0x8,%rsp
    701a:	c3                   	retq   

Disassembly of section .plt:

0000000000007020 <.plt>:
    7020:	ff 35 62 7c 01 00    	pushq  0x17c62(%rip)        # 1ec88 <_GLOBAL_OFFSET_TABLE_+0x8>
    7026:	f2 ff 25 63 7c 01 00 	bnd jmpq *0x17c63(%rip)        # 1ec90 <_GLOBAL_OFFSET_TABLE_+0x10>
    702d:	0f 1f 00             	nopl   (%rax)
    7030:	f3 0f 1e fa          	endbr64 
    7034:	68 00 00 00 00       	pushq  $0x0
    7039:	f2 e9 e1 ff ff ff    	bnd jmpq 7020 <.plt>
    703f:	90                   	nop
    7040:	f3 0f 1e fa          	endbr64 
    7044:	68 01 00 00 00       	pushq  $0x1
    7049:	f2 e9 d1 ff ff ff    	bnd jmpq 7020 <.plt>
    704f:	90                   	nop
    7050:	f3 0f 1e fa          	endbr64 
    7054:	68 02 00 00 00       	pushq  $0x2
    7059:	f2 e9 c1 ff ff ff    	bnd jmpq 7020 <.plt>
    705f:	90                   	nop
    7060:	f3 0f 1e fa          	endbr64 
    7064:	68 03 00 00 00       	pushq  $0x3
    7069:	f2 e9 b1 ff ff ff    	bnd jmpq 7020 <.plt>
    706f:	90                   	nop
    7070:	f3 0f 1e fa          	endbr64 
    7074:	68 04 00 00 00       	pushq  $0x4
    7079:	f2 e9 a1 ff ff ff    	bnd jmpq 7020 <.plt>
    707f:	90                   	nop
    7080:	f3 0f 1e fa          	endbr64 
    7084:	68 05 00 00 00       	pushq  $0x5
    7089:	f2 e9 91 ff ff ff    	bnd jmpq 7020 <.plt>
    708f:	90                   	nop
    7090:	f3 0f 1e fa          	endbr64 
    7094:	68 06 00 00 00       	pushq  $0x6
    7099:	f2 e9 81 ff ff ff    	bnd jmpq 7020 <.plt>
    709f:	90                   	nop
    70a0:	f3 0f 1e fa          	endbr64 
    70a4:	68 07 00 00 00       	pushq  $0x7
    70a9:	f2 e9 71 ff ff ff    	bnd jmpq 7020 <.plt>
    70af:	90                   	nop
    70b0:	f3 0f 1e fa          	endbr64 
    70b4:	68 08 00 00 00       	pushq  $0x8
    70b9:	f2 e9 61 ff ff ff    	bnd jmpq 7020 <.plt>
    70bf:	90                   	nop
    70c0:	f3 0f 1e fa          	endbr64 
    70c4:	68 09 00 00 00       	pushq  $0x9
    70c9:	f2 e9 51 ff ff ff    	bnd jmpq 7020 <.plt>
    70cf:	90                   	nop
    70d0:	f3 0f 1e fa          	endbr64 
    70d4:	68 0a 00 00 00       	pushq  $0xa
    70d9:	f2 e9 41 ff ff ff    	bnd jmpq 7020 <.plt>
    70df:	90                   	nop
    70e0:	f3 0f 1e fa          	endbr64 
    70e4:	68 0b 00 00 00       	pushq  $0xb
    70e9:	f2 e9 31 ff ff ff    	bnd jmpq 7020 <.plt>
    70ef:	90                   	nop
    70f0:	f3 0f 1e fa          	endbr64 
    70f4:	68 0c 00 00 00       	pushq  $0xc
    70f9:	f2 e9 21 ff ff ff    	bnd jmpq 7020 <.plt>
    70ff:	90                   	nop
    7100:	f3 0f 1e fa          	endbr64 
    7104:	68 0d 00 00 00       	pushq  $0xd
    7109:	f2 e9 11 ff ff ff    	bnd jmpq 7020 <.plt>
    710f:	90                   	nop
    7110:	f3 0f 1e fa          	endbr64 
    7114:	68 0e 00 00 00       	pushq  $0xe
    7119:	f2 e9 01 ff ff ff    	bnd jmpq 7020 <.plt>
    711f:	90                   	nop
    7120:	f3 0f 1e fa          	endbr64 
    7124:	68 0f 00 00 00       	pushq  $0xf
    7129:	f2 e9 f1 fe ff ff    	bnd jmpq 7020 <.plt>
    712f:	90                   	nop
    7130:	f3 0f 1e fa          	endbr64 
    7134:	68 10 00 00 00       	pushq  $0x10
    7139:	f2 e9 e1 fe ff ff    	bnd jmpq 7020 <.plt>
    713f:	90                   	nop
    7140:	f3 0f 1e fa          	endbr64 
    7144:	68 11 00 00 00       	pushq  $0x11
    7149:	f2 e9 d1 fe ff ff    	bnd jmpq 7020 <.plt>
    714f:	90                   	nop
    7150:	f3 0f 1e fa          	endbr64 
    7154:	68 12 00 00 00       	pushq  $0x12
    7159:	f2 e9 c1 fe ff ff    	bnd jmpq 7020 <.plt>
    715f:	90                   	nop
    7160:	f3 0f 1e fa          	endbr64 
    7164:	68 13 00 00 00       	pushq  $0x13
    7169:	f2 e9 b1 fe ff ff    	bnd jmpq 7020 <.plt>
    716f:	90                   	nop
    7170:	f3 0f 1e fa          	endbr64 
    7174:	68 14 00 00 00       	pushq  $0x14
    7179:	f2 e9 a1 fe ff ff    	bnd jmpq 7020 <.plt>
    717f:	90                   	nop
    7180:	f3 0f 1e fa          	endbr64 
    7184:	68 15 00 00 00       	pushq  $0x15
    7189:	f2 e9 91 fe ff ff    	bnd jmpq 7020 <.plt>
    718f:	90                   	nop
    7190:	f3 0f 1e fa          	endbr64 
    7194:	68 16 00 00 00       	pushq  $0x16
    7199:	f2 e9 81 fe ff ff    	bnd jmpq 7020 <.plt>
    719f:	90                   	nop
    71a0:	f3 0f 1e fa          	endbr64 
    71a4:	68 17 00 00 00       	pushq  $0x17
    71a9:	f2 e9 71 fe ff ff    	bnd jmpq 7020 <.plt>
    71af:	90                   	nop
    71b0:	f3 0f 1e fa          	endbr64 
    71b4:	68 18 00 00 00       	pushq  $0x18
    71b9:	f2 e9 61 fe ff ff    	bnd jmpq 7020 <.plt>
    71bf:	90                   	nop
    71c0:	f3 0f 1e fa          	endbr64 
    71c4:	68 19 00 00 00       	pushq  $0x19
    71c9:	f2 e9 51 fe ff ff    	bnd jmpq 7020 <.plt>
    71cf:	90                   	nop
    71d0:	f3 0f 1e fa          	endbr64 
    71d4:	68 1a 00 00 00       	pushq  $0x1a
    71d9:	f2 e9 41 fe ff ff    	bnd jmpq 7020 <.plt>
    71df:	90                   	nop
    71e0:	f3 0f 1e fa          	endbr64 
    71e4:	68 1b 00 00 00       	pushq  $0x1b
    71e9:	f2 e9 31 fe ff ff    	bnd jmpq 7020 <.plt>
    71ef:	90                   	nop
    71f0:	f3 0f 1e fa          	endbr64 
    71f4:	68 1c 00 00 00       	pushq  $0x1c
    71f9:	f2 e9 21 fe ff ff    	bnd jmpq 7020 <.plt>
    71ff:	90                   	nop
    7200:	f3 0f 1e fa          	endbr64 
    7204:	68 1d 00 00 00       	pushq  $0x1d
    7209:	f2 e9 11 fe ff ff    	bnd jmpq 7020 <.plt>
    720f:	90                   	nop
    7210:	f3 0f 1e fa          	endbr64 
    7214:	68 1e 00 00 00       	pushq  $0x1e
    7219:	f2 e9 01 fe ff ff    	bnd jmpq 7020 <.plt>
    721f:	90                   	nop
    7220:	f3 0f 1e fa          	endbr64 
    7224:	68 1f 00 00 00       	pushq  $0x1f
    7229:	f2 e9 f1 fd ff ff    	bnd jmpq 7020 <.plt>
    722f:	90                   	nop
    7230:	f3 0f 1e fa          	endbr64 
    7234:	68 20 00 00 00       	pushq  $0x20
    7239:	f2 e9 e1 fd ff ff    	bnd jmpq 7020 <.plt>
    723f:	90                   	nop
    7240:	f3 0f 1e fa          	endbr64 
    7244:	68 21 00 00 00       	pushq  $0x21
    7249:	f2 e9 d1 fd ff ff    	bnd jmpq 7020 <.plt>
    724f:	90                   	nop
    7250:	f3 0f 1e fa          	endbr64 
    7254:	68 22 00 00 00       	pushq  $0x22
    7259:	f2 e9 c1 fd ff ff    	bnd jmpq 7020 <.plt>
    725f:	90                   	nop
    7260:	f3 0f 1e fa          	endbr64 
    7264:	68 23 00 00 00       	pushq  $0x23
    7269:	f2 e9 b1 fd ff ff    	bnd jmpq 7020 <.plt>
    726f:	90                   	nop
    7270:	f3 0f 1e fa          	endbr64 
    7274:	68 24 00 00 00       	pushq  $0x24
    7279:	f2 e9 a1 fd ff ff    	bnd jmpq 7020 <.plt>
    727f:	90                   	nop
    7280:	f3 0f 1e fa          	endbr64 
    7284:	68 25 00 00 00       	pushq  $0x25
    7289:	f2 e9 91 fd ff ff    	bnd jmpq 7020 <.plt>
    728f:	90                   	nop
    7290:	f3 0f 1e fa          	endbr64 
    7294:	68 26 00 00 00       	pushq  $0x26
    7299:	f2 e9 81 fd ff ff    	bnd jmpq 7020 <.plt>
    729f:	90                   	nop
    72a0:	f3 0f 1e fa          	endbr64 
    72a4:	68 27 00 00 00       	pushq  $0x27
    72a9:	f2 e9 71 fd ff ff    	bnd jmpq 7020 <.plt>
    72af:	90                   	nop
    72b0:	f3 0f 1e fa          	endbr64 
    72b4:	68 28 00 00 00       	pushq  $0x28
    72b9:	f2 e9 61 fd ff ff    	bnd jmpq 7020 <.plt>
    72bf:	90                   	nop
    72c0:	f3 0f 1e fa          	endbr64 
    72c4:	68 29 00 00 00       	pushq  $0x29
    72c9:	f2 e9 51 fd ff ff    	bnd jmpq 7020 <.plt>
    72cf:	90                   	nop
    72d0:	f3 0f 1e fa          	endbr64 
    72d4:	68 2a 00 00 00       	pushq  $0x2a
    72d9:	f2 e9 41 fd ff ff    	bnd jmpq 7020 <.plt>
    72df:	90                   	nop
    72e0:	f3 0f 1e fa          	endbr64 
    72e4:	68 2b 00 00 00       	pushq  $0x2b
    72e9:	f2 e9 31 fd ff ff    	bnd jmpq 7020 <.plt>
    72ef:	90                   	nop
    72f0:	f3 0f 1e fa          	endbr64 
    72f4:	68 2c 00 00 00       	pushq  $0x2c
    72f9:	f2 e9 21 fd ff ff    	bnd jmpq 7020 <.plt>
    72ff:	90                   	nop
    7300:	f3 0f 1e fa          	endbr64 
    7304:	68 2d 00 00 00       	pushq  $0x2d
    7309:	f2 e9 11 fd ff ff    	bnd jmpq 7020 <.plt>
    730f:	90                   	nop
    7310:	f3 0f 1e fa          	endbr64 
    7314:	68 2e 00 00 00       	pushq  $0x2e
    7319:	f2 e9 01 fd ff ff    	bnd jmpq 7020 <.plt>
    731f:	90                   	nop
    7320:	f3 0f 1e fa          	endbr64 
    7324:	68 2f 00 00 00       	pushq  $0x2f
    7329:	f2 e9 f1 fc ff ff    	bnd jmpq 7020 <.plt>
    732f:	90                   	nop
    7330:	f3 0f 1e fa          	endbr64 
    7334:	68 30 00 00 00       	pushq  $0x30
    7339:	f2 e9 e1 fc ff ff    	bnd jmpq 7020 <.plt>
    733f:	90                   	nop
    7340:	f3 0f 1e fa          	endbr64 
    7344:	68 31 00 00 00       	pushq  $0x31
    7349:	f2 e9 d1 fc ff ff    	bnd jmpq 7020 <.plt>
    734f:	90                   	nop
    7350:	f3 0f 1e fa          	endbr64 
    7354:	68 32 00 00 00       	pushq  $0x32
    7359:	f2 e9 c1 fc ff ff    	bnd jmpq 7020 <.plt>
    735f:	90                   	nop
    7360:	f3 0f 1e fa          	endbr64 
    7364:	68 33 00 00 00       	pushq  $0x33
    7369:	f2 e9 b1 fc ff ff    	bnd jmpq 7020 <.plt>
    736f:	90                   	nop
    7370:	f3 0f 1e fa          	endbr64 
    7374:	68 34 00 00 00       	pushq  $0x34
    7379:	f2 e9 a1 fc ff ff    	bnd jmpq 7020 <.plt>
    737f:	90                   	nop
    7380:	f3 0f 1e fa          	endbr64 
    7384:	68 35 00 00 00       	pushq  $0x35
    7389:	f2 e9 91 fc ff ff    	bnd jmpq 7020 <.plt>
    738f:	90                   	nop
    7390:	f3 0f 1e fa          	endbr64 
    7394:	68 36 00 00 00       	pushq  $0x36
    7399:	f2 e9 81 fc ff ff    	bnd jmpq 7020 <.plt>
    739f:	90                   	nop
    73a0:	f3 0f 1e fa          	endbr64 
    73a4:	68 37 00 00 00       	pushq  $0x37
    73a9:	f2 e9 71 fc ff ff    	bnd jmpq 7020 <.plt>
    73af:	90                   	nop
    73b0:	f3 0f 1e fa          	endbr64 
    73b4:	68 38 00 00 00       	pushq  $0x38
    73b9:	f2 e9 61 fc ff ff    	bnd jmpq 7020 <.plt>
    73bf:	90                   	nop
    73c0:	f3 0f 1e fa          	endbr64 
    73c4:	68 39 00 00 00       	pushq  $0x39
    73c9:	f2 e9 51 fc ff ff    	bnd jmpq 7020 <.plt>
    73cf:	90                   	nop
    73d0:	f3 0f 1e fa          	endbr64 
    73d4:	68 3a 00 00 00       	pushq  $0x3a
    73d9:	f2 e9 41 fc ff ff    	bnd jmpq 7020 <.plt>
    73df:	90                   	nop
    73e0:	f3 0f 1e fa          	endbr64 
    73e4:	68 3b 00 00 00       	pushq  $0x3b
    73e9:	f2 e9 31 fc ff ff    	bnd jmpq 7020 <.plt>
    73ef:	90                   	nop
    73f0:	f3 0f 1e fa          	endbr64 
    73f4:	68 3c 00 00 00       	pushq  $0x3c
    73f9:	f2 e9 21 fc ff ff    	bnd jmpq 7020 <.plt>
    73ff:	90                   	nop
    7400:	f3 0f 1e fa          	endbr64 
    7404:	68 3d 00 00 00       	pushq  $0x3d
    7409:	f2 e9 11 fc ff ff    	bnd jmpq 7020 <.plt>
    740f:	90                   	nop
    7410:	f3 0f 1e fa          	endbr64 
    7414:	68 3e 00 00 00       	pushq  $0x3e
    7419:	f2 e9 01 fc ff ff    	bnd jmpq 7020 <.plt>
    741f:	90                   	nop
    7420:	f3 0f 1e fa          	endbr64 
    7424:	68 3f 00 00 00       	pushq  $0x3f
    7429:	f2 e9 f1 fb ff ff    	bnd jmpq 7020 <.plt>
    742f:	90                   	nop
    7430:	f3 0f 1e fa          	endbr64 
    7434:	68 40 00 00 00       	pushq  $0x40
    7439:	f2 e9 e1 fb ff ff    	bnd jmpq 7020 <.plt>
    743f:	90                   	nop
    7440:	f3 0f 1e fa          	endbr64 
    7444:	68 41 00 00 00       	pushq  $0x41
    7449:	f2 e9 d1 fb ff ff    	bnd jmpq 7020 <.plt>
    744f:	90                   	nop
    7450:	f3 0f 1e fa          	endbr64 
    7454:	68 42 00 00 00       	pushq  $0x42
    7459:	f2 e9 c1 fb ff ff    	bnd jmpq 7020 <.plt>
    745f:	90                   	nop
    7460:	f3 0f 1e fa          	endbr64 
    7464:	68 43 00 00 00       	pushq  $0x43
    7469:	f2 e9 b1 fb ff ff    	bnd jmpq 7020 <.plt>
    746f:	90                   	nop
    7470:	f3 0f 1e fa          	endbr64 
    7474:	68 44 00 00 00       	pushq  $0x44
    7479:	f2 e9 a1 fb ff ff    	bnd jmpq 7020 <.plt>
    747f:	90                   	nop
    7480:	f3 0f 1e fa          	endbr64 
    7484:	68 45 00 00 00       	pushq  $0x45
    7489:	f2 e9 91 fb ff ff    	bnd jmpq 7020 <.plt>
    748f:	90                   	nop
    7490:	f3 0f 1e fa          	endbr64 
    7494:	68 46 00 00 00       	pushq  $0x46
    7499:	f2 e9 81 fb ff ff    	bnd jmpq 7020 <.plt>
    749f:	90                   	nop
    74a0:	f3 0f 1e fa          	endbr64 
    74a4:	68 47 00 00 00       	pushq  $0x47
    74a9:	f2 e9 71 fb ff ff    	bnd jmpq 7020 <.plt>
    74af:	90                   	nop
    74b0:	f3 0f 1e fa          	endbr64 
    74b4:	68 48 00 00 00       	pushq  $0x48
    74b9:	f2 e9 61 fb ff ff    	bnd jmpq 7020 <.plt>
    74bf:	90                   	nop
    74c0:	f3 0f 1e fa          	endbr64 
    74c4:	68 49 00 00 00       	pushq  $0x49
    74c9:	f2 e9 51 fb ff ff    	bnd jmpq 7020 <.plt>
    74cf:	90                   	nop
    74d0:	f3 0f 1e fa          	endbr64 
    74d4:	68 4a 00 00 00       	pushq  $0x4a
    74d9:	f2 e9 41 fb ff ff    	bnd jmpq 7020 <.plt>
    74df:	90                   	nop
    74e0:	f3 0f 1e fa          	endbr64 
    74e4:	68 4b 00 00 00       	pushq  $0x4b
    74e9:	f2 e9 31 fb ff ff    	bnd jmpq 7020 <.plt>
    74ef:	90                   	nop
    74f0:	f3 0f 1e fa          	endbr64 
    74f4:	68 4c 00 00 00       	pushq  $0x4c
    74f9:	f2 e9 21 fb ff ff    	bnd jmpq 7020 <.plt>
    74ff:	90                   	nop
    7500:	f3 0f 1e fa          	endbr64 
    7504:	68 4d 00 00 00       	pushq  $0x4d
    7509:	f2 e9 11 fb ff ff    	bnd jmpq 7020 <.plt>
    750f:	90                   	nop
    7510:	f3 0f 1e fa          	endbr64 
    7514:	68 4e 00 00 00       	pushq  $0x4e
    7519:	f2 e9 01 fb ff ff    	bnd jmpq 7020 <.plt>
    751f:	90                   	nop
    7520:	f3 0f 1e fa          	endbr64 
    7524:	68 4f 00 00 00       	pushq  $0x4f
    7529:	f2 e9 f1 fa ff ff    	bnd jmpq 7020 <.plt>
    752f:	90                   	nop
    7530:	f3 0f 1e fa          	endbr64 
    7534:	68 50 00 00 00       	pushq  $0x50
    7539:	f2 e9 e1 fa ff ff    	bnd jmpq 7020 <.plt>
    753f:	90                   	nop
    7540:	f3 0f 1e fa          	endbr64 
    7544:	68 51 00 00 00       	pushq  $0x51
    7549:	f2 e9 d1 fa ff ff    	bnd jmpq 7020 <.plt>
    754f:	90                   	nop
    7550:	f3 0f 1e fa          	endbr64 
    7554:	68 52 00 00 00       	pushq  $0x52
    7559:	f2 e9 c1 fa ff ff    	bnd jmpq 7020 <.plt>
    755f:	90                   	nop
    7560:	f3 0f 1e fa          	endbr64 
    7564:	68 53 00 00 00       	pushq  $0x53
    7569:	f2 e9 b1 fa ff ff    	bnd jmpq 7020 <.plt>
    756f:	90                   	nop
    7570:	f3 0f 1e fa          	endbr64 
    7574:	68 54 00 00 00       	pushq  $0x54
    7579:	f2 e9 a1 fa ff ff    	bnd jmpq 7020 <.plt>
    757f:	90                   	nop
    7580:	f3 0f 1e fa          	endbr64 
    7584:	68 55 00 00 00       	pushq  $0x55
    7589:	f2 e9 91 fa ff ff    	bnd jmpq 7020 <.plt>
    758f:	90                   	nop
    7590:	f3 0f 1e fa          	endbr64 
    7594:	68 56 00 00 00       	pushq  $0x56
    7599:	f2 e9 81 fa ff ff    	bnd jmpq 7020 <.plt>
    759f:	90                   	nop
    75a0:	f3 0f 1e fa          	endbr64 
    75a4:	68 57 00 00 00       	pushq  $0x57
    75a9:	f2 e9 71 fa ff ff    	bnd jmpq 7020 <.plt>
    75af:	90                   	nop
    75b0:	f3 0f 1e fa          	endbr64 
    75b4:	68 58 00 00 00       	pushq  $0x58
    75b9:	f2 e9 61 fa ff ff    	bnd jmpq 7020 <.plt>
    75bf:	90                   	nop
    75c0:	f3 0f 1e fa          	endbr64 
    75c4:	68 59 00 00 00       	pushq  $0x59
    75c9:	f2 e9 51 fa ff ff    	bnd jmpq 7020 <.plt>
    75cf:	90                   	nop
    75d0:	f3 0f 1e fa          	endbr64 
    75d4:	68 5a 00 00 00       	pushq  $0x5a
    75d9:	f2 e9 41 fa ff ff    	bnd jmpq 7020 <.plt>
    75df:	90                   	nop
    75e0:	f3 0f 1e fa          	endbr64 
    75e4:	68 5b 00 00 00       	pushq  $0x5b
    75e9:	f2 e9 31 fa ff ff    	bnd jmpq 7020 <.plt>
    75ef:	90                   	nop
    75f0:	f3 0f 1e fa          	endbr64 
    75f4:	68 5c 00 00 00       	pushq  $0x5c
    75f9:	f2 e9 21 fa ff ff    	bnd jmpq 7020 <.plt>
    75ff:	90                   	nop
    7600:	f3 0f 1e fa          	endbr64 
    7604:	68 5d 00 00 00       	pushq  $0x5d
    7609:	f2 e9 11 fa ff ff    	bnd jmpq 7020 <.plt>
    760f:	90                   	nop
    7610:	f3 0f 1e fa          	endbr64 
    7614:	68 5e 00 00 00       	pushq  $0x5e
    7619:	f2 e9 01 fa ff ff    	bnd jmpq 7020 <.plt>
    761f:	90                   	nop
    7620:	f3 0f 1e fa          	endbr64 
    7624:	68 5f 00 00 00       	pushq  $0x5f
    7629:	f2 e9 f1 f9 ff ff    	bnd jmpq 7020 <.plt>
    762f:	90                   	nop
    7630:	f3 0f 1e fa          	endbr64 
    7634:	68 60 00 00 00       	pushq  $0x60
    7639:	f2 e9 e1 f9 ff ff    	bnd jmpq 7020 <.plt>
    763f:	90                   	nop
    7640:	f3 0f 1e fa          	endbr64 
    7644:	68 61 00 00 00       	pushq  $0x61
    7649:	f2 e9 d1 f9 ff ff    	bnd jmpq 7020 <.plt>
    764f:	90                   	nop
    7650:	f3 0f 1e fa          	endbr64 
    7654:	68 62 00 00 00       	pushq  $0x62
    7659:	f2 e9 c1 f9 ff ff    	bnd jmpq 7020 <.plt>
    765f:	90                   	nop
    7660:	f3 0f 1e fa          	endbr64 
    7664:	68 63 00 00 00       	pushq  $0x63
    7669:	f2 e9 b1 f9 ff ff    	bnd jmpq 7020 <.plt>
    766f:	90                   	nop
    7670:	f3 0f 1e fa          	endbr64 
    7674:	68 64 00 00 00       	pushq  $0x64
    7679:	f2 e9 a1 f9 ff ff    	bnd jmpq 7020 <.plt>
    767f:	90                   	nop
    7680:	f3 0f 1e fa          	endbr64 
    7684:	68 65 00 00 00       	pushq  $0x65
    7689:	f2 e9 91 f9 ff ff    	bnd jmpq 7020 <.plt>
    768f:	90                   	nop
    7690:	f3 0f 1e fa          	endbr64 
    7694:	68 66 00 00 00       	pushq  $0x66
    7699:	f2 e9 81 f9 ff ff    	bnd jmpq 7020 <.plt>
    769f:	90                   	nop

Disassembly of section .plt.got:

00000000000076a0 <__cxa_finalize@plt>:
    76a0:	f3 0f 1e fa          	endbr64 
    76a4:	f2 ff 25 45 79 01 00 	bnd jmpq *0x17945(%rip)        # 1eff0 <__cxa_finalize@GLIBC_2.2.5>
    76ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

00000000000076b0 <wattrset@plt>:
    76b0:	f3 0f 1e fa          	endbr64 
    76b4:	f2 ff 25 dd 75 01 00 	bnd jmpq *0x175dd(%rip)        # 1ec98 <wattrset@NCURSES6_5.0.19991023>
    76bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000076c0 <werase@plt>:
    76c0:	f3 0f 1e fa          	endbr64 
    76c4:	f2 ff 25 d5 75 01 00 	bnd jmpq *0x175d5(%rip)        # 1eca0 <werase@NCURSES6_5.0.19991023>
    76cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000076d0 <sigprocmask@plt>:
    76d0:	f3 0f 1e fa          	endbr64 
    76d4:	f2 ff 25 cd 75 01 00 	bnd jmpq *0x175cd(%rip)        # 1eca8 <sigprocmask@GLIBC_2.2.5>
    76db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000076e0 <raise@plt>:
    76e0:	f3 0f 1e fa          	endbr64 
    76e4:	f2 ff 25 c5 75 01 00 	bnd jmpq *0x175c5(%rip)        # 1ecb0 <raise@GLIBC_2.2.5>
    76eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000076f0 <free@plt>:
    76f0:	f3 0f 1e fa          	endbr64 
    76f4:	f2 ff 25 bd 75 01 00 	bnd jmpq *0x175bd(%rip)        # 1ecb8 <free@GLIBC_2.2.5>
    76fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007700 <localtime@plt>:
    7700:	f3 0f 1e fa          	endbr64 
    7704:	f2 ff 25 b5 75 01 00 	bnd jmpq *0x175b5(%rip)        # 1ecc0 <localtime@GLIBC_2.2.5>
    770b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007710 <__vfprintf_chk@plt>:
    7710:	f3 0f 1e fa          	endbr64 
    7714:	f2 ff 25 ad 75 01 00 	bnd jmpq *0x175ad(%rip)        # 1ecc8 <__vfprintf_chk@GLIBC_2.3.4>
    771b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007720 <abort@plt>:
    7720:	f3 0f 1e fa          	endbr64 
    7724:	f2 ff 25 a5 75 01 00 	bnd jmpq *0x175a5(%rip)        # 1ecd0 <abort@GLIBC_2.2.5>
    772b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007730 <__errno_location@plt>:
    7730:	f3 0f 1e fa          	endbr64 
    7734:	f2 ff 25 9d 75 01 00 	bnd jmpq *0x1759d(%rip)        # 1ecd8 <__errno_location@GLIBC_2.2.5>
    773b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007740 <strncpy@plt>:
    7740:	f3 0f 1e fa          	endbr64 
    7744:	f2 ff 25 95 75 01 00 	bnd jmpq *0x17595(%rip)        # 1ece0 <strncpy@GLIBC_2.2.5>
    774b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007750 <newwin@plt>:
    7750:	f3 0f 1e fa          	endbr64 
    7754:	f2 ff 25 8d 75 01 00 	bnd jmpq *0x1758d(%rip)        # 1ece8 <newwin@NCURSES6_5.0.19991023>
    775b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007760 <strcpy@plt>:
    7760:	f3 0f 1e fa          	endbr64 
    7764:	f2 ff 25 85 75 01 00 	bnd jmpq *0x17585(%rip)        # 1ecf0 <strcpy@GLIBC_2.2.5>
    776b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007770 <__isoc99_fscanf@plt>:
    7770:	f3 0f 1e fa          	endbr64 
    7774:	f2 ff 25 7d 75 01 00 	bnd jmpq *0x1757d(%rip)        # 1ecf8 <__isoc99_fscanf@GLIBC_2.7>
    777b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007780 <curs_set@plt>:
    7780:	f3 0f 1e fa          	endbr64 
    7784:	f2 ff 25 75 75 01 00 	bnd jmpq *0x17575(%rip)        # 1ed00 <curs_set@NCURSES6_TINFO_5.0.19991023>
    778b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007790 <puts@plt>:
    7790:	f3 0f 1e fa          	endbr64 
    7794:	f2 ff 25 6d 75 01 00 	bnd jmpq *0x1756d(%rip)        # 1ed08 <puts@GLIBC_2.2.5>
    779b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000077a0 <ferror@plt>:
    77a0:	f3 0f 1e fa          	endbr64 
    77a4:	f2 ff 25 65 75 01 00 	bnd jmpq *0x17565(%rip)        # 1ed10 <ferror@GLIBC_2.2.5>
    77ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000077b0 <qsort@plt>:
    77b0:	f3 0f 1e fa          	endbr64 
    77b4:	f2 ff 25 5d 75 01 00 	bnd jmpq *0x1755d(%rip)        # 1ed18 <qsort@GLIBC_2.2.5>
    77bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000077c0 <isatty@plt>:
    77c0:	f3 0f 1e fa          	endbr64 
    77c4:	f2 ff 25 55 75 01 00 	bnd jmpq *0x17555(%rip)        # 1ed20 <isatty@GLIBC_2.2.5>
    77cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000077d0 <sigaction@plt>:
    77d0:	f3 0f 1e fa          	endbr64 
    77d4:	f2 ff 25 4d 75 01 00 	bnd jmpq *0x1754d(%rip)        # 1ed28 <sigaction@GLIBC_2.2.5>
    77db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000077e0 <fcntl@plt>:
    77e0:	f3 0f 1e fa          	endbr64 
    77e4:	f2 ff 25 45 75 01 00 	bnd jmpq *0x17545(%rip)        # 1ed30 <fcntl@GLIBC_2.2.5>
    77eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000077f0 <wgetch@plt>:
    77f0:	f3 0f 1e fa          	endbr64 
    77f4:	f2 ff 25 3d 75 01 00 	bnd jmpq *0x1753d(%rip)        # 1ed38 <wgetch@NCURSES6_5.0.19991023>
    77fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007800 <wclear@plt>:
    7800:	f3 0f 1e fa          	endbr64 
    7804:	f2 ff 25 35 75 01 00 	bnd jmpq *0x17535(%rip)        # 1ed40 <wclear@NCURSES6_5.0.19991023>
    780b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007810 <beep@plt>:
    7810:	f3 0f 1e fa          	endbr64 
    7814:	f2 ff 25 2d 75 01 00 	bnd jmpq *0x1752d(%rip)        # 1ed48 <beep@NCURSES6_5.0.19991023>
    781b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007820 <fclose@plt>:
    7820:	f3 0f 1e fa          	endbr64 
    7824:	f2 ff 25 25 75 01 00 	bnd jmpq *0x17525(%rip)        # 1ed50 <fclose@GLIBC_2.2.5>
    782b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007830 <getpwuid@plt>:
    7830:	f3 0f 1e fa          	endbr64 
    7834:	f2 ff 25 1d 75 01 00 	bnd jmpq *0x1751d(%rip)        # 1ed58 <getpwuid@GLIBC_2.2.5>
    783b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007840 <strlen@plt>:
    7840:	f3 0f 1e fa          	endbr64 
    7844:	f2 ff 25 15 75 01 00 	bnd jmpq *0x17515(%rip)        # 1ed60 <strlen@GLIBC_2.2.5>
    784b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007850 <noecho@plt>:
    7850:	f3 0f 1e fa          	endbr64 
    7854:	f2 ff 25 0d 75 01 00 	bnd jmpq *0x1750d(%rip)        # 1ed68 <noecho@NCURSES6_5.0.19991023>
    785b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007860 <__stack_chk_fail@plt>:
    7860:	f3 0f 1e fa          	endbr64 
    7864:	f2 ff 25 05 75 01 00 	bnd jmpq *0x17505(%rip)        # 1ed70 <__stack_chk_fail@GLIBC_2.4>
    786b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007870 <getuid@plt>:
    7870:	f3 0f 1e fa          	endbr64 
    7874:	f2 ff 25 fd 74 01 00 	bnd jmpq *0x174fd(%rip)        # 1ed78 <getuid@GLIBC_2.2.5>
    787b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007880 <getopt_long@plt>:
    7880:	f3 0f 1e fa          	endbr64 
    7884:	f2 ff 25 f5 74 01 00 	bnd jmpq *0x174f5(%rip)        # 1ed80 <getopt_long@GLIBC_2.2.5>
    788b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007890 <difftime@plt>:
    7890:	f3 0f 1e fa          	endbr64 
    7894:	f2 ff 25 ed 74 01 00 	bnd jmpq *0x174ed(%rip)        # 1ed88 <difftime@GLIBC_2.2.5>
    789b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000078a0 <modf@plt>:
    78a0:	f3 0f 1e fa          	endbr64 
    78a4:	f2 ff 25 e5 74 01 00 	bnd jmpq *0x174e5(%rip)        # 1ed90 <modf@GLIBC_2.2.5>
    78ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000078b0 <strrchr@plt>:
    78b0:	f3 0f 1e fa          	endbr64 
    78b4:	f2 ff 25 dd 74 01 00 	bnd jmpq *0x174dd(%rip)        # 1ed98 <strrchr@GLIBC_2.2.5>
    78bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000078c0 <ftruncate@plt>:
    78c0:	f3 0f 1e fa          	endbr64 
    78c4:	f2 ff 25 d5 74 01 00 	bnd jmpq *0x174d5(%rip)        # 1eda0 <ftruncate@GLIBC_2.2.5>
    78cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000078d0 <gettimeofday@plt>:
    78d0:	f3 0f 1e fa          	endbr64 
    78d4:	f2 ff 25 cd 74 01 00 	bnd jmpq *0x174cd(%rip)        # 1eda8 <gettimeofday@GLIBC_2.2.5>
    78db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000078e0 <__assert_fail@plt>:
    78e0:	f3 0f 1e fa          	endbr64 
    78e4:	f2 ff 25 c5 74 01 00 	bnd jmpq *0x174c5(%rip)        # 1edb0 <__assert_fail@GLIBC_2.2.5>
    78eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000078f0 <initscr@plt>:
    78f0:	f3 0f 1e fa          	endbr64 
    78f4:	f2 ff 25 bd 74 01 00 	bnd jmpq *0x174bd(%rip)        # 1edb8 <initscr@NCURSES6_5.0.19991023>
    78fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007900 <wrefresh@plt>:
    7900:	f3 0f 1e fa          	endbr64 
    7904:	f2 ff 25 b5 74 01 00 	bnd jmpq *0x174b5(%rip)        # 1edc0 <wrefresh@NCURSES6_5.0.19991023>
    790b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007910 <mvwprintw@plt>:
    7910:	f3 0f 1e fa          	endbr64 
    7914:	f2 ff 25 ad 74 01 00 	bnd jmpq *0x174ad(%rip)        # 1edc8 <mvwprintw@NCURSES6_5.0.19991023>
    791b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007920 <geteuid@plt>:
    7920:	f3 0f 1e fa          	endbr64 
    7924:	f2 ff 25 a5 74 01 00 	bnd jmpq *0x174a5(%rip)        # 1edd0 <geteuid@GLIBC_2.2.5>
    792b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007930 <keypad@plt>:
    7930:	f3 0f 1e fa          	endbr64 
    7934:	f2 ff 25 9d 74 01 00 	bnd jmpq *0x1749d(%rip)        # 1edd8 <keypad@NCURSES6_TINFO_5.0.19991023>
    793b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007940 <fputc@plt>:
    7940:	f3 0f 1e fa          	endbr64 
    7944:	f2 ff 25 95 74 01 00 	bnd jmpq *0x17495(%rip)        # 1ede0 <fputc@GLIBC_2.2.5>
    794b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007950 <wattr_on@plt>:
    7950:	f3 0f 1e fa          	endbr64 
    7954:	f2 ff 25 8d 74 01 00 	bnd jmpq *0x1748d(%rip)        # 1ede8 <wattr_on@NCURSES6_5.0.19991023>
    795b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007960 <read@plt>:
    7960:	f3 0f 1e fa          	endbr64 
    7964:	f2 ff 25 85 74 01 00 	bnd jmpq *0x17485(%rip)        # 1edf0 <read@GLIBC_2.2.5>
    796b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007970 <srand@plt>:
    7970:	f3 0f 1e fa          	endbr64 
    7974:	f2 ff 25 7d 74 01 00 	bnd jmpq *0x1747d(%rip)        # 1edf8 <srand@GLIBC_2.2.5>
    797b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007980 <leaveok@plt>:
    7980:	f3 0f 1e fa          	endbr64 
    7984:	f2 ff 25 75 74 01 00 	bnd jmpq *0x17475(%rip)        # 1ee00 <leaveok@NCURSES6_5.0.19991023>
    798b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007990 <strcmp@plt>:
    7990:	f3 0f 1e fa          	endbr64 
    7994:	f2 ff 25 6d 74 01 00 	bnd jmpq *0x1746d(%rip)        # 1ee08 <strcmp@GLIBC_2.2.5>
    799b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000079a0 <sigemptyset@plt>:
    79a0:	f3 0f 1e fa          	endbr64 
    79a4:	f2 ff 25 65 74 01 00 	bnd jmpq *0x17465(%rip)        # 1ee10 <sigemptyset@GLIBC_2.2.5>
    79ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000079b0 <ftell@plt>:
    79b0:	f3 0f 1e fa          	endbr64 
    79b4:	f2 ff 25 5d 74 01 00 	bnd jmpq *0x1745d(%rip)        # 1ee18 <ftell@GLIBC_2.2.5>
    79bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000079c0 <umask@plt>:
    79c0:	f3 0f 1e fa          	endbr64 
    79c4:	f2 ff 25 55 74 01 00 	bnd jmpq *0x17455(%rip)        # 1ee20 <umask@GLIBC_2.2.5>
    79cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000079d0 <sigfillset@plt>:
    79d0:	f3 0f 1e fa          	endbr64 
    79d4:	f2 ff 25 4d 74 01 00 	bnd jmpq *0x1744d(%rip)        # 1ee28 <sigfillset@GLIBC_2.2.5>
    79db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000079e0 <time@plt>:
    79e0:	f3 0f 1e fa          	endbr64 
    79e4:	f2 ff 25 45 74 01 00 	bnd jmpq *0x17445(%rip)        # 1ee30 <time@GLIBC_2.2.5>
    79eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000079f0 <fileno@plt>:
    79f0:	f3 0f 1e fa          	endbr64 
    79f4:	f2 ff 25 3d 74 01 00 	bnd jmpq *0x1743d(%rip)        # 1ee38 <fileno@GLIBC_2.2.5>
    79fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a00 <getgid@plt>:
    7a00:	f3 0f 1e fa          	endbr64 
    7a04:	f2 ff 25 35 74 01 00 	bnd jmpq *0x17435(%rip)        # 1ee40 <getgid@GLIBC_2.2.5>
    7a0b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a10 <select@plt>:
    7a10:	f3 0f 1e fa          	endbr64 
    7a14:	f2 ff 25 2d 74 01 00 	bnd jmpq *0x1742d(%rip)        # 1ee48 <select@GLIBC_2.2.5>
    7a1b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a20 <delwin@plt>:
    7a20:	f3 0f 1e fa          	endbr64 
    7a24:	f2 ff 25 25 74 01 00 	bnd jmpq *0x17425(%rip)        # 1ee50 <delwin@NCURSES6_5.0.19991023>
    7a2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a30 <intrflush@plt>:
    7a30:	f3 0f 1e fa          	endbr64 
    7a34:	f2 ff 25 1d 74 01 00 	bnd jmpq *0x1741d(%rip)        # 1ee58 <intrflush@NCURSES6_TINFO_5.0.19991023>
    7a3b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a40 <cbreak@plt>:
    7a40:	f3 0f 1e fa          	endbr64 
    7a44:	f2 ff 25 15 74 01 00 	bnd jmpq *0x17415(%rip)        # 1ee60 <cbreak@NCURSES6_TINFO_5.0.19991023>
    7a4b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a50 <malloc@plt>:
    7a50:	f3 0f 1e fa          	endbr64 
    7a54:	f2 ff 25 0d 74 01 00 	bnd jmpq *0x1740d(%rip)        # 1ee68 <malloc@GLIBC_2.2.5>
    7a5b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a60 <fflush@plt>:
    7a60:	f3 0f 1e fa          	endbr64 
    7a64:	f2 ff 25 05 74 01 00 	bnd jmpq *0x17405(%rip)        # 1ee70 <fflush@GLIBC_2.2.5>
    7a6b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a70 <__isoc99_sscanf@plt>:
    7a70:	f3 0f 1e fa          	endbr64 
    7a74:	f2 ff 25 fd 73 01 00 	bnd jmpq *0x173fd(%rip)        # 1ee78 <__isoc99_sscanf@GLIBC_2.7>
    7a7b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a80 <__fxstat@plt>:
    7a80:	f3 0f 1e fa          	endbr64 
    7a84:	f2 ff 25 f5 73 01 00 	bnd jmpq *0x173f5(%rip)        # 1ee80 <__fxstat@GLIBC_2.2.5>
    7a8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007a90 <getegid@plt>:
    7a90:	f3 0f 1e fa          	endbr64 
    7a94:	f2 ff 25 ed 73 01 00 	bnd jmpq *0x173ed(%rip)        # 1ee88 <getegid@GLIBC_2.2.5>
    7a9b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007aa0 <mktime@plt>:
    7aa0:	f3 0f 1e fa          	endbr64 
    7aa4:	f2 ff 25 e5 73 01 00 	bnd jmpq *0x173e5(%rip)        # 1ee90 <mktime@GLIBC_2.2.5>
    7aab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ab0 <echo@plt>:
    7ab0:	f3 0f 1e fa          	endbr64 
    7ab4:	f2 ff 25 dd 73 01 00 	bnd jmpq *0x173dd(%rip)        # 1ee98 <echo@NCURSES6_5.0.19991023>
    7abb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ac0 <wnoutrefresh@plt>:
    7ac0:	f3 0f 1e fa          	endbr64 
    7ac4:	f2 ff 25 d5 73 01 00 	bnd jmpq *0x173d5(%rip)        # 1eea0 <wnoutrefresh@NCURSES6_5.0.19991023>
    7acb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ad0 <fseek@plt>:
    7ad0:	f3 0f 1e fa          	endbr64 
    7ad4:	f2 ff 25 cd 73 01 00 	bnd jmpq *0x173cd(%rip)        # 1eea8 <fseek@GLIBC_2.2.5>
    7adb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ae0 <setreuid@plt>:
    7ae0:	f3 0f 1e fa          	endbr64 
    7ae4:	f2 ff 25 c5 73 01 00 	bnd jmpq *0x173c5(%rip)        # 1eeb0 <setreuid@GLIBC_2.2.5>
    7aeb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007af0 <setregid@plt>:
    7af0:	f3 0f 1e fa          	endbr64 
    7af4:	f2 ff 25 bd 73 01 00 	bnd jmpq *0x173bd(%rip)        # 1eeb8 <setregid@GLIBC_2.2.5>
    7afb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b00 <realloc@plt>:
    7b00:	f3 0f 1e fa          	endbr64 
    7b04:	f2 ff 25 b5 73 01 00 	bnd jmpq *0x173b5(%rip)        # 1eec0 <realloc@GLIBC_2.2.5>
    7b0b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b10 <__strcpy_chk@plt>:
    7b10:	f3 0f 1e fa          	endbr64 
    7b14:	f2 ff 25 ad 73 01 00 	bnd jmpq *0x173ad(%rip)        # 1eec8 <__strcpy_chk@GLIBC_2.3.4>
    7b1b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b20 <fdopen@plt>:
    7b20:	f3 0f 1e fa          	endbr64 
    7b24:	f2 ff 25 a5 73 01 00 	bnd jmpq *0x173a5(%rip)        # 1eed0 <fdopen@GLIBC_2.2.5>
    7b2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b30 <setlocale@plt>:
    7b30:	f3 0f 1e fa          	endbr64 
    7b34:	f2 ff 25 9d 73 01 00 	bnd jmpq *0x1739d(%rip)        # 1eed8 <setlocale@GLIBC_2.2.5>
    7b3b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b40 <__printf_chk@plt>:
    7b40:	f3 0f 1e fa          	endbr64 
    7b44:	f2 ff 25 95 73 01 00 	bnd jmpq *0x17395(%rip)        # 1eee0 <__printf_chk@GLIBC_2.3.4>
    7b4b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b50 <fchmod@plt>:
    7b50:	f3 0f 1e fa          	endbr64 
    7b54:	f2 ff 25 8d 73 01 00 	bnd jmpq *0x1738d(%rip)        # 1eee8 <fchmod@GLIBC_2.2.5>
    7b5b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b60 <wgetnstr@plt>:
    7b60:	f3 0f 1e fa          	endbr64 
    7b64:	f2 ff 25 85 73 01 00 	bnd jmpq *0x17385(%rip)        # 1eef0 <wgetnstr@NCURSES6_5.0.19991023>
    7b6b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b70 <memmove@plt>:
    7b70:	f3 0f 1e fa          	endbr64 
    7b74:	f2 ff 25 7d 73 01 00 	bnd jmpq *0x1737d(%rip)        # 1eef8 <memmove@GLIBC_2.2.5>
    7b7b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b80 <setgid@plt>:
    7b80:	f3 0f 1e fa          	endbr64 
    7b84:	f2 ff 25 75 73 01 00 	bnd jmpq *0x17375(%rip)        # 1ef00 <setgid@GLIBC_2.2.5>
    7b8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007b90 <tcgetattr@plt>:
    7b90:	f3 0f 1e fa          	endbr64 
    7b94:	f2 ff 25 6d 73 01 00 	bnd jmpq *0x1736d(%rip)        # 1ef08 <tcgetattr@GLIBC_2.2.5>
    7b9b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ba0 <doupdate@plt>:
    7ba0:	f3 0f 1e fa          	endbr64 
    7ba4:	f2 ff 25 65 73 01 00 	bnd jmpq *0x17365(%rip)        # 1ef10 <doupdate@NCURSES6_5.0.19991023>
    7bab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007bb0 <tcsetattr@plt>:
    7bb0:	f3 0f 1e fa          	endbr64 
    7bb4:	f2 ff 25 5d 73 01 00 	bnd jmpq *0x1735d(%rip)        # 1ef18 <tcsetattr@GLIBC_2.2.5>
    7bbb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007bc0 <open@plt>:
    7bc0:	f3 0f 1e fa          	endbr64 
    7bc4:	f2 ff 25 55 73 01 00 	bnd jmpq *0x17355(%rip)        # 1ef20 <open@GLIBC_2.2.5>
    7bcb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007bd0 <wmove@plt>:
    7bd0:	f3 0f 1e fa          	endbr64 
    7bd4:	f2 ff 25 4d 73 01 00 	bnd jmpq *0x1734d(%rip)        # 1ef28 <wmove@NCURSES6_5.0.19991023>
    7bdb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007be0 <wclrtoeol@plt>:
    7be0:	f3 0f 1e fa          	endbr64 
    7be4:	f2 ff 25 45 73 01 00 	bnd jmpq *0x17345(%rip)        # 1ef30 <wclrtoeol@NCURSES6_5.0.19991023>
    7beb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007bf0 <waddch@plt>:
    7bf0:	f3 0f 1e fa          	endbr64 
    7bf4:	f2 ff 25 3d 73 01 00 	bnd jmpq *0x1733d(%rip)        # 1ef38 <waddch@NCURSES6_5.0.19991023>
    7bfb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c00 <strcat@plt>:
    7c00:	f3 0f 1e fa          	endbr64 
    7c04:	f2 ff 25 35 73 01 00 	bnd jmpq *0x17335(%rip)        # 1ef40 <strcat@GLIBC_2.2.5>
    7c0b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c10 <has_key@plt>:
    7c10:	f3 0f 1e fa          	endbr64 
    7c14:	f2 ff 25 2d 73 01 00 	bnd jmpq *0x1732d(%rip)        # 1ef48 <has_key@NCURSES6_TINFO_5.0.19991023>
    7c1b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c20 <exit@plt>:
    7c20:	f3 0f 1e fa          	endbr64 
    7c24:	f2 ff 25 25 73 01 00 	bnd jmpq *0x17325(%rip)        # 1ef50 <exit@GLIBC_2.2.5>
    7c2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c30 <fwrite@plt>:
    7c30:	f3 0f 1e fa          	endbr64 
    7c34:	f2 ff 25 1d 73 01 00 	bnd jmpq *0x1731d(%rip)        # 1ef58 <fwrite@GLIBC_2.2.5>
    7c3b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c40 <__fprintf_chk@plt>:
    7c40:	f3 0f 1e fa          	endbr64 
    7c44:	f2 ff 25 15 73 01 00 	bnd jmpq *0x17315(%rip)        # 1ef60 <__fprintf_chk@GLIBC_2.3.4>
    7c4b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c50 <__strncat_chk@plt>:
    7c50:	f3 0f 1e fa          	endbr64 
    7c54:	f2 ff 25 0d 73 01 00 	bnd jmpq *0x1730d(%rip)        # 1ef68 <__strncat_chk@GLIBC_2.3.4>
    7c5b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c60 <wprintw@plt>:
    7c60:	f3 0f 1e fa          	endbr64 
    7c64:	f2 ff 25 05 73 01 00 	bnd jmpq *0x17305(%rip)        # 1ef70 <wprintw@NCURSES6_5.0.19991023>
    7c6b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c70 <setuid@plt>:
    7c70:	f3 0f 1e fa          	endbr64 
    7c74:	f2 ff 25 fd 72 01 00 	bnd jmpq *0x172fd(%rip)        # 1ef78 <setuid@GLIBC_2.2.5>
    7c7b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c80 <endwin@plt>:
    7c80:	f3 0f 1e fa          	endbr64 
    7c84:	f2 ff 25 f5 72 01 00 	bnd jmpq *0x172f5(%rip)        # 1ef80 <endwin@NCURSES6_5.0.19991023>
    7c8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007c90 <strerror@plt>:
    7c90:	f3 0f 1e fa          	endbr64 
    7c94:	f2 ff 25 ed 72 01 00 	bnd jmpq *0x172ed(%rip)        # 1ef88 <strerror@GLIBC_2.2.5>
    7c9b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ca0 <waddnstr@plt>:
    7ca0:	f3 0f 1e fa          	endbr64 
    7ca4:	f2 ff 25 e5 72 01 00 	bnd jmpq *0x172e5(%rip)        # 1ef90 <waddnstr@NCURSES6_5.0.19991023>
    7cab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007cb0 <sleep@plt>:
    7cb0:	f3 0f 1e fa          	endbr64 
    7cb4:	f2 ff 25 dd 72 01 00 	bnd jmpq *0x172dd(%rip)        # 1ef98 <sleep@GLIBC_2.2.5>
    7cbb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007cc0 <wattr_off@plt>:
    7cc0:	f3 0f 1e fa          	endbr64 
    7cc4:	f2 ff 25 d5 72 01 00 	bnd jmpq *0x172d5(%rip)        # 1efa0 <wattr_off@NCURSES6_5.0.19991023>
    7ccb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007cd0 <strstr@plt>:
    7cd0:	f3 0f 1e fa          	endbr64 
    7cd4:	f2 ff 25 cd 72 01 00 	bnd jmpq *0x172cd(%rip)        # 1efa8 <strstr@GLIBC_2.2.5>
    7cdb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007ce0 <rand@plt>:
    7ce0:	f3 0f 1e fa          	endbr64 
    7ce4:	f2 ff 25 c5 72 01 00 	bnd jmpq *0x172c5(%rip)        # 1efb0 <rand@GLIBC_2.2.5>
    7ceb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007cf0 <__ctype_tolower_loc@plt>:
    7cf0:	f3 0f 1e fa          	endbr64 
    7cf4:	f2 ff 25 bd 72 01 00 	bnd jmpq *0x172bd(%rip)        # 1efb8 <__ctype_tolower_loc@GLIBC_2.3>
    7cfb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007d00 <__ctype_b_loc@plt>:
    7d00:	f3 0f 1e fa          	endbr64 
    7d04:	f2 ff 25 b5 72 01 00 	bnd jmpq *0x172b5(%rip)        # 1efc0 <__ctype_b_loc@GLIBC_2.3>
    7d0b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007d10 <__sprintf_chk@plt>:
    7d10:	f3 0f 1e fa          	endbr64 
    7d14:	f2 ff 25 ad 72 01 00 	bnd jmpq *0x172ad(%rip)        # 1efc8 <__sprintf_chk@GLIBC_2.3.4>
    7d1b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000007d20 <set_persona.cold>:
    new_uid = user_uid;
    old_gid = game_gid;
    new_gid = user_gid;
    break;
  default:
    abort ();			/* should not happen */
    7d20:	e8 fb f9 ff ff       	callq  7720 <abort@plt>
    7d25:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    7d2c:	00 00 00 
    7d2f:	90                   	nop

0000000000007d30 <main>:
 * main procedure
 */

int
main (int argc, char **argv)
{
    7d30:	f3 0f 1e fa          	endbr64 
    7d34:	41 57                	push   %r15
    7d36:	41 56                	push   %r14
    7d38:	41 55                	push   %r13
    7d3a:	41 54                	push   %r12
    7d3c:	41 89 fc             	mov    %edi,%r12d
    7d3f:	55                   	push   %rbp
    7d40:	48 89 f5             	mov    %rsi,%rbp
    7d43:	53                   	push   %rbx
    7d44:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
    7d4b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    7d52:	00 00 
    7d54:	48 89 84 24 08 01 00 	mov    %rax,0x108(%rsp)
    7d5b:	00 
    7d5c:	31 c0                	xor    %eax,%eax
#ifdef HAVE_GETOPT_LONG
  struct option  long_options [] = {
    7d5e:	48 8d 05 a3 82 00 00 	lea    0x82a3(%rip),%rax        # 10008 <_IO_stdin_used+0x8>
    7d65:	c7 44 24 28 00 00 00 	movl   $0x0,0x28(%rsp)
    7d6c:	00 
    7d6d:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    7d72:	48 8d 05 9d 82 00 00 	lea    0x829d(%rip),%rax        # 10016 <_IO_stdin_used+0x16>
    7d79:	48 89 44 24 40       	mov    %rax,0x40(%rsp)
    7d7e:	48 8d 05 96 82 00 00 	lea    0x8296(%rip),%rax        # 1001b <_IO_stdin_used+0x1b>
    7d85:	48 89 44 24 60       	mov    %rax,0x60(%rsp)
    7d8a:	48 8d 05 8f 82 00 00 	lea    0x828f(%rip),%rax        # 10020 <_IO_stdin_used+0x20>
    7d91:	48 89 84 24 80 00 00 	mov    %rax,0x80(%rsp)
    7d98:	00 
    7d99:	48 8d 05 89 82 00 00 	lea    0x8289(%rip),%rax        # 10029 <_IO_stdin_used+0x29>
    7da0:	48 89 84 24 a0 00 00 	mov    %rax,0xa0(%rsp)
    7da7:	00 
    7da8:	48 8d 05 86 82 00 00 	lea    0x8286(%rip),%rax        # 10035 <_IO_stdin_used+0x35>
    7daf:	48 89 84 24 c0 00 00 	mov    %rax,0xc0(%rsp)
    7db6:	00 
    7db7:	48 c7 44 24 30 00 00 	movq   $0x0,0x30(%rsp)
    7dbe:	00 00 
    7dc0:	c7 44 24 38 63 00 00 	movl   $0x63,0x38(%rsp)
    7dc7:	00 
    7dc8:	c7 44 24 48 00 00 00 	movl   $0x0,0x48(%rsp)
    7dcf:	00 
    7dd0:	48 c7 44 24 50 00 00 	movq   $0x0,0x50(%rsp)
    7dd7:	00 00 
    7dd9:	c7 44 24 58 68 00 00 	movl   $0x68,0x58(%rsp)
    7de0:	00 
    7de1:	c7 44 24 68 00 00 00 	movl   $0x0,0x68(%rsp)
    7de8:	00 
    7de9:	48 c7 44 24 70 00 00 	movq   $0x0,0x70(%rsp)
    7df0:	00 00 
    7df2:	c7 44 24 78 6d 00 00 	movl   $0x6d,0x78(%rsp)
    7df9:	00 
    7dfa:	c7 84 24 88 00 00 00 	movl   $0x0,0x88(%rsp)
    7e01:	00 00 00 00 
    7e05:	48 c7 84 24 90 00 00 	movq   $0x0,0x90(%rsp)
    7e0c:	00 00 00 00 00 
    7e11:	c7 84 24 98 00 00 00 	movl   $0x6e,0x98(%rsp)
    7e18:	6e 00 00 00 
    7e1c:	c7 84 24 a8 00 00 00 	movl   $0x0,0xa8(%rsp)
    7e23:	00 00 00 00 
    7e27:	48 c7 84 24 b0 00 00 	movq   $0x0,0xb0(%rsp)
    7e2e:	00 00 00 00 00 
    7e33:	c7 84 24 b8 00 00 00 	movl   $0x73,0xb8(%rsp)
    7e3a:	73 00 00 00 
    7e3e:	c7 84 24 c8 00 00 00 	movl   $0x0,0xc8(%rsp)
    7e45:	00 00 00 00 
    7e49:	48 c7 84 24 d0 00 00 	movq   $0x0,0xd0(%rsp)
    7e50:	00 00 00 00 00 
    7e55:	c7 84 24 d8 00 00 00 	movl   $0x56,0xd8(%rsp)
    7e5c:	56 00 00 00 
    7e60:	48 c7 84 24 e0 00 00 	movq   $0x0,0xe0(%rsp)
    7e67:	00 00 00 00 00 
    7e6c:	c7 84 24 e8 00 00 00 	movl   $0x0,0xe8(%rsp)
    7e73:	00 00 00 00 
    7e77:	48 c7 84 24 f0 00 00 	movq   $0x0,0xf0(%rsp)
    7e7e:	00 00 00 00 00 
    7e83:	c7 84 24 f8 00 00 00 	movl   $0x0,0xf8(%rsp)
    7e8a:	00 00 00 00 
  int  highscore_flag = 0;
  int  title_flag = 1;
  int  version_flag = 0;
  int  error_flag = 0;

  initialise_persona ();
    7e8e:	e8 5d 60 00 00       	callq  def0 <initialise_persona>
  set_persona (pers_USER);
    7e93:	bf 01 00 00 00       	mov    $0x1,%edi
    7e98:	e8 f3 60 00 00       	callq  df90 <set_persona>

#ifdef HAVE_SETLOCALE
  setlocale (LC_CTYPE, "");
    7e9d:	48 8d 35 db 81 00 00 	lea    0x81db(%rip),%rsi        # 1007f <_IO_stdin_used+0x7f>
    7ea4:	31 ff                	xor    %edi,%edi
    7ea6:	e8 85 fc ff ff       	callq  7b30 <setlocale@plt>
#endif

  /* `basename' seems to be non-standard.  So we avoid it.  */
  my_name = strrchr (argv[0], '/');
    7eab:	48 8b 7d 00          	mov    0x0(%rbp),%rdi
    7eaf:	be 2f 00 00 00       	mov    $0x2f,%esi
    7eb4:	e8 f7 f9 ff ff       	callq  78b0 <strrchr@plt>
    7eb9:	48 89 05 48 8f 01 00 	mov    %rax,0x18f48(%rip)        # 20e08 <my_name>
  my_name = xstrdup (my_name ? my_name+1 : argv[0]);
    7ec0:	48 8d 78 01          	lea    0x1(%rax),%rdi
    7ec4:	48 85 c0             	test   %rax,%rax
    7ec7:	0f 84 ff 01 00 00    	je     80cc <main+0x39c>
    7ecd:	e8 fe 77 00 00       	callq  f6d0 <xstrdup>
  int  version_flag = 0;
    7ed2:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%rsp)
    7ed9:	00 
  int  highscore_flag = 0;
    7eda:	45 31 f6             	xor    %r14d,%r14d
    7edd:	4c 8d 7c 24 1c       	lea    0x1c(%rsp),%r15
  my_name = xstrdup (my_name ? my_name+1 : argv[0]);
    7ee2:	48 89 05 1f 8f 01 00 	mov    %rax,0x18f1f(%rip)        # 20e08 <my_name>
    7ee9:	4c 8d 6c 24 20       	lea    0x20(%rsp),%r13
    7eee:	48 8d 1d 27 84 00 00 	lea    0x8427(%rip),%rbx        # 1031c <_IO_stdin_used+0x31c>
  int  title_flag = 1;
    7ef5:	c7 44 24 0c 01 00 00 	movl   $0x1,0xc(%rsp)
    7efc:	00 
  int  help_flag = 0;
    7efd:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%rsp)
    7f04:	00 
    7f05:	0f 1f 00             	nopl   (%rax)

  do {
    int  c;
#ifdef HAVE_GETOPT_LONG
    int  ind;
    c = getopt_long (argc, argv, MB_SHORT_OPTIONS, long_options, &ind);
    7f08:	4d 89 f8             	mov    %r15,%r8
    7f0b:	4c 89 e9             	mov    %r13,%rcx
    7f0e:	48 8d 15 28 81 00 00 	lea    0x8128(%rip),%rdx        # 1003d <_IO_stdin_used+0x3d>
    7f15:	48 89 ee             	mov    %rbp,%rsi
    7f18:	44 89 e7             	mov    %r12d,%edi
    7f1b:	e8 60 f9 ff ff       	callq  7880 <getopt_long@plt>
#else
    c = getopt (argc, argv, MB_SHORT_OPTIONS);
#endif
    if (c == -1)  break;
    7f20:	83 f8 ff             	cmp    $0xffffffff,%eax
    7f23:	0f 84 91 00 00 00    	je     7fba <main+0x28a>
    switch (c) {
    7f29:	83 e8 56             	sub    $0x56,%eax
    7f2c:	83 f8 1d             	cmp    $0x1d,%eax
    7f2f:	77 44                	ja     7f75 <main+0x245>
    7f31:	48 63 04 83          	movslq (%rbx,%rax,4),%rax
    7f35:	48 01 d8             	add    %rbx,%rax
    7f38:	3e ff e0             	notrack jmpq *%rax
      break;
    case 'n':
      title_flag = 0;
      break;
    case 's':
      highscore_flag = 1;
    7f3b:	41 be 01 00 00 00    	mov    $0x1,%r14d
    7f41:	eb c5                	jmp    7f08 <main+0x1d8>
      title_flag = 0;
    7f43:	c7 44 24 0c 00 00 00 	movl   $0x0,0xc(%rsp)
    7f4a:	00 
    7f4b:	eb bb                	jmp    7f08 <main+0x1d8>
      mesg_flag = 1;
    7f4d:	c7 05 55 73 01 00 01 	movl   $0x1,0x17355(%rip)        # 1f2ac <mesg_flag>
    7f54:	00 00 00 
      version_flag = 1;
      break;
    default:
      error_flag = 1;
    }
  } while (! error_flag);
    7f57:	eb af                	jmp    7f08 <main+0x1d8>
      help_flag = 1;
    7f59:	c7 44 24 08 01 00 00 	movl   $0x1,0x8(%rsp)
    7f60:	00 
    7f61:	eb a5                	jmp    7f08 <main+0x1d8>
      highscore_flag = 2;
    7f63:	41 be 02 00 00 00    	mov    $0x2,%r14d
    7f69:	eb 9d                	jmp    7f08 <main+0x1d8>
      version_flag = 1;
    7f6b:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%rsp)
    7f72:	00 
    7f73:	eb 93                	jmp    7f08 <main+0x1d8>
      error_flag = 1;
    7f75:	bd 01 00 00 00       	mov    $0x1,%ebp

  if (argc != optind) {
    7f7a:	44 39 25 e7 72 01 00 	cmp    %r12d,0x172e7(%rip)        # 1f268 <optind@@GLIBC_2.2.5>
    7f81:	75 42                	jne    7fc5 <main+0x295>
    fputs ("too many arguments\n", stderr);
    error_flag = 1;
  }

  if (version_flag) {
    7f83:	83 7c 24 04 00       	cmpl   $0x0,0x4(%rsp)
    7f88:	0f 85 ed 01 00 00    	jne    817b <main+0x44b>
You may redistribute copies of Moon-Buggy under the terms of the GNU\n\
General Public License.  For more information about these matters, see\n\
the file named COPYING or press `c' at Moon-Buggy's title screen.");
    if (! error_flag)  exit (0);
  }
  if (error_flag || help_flag) {
    7f8e:	8b 44 24 08          	mov    0x8(%rsp),%eax
    7f92:	09 e8                	or     %ebp,%eax
    7f94:	0f 85 69 02 00 00    	jne    8203 <main+0x4d3>
           out);
    fputs ("Please report bugs to <voss@seehuhn.de>.\n", out);
    exit (error_flag);
  }

  init_rnd ();
    7f9a:	e8 41 75 00 00       	callq  f4e0 <init_rnd>

  if (highscore_flag) {
    7f9f:	45 85 f6             	test   %r14d,%r14d
    7fa2:	0f 84 2d 01 00 00    	je     80d5 <main+0x3a5>
    if (highscore_flag == 1) {
    7fa8:	41 83 ee 01          	sub    $0x1,%r14d
    7fac:	74 10                	je     7fbe <main+0x28e>
      show_highscores ();
    } else {
      create_highscores ();
    7fae:	e8 2d 50 00 00       	callq  cfe0 <create_highscores>
    if (! error_flag)  exit (0);
    7fb3:	31 ff                	xor    %edi,%edi
    7fb5:	e8 66 fc ff ff       	callq  7c20 <exit@plt>
    7fba:	31 ed                	xor    %ebp,%ebp
    7fbc:	eb bc                	jmp    7f7a <main+0x24a>
      show_highscores ();
    7fbe:	e8 3d 50 00 00       	callq  d000 <show_highscores>
    7fc3:	eb ee                	jmp    7fb3 <main+0x283>
    fputs ("too many arguments\n", stderr);
    7fc5:	48 8b 0d d4 72 01 00 	mov    0x172d4(%rip),%rcx        # 1f2a0 <stderr@@GLIBC_2.2.5>
    7fcc:	ba 13 00 00 00       	mov    $0x13,%edx
    7fd1:	be 01 00 00 00       	mov    $0x1,%esi
    7fd6:	48 8d 3d 67 80 00 00 	lea    0x8067(%rip),%rdi        # 10044 <_IO_stdin_used+0x44>
    7fdd:	e8 4e fc ff ff       	callq  7c30 <fwrite@plt>
  if (version_flag) {
    7fe2:	83 7c 24 04 00       	cmpl   $0x0,0x4(%rsp)
    7fe7:	0f 85 dc 01 00 00    	jne    81c9 <main+0x499>
    FILE *out = error_flag ? stderr : stdout;
    7fed:	4c 8b 25 ac 72 01 00 	mov    0x172ac(%rip),%r12        # 1f2a0 <stderr@@GLIBC_2.2.5>
    7ff4:	bd 01 00 00 00       	mov    $0x1,%ebp

# ifdef __va_arg_pack
__fortify_function int
fprintf (FILE *__restrict __stream, const char *__restrict __fmt, ...)
{
  return __fprintf_chk (__stream, __USE_FORTIFY_LEVEL - 1, __fmt,
    7ff9:	48 8b 0d 08 8e 01 00 	mov    0x18e08(%rip),%rcx        # 20e08 <my_name>
    8000:	48 8d 15 63 80 00 00 	lea    0x8063(%rip),%rdx        # 1006a <_IO_stdin_used+0x6a>
    8007:	4c 89 e7             	mov    %r12,%rdi
    800a:	31 c0                	xor    %eax,%eax
    800c:	be 01 00 00 00       	mov    $0x1,%esi
    8011:	e8 2a fc ff ff       	callq  7c40 <__fprintf_chk@plt>
    fputs ("The options are\n", out);
    8016:	4c 89 e1             	mov    %r12,%rcx
    8019:	ba 10 00 00 00       	mov    $0x10,%edx
    801e:	be 01 00 00 00       	mov    $0x1,%esi
    8023:	48 8d 3d 56 80 00 00 	lea    0x8056(%rip),%rdi        # 10080 <_IO_stdin_used+0x80>
    802a:	e8 01 fc ff ff       	callq  7c30 <fwrite@plt>
    fputs (OPT("-h","--help         ") "show this message and exit\n", out);
    802f:	4c 89 e1             	mov    %r12,%rcx
    8032:	ba 34 00 00 00       	mov    $0x34,%edx
    8037:	be 01 00 00 00       	mov    $0x1,%esi
    803c:	48 8d 3d 95 81 00 00 	lea    0x8195(%rip),%rdi        # 101d8 <_IO_stdin_used+0x1d8>
    8043:	e8 e8 fb ff ff       	callq  7c30 <fwrite@plt>
    fputs (OPT("-m","--mesg         ") "imply the effect of \"mesg n\"\n",
    8048:	4c 89 e1             	mov    %r12,%rcx
    804b:	ba 36 00 00 00       	mov    $0x36,%edx
    8050:	be 01 00 00 00       	mov    $0x1,%esi
    8055:	48 8d 3d b4 81 00 00 	lea    0x81b4(%rip),%rdi        # 10210 <_IO_stdin_used+0x210>
    805c:	e8 cf fb ff ff       	callq  7c30 <fwrite@plt>
    fputs (OPT("-n","--no-title     ") "omit the title screen\n", out);
    8061:	4c 89 e1             	mov    %r12,%rcx
    8064:	ba 2f 00 00 00       	mov    $0x2f,%edx
    8069:	be 01 00 00 00       	mov    $0x1,%esi
    806e:	48 8d 3d d3 81 00 00 	lea    0x81d3(%rip),%rdi        # 10248 <_IO_stdin_used+0x248>
    8075:	e8 b6 fb ff ff       	callq  7c30 <fwrite@plt>
    fputs (OPT("-s","--show-scores  ") "only show the highscore list\n", out);
    807a:	4c 89 e1             	mov    %r12,%rcx
    807d:	ba 36 00 00 00       	mov    $0x36,%edx
    8082:	be 01 00 00 00       	mov    $0x1,%esi
    8087:	48 8d 3d ea 81 00 00 	lea    0x81ea(%rip),%rdi        # 10278 <_IO_stdin_used+0x278>
    808e:	e8 9d fb ff ff       	callq  7c30 <fwrite@plt>
    fputs (OPT("-V","--version      ") "show the version number and exit\n\n",
    8093:	4c 89 e1             	mov    %r12,%rcx
    8096:	ba 3b 00 00 00       	mov    $0x3b,%edx
    809b:	be 01 00 00 00       	mov    $0x1,%esi
    80a0:	48 8d 3d 09 82 00 00 	lea    0x8209(%rip),%rdi        # 102b0 <_IO_stdin_used+0x2b0>
    80a7:	e8 84 fb ff ff       	callq  7c30 <fwrite@plt>
    fputs ("Please report bugs to <voss@seehuhn.de>.\n", out);
    80ac:	48 8d 3d 3d 82 00 00 	lea    0x823d(%rip),%rdi        # 102f0 <_IO_stdin_used+0x2f0>
    80b3:	4c 89 e1             	mov    %r12,%rcx
    80b6:	ba 29 00 00 00       	mov    $0x29,%edx
    80bb:	be 01 00 00 00       	mov    $0x1,%esi
    80c0:	e8 6b fb ff ff       	callq  7c30 <fwrite@plt>
    exit (error_flag);
    80c5:	89 ef                	mov    %ebp,%edi
    80c7:	e8 54 fb ff ff       	callq  7c20 <exit@plt>
  my_name = xstrdup (my_name ? my_name+1 : argv[0]);
    80cc:	48 8b 7d 00          	mov    0x0(%rbp),%rdi
    80d0:	e9 f8 fd ff ff       	jmpq   7ecd <main+0x19d>
    }
    exit (0);
  }

  initialise_signals ();
    80d5:	e8 26 63 00 00       	callq  e400 <initialise_signals>

  allocate_windows ();
    80da:	e8 21 04 00 00       	callq  8500 <allocate_windows>
  curses_initialised = 1;
    80df:	c7 05 c7 71 01 00 01 	movl   $0x1,0x171c7(%rip)        # 1f2b0 <curses_initialised>
    80e6:	00 00 00 
  prepare_screen ();
    80e9:	e8 c2 03 00 00       	callq  84b0 <prepare_screen>

  install_keys ();
    80ee:	e8 9d 65 00 00       	callq  e690 <install_keys>
  setup_title_mode ();
    80f3:	e8 c8 09 00 00       	callq  8ac0 <setup_title_mode>
  setup_pager_mode ();
    80f8:	e8 b3 0d 00 00       	callq  8eb0 <setup_pager_mode>
  setup_game_mode ();
    80fd:	e8 ce 13 00 00       	callq  94d0 <setup_game_mode>
  setup_highscore_mode ();
    8102:	e8 89 50 00 00       	callq  d190 <setup_highscore_mode>

  clear_windows ();
    8107:	e8 b4 04 00 00       	callq  85c0 <clear_windows>

  resize_ground (1);
    810c:	bf 01 00 00 00       	mov    $0x1,%edi
    8111:	e8 4a 23 00 00       	callq  a460 <resize_ground>
  initialise_buggy ();
    8116:	e8 15 28 00 00       	callq  a930 <initialise_buggy>

  if (title_flag) {
    mode_change (title_mode, 0);
    811b:	31 f6                	xor    %esi,%esi
  if (title_flag) {
    811d:	83 7c 24 0c 00       	cmpl   $0x0,0xc(%rsp)
    8122:	0f 85 90 00 00 00    	jne    81b8 <main+0x488>
  } else {
    mode_change (game_mode, 0);
    8128:	48 8b 3d 11 8d 01 00 	mov    0x18d11(%rip),%rdi        # 20e40 <game_mode>
    812f:	e8 2c 06 00 00       	callq  8760 <mode_change>
  }
  main_loop ();
    8134:	e8 27 58 00 00       	callq  d960 <main_loop>
  mode_change (NULL, 0);
    8139:	31 f6                	xor    %esi,%esi
    813b:	31 ff                	xor    %edi,%edi
    813d:	e8 1e 06 00 00       	callq  8760 <mode_change>
  if (! curses_initialised)  return;
    8142:	83 3d 67 71 01 00 00 	cmpl   $0x0,0x17167(%rip)        # 1f2b0 <curses_initialised>
    8149:	74 05                	je     8150 <main+0x420>
    814b:	e8 c0 01 00 00       	callq  8310 <prepare_for_exit.part.0>

  prepare_for_exit ();
  return  0;
}
    8150:	48 8b 84 24 08 01 00 	mov    0x108(%rsp),%rax
    8157:	00 
    8158:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    815f:	00 00 
    8161:	0f 85 97 00 00 00    	jne    81fe <main+0x4ce>
    8167:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
    816e:	31 c0                	xor    %eax,%eax
    8170:	5b                   	pop    %rbx
    8171:	5d                   	pop    %rbp
    8172:	41 5c                	pop    %r12
    8174:	41 5d                	pop    %r13
    8176:	41 5e                	pop    %r14
    8178:	41 5f                	pop    %r15
    817a:	c3                   	retq   
    puts ("Moon-Buggy " VERSION);
    817b:	48 8d 3d d6 7e 00 00 	lea    0x7ed6(%rip),%rdi        # 10058 <_IO_stdin_used+0x58>
    8182:	e8 09 f6 ff ff       	callq  7790 <puts@plt>
    puts ("Copyright 1998-2006  Jochen Voss");
    8187:	48 8d 3d 0a 7f 00 00 	lea    0x7f0a(%rip),%rdi        # 10098 <_IO_stdin_used+0x98>
    818e:	e8 fd f5 ff ff       	callq  7790 <puts@plt>
    puts ("\
    8193:	48 8d 3d 26 7f 00 00 	lea    0x7f26(%rip),%rdi        # 100c0 <_IO_stdin_used+0xc0>
    819a:	e8 f1 f5 ff ff       	callq  7790 <puts@plt>
    puts ("\
    819f:	48 8d 3d 62 7f 00 00 	lea    0x7f62(%rip),%rdi        # 10108 <_IO_stdin_used+0x108>
    81a6:	e8 e5 f5 ff ff       	callq  7790 <puts@plt>
    if (! error_flag)  exit (0);
    81ab:	85 ed                	test   %ebp,%ebp
    81ad:	0f 84 00 fe ff ff    	je     7fb3 <main+0x283>
    81b3:	e9 35 fe ff ff       	jmpq   7fed <main+0x2bd>
    mode_change (title_mode, 0);
    81b8:	48 8b 3d 61 8c 01 00 	mov    0x18c61(%rip),%rdi        # 20e20 <title_mode>
    81bf:	e8 9c 05 00 00       	callq  8760 <mode_change>
    81c4:	e9 6b ff ff ff       	jmpq   8134 <main+0x404>
    puts ("Moon-Buggy " VERSION);
    81c9:	48 8d 3d 88 7e 00 00 	lea    0x7e88(%rip),%rdi        # 10058 <_IO_stdin_used+0x58>
    81d0:	e8 bb f5 ff ff       	callq  7790 <puts@plt>
    puts ("Copyright 1998-2006  Jochen Voss");
    81d5:	48 8d 3d bc 7e 00 00 	lea    0x7ebc(%rip),%rdi        # 10098 <_IO_stdin_used+0x98>
    81dc:	e8 af f5 ff ff       	callq  7790 <puts@plt>
    puts ("\
    81e1:	48 8d 3d d8 7e 00 00 	lea    0x7ed8(%rip),%rdi        # 100c0 <_IO_stdin_used+0xc0>
    81e8:	e8 a3 f5 ff ff       	callq  7790 <puts@plt>
    puts ("\
    81ed:	48 8d 3d 14 7f 00 00 	lea    0x7f14(%rip),%rdi        # 10108 <_IO_stdin_used+0x108>
    81f4:	e8 97 f5 ff ff       	callq  7790 <puts@plt>
    if (! error_flag)  exit (0);
    81f9:	e9 ef fd ff ff       	jmpq   7fed <main+0x2bd>
}
    81fe:	e8 5d f6 ff ff       	callq  7860 <__stack_chk_fail@plt>
    FILE *out = error_flag ? stderr : stdout;
    8203:	4c 8b 25 56 70 01 00 	mov    0x17056(%rip),%r12        # 1f260 <stdout@@GLIBC_2.2.5>
    820a:	85 ed                	test   %ebp,%ebp
    820c:	0f 84 e7 fd ff ff    	je     7ff9 <main+0x2c9>
    8212:	e9 d6 fd ff ff       	jmpq   7fed <main+0x2bd>
    8217:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    821e:	00 00 

0000000000008220 <_start>:
    8220:	f3 0f 1e fa          	endbr64 
    8224:	31 ed                	xor    %ebp,%ebp
    8226:	49 89 d1             	mov    %rdx,%r9
    8229:	5e                   	pop    %rsi
    822a:	48 89 e2             	mov    %rsp,%rdx
    822d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    8231:	50                   	push   %rax
    8232:	54                   	push   %rsp
    8233:	4c 8d 05 e6 75 00 00 	lea    0x75e6(%rip),%r8        # f820 <__libc_csu_fini>
    823a:	48 8d 0d 6f 75 00 00 	lea    0x756f(%rip),%rcx        # f7b0 <__libc_csu_init>
    8241:	48 8d 3d e8 fa ff ff 	lea    -0x518(%rip),%rdi        # 7d30 <main>
    8248:	ff 15 8a 6d 01 00    	callq  *0x16d8a(%rip)        # 1efd8 <__libc_start_main@GLIBC_2.2.5>
    824e:	f4                   	hlt    
    824f:	90                   	nop

0000000000008250 <deregister_tm_clones>:
    8250:	48 8d 3d f1 6f 01 00 	lea    0x16ff1(%rip),%rdi        # 1f248 <__TMC_END__>
    8257:	48 8d 05 ea 6f 01 00 	lea    0x16fea(%rip),%rax        # 1f248 <__TMC_END__>
    825e:	48 39 f8             	cmp    %rdi,%rax
    8261:	74 15                	je     8278 <deregister_tm_clones+0x28>
    8263:	48 8b 05 66 6d 01 00 	mov    0x16d66(%rip),%rax        # 1efd0 <_ITM_deregisterTMCloneTable>
    826a:	48 85 c0             	test   %rax,%rax
    826d:	74 09                	je     8278 <deregister_tm_clones+0x28>
    826f:	ff e0                	jmpq   *%rax
    8271:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    8278:	c3                   	retq   
    8279:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000008280 <register_tm_clones>:
    8280:	48 8d 3d c1 6f 01 00 	lea    0x16fc1(%rip),%rdi        # 1f248 <__TMC_END__>
    8287:	48 8d 35 ba 6f 01 00 	lea    0x16fba(%rip),%rsi        # 1f248 <__TMC_END__>
    828e:	48 29 fe             	sub    %rdi,%rsi
    8291:	48 89 f0             	mov    %rsi,%rax
    8294:	48 c1 ee 3f          	shr    $0x3f,%rsi
    8298:	48 c1 f8 03          	sar    $0x3,%rax
    829c:	48 01 c6             	add    %rax,%rsi
    829f:	48 d1 fe             	sar    %rsi
    82a2:	74 14                	je     82b8 <register_tm_clones+0x38>
    82a4:	48 8b 05 3d 6d 01 00 	mov    0x16d3d(%rip),%rax        # 1efe8 <_ITM_registerTMCloneTable>
    82ab:	48 85 c0             	test   %rax,%rax
    82ae:	74 08                	je     82b8 <register_tm_clones+0x38>
    82b0:	ff e0                	jmpq   *%rax
    82b2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    82b8:	c3                   	retq   
    82b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000082c0 <__do_global_dtors_aux>:
    82c0:	f3 0f 1e fa          	endbr64 
    82c4:	80 3d dd 6f 01 00 00 	cmpb   $0x0,0x16fdd(%rip)        # 1f2a8 <completed.8061>
    82cb:	75 2b                	jne    82f8 <__do_global_dtors_aux+0x38>
    82cd:	55                   	push   %rbp
    82ce:	48 83 3d 1a 6d 01 00 	cmpq   $0x0,0x16d1a(%rip)        # 1eff0 <__cxa_finalize@GLIBC_2.2.5>
    82d5:	00 
    82d6:	48 89 e5             	mov    %rsp,%rbp
    82d9:	74 0c                	je     82e7 <__do_global_dtors_aux+0x27>
    82db:	48 8b 3d 26 6d 01 00 	mov    0x16d26(%rip),%rdi        # 1f008 <__dso_handle>
    82e2:	e8 b9 f3 ff ff       	callq  76a0 <__cxa_finalize@plt>
    82e7:	e8 64 ff ff ff       	callq  8250 <deregister_tm_clones>
    82ec:	c6 05 b5 6f 01 00 01 	movb   $0x1,0x16fb5(%rip)        # 1f2a8 <completed.8061>
    82f3:	5d                   	pop    %rbp
    82f4:	c3                   	retq   
    82f5:	0f 1f 00             	nopl   (%rax)
    82f8:	c3                   	retq   
    82f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000008300 <frame_dummy>:
    8300:	f3 0f 1e fa          	endbr64 
    8304:	e9 77 ff ff ff       	jmpq   8280 <register_tm_clones>
    8309:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000008310 <prepare_for_exit.part.0>:
prepare_for_exit (void)
    8310:	48 83 ec 08          	sub    $0x8,%rsp
  term_restore ();
    8314:	e8 47 70 00 00       	callq  f360 <term_restore>
  show_cursor ();
    8319:	e8 82 71 00 00       	callq  f4a0 <show_cursor>
  wrefresh (moon);
    831e:	48 8b 3d f3 8a 01 00 	mov    0x18af3(%rip),%rdi        # 20e18 <moon>
    8325:	e8 d6 f5 ff ff       	callq  7900 <wrefresh@plt>
  wrefresh (message);
    832a:	48 8b 3d cf 8a 01 00 	mov    0x18acf(%rip),%rdi        # 20e00 <message>
    8331:	e8 ca f5 ff ff       	callq  7900 <wrefresh@plt>
  werase (status);
    8336:	48 8b 3d d3 8a 01 00 	mov    0x18ad3(%rip),%rdi        # 20e10 <status>
    833d:	e8 7e f3 ff ff       	callq  76c0 <werase@plt>
  wmove (status, 0, 0);
    8342:	48 8b 3d c7 8a 01 00 	mov    0x18ac7(%rip),%rdi        # 20e10 <status>
    8349:	31 d2                	xor    %edx,%edx
    834b:	31 f6                	xor    %esi,%esi
    834d:	e8 7e f8 ff ff       	callq  7bd0 <wmove@plt>
  wrefresh (status);
    8352:	48 8b 3d b7 8a 01 00 	mov    0x18ab7(%rip),%rdi        # 20e10 <status>
    8359:	e8 a2 f5 ff ff       	callq  7900 <wrefresh@plt>
  endwin ();
    835e:	e8 1d f9 ff ff       	callq  7c80 <endwin@plt>
  fflush (NULL);
    8363:	31 ff                	xor    %edi,%edi
}
    8365:	48 83 c4 08          	add    $0x8,%rsp
  fflush (NULL);
    8369:	e9 f2 f6 ff ff       	jmpq   7a60 <fflush@plt>
    836e:	66 90                	xchg   %ax,%ax

0000000000008370 <print_message>:
{
    8370:	f3 0f 1e fa          	endbr64 
  if (curses_initialised) {
    8374:	8b 05 36 6f 01 00    	mov    0x16f36(%rip),%eax        # 1f2b0 <curses_initialised>
{
    837a:	41 54                	push   %r12
    837c:	49 89 fc             	mov    %rdi,%r12
  if (curses_initialised) {
    837f:	85 c0                	test   %eax,%eax
    8381:	74 35                	je     83b8 <print_message+0x48>
    werase (message);
    8383:	48 8b 3d 76 8a 01 00 	mov    0x18a76(%rip),%rdi        # 20e00 <message>
    838a:	e8 31 f3 ff ff       	callq  76c0 <werase@plt>
    waddstr (message, str);
    838f:	48 8b 3d 6a 8a 01 00 	mov    0x18a6a(%rip),%rdi        # 20e00 <message>
    8396:	4c 89 e6             	mov    %r12,%rsi
    8399:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    839e:	e8 fd f8 ff ff       	callq  7ca0 <waddnstr@plt>
    wnoutrefresh (message);
    83a3:	48 8b 3d 56 8a 01 00 	mov    0x18a56(%rip),%rdi        # 20e00 <message>
}
    83aa:	41 5c                	pop    %r12
    wnoutrefresh (message);
    83ac:	e9 0f f7 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    83b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    83b8:	48 89 f9             	mov    %rdi,%rcx
    83bb:	48 8b 3d de 6e 01 00 	mov    0x16ede(%rip),%rdi        # 1f2a0 <stderr@@GLIBC_2.2.5>
    83c2:	31 c0                	xor    %eax,%eax
}
    83c4:	41 5c                	pop    %r12
    83c6:	48 8d 15 37 7c 00 00 	lea    0x7c37(%rip),%rdx        # 10004 <_IO_stdin_used+0x4>
    83cd:	be 01 00 00 00       	mov    $0x1,%esi
    83d2:	e9 69 f8 ff ff       	jmpq   7c40 <__fprintf_chk@plt>
    83d7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    83de:	00 00 

00000000000083e0 <print_hint>:
{
    83e0:	f3 0f 1e fa          	endbr64 
  if (curses_initialised) {
    83e4:	8b 05 c6 6e 01 00    	mov    0x16ec6(%rip),%eax        # 1f2b0 <curses_initialised>
    83ea:	85 c0                	test   %eax,%eax
    83ec:	0f 84 ae 00 00 00    	je     84a0 <print_hint+0xc0>
{
    83f2:	41 54                	push   %r12
    83f4:	55                   	push   %rbp
    83f5:	48 89 fd             	mov    %rdi,%rbp
    83f8:	48 83 ec 08          	sub    $0x8,%rsp
    int  len = strlen (str);
    83fc:	e8 3f f4 ff ff       	callq  7840 <strlen@plt>
    int  cols = COLS;
    8401:	8b 35 79 6e 01 00    	mov    0x16e79(%rip),%esi        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
    if (car_base+3+len/2 >= cols) {
    8407:	8b 15 eb 89 01 00    	mov    0x189eb(%rip),%edx        # 20df8 <car_base>
    840d:	89 c1                	mov    %eax,%ecx
    840f:	c1 e9 1f             	shr    $0x1f,%ecx
    8412:	83 c2 03             	add    $0x3,%edx
      pos = cols - len - 1;
    8415:	41 89 f4             	mov    %esi,%r12d
    if (car_base+3+len/2 >= cols) {
    8418:	01 c1                	add    %eax,%ecx
      pos = cols - len - 1;
    841a:	41 29 c4             	sub    %eax,%r12d
    wmove (moon, LINES-11, 0);
    841d:	8b 05 61 6e 01 00    	mov    0x16e61(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    if (car_base+3+len/2 >= cols) {
    8423:	d1 f9                	sar    %ecx
      pos = cols - len - 1;
    8425:	41 83 ec 01          	sub    $0x1,%r12d
    if (car_base+3+len/2 >= cols) {
    8429:	8d 3c 11             	lea    (%rcx,%rdx,1),%edi
      pos = cols - len - 1;
    842c:	29 ca                	sub    %ecx,%edx
    842e:	39 f7                	cmp    %esi,%edi
    wmove (moon, LINES-11, 0);
    8430:	48 8b 3d e1 89 01 00 	mov    0x189e1(%rip),%rdi        # 20e18 <moon>
    8437:	8d 70 f5             	lea    -0xb(%rax),%esi
      pos = cols - len - 1;
    843a:	44 0f 4c e2          	cmovl  %edx,%r12d
    wmove (moon, LINES-11, 0);
    843e:	31 d2                	xor    %edx,%edx
    8440:	e8 8b f7 ff ff       	callq  7bd0 <wmove@plt>
    wclrtoeol (moon);
    8445:	48 8b 3d cc 89 01 00 	mov    0x189cc(%rip),%rdi        # 20e18 <moon>
    844c:	e8 8f f7 ff ff       	callq  7be0 <wclrtoeol@plt>
    mvwaddstr (moon, LINES-11, pos, str);
    8451:	8b 05 2d 6e 01 00    	mov    0x16e2d(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    8457:	48 8b 3d ba 89 01 00 	mov    0x189ba(%rip),%rdi        # 20e18 <moon>
    845e:	44 89 e2             	mov    %r12d,%edx
    8461:	8d 70 f5             	lea    -0xb(%rax),%esi
    8464:	e8 67 f7 ff ff       	callq  7bd0 <wmove@plt>
    8469:	83 f8 ff             	cmp    $0xffffffff,%eax
    846c:	75 1a                	jne    8488 <print_hint+0xa8>
    wnoutrefresh (moon);
    846e:	48 8b 3d a3 89 01 00 	mov    0x189a3(%rip),%rdi        # 20e18 <moon>
}
    8475:	48 83 c4 08          	add    $0x8,%rsp
    8479:	5d                   	pop    %rbp
    847a:	41 5c                	pop    %r12
    wnoutrefresh (moon);
    847c:	e9 3f f6 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    8481:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    mvwaddstr (moon, LINES-11, pos, str);
    8488:	48 8b 3d 89 89 01 00 	mov    0x18989(%rip),%rdi        # 20e18 <moon>
    848f:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8494:	48 89 ee             	mov    %rbp,%rsi
    8497:	e8 04 f8 ff ff       	callq  7ca0 <waddnstr@plt>
    849c:	eb d0                	jmp    846e <print_hint+0x8e>
    849e:	66 90                	xchg   %ax,%ax
    84a0:	c3                   	retq   
    84a1:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    84a8:	00 00 00 00 
    84ac:	0f 1f 40 00          	nopl   0x0(%rax)

00000000000084b0 <prepare_screen>:
{
    84b0:	f3 0f 1e fa          	endbr64 
    84b4:	48 83 ec 08          	sub    $0x8,%rsp
  cbreak ();
    84b8:	e8 83 f5 ff ff       	callq  7a40 <cbreak@plt>
  noecho ();
    84bd:	e8 8e f3 ff ff       	callq  7850 <noecho@plt>
  hide_cursor ();
    84c2:	e8 89 6f 00 00       	callq  f450 <hide_cursor>
  term_prepare (mesg_flag);
    84c7:	8b 3d df 6d 01 00    	mov    0x16ddf(%rip),%edi        # 1f2ac <mesg_flag>
}
    84cd:	48 83 c4 08          	add    $0x8,%rsp
  term_prepare (mesg_flag);
    84d1:	e9 2a 6d 00 00       	jmpq   f200 <term_prepare>
    84d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    84dd:	00 00 00 

00000000000084e0 <prepare_for_exit>:
{
    84e0:	f3 0f 1e fa          	endbr64 
  if (! curses_initialised)  return;
    84e4:	8b 05 c6 6d 01 00    	mov    0x16dc6(%rip),%eax        # 1f2b0 <curses_initialised>
    84ea:	85 c0                	test   %eax,%eax
    84ec:	75 02                	jne    84f0 <prepare_for_exit+0x10>
}
    84ee:	c3                   	retq   
    84ef:	90                   	nop
    84f0:	e9 1b fe ff ff       	jmpq   8310 <prepare_for_exit.part.0>
    84f5:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    84fc:	00 00 00 00 

0000000000008500 <allocate_windows>:
{
    8500:	f3 0f 1e fa          	endbr64 
    8504:	48 83 ec 08          	sub    $0x8,%rsp
  initscr ();
    8508:	e8 e3 f3 ff ff       	callq  78f0 <initscr@plt>
  moon = newwin (LINES-2, 0, 0, 0);
    850d:	8b 05 71 6d 01 00    	mov    0x16d71(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    8513:	31 c9                	xor    %ecx,%ecx
    8515:	31 d2                	xor    %edx,%edx
    8517:	31 f6                	xor    %esi,%esi
    8519:	8d 78 fe             	lea    -0x2(%rax),%edi
    851c:	e8 2f f2 ff ff       	callq  7750 <newwin@plt>
  keypad (moon, TRUE);
    8521:	be 01 00 00 00       	mov    $0x1,%esi
  moon = newwin (LINES-2, 0, 0, 0);
    8526:	48 89 c7             	mov    %rax,%rdi
    8529:	48 89 05 e8 88 01 00 	mov    %rax,0x188e8(%rip)        # 20e18 <moon>
  keypad (moon, TRUE);
    8530:	e8 fb f3 ff ff       	callq  7930 <keypad@plt>
  intrflush (moon, FALSE);
    8535:	48 8b 3d dc 88 01 00 	mov    0x188dc(%rip),%rdi        # 20e18 <moon>
    853c:	31 f6                	xor    %esi,%esi
    853e:	e8 ed f4 ff ff       	callq  7a30 <intrflush@plt>
  status = newwin (1, 0, LINES-1, 0);
    8543:	8b 05 3b 6d 01 00    	mov    0x16d3b(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    8549:	31 c9                	xor    %ecx,%ecx
    854b:	31 f6                	xor    %esi,%esi
    854d:	bf 01 00 00 00       	mov    $0x1,%edi
    8552:	8d 50 ff             	lea    -0x1(%rax),%edx
    8555:	e8 f6 f1 ff ff       	callq  7750 <newwin@plt>
  keypad (status, TRUE);
    855a:	be 01 00 00 00       	mov    $0x1,%esi
  status = newwin (1, 0, LINES-1, 0);
    855f:	48 89 c7             	mov    %rax,%rdi
    8562:	48 89 05 a7 88 01 00 	mov    %rax,0x188a7(%rip)        # 20e10 <status>
  keypad (status, TRUE);
    8569:	e8 c2 f3 ff ff       	callq  7930 <keypad@plt>
  intrflush (status, FALSE);
    856e:	48 8b 3d 9b 88 01 00 	mov    0x1889b(%rip),%rdi        # 20e10 <status>
    8575:	31 f6                	xor    %esi,%esi
    8577:	e8 b4 f4 ff ff       	callq  7a30 <intrflush@plt>
  message = newwin (1, 0, LINES-2, 0);
    857c:	8b 05 02 6d 01 00    	mov    0x16d02(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    8582:	31 c9                	xor    %ecx,%ecx
    8584:	31 f6                	xor    %esi,%esi
    8586:	bf 01 00 00 00       	mov    $0x1,%edi
    858b:	8d 50 fe             	lea    -0x2(%rax),%edx
    858e:	e8 bd f1 ff ff       	callq  7750 <newwin@plt>
  keypad (message, TRUE);
    8593:	be 01 00 00 00       	mov    $0x1,%esi
  message = newwin (1, 0, LINES-2, 0);
    8598:	48 89 c7             	mov    %rax,%rdi
    859b:	48 89 05 5e 88 01 00 	mov    %rax,0x1885e(%rip)        # 20e00 <message>
  keypad (message, TRUE);
    85a2:	e8 89 f3 ff ff       	callq  7930 <keypad@plt>
  intrflush (message, FALSE);
    85a7:	48 8b 3d 52 88 01 00 	mov    0x18852(%rip),%rdi        # 20e00 <message>
    85ae:	31 f6                	xor    %esi,%esi
}
    85b0:	48 83 c4 08          	add    $0x8,%rsp
  intrflush (message, FALSE);
    85b4:	e9 77 f4 ff ff       	jmpq   7a30 <intrflush@plt>
    85b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000085c0 <clear_windows>:
{
    85c0:	f3 0f 1e fa          	endbr64 
    85c4:	48 83 ec 08          	sub    $0x8,%rsp
  wclear (moon);  wnoutrefresh (moon);
    85c8:	48 8b 3d 49 88 01 00 	mov    0x18849(%rip),%rdi        # 20e18 <moon>
    85cf:	e8 2c f2 ff ff       	callq  7800 <wclear@plt>
    85d4:	48 8b 3d 3d 88 01 00 	mov    0x1883d(%rip),%rdi        # 20e18 <moon>
    85db:	e8 e0 f4 ff ff       	callq  7ac0 <wnoutrefresh@plt>
  wclear (status);  wnoutrefresh (status);
    85e0:	48 8b 3d 29 88 01 00 	mov    0x18829(%rip),%rdi        # 20e10 <status>
    85e7:	e8 14 f2 ff ff       	callq  7800 <wclear@plt>
    85ec:	48 8b 3d 1d 88 01 00 	mov    0x1881d(%rip),%rdi        # 20e10 <status>
    85f3:	e8 c8 f4 ff ff       	callq  7ac0 <wnoutrefresh@plt>
  wclear (message);  wnoutrefresh (message);
    85f8:	48 8b 3d 01 88 01 00 	mov    0x18801(%rip),%rdi        # 20e00 <message>
    85ff:	e8 fc f1 ff ff       	callq  7800 <wclear@plt>
    8604:	48 8b 3d f5 87 01 00 	mov    0x187f5(%rip),%rdi        # 20e00 <message>
}
    860b:	48 83 c4 08          	add    $0x8,%rsp
  wclear (message);  wnoutrefresh (message);
    860f:	e9 ac f4 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    8614:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    861b:	00 00 00 
    861e:	66 90                	xchg   %ax,%ax

0000000000008620 <mode_redraw.part.0>:
  }
  doupdate ();
}

void
mode_redraw (void)
    8620:	48 83 ec 08          	sub    $0x8,%rsp
/* Make the current mode redraw the screen but leave the status message intact.
 * This is also called after the screen is resized.  */
{
  if (! mode_entered)  return;
  describe_keys (current->keys.used, current->keys.data);
    8624:	48 8b 05 95 6c 01 00 	mov    0x16c95(%rip),%rax        # 1f2c0 <current>
    862b:	48 8b 70 20          	mov    0x20(%rax),%rsi
    862f:	8b 78 28             	mov    0x28(%rax),%edi
    8632:	e8 c9 65 00 00       	callq  ec00 <describe_keys>
  if (current->redraw)  current->redraw ();
    8637:	48 8b 05 82 6c 01 00 	mov    0x16c82(%rip),%rax        # 1f2c0 <current>
    863e:	48 8b 40 10          	mov    0x10(%rax),%rax
    8642:	48 85 c0             	test   %rax,%rax
    8645:	74 02                	je     8649 <mode_redraw.part.0+0x29>
    8647:	ff d0                	callq  *%rax
  doupdate ();
}
    8649:	48 83 c4 08          	add    $0x8,%rsp
  doupdate ();
    864d:	e9 4e f5 ff ff       	jmpq   7ba0 <doupdate@plt>
    8652:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    8659:	00 00 00 00 
    865d:	0f 1f 00             	nopl   (%rax)

0000000000008660 <new_mode>:
{
    8660:	f3 0f 1e fa          	endbr64 
    8664:	41 54                	push   %r12
  struct mode *res = xmalloc (sizeof (struct mode));
    8666:	bf 38 00 00 00       	mov    $0x38,%edi
    866b:	e8 f0 6f 00 00       	callq  f660 <xmalloc>
  DA_INIT (res->keys, struct binding);
    8670:	bf 60 00 00 00       	mov    $0x60,%edi
  res->enter = NULL;
    8675:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
  struct mode *res = xmalloc (sizeof (struct mode));
    867c:	49 89 c4             	mov    %rax,%r12
  res->leave = NULL;
    867f:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
    8686:	00 
  res->redraw = NULL;
    8687:	48 c7 40 10 00 00 00 	movq   $0x0,0x10(%rax)
    868e:	00 
  DA_INIT (res->keys, struct binding);
    868f:	c7 40 2c 04 00 00 00 	movl   $0x4,0x2c(%rax)
    8696:	e8 c5 6f 00 00       	callq  f660 <xmalloc>
    869b:	41 c7 44 24 28 00 00 	movl   $0x0,0x28(%r12)
    86a2:	00 00 
    86a4:	49 89 44 24 20       	mov    %rax,0x20(%r12)
}
    86a9:	4c 89 e0             	mov    %r12,%rax
  res->keypress = NULL;
    86ac:	49 c7 44 24 30 00 00 	movq   $0x0,0x30(%r12)
    86b3:	00 00 
}
    86b5:	41 5c                	pop    %r12
    86b7:	c3                   	retq   
    86b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    86bf:	00 

00000000000086c0 <mode_add_key>:
{
    86c0:	f3 0f 1e fa          	endbr64 
    86c4:	41 55                	push   %r13
    86c6:	41 89 f5             	mov    %esi,%r13d
    86c9:	41 54                	push   %r12
    86cb:	49 89 d4             	mov    %rdx,%r12
    86ce:	55                   	push   %rbp
    86cf:	89 cd                	mov    %ecx,%ebp
    86d1:	53                   	push   %rbx
    86d2:	48 89 fb             	mov    %rdi,%rbx
    86d5:	48 83 ec 08          	sub    $0x8,%rsp
  DA_ADD_EMPTY (m->keys, struct binding, keys);
    86d9:	8b 77 28             	mov    0x28(%rdi),%esi
    86dc:	44 8b 47 2c          	mov    0x2c(%rdi),%r8d
    86e0:	48 8b 7f 20          	mov    0x20(%rdi),%rdi
    86e4:	44 39 c6             	cmp    %r8d,%esi
    86e7:	7d 27                	jge    8710 <mode_add_key+0x50>
    86e9:	48 63 c6             	movslq %esi,%rax
    86ec:	83 c6 01             	add    $0x1,%esi
    86ef:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
    86f3:	89 73 28             	mov    %esi,0x28(%rbx)
    86f6:	48 8d 04 c7          	lea    (%rdi,%rax,8),%rax
  keys->meanings = meanings;
    86fa:	44 89 28             	mov    %r13d,(%rax)
  keys->desc = desc;
    86fd:	4c 89 60 08          	mov    %r12,0x8(%rax)
  keys->res = res;
    8701:	89 68 10             	mov    %ebp,0x10(%rax)
}
    8704:	48 83 c4 08          	add    $0x8,%rsp
    8708:	5b                   	pop    %rbx
    8709:	5d                   	pop    %rbp
    870a:	41 5c                	pop    %r12
    870c:	41 5d                	pop    %r13
    870e:	c3                   	retq   
    870f:	90                   	nop
  DA_ADD_EMPTY (m->keys, struct binding, keys);
    8710:	41 83 c0 04          	add    $0x4,%r8d
    8714:	44 89 43 2c          	mov    %r8d,0x2c(%rbx)
    8718:	4d 63 c0             	movslq %r8d,%r8
    871b:	4b 8d 34 40          	lea    (%r8,%r8,2),%rsi
    871f:	48 c1 e6 03          	shl    $0x3,%rsi
    8723:	e8 68 6f 00 00       	callq  f690 <xrealloc>
    8728:	8b 73 28             	mov    0x28(%rbx),%esi
    872b:	48 89 43 20          	mov    %rax,0x20(%rbx)
    872f:	48 89 c7             	mov    %rax,%rdi
    8732:	eb b5                	jmp    86e9 <mode_add_key+0x29>
    8734:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    873b:	00 00 00 00 
    873f:	90                   	nop

0000000000008740 <mode_complete>:
{
    8740:	f3 0f 1e fa          	endbr64 
  mode_add_key (m, mbk_redraw, "redraw", 0);
    8744:	31 c9                	xor    %ecx,%ecx
    8746:	48 8d 15 47 7c 00 00 	lea    0x7c47(%rip),%rdx        # 10394 <_IO_stdin_used+0x394>
    874d:	be 00 20 00 00       	mov    $0x2000,%esi
    8752:	e9 69 ff ff ff       	jmpq   86c0 <mode_add_key>
    8757:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    875e:	00 00 

0000000000008760 <mode_change>:
{
    8760:	f3 0f 1e fa          	endbr64 
    8764:	55                   	push   %rbp
    8765:	48 89 fd             	mov    %rdi,%rbp
    8768:	53                   	push   %rbx
    8769:	89 f3                	mov    %esi,%ebx
    876b:	48 83 ec 08          	sub    $0x8,%rsp
  if (mode_entered && current->leave)  current->leave ();
    876f:	8b 05 47 6b 01 00    	mov    0x16b47(%rip),%eax        # 1f2bc <mode_entered>
    8775:	85 c0                	test   %eax,%eax
    8777:	74 12                	je     878b <mode_change+0x2b>
    8779:	48 8b 05 40 6b 01 00 	mov    0x16b40(%rip),%rax        # 1f2c0 <current>
    8780:	48 8b 40 08          	mov    0x8(%rax),%rax
    8784:	48 85 c0             	test   %rax,%rax
    8787:	74 02                	je     878b <mode_change+0x2b>
    8789:	ff d0                	callq  *%rax
  current = m;
    878b:	48 89 2d 2e 6b 01 00 	mov    %rbp,0x16b2e(%rip)        # 1f2c0 <current>
  mode_seed = seed;
    8792:	89 1d 20 6b 01 00    	mov    %ebx,0x16b20(%rip)        # 1f2b8 <mode_seed>
  mode_entered = 0;
    8798:	c7 05 1a 6b 01 00 00 	movl   $0x0,0x16b1a(%rip)        # 1f2bc <mode_entered>
    879f:	00 00 00 
}
    87a2:	48 83 c4 08          	add    $0x8,%rsp
    87a6:	5b                   	pop    %rbx
    87a7:	5d                   	pop    %rbp
    87a8:	c3                   	retq   
    87a9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000087b0 <mode_update>:
{
    87b0:	f3 0f 1e fa          	endbr64 
  if (! mode_entered) {
    87b4:	8b 15 02 6b 01 00    	mov    0x16b02(%rip),%edx        # 1f2bc <mode_entered>
    87ba:	85 d2                	test   %edx,%edx
    87bc:	74 0a                	je     87c8 <mode_update+0x18>
  doupdate ();
    87be:	e9 dd f3 ff ff       	jmpq   7ba0 <doupdate@plt>
    87c3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
{
    87c8:	48 83 ec 08          	sub    $0x8,%rsp
    clear_queue ();
    87cc:	e8 ef 4e 00 00       	callq  d6c0 <clear_queue>
  werase (moon);
    87d1:	48 8b 3d 40 86 01 00 	mov    0x18640(%rip),%rdi        # 20e18 <moon>
    87d8:	e8 e3 ee ff ff       	callq  76c0 <werase@plt>
  wnoutrefresh (moon);
    87dd:	48 8b 3d 34 86 01 00 	mov    0x18634(%rip),%rdi        # 20e18 <moon>
    87e4:	e8 d7 f2 ff ff       	callq  7ac0 <wnoutrefresh@plt>
  if (! current)  return;
    87e9:	48 8b 05 d0 6a 01 00 	mov    0x16ad0(%rip),%rax        # 1f2c0 <current>
    87f0:	48 85 c0             	test   %rax,%rax
    87f3:	74 2b                	je     8820 <mode_update+0x70>
  if (current->enter)  current->enter (mode_seed);
    87f5:	48 8b 00             	mov    (%rax),%rax
    87f8:	48 85 c0             	test   %rax,%rax
    87fb:	74 08                	je     8805 <mode_update+0x55>
    87fd:	8b 3d b5 6a 01 00    	mov    0x16ab5(%rip),%edi        # 1f2b8 <mode_seed>
    8803:	ff d0                	callq  *%rax
  mode_entered = 1;
    8805:	c7 05 ad 6a 01 00 01 	movl   $0x1,0x16aad(%rip)        # 1f2bc <mode_entered>
    880c:	00 00 00 
  if (! mode_entered)  return;
    880f:	e8 0c fe ff ff       	callq  8620 <mode_redraw.part.0>
}
    8814:	48 83 c4 08          	add    $0x8,%rsp
  doupdate ();
    8818:	e9 83 f3 ff ff       	jmpq   7ba0 <doupdate@plt>
    881d:	0f 1f 00             	nopl   (%rax)
  if (! mode_entered)  return;
    8820:	8b 05 96 6a 01 00    	mov    0x16a96(%rip),%eax        # 1f2bc <mode_entered>
    8826:	85 c0                	test   %eax,%eax
    8828:	75 e5                	jne    880f <mode_update+0x5f>
}
    882a:	48 83 c4 08          	add    $0x8,%rsp
  doupdate ();
    882e:	e9 6d f3 ff ff       	jmpq   7ba0 <doupdate@plt>
    8833:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    883a:	00 00 00 00 
    883e:	66 90                	xchg   %ax,%ax

0000000000008840 <mode_redraw>:
{
    8840:	f3 0f 1e fa          	endbr64 
  if (! mode_entered)  return;
    8844:	8b 05 72 6a 01 00    	mov    0x16a72(%rip),%eax        # 1f2bc <mode_entered>
    884a:	85 c0                	test   %eax,%eax
    884c:	75 02                	jne    8850 <mode_redraw+0x10>
}
    884e:	c3                   	retq   
    884f:	90                   	nop
    8850:	e9 cb fd ff ff       	jmpq   8620 <mode_redraw.part.0>
    8855:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    885c:	00 00 00 00 

0000000000008860 <mode_keypress>:

int
mode_keypress (game_time t, int meaning)
/* Feed a keypress with meaning MEANING to the current mode.
 * Return 1 if the keypress could be processed, and 0 else.  */
{
    8860:	f3 0f 1e fa          	endbr64 
    8864:	41 54                	push   %r12
  int  i;

  if (meaning == mbk_redraw) {
    8866:	81 ff 00 20 00 00    	cmp    $0x2000,%edi
    886c:	74 52                	je     88c0 <mode_keypress+0x60>
    clear_windows ();
    mode_redraw ();
    return  1;
  }
  for (i=0; i<current->keys.used; ++i) {
    886e:	48 8b 0d 4b 6a 01 00 	mov    0x16a4b(%rip),%rcx        # 1f2c0 <current>
    if (current->keys.data[i].meanings & meaning) {
      current->keypress (t, current->keys.data[i].res);
      return  1;
    }
  }
  return  0;
    8875:	45 31 e4             	xor    %r12d,%r12d
  for (i=0; i<current->keys.used; ++i) {
    8878:	8b 51 28             	mov    0x28(%rcx),%edx
    887b:	85 d2                	test   %edx,%edx
    887d:	7e 36                	jle    88b5 <mode_keypress+0x55>
    887f:	48 8b 41 20          	mov    0x20(%rcx),%rax
    8883:	83 ea 01             	sub    $0x1,%edx
    8886:	48 8d 14 52          	lea    (%rdx,%rdx,2),%rdx
    888a:	48 8d 54 d0 18       	lea    0x18(%rax,%rdx,8),%rdx
    888f:	eb 10                	jmp    88a1 <mode_keypress+0x41>
    8891:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    8898:	48 83 c0 18          	add    $0x18,%rax
    889c:	48 39 d0             	cmp    %rdx,%rax
    889f:	74 14                	je     88b5 <mode_keypress+0x55>
    if (current->keys.data[i].meanings & meaning) {
    88a1:	41 89 fc             	mov    %edi,%r12d
    88a4:	44 23 20             	and    (%rax),%r12d
    88a7:	74 ef                	je     8898 <mode_keypress+0x38>
      current->keypress (t, current->keys.data[i].res);
    88a9:	8b 78 10             	mov    0x10(%rax),%edi
      return  1;
    88ac:	41 bc 01 00 00 00    	mov    $0x1,%r12d
      current->keypress (t, current->keys.data[i].res);
    88b2:	ff 51 30             	callq  *0x30(%rcx)
}
    88b5:	44 89 e0             	mov    %r12d,%eax
    88b8:	41 5c                	pop    %r12
    88ba:	c3                   	retq   
    88bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    clear_windows ();
    88c0:	e8 fb fc ff ff       	callq  85c0 <clear_windows>
  if (! mode_entered)  return;
    88c5:	8b 05 f1 69 01 00    	mov    0x169f1(%rip),%eax        # 1f2bc <mode_entered>
    return  1;
    88cb:	41 bc 01 00 00 00    	mov    $0x1,%r12d
  if (! mode_entered)  return;
    88d1:	85 c0                	test   %eax,%eax
    88d3:	74 e0                	je     88b5 <mode_keypress+0x55>
    88d5:	e8 46 fd ff ff       	callq  8620 <mode_redraw.part.0>
    88da:	eb d9                	jmp    88b5 <mode_keypress+0x55>
    88dc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000000088e0 <mode_signal>:

void
mode_signal (int signum)
/* Feed signal SIGNUM to the current mode.  */
{
    88e0:	f3 0f 1e fa          	endbr64 
  if (current->signal)  current->signal (signum);
    88e4:	48 8b 05 d5 69 01 00 	mov    0x169d5(%rip),%rax        # 1f2c0 <current>
    88eb:	48 8b 40 18          	mov    0x18(%rax),%rax
    88ef:	48 85 c0             	test   %rax,%rax
    88f2:	74 0c                	je     8900 <mode_signal+0x20>
    88f4:	ff e0                	jmpq   *%rax
    88f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    88fd:	00 00 00 
}
    8900:	c3                   	retq   
    8901:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8908:	00 00 00 
    890b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000008910 <title_redraw>:
  wnoutrefresh (moon);
}

static void
title_redraw (void)
{
    8910:	f3 0f 1e fa          	endbr64 
    8914:	41 54                	push   %r12
  resize_ground (1);
    8916:	bf 01 00 00 00       	mov    $0x1,%edi
{
    891b:	55                   	push   %rbp
    891c:	53                   	push   %rbx
  resize_ground (1);
    891d:	e8 3e 1b 00 00       	callq  a460 <resize_ground>
  print_ground ();
    8922:	e8 29 1c 00 00       	callq  a550 <print_ground>
  mvwaddstr (moon, 0, 0, "  Moon-Buggy version "
    8927:	48 8b 3d ea 84 01 00 	mov    0x184ea(%rip),%rdi        # 20e18 <moon>
    892e:	31 d2                	xor    %edx,%edx
    8930:	31 f6                	xor    %esi,%esi
    8932:	e8 99 f2 ff ff       	callq  7bd0 <wmove@plt>
    8937:	83 f8 ff             	cmp    $0xffffffff,%eax
    893a:	74 18                	je     8954 <title_redraw+0x44>
    893c:	48 8b 3d d5 84 01 00 	mov    0x184d5(%rip),%rdi        # 20e18 <moon>
    8943:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8948:	48 8d 35 51 7a 00 00 	lea    0x7a51(%rip),%rsi        # 103a0 <_IO_stdin_used+0x3a0>
    894f:	e8 4c f3 ff ff       	callq  7ca0 <waddnstr@plt>
  waddstr (moon, "  Moon-Buggy comes with ABSOLUTELY NO WARRANTY;"
    8954:	48 8b 3d bd 84 01 00 	mov    0x184bd(%rip),%rdi        # 20e18 <moon>
    895b:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8960:	48 8d 35 89 7a 00 00 	lea    0x7a89(%rip),%rsi        # 103f0 <_IO_stdin_used+0x3f0>
    8967:	e8 34 f3 ff ff       	callq  7ca0 <waddnstr@plt>
  waddstr (moon,
    896c:	48 8b 3d a5 84 01 00 	mov    0x184a5(%rip),%rdi        # 20e18 <moon>
    8973:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8978:	48 8d 35 b9 7a 00 00 	lea    0x7ab9(%rip),%rsi        # 10438 <_IO_stdin_used+0x438>
    897f:	e8 1c f3 ff ff       	callq  7ca0 <waddnstr@plt>
  if (5 + title_lines + 5 <= LINES) {
    8984:	8b 05 fa 68 01 00    	mov    0x168fa(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    898a:	83 f8 16             	cmp    $0x16,%eax
    898d:	0f 8e 89 00 00 00    	jle    8a1c <title_redraw+0x10c>
    int  top = (LINES-title_lines)/3.0 + 0.5;
    8993:	83 e8 0d             	sub    $0xd,%eax
    8996:	66 0f ef c0          	pxor   %xmm0,%xmm0
    899a:	4c 8d 25 7f 66 01 00 	lea    0x1667f(%rip),%r12        # 1f020 <title>
    89a1:	f2 0f 2a c0          	cvtsi2sd %eax,%xmm0
    89a5:	b8 05 00 00 00       	mov    $0x5,%eax
    89aa:	49 8d 6c 24 68       	lea    0x68(%r12),%rbp
    89af:	f2 0f 5e 05 71 7d 00 	divsd  0x7d71(%rip),%xmm0        # 10728 <_IO_stdin_used+0x728>
    89b6:	00 
    89b7:	f2 0f 58 05 71 7d 00 	addsd  0x7d71(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    89be:	00 
    89bf:	f2 0f 2c d8          	cvttsd2si %xmm0,%ebx
    for (i=0; i<title_lines; ++i) {
    89c3:	83 fb 05             	cmp    $0x5,%ebx
    89c6:	0f 4c d8             	cmovl  %eax,%ebx
    89c9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      mvwaddstr (moon, top+i, (COLS-49)/2, title[i]);
    89d0:	8b 05 aa 68 01 00    	mov    0x168aa(%rip),%eax        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
    89d6:	48 8b 3d 3b 84 01 00 	mov    0x1843b(%rip),%rdi        # 20e18 <moon>
    89dd:	89 de                	mov    %ebx,%esi
    89df:	83 e8 31             	sub    $0x31,%eax
    89e2:	89 c2                	mov    %eax,%edx
    89e4:	c1 ea 1f             	shr    $0x1f,%edx
    89e7:	01 c2                	add    %eax,%edx
    89e9:	d1 fa                	sar    %edx
    89eb:	e8 e0 f1 ff ff       	callq  7bd0 <wmove@plt>
    89f0:	83 f8 ff             	cmp    $0xffffffff,%eax
    89f3:	74 15                	je     8a0a <title_redraw+0xfa>
    89f5:	49 8b 34 24          	mov    (%r12),%rsi
    89f9:	48 8b 3d 18 84 01 00 	mov    0x18418(%rip),%rdi        # 20e18 <moon>
    8a00:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8a05:	e8 96 f2 ff ff       	callq  7ca0 <waddnstr@plt>
    for (i=0; i<title_lines; ++i) {
    8a0a:	49 83 c4 08          	add    $0x8,%r12
    8a0e:	83 c3 01             	add    $0x1,%ebx
    8a11:	4c 39 e5             	cmp    %r12,%rbp
    8a14:	75 ba                	jne    89d0 <title_redraw+0xc0>
    8a16:	8b 05 68 68 01 00    	mov    0x16868(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
      || 5 + title_lines + 5 > LINES)  print_buggy ();
    8a1c:	83 e8 17             	sub    $0x17,%eax
    8a1f:	83 f8 01             	cmp    $0x1,%eax
    8a22:	76 05                	jbe    8a29 <title_redraw+0x119>
    8a24:	e8 97 1f 00 00       	callq  a9c0 <print_buggy>
  wnoutrefresh (moon);
    8a29:	48 8b 3d e8 83 01 00 	mov    0x183e8(%rip),%rdi        # 20e18 <moon>
  print_title ();
}
    8a30:	5b                   	pop    %rbx
    8a31:	5d                   	pop    %rbp
    8a32:	41 5c                	pop    %r12
  wnoutrefresh (moon);
    8a34:	e9 87 f0 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    8a39:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000008a40 <key_handler>:

static void
key_handler (game_time t, int val)
{
    8a40:	f3 0f 1e fa          	endbr64 
  switch (val) {
    8a44:	83 ff 05             	cmp    $0x5,%edi
    8a47:	77 68                	ja     8ab1 <key_handler+0x71>
    8a49:	48 8d 15 80 7c 00 00 	lea    0x7c80(%rip),%rdx        # 106d0 <_IO_stdin_used+0x6d0>
    8a50:	89 ff                	mov    %edi,%edi
    8a52:	48 63 04 ba          	movslq (%rdx,%rdi,4),%rax
    8a56:	48 01 d0             	add    %rdx,%rax
    8a59:	3e ff e0             	notrack jmpq *%rax
    8a5c:	0f 1f 40 00          	nopl   0x0(%rax)
    break;
  case 4:
    mode_change (pager_mode, 1);
    break;
  case 5:
    mode_change (highscore_mode, 0);
    8a60:	48 8b 3d 09 84 01 00 	mov    0x18409(%rip),%rdi        # 20e70 <highscore_mode>
    8a67:	31 f6                	xor    %esi,%esi
    8a69:	e9 f2 fc ff ff       	jmpq   8760 <mode_change>
    8a6e:	66 90                	xchg   %ax,%ax
    mode_change (game_mode, 0);
    8a70:	48 8b 3d c9 83 01 00 	mov    0x183c9(%rip),%rdi        # 20e40 <game_mode>
    8a77:	31 f6                	xor    %esi,%esi
    8a79:	e9 e2 fc ff ff       	jmpq   8760 <mode_change>
    8a7e:	66 90                	xchg   %ax,%ax
    quit_main_loop ();
    8a80:	e9 cb 4e 00 00       	jmpq   d950 <quit_main_loop>
    8a85:	0f 1f 00             	nopl   (%rax)
    mode_change (pager_mode, 0);
    8a88:	48 8b 3d 99 83 01 00 	mov    0x18399(%rip),%rdi        # 20e28 <pager_mode>
    8a8f:	31 f6                	xor    %esi,%esi
    8a91:	e9 ca fc ff ff       	jmpq   8760 <mode_change>
    8a96:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8a9d:	00 00 00 
    mode_change (pager_mode, 1);
    8aa0:	48 8b 3d 81 83 01 00 	mov    0x18381(%rip),%rdi        # 20e28 <pager_mode>
    8aa7:	be 01 00 00 00       	mov    $0x1,%esi
    8aac:	e9 af fc ff ff       	jmpq   8760 <mode_change>
    break;
  }
}
    8ab1:	c3                   	retq   
    8ab2:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    8ab9:	00 00 00 00 
    8abd:	0f 1f 00             	nopl   (%rax)

0000000000008ac0 <setup_title_mode>:

void
setup_title_mode (void)
{
    8ac0:	f3 0f 1e fa          	endbr64 
    8ac4:	48 83 ec 08          	sub    $0x8,%rsp
  title_mode = new_mode ();
    8ac8:	e8 93 fb ff ff       	callq  8660 <new_mode>
  title_mode->redraw = title_redraw;
  title_mode->keypress = key_handler;
  mode_add_key (title_mode, mbk_start, "start game", 1);
    8acd:	b9 01 00 00 00       	mov    $0x1,%ecx
    8ad2:	be 00 02 00 00       	mov    $0x200,%esi
    8ad7:	48 8d 15 0a 7c 00 00 	lea    0x7c0a(%rip),%rdx        # 106e8 <_IO_stdin_used+0x6e8>
  title_mode = new_mode ();
    8ade:	48 89 c7             	mov    %rax,%rdi
    8ae1:	48 89 05 38 83 01 00 	mov    %rax,0x18338(%rip)        # 20e20 <title_mode>
  title_mode->redraw = title_redraw;
    8ae8:	48 8d 05 21 fe ff ff 	lea    -0x1df(%rip),%rax        # 8910 <title_redraw>
    8aef:	48 89 47 10          	mov    %rax,0x10(%rdi)
  title_mode->keypress = key_handler;
    8af3:	48 8d 05 46 ff ff ff 	lea    -0xba(%rip),%rax        # 8a40 <key_handler>
    8afa:	48 89 47 30          	mov    %rax,0x30(%rdi)
  mode_add_key (title_mode, mbk_start, "start game", 1);
    8afe:	e8 bd fb ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (title_mode, mbk_end, "quit", 2);
    8b03:	b9 02 00 00 00       	mov    $0x2,%ecx
    8b08:	be 04 00 00 00       	mov    $0x4,%esi
    8b0d:	48 8b 3d 0c 83 01 00 	mov    0x1830c(%rip),%rdi        # 20e20 <title_mode>
    8b14:	48 8d 15 d8 7b 00 00 	lea    0x7bd8(%rip),%rdx        # 106f3 <_IO_stdin_used+0x6f3>
    8b1b:	e8 a0 fb ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (title_mode, mbk_copyright, "show copyright", 3);
    8b20:	b9 03 00 00 00       	mov    $0x3,%ecx
    8b25:	be 01 00 00 00       	mov    $0x1,%esi
    8b2a:	48 8b 3d ef 82 01 00 	mov    0x182ef(%rip),%rdi        # 20e20 <title_mode>
    8b31:	48 8d 15 c0 7b 00 00 	lea    0x7bc0(%rip),%rdx        # 106f8 <_IO_stdin_used+0x6f8>
    8b38:	e8 83 fb ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (title_mode, mbk_warranty, "show warranty", 4);
    8b3d:	b9 04 00 00 00       	mov    $0x4,%ecx
    8b42:	be 00 08 00 00       	mov    $0x800,%esi
    8b47:	48 8b 3d d2 82 01 00 	mov    0x182d2(%rip),%rdi        # 20e20 <title_mode>
    8b4e:	48 8d 15 b2 7b 00 00 	lea    0x7bb2(%rip),%rdx        # 10707 <_IO_stdin_used+0x707>
    8b55:	e8 66 fb ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (title_mode, mbk_scores, "show scores", 5);
    8b5a:	b9 05 00 00 00       	mov    $0x5,%ecx
    8b5f:	be 00 10 00 00       	mov    $0x1000,%esi
    8b64:	48 8b 3d b5 82 01 00 	mov    0x182b5(%rip),%rdi        # 20e20 <title_mode>
    8b6b:	48 8d 15 a3 7b 00 00 	lea    0x7ba3(%rip),%rdx        # 10715 <_IO_stdin_used+0x715>
    8b72:	e8 49 fb ff ff       	callq  86c0 <mode_add_key>
  mode_complete (title_mode);
    8b77:	48 8b 3d a2 82 01 00 	mov    0x182a2(%rip),%rdi        # 20e20 <title_mode>
}
    8b7e:	48 83 c4 08          	add    $0x8,%rsp
  mode_complete (title_mode);
    8b82:	e9 b9 fb ff ff       	jmpq   8740 <mode_complete>
    8b87:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    8b8e:	00 00 

0000000000008b90 <print_page>:
static  int  mb_lines = 25;


static void
print_page (unsigned current_line)
{
    8b90:	41 55                	push   %r13
    8b92:	4c 8d 2d 87 47 01 00 	lea    0x14787(%rip),%r13        # 1d320 <copying_lines>
    8b99:	41 54                	push   %r12
    8b9b:	41 89 fc             	mov    %edi,%r12d
    8b9e:	55                   	push   %rbp
    8b9f:	44 89 e5             	mov    %r12d,%ebp
    8ba2:	53                   	push   %rbx
    8ba3:	31 db                	xor    %ebx,%ebx
    8ba5:	48 83 ec 08          	sub    $0x8,%rsp
  int  i;

  for (i=0; i<mb_lines-3; ++i) {
    8ba9:	83 3d d8 64 01 00 03 	cmpl   $0x3,0x164d8(%rip)        # 1f088 <mb_lines>
    8bb0:	7f 4f                	jg     8c01 <print_page+0x71>
    8bb2:	e9 89 00 00 00       	jmpq   8c40 <print_page+0xb0>
    8bb7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    8bbe:	00 00 
    if (current_line + i < lines_used) {
      mvwaddstr (moon, i, 2, copying_lines[current_line+i]);
    8bc0:	e8 0b f0 ff ff       	callq  7bd0 <wmove@plt>
    8bc5:	83 f8 ff             	cmp    $0xffffffff,%eax
    8bc8:	74 18                	je     8be2 <print_page+0x52>
    8bca:	89 e8                	mov    %ebp,%eax
    8bcc:	48 8b 3d 45 82 01 00 	mov    0x18245(%rip),%rdi        # 20e18 <moon>
    8bd3:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8bd8:	49 8b 74 c5 00       	mov    0x0(%r13,%rax,8),%rsi
    8bdd:	e8 be f0 ff ff       	callq  7ca0 <waddnstr@plt>
    } else {
      mvwaddstr (moon, i, 2, "~");
    }
    wclrtoeol (moon);
    8be2:	48 8b 3d 2f 82 01 00 	mov    0x1822f(%rip),%rdi        # 20e18 <moon>
  for (i=0; i<mb_lines-3; ++i) {
    8be9:	83 c3 01             	add    $0x1,%ebx
    8bec:	83 c5 01             	add    $0x1,%ebp
    wclrtoeol (moon);
    8bef:	e8 ec ef ff ff       	callq  7be0 <wclrtoeol@plt>
  for (i=0; i<mb_lines-3; ++i) {
    8bf4:	8b 05 8e 64 01 00    	mov    0x1648e(%rip),%eax        # 1f088 <mb_lines>
    8bfa:	83 e8 03             	sub    $0x3,%eax
    8bfd:	39 d8                	cmp    %ebx,%eax
    8bff:	7e 3f                	jle    8c40 <print_page+0xb0>
    if (current_line + i < lines_used) {
    8c01:	39 2d c5 66 01 00    	cmp    %ebp,0x166c5(%rip)        # 1f2cc <lines_used>
    8c07:	48 8b 3d 0a 82 01 00 	mov    0x1820a(%rip),%rdi        # 20e18 <moon>
      mvwaddstr (moon, i, 2, copying_lines[current_line+i]);
    8c0e:	ba 02 00 00 00       	mov    $0x2,%edx
    8c13:	89 de                	mov    %ebx,%esi
    if (current_line + i < lines_used) {
    8c15:	77 a9                	ja     8bc0 <print_page+0x30>
      mvwaddstr (moon, i, 2, "~");
    8c17:	e8 b4 ef ff ff       	callq  7bd0 <wmove@plt>
    8c1c:	83 f8 ff             	cmp    $0xffffffff,%eax
    8c1f:	74 c1                	je     8be2 <print_page+0x52>
    8c21:	48 8b 3d f0 81 01 00 	mov    0x181f0(%rip),%rdi        # 20e18 <moon>
    8c28:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    8c2d:	48 8d 35 04 7b 00 00 	lea    0x7b04(%rip),%rsi        # 10738 <_IO_stdin_used+0x738>
    8c34:	e8 67 f0 ff ff       	callq  7ca0 <waddnstr@plt>
    8c39:	eb a7                	jmp    8be2 <print_page+0x52>
    8c3b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  }
  wnoutrefresh (moon);
    8c40:	48 8b 3d d1 81 01 00 	mov    0x181d1(%rip),%rdi        # 20e18 <moon>
    8c47:	e8 74 ee ff ff       	callq  7ac0 <wnoutrefresh@plt>

  mvwprintw (status, 0, 0, "=== COPYING %3d%% ===  ",
             lines_used==0 ? 100 :(int)(current_line*100.0/(lines_used-1)+.5));
    8c4c:	8b 05 7a 66 01 00    	mov    0x1667a(%rip),%eax        # 1f2cc <lines_used>
  mvwprintw (status, 0, 0, "=== COPYING %3d%% ===  ",
    8c52:	41 b8 64 00 00 00    	mov    $0x64,%r8d
    8c58:	85 c0                	test   %eax,%eax
    8c5a:	74 2d                	je     8c89 <print_page+0xf9>
             lines_used==0 ? 100 :(int)(current_line*100.0/(lines_used-1)+.5));
    8c5c:	66 0f ef c0          	pxor   %xmm0,%xmm0
    8c60:	83 e8 01             	sub    $0x1,%eax
    8c63:	66 0f ef c9          	pxor   %xmm1,%xmm1
    8c67:	f2 49 0f 2a c4       	cvtsi2sd %r12,%xmm0
    8c6c:	f2 0f 59 05 bc 0a 01 	mulsd  0x10abc(%rip),%xmm0        # 19730 <_IO_stdin_used+0x9730>
    8c73:	00 
    8c74:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    8c78:	f2 0f 5e c1          	divsd  %xmm1,%xmm0
    8c7c:	f2 0f 58 05 ac 7a 00 	addsd  0x7aac(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    8c83:	00 
  mvwprintw (status, 0, 0, "=== COPYING %3d%% ===  ",
    8c84:	f2 44 0f 2c c0       	cvttsd2si %xmm0,%r8d
    8c89:	48 8b 3d 80 81 01 00 	mov    0x18180(%rip),%rdi        # 20e10 <status>
    8c90:	31 d2                	xor    %edx,%edx
    8c92:	31 f6                	xor    %esi,%esi
    8c94:	31 c0                	xor    %eax,%eax
    8c96:	48 8d 0d 9d 7a 00 00 	lea    0x7a9d(%rip),%rcx        # 1073a <_IO_stdin_used+0x73a>
    8c9d:	e8 6e ec ff ff       	callq  7910 <mvwprintw@plt>
  wnoutrefresh (status);
    8ca2:	48 8b 3d 67 81 01 00 	mov    0x18167(%rip),%rdi        # 20e10 <status>
}
    8ca9:	48 83 c4 08          	add    $0x8,%rsp
    8cad:	5b                   	pop    %rbx
    8cae:	5d                   	pop    %rbp
    8caf:	41 5c                	pop    %r12
    8cb1:	41 5d                	pop    %r13
  wnoutrefresh (status);
    8cb3:	e9 08 ee ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    8cb8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    8cbf:	00 

0000000000008cc0 <key_handler>:
  print_page (current_line);
}

static void
key_handler (game_time t, int val)
{
    8cc0:	f3 0f 1e fa          	endbr64 
  switch (val) {
    8cc4:	83 ff 07             	cmp    $0x7,%edi
    8cc7:	0f 87 e8 00 00 00    	ja     8db5 <key_handler+0xf5>
    8ccd:	48 8d 15 30 7d 00 00 	lea    0x7d30(%rip),%rdx        # 10a04 <_IO_stdin_used+0xa04>
    8cd4:	89 ff                	mov    %edi,%edi
    8cd6:	48 63 04 ba          	movslq (%rdx,%rdi,4),%rax
    8cda:	48 01 d0             	add    %rdx,%rax
    8cdd:	3e ff e0             	notrack jmpq *%rax
      current_line = 0;
    }
    print_page (current_line);
    break;
  case 5:
    current_line += mb_lines-3;
    8ce0:	8b 05 e2 65 01 00    	mov    0x165e2(%rip),%eax        # 1f2c8 <current_line>
    8ce6:	8b 15 9c 63 01 00    	mov    0x1639c(%rip),%edx        # 1f088 <mb_lines>
    8cec:	8d 7c 02 fd          	lea    -0x3(%rdx,%rax,1),%edi
    if (current_line >= lines_used) {
    8cf0:	8b 05 d6 65 01 00    	mov    0x165d6(%rip),%eax        # 1f2cc <lines_used>
    current_line += mb_lines-3;
    8cf6:	89 3d cc 65 01 00    	mov    %edi,0x165cc(%rip)        # 1f2c8 <current_line>
    if (current_line >= lines_used) {
    8cfc:	39 c7                	cmp    %eax,%edi
    8cfe:	7c 1c                	jl     8d1c <key_handler+0x5c>
      current_line = lines_used-1;
      if (current_line < 0)  current_line = 0;
    8d00:	83 e8 01             	sub    $0x1,%eax
    8d03:	89 c7                	mov    %eax,%edi
    8d05:	79 2c                	jns    8d33 <key_handler+0x73>
    8d07:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    8d0e:	00 00 
    current_line = 0;
    print_page (current_line);
    break;
  case 7:
    current_line = lines_used-1;
    if (current_line < 0)  current_line = 0;
    8d10:	c7 05 ae 65 01 00 00 	movl   $0x0,0x165ae(%rip)        # 1f2c8 <current_line>
    8d17:	00 00 00 
    8d1a:	31 ff                	xor    %edi,%edi
    print_page (current_line);
    8d1c:	e9 6f fe ff ff       	jmpq   8b90 <print_page>
    8d21:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    if (current_line < 0)  current_line = 0;
    8d28:	8b 3d 9e 65 01 00    	mov    0x1659e(%rip),%edi        # 1f2cc <lines_used>
    8d2e:	83 ef 01             	sub    $0x1,%edi
    8d31:	78 dd                	js     8d10 <key_handler+0x50>
    current_line = lines_used-1;
    8d33:	89 3d 8f 65 01 00    	mov    %edi,0x1658f(%rip)        # 1f2c8 <current_line>
    print_page (current_line);
    8d39:	e9 52 fe ff ff       	jmpq   8b90 <print_page>
    8d3e:	66 90                	xchg   %ax,%ax
    mode_change (title_mode, 0);
    8d40:	48 8b 3d d9 80 01 00 	mov    0x180d9(%rip),%rdi        # 20e20 <title_mode>
    8d47:	31 f6                	xor    %esi,%esi
    8d49:	e9 12 fa ff ff       	jmpq   8760 <mode_change>
    8d4e:	66 90                	xchg   %ax,%ax
    if (current_line > 0)  --current_line;
    8d50:	8b 3d 72 65 01 00    	mov    0x16572(%rip),%edi        # 1f2c8 <current_line>
    8d56:	85 ff                	test   %edi,%edi
    8d58:	7e c2                	jle    8d1c <key_handler+0x5c>
    8d5a:	83 ef 01             	sub    $0x1,%edi
    8d5d:	89 3d 65 65 01 00    	mov    %edi,0x16565(%rip)        # 1f2c8 <current_line>
    print_page (current_line);
    8d63:	eb b7                	jmp    8d1c <key_handler+0x5c>
    8d65:	0f 1f 00             	nopl   (%rax)
    if (current_line < lines_used-1)  ++current_line;
    8d68:	8b 05 5e 65 01 00    	mov    0x1655e(%rip),%eax        # 1f2cc <lines_used>
    8d6e:	8b 3d 54 65 01 00    	mov    0x16554(%rip),%edi        # 1f2c8 <current_line>
    8d74:	83 e8 01             	sub    $0x1,%eax
    8d77:	39 f8                	cmp    %edi,%eax
    8d79:	7e a1                	jle    8d1c <key_handler+0x5c>
    8d7b:	83 c7 01             	add    $0x1,%edi
    8d7e:	89 3d 44 65 01 00    	mov    %edi,0x16544(%rip)        # 1f2c8 <current_line>
    print_page (current_line);
    8d84:	eb 96                	jmp    8d1c <key_handler+0x5c>
    8d86:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8d8d:	00 00 00 
    if (current_line > mb_lines-3) {
    8d90:	8b 15 f2 62 01 00    	mov    0x162f2(%rip),%edx        # 1f088 <mb_lines>
    8d96:	8b 05 2c 65 01 00    	mov    0x1652c(%rip),%eax        # 1f2c8 <current_line>
    8d9c:	8d 4a fe             	lea    -0x2(%rdx),%ecx
    8d9f:	39 c1                	cmp    %eax,%ecx
    8da1:	7f 1d                	jg     8dc0 <key_handler+0x100>
      current_line -= mb_lines-3;
    8da3:	83 ea 03             	sub    $0x3,%edx
    8da6:	29 d0                	sub    %edx,%eax
    8da8:	89 c7                	mov    %eax,%edi
    8daa:	89 05 18 65 01 00    	mov    %eax,0x16518(%rip)        # 1f2c8 <current_line>
    print_page (current_line);
    8db0:	e9 db fd ff ff       	jmpq   8b90 <print_page>
    break;
  }
}
    8db5:	c3                   	retq   
    8db6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8dbd:	00 00 00 
    8dc0:	31 ff                	xor    %edi,%edi
      current_line = 0;
    8dc2:	31 c0                	xor    %eax,%eax
    8dc4:	eb e4                	jmp    8daa <key_handler+0xea>
    8dc6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8dcd:	00 00 00 

0000000000008dd0 <pager_redraw>:
{
    8dd0:	f3 0f 1e fa          	endbr64 
  mb_lines = LINES;
    8dd4:	8b 05 aa 64 01 00    	mov    0x164aa(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
  print_page (current_line);
    8dda:	8b 3d e8 64 01 00    	mov    0x164e8(%rip),%edi        # 1f2c8 <current_line>
  mb_lines = LINES;
    8de0:	89 05 a2 62 01 00    	mov    %eax,0x162a2(%rip)        # 1f088 <mb_lines>
  print_page (current_line);
    8de6:	e9 a5 fd ff ff       	jmpq   8b90 <print_page>
    8deb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000008df0 <pager_leave>:
  }
}

static void
pager_leave (void)
{
    8df0:	f3 0f 1e fa          	endbr64 
    8df4:	48 83 ec 08          	sub    $0x8,%rsp
  werase (status);
    8df8:	48 8b 3d 11 80 01 00 	mov    0x18011(%rip),%rdi        # 20e10 <status>
    8dff:	e8 bc e8 ff ff       	callq  76c0 <werase@plt>
  wnoutrefresh (status);
    8e04:	48 8b 3d 05 80 01 00 	mov    0x18005(%rip),%rdi        # 20e10 <status>
}
    8e0b:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (status);
    8e0f:	e9 ac ec ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    8e14:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    8e1b:	00 00 00 00 
    8e1f:	90                   	nop

0000000000008e20 <pager_enter>:
{
    8e20:	f3 0f 1e fa          	endbr64 
  lines_used = sizeof (copying_lines) / sizeof (const char *);
    8e24:	c7 05 9e 64 01 00 a2 	movl   $0x2a2,0x1649e(%rip)        # 1f2cc <lines_used>
    8e2b:	02 00 00 
  switch (what) {
    8e2e:	85 ff                	test   %edi,%edi
    8e30:	74 6e                	je     8ea0 <pager_enter+0x80>
    8e32:	83 ff 01             	cmp    $0x1,%edi
    8e35:	75 61                	jne    8e98 <pager_enter+0x78>
{
    8e37:	41 55                	push   %r13
      if (strstr (copying_lines[i], "NO WARRANTY")) {
    8e39:	4c 8d 2d e0 44 01 00 	lea    0x144e0(%rip),%r13        # 1d320 <copying_lines>
{
    8e40:	41 54                	push   %r12
      if (strstr (copying_lines[i], "NO WARRANTY")) {
    8e42:	4c 8d 25 09 79 00 00 	lea    0x7909(%rip),%r12        # 10752 <_IO_stdin_used+0x752>
{
    8e49:	55                   	push   %rbp
    8e4a:	53                   	push   %rbx
    current_line = 0;
    8e4b:	bb 01 00 00 00       	mov    $0x1,%ebx
{
    8e50:	48 83 ec 08          	sub    $0x8,%rsp
    current_line = 0;
    8e54:	c7 05 6a 64 01 00 00 	movl   $0x0,0x1646a(%rip)        # 1f2c8 <current_line>
    8e5b:	00 00 00 
      if (strstr (copying_lines[i], "NO WARRANTY")) {
    8e5e:	66 90                	xchg   %ax,%ax
    for (i=0; i<lines_used; ++i) {
    8e60:	89 dd                	mov    %ebx,%ebp
    8e62:	48 81 fb a2 02 00 00 	cmp    $0x2a2,%rbx
    8e69:	74 1c                	je     8e87 <pager_enter+0x67>
      if (strstr (copying_lines[i], "NO WARRANTY")) {
    8e6b:	49 8b 7c dd 00       	mov    0x0(%r13,%rbx,8),%rdi
    8e70:	4c 89 e6             	mov    %r12,%rsi
    8e73:	48 83 c3 01          	add    $0x1,%rbx
    8e77:	e8 54 ee ff ff       	callq  7cd0 <strstr@plt>
    8e7c:	48 85 c0             	test   %rax,%rax
    8e7f:	74 df                	je     8e60 <pager_enter+0x40>
        current_line = i;
    8e81:	89 2d 41 64 01 00    	mov    %ebp,0x16441(%rip)        # 1f2c8 <current_line>
}
    8e87:	48 83 c4 08          	add    $0x8,%rsp
    8e8b:	5b                   	pop    %rbx
    8e8c:	5d                   	pop    %rbp
    8e8d:	41 5c                	pop    %r12
    8e8f:	41 5d                	pop    %r13
    8e91:	c3                   	retq   
    8e92:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    8e98:	c3                   	retq   
    8e99:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    current_line = 0;
    8ea0:	c7 05 1e 64 01 00 00 	movl   $0x0,0x1641e(%rip)        # 1f2c8 <current_line>
    8ea7:	00 00 00 
    break;
    8eaa:	c3                   	retq   
    8eab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000008eb0 <setup_pager_mode>:

void
setup_pager_mode (void)
{
    8eb0:	f3 0f 1e fa          	endbr64 
    8eb4:	48 83 ec 08          	sub    $0x8,%rsp
  pager_mode = new_mode ();
    8eb8:	e8 a3 f7 ff ff       	callq  8660 <new_mode>
  pager_mode->enter = pager_enter;
  pager_mode->leave = pager_leave;
  pager_mode->redraw = pager_redraw;
  pager_mode->keypress = key_handler;
  mode_add_key (pager_mode, mbk_end, "quit", 1);
    8ebd:	b9 01 00 00 00       	mov    $0x1,%ecx
    8ec2:	be 04 00 00 00       	mov    $0x4,%esi
    8ec7:	48 8d 15 25 78 00 00 	lea    0x7825(%rip),%rdx        # 106f3 <_IO_stdin_used+0x6f3>
  pager_mode = new_mode ();
    8ece:	48 89 c7             	mov    %rax,%rdi
    8ed1:	48 89 05 50 7f 01 00 	mov    %rax,0x17f50(%rip)        # 20e28 <pager_mode>
  pager_mode->enter = pager_enter;
    8ed8:	48 8d 05 41 ff ff ff 	lea    -0xbf(%rip),%rax        # 8e20 <pager_enter>
    8edf:	48 89 07             	mov    %rax,(%rdi)
  pager_mode->leave = pager_leave;
    8ee2:	48 8d 05 07 ff ff ff 	lea    -0xf9(%rip),%rax        # 8df0 <pager_leave>
    8ee9:	48 89 47 08          	mov    %rax,0x8(%rdi)
  pager_mode->redraw = pager_redraw;
    8eed:	48 8d 05 dc fe ff ff 	lea    -0x124(%rip),%rax        # 8dd0 <pager_redraw>
    8ef4:	48 89 47 10          	mov    %rax,0x10(%rdi)
  pager_mode->keypress = key_handler;
    8ef8:	48 8d 05 c1 fd ff ff 	lea    -0x23f(%rip),%rax        # 8cc0 <key_handler>
    8eff:	48 89 47 30          	mov    %rax,0x30(%rdi)
  mode_add_key (pager_mode, mbk_end, "quit", 1);
    8f03:	e8 b8 f7 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (pager_mode, mbk_up, "up", 2);
    8f08:	b9 02 00 00 00       	mov    $0x2,%ecx
    8f0d:	be 00 04 00 00       	mov    $0x400,%esi
    8f12:	48 8b 3d 0f 7f 01 00 	mov    0x17f0f(%rip),%rdi        # 20e28 <pager_mode>
    8f19:	48 8d 15 41 78 00 00 	lea    0x7841(%rip),%rdx        # 10761 <_IO_stdin_used+0x761>
    8f20:	e8 9b f7 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (pager_mode, mbk_down, "down", 3);
    8f25:	b9 03 00 00 00       	mov    $0x3,%ecx
    8f2a:	be 02 00 00 00       	mov    $0x2,%esi
    8f2f:	48 8b 3d f2 7e 01 00 	mov    0x17ef2(%rip),%rdi        # 20e28 <pager_mode>
    8f36:	48 8d 15 2a 78 00 00 	lea    0x782a(%rip),%rdx        # 10767 <_IO_stdin_used+0x767>
    8f3d:	e8 7e f7 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (pager_mode, mbk_pageup, "pg up", 4);
    8f42:	b9 04 00 00 00       	mov    $0x4,%ecx
    8f47:	be 00 01 00 00       	mov    $0x100,%esi
    8f4c:	48 8b 3d d5 7e 01 00 	mov    0x17ed5(%rip),%rdi        # 20e28 <pager_mode>
    8f53:	48 8d 15 04 78 00 00 	lea    0x7804(%rip),%rdx        # 1075e <_IO_stdin_used+0x75e>
    8f5a:	e8 61 f7 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (pager_mode, mbk_pagedown, "pg down", 5);
    8f5f:	b9 05 00 00 00       	mov    $0x5,%ecx
    8f64:	be 80 00 00 00       	mov    $0x80,%esi
    8f69:	48 8b 3d b8 7e 01 00 	mov    0x17eb8(%rip),%rdi        # 20e28 <pager_mode>
    8f70:	48 8d 15 ed 77 00 00 	lea    0x77ed(%rip),%rdx        # 10764 <_IO_stdin_used+0x764>
    8f77:	e8 44 f7 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (pager_mode, mbk_first, "home", 6);
    8f7c:	b9 06 00 00 00       	mov    $0x6,%ecx
    8f81:	be 10 00 00 00       	mov    $0x10,%esi
    8f86:	48 8b 3d 9b 7e 01 00 	mov    0x17e9b(%rip),%rdi        # 20e28 <pager_mode>
    8f8d:	48 8d 15 d8 77 00 00 	lea    0x77d8(%rip),%rdx        # 1076c <_IO_stdin_used+0x76c>
    8f94:	e8 27 f7 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (pager_mode, mbk_last, "end", 7);
    8f99:	b9 07 00 00 00       	mov    $0x7,%ecx
    8f9e:	be 40 00 00 00       	mov    $0x40,%esi
    8fa3:	48 8b 3d 7e 7e 01 00 	mov    0x17e7e(%rip),%rdi        # 20e28 <pager_mode>
    8faa:	48 8d 15 c0 77 00 00 	lea    0x77c0(%rip),%rdx        # 10771 <_IO_stdin_used+0x771>
    8fb1:	e8 0a f7 ff ff       	callq  86c0 <mode_add_key>
  mode_complete (pager_mode);
    8fb6:	48 8b 3d 6b 7e 01 00 	mov    0x17e6b(%rip),%rdi        # 20e28 <pager_mode>
}
    8fbd:	48 83 c4 08          	add    $0x8,%rsp
  mode_complete (pager_mode);
    8fc1:	e9 7a f7 ff ff       	jmpq   8740 <mode_complete>
    8fc6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8fcd:	00 00 00 

0000000000008fd0 <game_leave>:
  start_scrolling (1);
}

static void
game_leave (void)
{
    8fd0:	f3 0f 1e fa          	endbr64 
    8fd4:	48 83 ec 08          	sub    $0x8,%rsp
  --lives;
    8fd8:	83 2d f9 62 01 00 01 	subl   $0x1,0x162f9(%rip)        # 1f2d8 <lives>
  level = current_level ();
    8fdf:	e8 4c 14 00 00       	callq  a430 <current_level>
    8fe4:	89 05 f2 62 01 00    	mov    %eax,0x162f2(%rip)        # 1f2dc <level>
  extinguish_laser ();
    8fea:	e8 51 24 00 00       	callq  b440 <extinguish_laser>
  remove_meteors ();
}
    8fef:	48 83 c4 08          	add    $0x8,%rsp
  remove_meteors ();
    8ff3:	e9 28 28 00 00       	jmpq   b820 <remove_meteors>
    8ff8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    8fff:	00 

0000000000009000 <game_enter>:
{
    9000:	f3 0f 1e fa          	endbr64 
    9004:	53                   	push   %rbx
    9005:	89 fb                	mov    %edi,%ebx
  clock_reset ();
    9007:	e8 44 46 00 00       	callq  d650 <clock_reset>
  if (seed == 0) {
    900c:	85 db                	test   %ebx,%ebx
    900e:	74 40                	je     9050 <game_enter+0x50>
  resize_ground (1);
    9010:	bf 01 00 00 00       	mov    $0x1,%edi
    9015:	e8 46 14 00 00       	callq  a460 <resize_ground>
  level_start (level);
    901a:	8b 3d bc 62 01 00    	mov    0x162bc(%rip),%edi        # 1f2dc <level>
    9020:	e8 9b 11 00 00       	callq  a1c0 <level_start>
  crash_detected = 0;
    9025:	c7 05 01 7e 01 00 00 	movl   $0x0,0x17e01(%rip)        # 20e30 <crash_detected>
    902c:	00 00 00 
  stakes = 0;
    902f:	c7 05 0f 7e 01 00 00 	movl   $0x0,0x17e0f(%rip)        # 20e48 <stakes>
    9036:	00 00 00 
  initialise_buggy ();
    9039:	e8 f2 18 00 00       	callq  a930 <initialise_buggy>
  start_scrolling (1);
    903e:	f2 0f 10 05 62 07 01 	movsd  0x10762(%rip),%xmm0        # 197a8 <_IO_stdin_used+0x97a8>
    9045:	00 
}
    9046:	5b                   	pop    %rbx
  start_scrolling (1);
    9047:	e9 34 17 00 00       	jmpq   a780 <start_scrolling>
    904c:	0f 1f 40 00          	nopl   0x0(%rax)
    werase (status);
    9050:	48 8b 3d b9 7d 01 00 	mov    0x17db9(%rip),%rdi        # 20e10 <status>
    level = 0;
    9057:	c7 05 7b 62 01 00 00 	movl   $0x0,0x1627b(%rip)        # 1f2dc <level>
    905e:	00 00 00 
    score = 0;
    9061:	c7 05 69 62 01 00 00 	movl   $0x0,0x16269(%rip)        # 1f2d4 <score>
    9068:	00 00 00 
    lives = 3;
    906b:	c7 05 63 62 01 00 03 	movl   $0x3,0x16263(%rip)        # 1f2d8 <lives>
    9072:	00 00 00 
    werase (status);
    9075:	e8 46 e6 ff ff       	callq  76c0 <werase@plt>
    wnoutrefresh (status);
    907a:	48 8b 3d 8f 7d 01 00 	mov    0x17d8f(%rip),%rdi        # 20e10 <status>
    9081:	e8 3a ea ff ff       	callq  7ac0 <wnoutrefresh@plt>
    9086:	eb 88                	jmp    9010 <game_enter+0x10>
    9088:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    908f:	00 

0000000000009090 <leave_crash_mode>:
static void
leave_crash_mode (game_time t, void *client_data)
/* This function is a possible callback argument to `add_event'.
 * It switch control back to either `game_mode' or `highscore_mode'.
 * The arguments T and CLIENT_DATA are ignored.  */
{
    9090:	f3 0f 1e fa          	endbr64 
  if (lives > 0) {
    9094:	8b 05 3e 62 01 00    	mov    0x1623e(%rip),%eax        # 1f2d8 <lives>
    909a:	85 c0                	test   %eax,%eax
    909c:	7e 12                	jle    90b0 <leave_crash_mode+0x20>
    mode_change (game_mode, 1);
    909e:	48 8b 3d 9b 7d 01 00 	mov    0x17d9b(%rip),%rdi        # 20e40 <game_mode>
    90a5:	be 01 00 00 00       	mov    $0x1,%esi
    90aa:	e9 b1 f6 ff ff       	jmpq   8760 <mode_change>
    90af:	90                   	nop
{
    90b0:	48 83 ec 08          	sub    $0x8,%rsp
  } else {
    score_set (score, level+1);
    90b4:	8b 05 22 62 01 00    	mov    0x16222(%rip),%eax        # 1f2dc <level>
    90ba:	8b 3d 14 62 01 00    	mov    0x16214(%rip),%edi        # 1f2d4 <score>
    90c0:	8d 70 01             	lea    0x1(%rax),%esi
    90c3:	e8 a8 40 00 00       	callq  d170 <score_set>
    mode_change (highscore_mode, 0);
    90c8:	48 8b 3d a1 7d 01 00 	mov    0x17da1(%rip),%rdi        # 20e70 <highscore_mode>
    90cf:	31 f6                	xor    %esi,%esi
  }
}
    90d1:	48 83 c4 08          	add    $0x8,%rsp
    mode_change (highscore_mode, 0);
    90d5:	e9 86 f6 ff ff       	jmpq   8760 <mode_change>
    90da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000090e0 <crash_key_handler>:
  if (lives_flag)  print_lives ();
}

static void
crash_key_handler (game_time t, int val)
{
    90e0:	f3 0f 1e fa          	endbr64 
  if (t < 0.5)  return;
    90e4:	f2 0f 10 0d 44 76 00 	movsd  0x7644(%rip),%xmm1        # 10730 <_IO_stdin_used+0x730>
    90eb:	00 
    90ec:	66 0f 2f c8          	comisd %xmm0,%xmm1
    90f0:	77 1e                	ja     9110 <crash_key_handler+0x30>

  switch (val) {
    90f2:	83 ff 01             	cmp    $0x1,%edi
    90f5:	74 0f                	je     9106 <crash_key_handler+0x26>
    90f7:	83 ff 03             	cmp    $0x3,%edi
    90fa:	75 1c                	jne    9118 <crash_key_handler+0x38>
  case 1:
    leave_crash_mode (0, NULL);
    break;
  case 3:
    lives = 0;
    90fc:	c7 05 d2 61 01 00 00 	movl   $0x0,0x161d2(%rip)        # 1f2d8 <lives>
    9103:	00 00 00 
    leave_crash_mode (0, NULL);
    9106:	31 ff                	xor    %edi,%edi
    9108:	66 0f ef c0          	pxor   %xmm0,%xmm0
    910c:	eb 82                	jmp    9090 <leave_crash_mode>
    910e:	66 90                	xchg   %ax,%ax
    break;
  }
}
    9110:	c3                   	retq   
    9111:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    9118:	c3                   	retq   
    9119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000009120 <signal_handler>:
{
    9120:	f3 0f 1e fa          	endbr64 
  switch (signum) {
    9124:	83 ff 12             	cmp    $0x12,%edi
    9127:	74 2c                	je     9155 <signal_handler+0x35>
    9129:	83 ff 14             	cmp    $0x14,%edi
    912c:	75 3a                	jne    9168 <signal_handler+0x48>
    if (lives > 1)  lives = 1;
    912e:	83 3d a3 61 01 00 01 	cmpl   $0x1,0x161a3(%rip)        # 1f2d8 <lives>
    9135:	7e 0a                	jle    9141 <signal_handler+0x21>
    9137:	c7 05 97 61 01 00 01 	movl   $0x1,0x16197(%rip)        # 1f2d8 <lives>
    913e:	00 00 00 
    if (! crash_detected)  crash_detected = 1;
    9141:	8b 05 e9 7c 01 00    	mov    0x17ce9(%rip),%eax        # 20e30 <crash_detected>
    9147:	85 c0                	test   %eax,%eax
    9149:	75 0a                	jne    9155 <signal_handler+0x35>
    914b:	c7 05 db 7c 01 00 01 	movl   $0x1,0x17cdb(%rip)        # 20e30 <crash_detected>
    9152:	00 00 00 
    print_message ("GAME OVER (suspended)");
    9155:	48 8d 3d dc 05 01 00 	lea    0x105dc(%rip),%rdi        # 19738 <_IO_stdin_used+0x9738>
    915c:	e9 0f f2 ff ff       	jmpq   8370 <print_message>
    9161:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
}
    9168:	c3                   	retq   
    9169:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000009170 <key_handler>:
{
    9170:	f3 0f 1e fa          	endbr64 
  switch (val) {
    9174:	83 ff 02             	cmp    $0x2,%edi
    9177:	74 17                	je     9190 <key_handler+0x20>
{
    9179:	48 83 ec 18          	sub    $0x18,%rsp
  switch (val) {
    917d:	83 ff 03             	cmp    $0x3,%edi
    9180:	74 4e                	je     91d0 <key_handler+0x60>
    9182:	83 ff 01             	cmp    $0x1,%edi
    9185:	74 19                	je     91a0 <key_handler+0x30>
}
    9187:	48 83 c4 18          	add    $0x18,%rsp
    918b:	c3                   	retq   
    918c:	0f 1f 40 00          	nopl   0x0(%rax)
    if (! crash_detected)  fire_laser (t);
    9190:	8b 05 9a 7c 01 00    	mov    0x17c9a(%rip),%eax        # 20e30 <crash_detected>
    9196:	85 c0                	test   %eax,%eax
    9198:	74 66                	je     9200 <key_handler+0x90>
    919a:	c3                   	retq   
    919b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    if (! crash_detected && can_jump())  jump (t);
    91a0:	8b 15 8a 7c 01 00    	mov    0x17c8a(%rip),%edx        # 20e30 <crash_detected>
    91a6:	85 d2                	test   %edx,%edx
    91a8:	75 dd                	jne    9187 <key_handler+0x17>
    91aa:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
    91b0:	e8 7b 1c 00 00       	callq  ae30 <can_jump>
    91b5:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    91bb:	85 c0                	test   %eax,%eax
    91bd:	74 c8                	je     9187 <key_handler+0x17>
}
    91bf:	48 83 c4 18          	add    $0x18,%rsp
    if (! crash_detected && can_jump())  jump (t);
    91c3:	e9 f8 1b 00 00       	jmpq   adc0 <jump>
    91c8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    91cf:	00 
    print_message ("aborted at user's request");
    91d0:	48 8d 3d 77 05 01 00 	lea    0x10577(%rip),%rdi        # 1974e <_IO_stdin_used+0x974e>
    lives = 1;
    91d7:	c7 05 f7 60 01 00 01 	movl   $0x1,0x160f7(%rip)        # 1f2d8 <lives>
    91de:	00 00 00 
    print_message ("aborted at user's request");
    91e1:	e8 8a f1 ff ff       	callq  8370 <print_message>
    mode_change (crash_mode, 0);
    91e6:	48 8b 3d 4b 7c 01 00 	mov    0x17c4b(%rip),%rdi        # 20e38 <crash_mode>
    91ed:	31 f6                	xor    %esi,%esi
}
    91ef:	48 83 c4 18          	add    $0x18,%rsp
    mode_change (crash_mode, 0);
    91f3:	e9 68 f5 ff ff       	jmpq   8760 <mode_change>
    91f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    91ff:	00 
    if (! crash_detected)  fire_laser (t);
    9200:	e9 2b 21 00 00       	jmpq   b330 <fire_laser>
    9205:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    920c:	00 00 00 00 

0000000000009210 <adjust_score.part.0>:
adjust_score (int val)
    9210:	48 83 ec 08          	sub    $0x8,%rsp
  score += val;
    9214:	03 3d ba 60 01 00    	add    0x160ba(%rip),%edi        # 1f2d4 <score>
  mvwprintw (status, 0, car_base-7, "score: %-8d", score);
    921a:	8b 05 d8 7b 01 00    	mov    0x17bd8(%rip),%eax        # 20df8 <car_base>
    9220:	31 f6                	xor    %esi,%esi
  score += val;
    9222:	89 3d ac 60 01 00    	mov    %edi,0x160ac(%rip)        # 1f2d4 <score>
    9228:	41 89 f8             	mov    %edi,%r8d
  mvwprintw (status, 0, car_base-7, "score: %-8d", score);
    922b:	48 8b 3d de 7b 01 00 	mov    0x17bde(%rip),%rdi        # 20e10 <status>
    9232:	48 8d 0d 2f 05 01 00 	lea    0x1052f(%rip),%rcx        # 19768 <_IO_stdin_used+0x9768>
    9239:	8d 50 f9             	lea    -0x7(%rax),%edx
    923c:	31 c0                	xor    %eax,%eax
    923e:	e8 cd e6 ff ff       	callq  7910 <mvwprintw@plt>
  wnoutrefresh (status);
    9243:	48 8b 3d c6 7b 01 00 	mov    0x17bc6(%rip),%rdi        # 20e10 <status>
}
    924a:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (status);
    924e:	e9 6d e8 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    9253:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    925a:	00 00 00 00 
    925e:	66 90                	xchg   %ax,%ax

0000000000009260 <adjust_score>:
{
    9260:	f3 0f 1e fa          	endbr64 
  if (crash_detected)  return;
    9264:	8b 05 c6 7b 01 00    	mov    0x17bc6(%rip),%eax        # 20e30 <crash_detected>
    926a:	85 c0                	test   %eax,%eax
    926c:	74 02                	je     9270 <adjust_score+0x10>
}
    926e:	c3                   	retq   
    926f:	90                   	nop
    9270:	eb 9e                	jmp    9210 <adjust_score.part.0>
    9272:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    9279:	00 00 00 00 
    927d:	0f 1f 00             	nopl   (%rax)

0000000000009280 <print_lives>:
{
    9280:	f3 0f 1e fa          	endbr64 
    9284:	48 83 ec 08          	sub    $0x8,%rsp
  mvwprintw (status, 0, car_base-20, "lives: %d", lives);
    9288:	8b 05 6a 7b 01 00    	mov    0x17b6a(%rip),%eax        # 20df8 <car_base>
    928e:	31 f6                	xor    %esi,%esi
    9290:	48 8b 3d 79 7b 01 00 	mov    0x17b79(%rip),%rdi        # 20e10 <status>
    9297:	44 8b 05 3a 60 01 00 	mov    0x1603a(%rip),%r8d        # 1f2d8 <lives>
    929e:	48 8d 0d cf 04 01 00 	lea    0x104cf(%rip),%rcx        # 19774 <_IO_stdin_used+0x9774>
    92a5:	8d 50 ec             	lea    -0x14(%rax),%edx
    92a8:	31 c0                	xor    %eax,%eax
    92aa:	e8 61 e6 ff ff       	callq  7910 <mvwprintw@plt>
  wnoutrefresh (status);
    92af:	48 8b 3d 5a 7b 01 00 	mov    0x17b5a(%rip),%rdi        # 20e10 <status>
}
    92b6:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (status);
    92ba:	e9 01 e8 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    92bf:	90                   	nop

00000000000092c0 <crash_redraw>:
{
    92c0:	f3 0f 1e fa          	endbr64 
    92c4:	48 83 ec 08          	sub    $0x8,%rsp
  resize_ground (0);
    92c8:	31 ff                	xor    %edi,%edi
    92ca:	e8 91 11 00 00       	callq  a460 <resize_ground>
  print_ground ();
    92cf:	e8 7c 12 00 00       	callq  a550 <print_ground>
  print_buggy ();
    92d4:	e8 e7 16 00 00       	callq  a9c0 <print_buggy>
  if (crash_detected)  return;
    92d9:	8b 15 51 7b 01 00    	mov    0x17b51(%rip),%edx        # 20e30 <crash_detected>
    92df:	85 d2                	test   %edx,%edx
    92e1:	75 07                	jne    92ea <crash_redraw+0x2a>
    92e3:	31 ff                	xor    %edi,%edi
    92e5:	e8 26 ff ff ff       	callq  9210 <adjust_score.part.0>
  if (lives_flag)  print_lives ();
    92ea:	8b 05 e0 5f 01 00    	mov    0x15fe0(%rip),%eax        # 1f2d0 <lives_flag>
    92f0:	85 c0                	test   %eax,%eax
    92f2:	75 0c                	jne    9300 <crash_redraw+0x40>
}
    92f4:	48 83 c4 08          	add    $0x8,%rsp
    92f8:	c3                   	retq   
    92f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    9300:	48 83 c4 08          	add    $0x8,%rsp
  if (lives_flag)  print_lives ();
    9304:	e9 77 ff ff ff       	jmpq   9280 <print_lives>
    9309:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000009310 <print_lives_h>:
{
    9310:	f3 0f 1e fa          	endbr64 
    9314:	48 83 ec 08          	sub    $0x8,%rsp
  print_lives ();
    9318:	e8 63 ff ff ff       	callq  9280 <print_lives>
  lives_flag = 1;
    931d:	c7 05 a9 5f 01 00 01 	movl   $0x1,0x15fa9(%rip)        # 1f2d0 <lives_flag>
    9324:	00 00 00 
}
    9327:	48 83 c4 08          	add    $0x8,%rsp
    932b:	c3                   	retq   
    932c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000009330 <game_redraw>:
{
    9330:	f3 0f 1e fa          	endbr64 
    9334:	48 83 ec 08          	sub    $0x8,%rsp
  resize_meteors ();
    9338:	e8 83 28 00 00       	callq  bbc0 <resize_meteors>
  resize_laser ();
    933d:	e8 1e 22 00 00       	callq  b560 <resize_laser>
  resize_ground (0);
    9342:	31 ff                	xor    %edi,%edi
    9344:	e8 17 11 00 00       	callq  a460 <resize_ground>
  print_ground ();
    9349:	e8 02 12 00 00       	callq  a550 <print_ground>
  if (crash_detected)  return;
    934e:	8b 05 dc 7a 01 00    	mov    0x17adc(%rip),%eax        # 20e30 <crash_detected>
    9354:	85 c0                	test   %eax,%eax
    9356:	75 07                	jne    935f <game_redraw+0x2f>
    9358:	31 ff                	xor    %edi,%edi
    935a:	e8 b1 fe ff ff       	callq  9210 <adjust_score.part.0>
  print_lives ();
    935f:	e8 1c ff ff ff       	callq  9280 <print_lives>
}
    9364:	48 83 c4 08          	add    $0x8,%rsp
  print_buggy ();
    9368:	e9 53 16 00 00       	jmpq   a9c0 <print_buggy>
    936d:	0f 1f 00             	nopl   (%rax)

0000000000009370 <print_game_over>:
{
    9370:	f3 0f 1e fa          	endbr64 
    9374:	41 89 f8             	mov    %edi,%r8d
    9377:	48 83 ec 08          	sub    $0x8,%rsp
    937b:	48 8b 3d 96 7a 01 00 	mov    0x17a96(%rip),%rdi        # 20e18 <moon>
  if (blink)  wattron (moon, A_BLINK);
    9382:	45 85 c0             	test   %r8d,%r8d
    9385:	75 59                	jne    93e0 <print_game_over+0x70>
  mvwaddstr (moon, LINES-11, car_base-1, "GAME OVER");
    9387:	8b 05 6b 7a 01 00    	mov    0x17a6b(%rip),%eax        # 20df8 <car_base>
    938d:	8d 50 ff             	lea    -0x1(%rax),%edx
    9390:	8b 05 ee 5e 01 00    	mov    0x15eee(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    9396:	8d 70 f5             	lea    -0xb(%rax),%esi
    9399:	e8 32 e8 ff ff       	callq  7bd0 <wmove@plt>
    939e:	83 f8 ff             	cmp    $0xffffffff,%eax
    93a1:	75 15                	jne    93b8 <print_game_over+0x48>
  wnoutrefresh (moon);
    93a3:	48 8b 3d 6e 7a 01 00 	mov    0x17a6e(%rip),%rdi        # 20e18 <moon>
}
    93aa:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (moon);
    93ae:	e9 0d e7 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    93b3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  mvwaddstr (moon, LINES-11, car_base-1, "GAME OVER");
    93b8:	48 8b 3d 59 7a 01 00 	mov    0x17a59(%rip),%rdi        # 20e18 <moon>
    93bf:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    93c4:	48 8d 35 b3 03 01 00 	lea    0x103b3(%rip),%rsi        # 1977e <_IO_stdin_used+0x977e>
    93cb:	e8 d0 e8 ff ff       	callq  7ca0 <waddnstr@plt>
  wnoutrefresh (moon);
    93d0:	48 8b 3d 41 7a 01 00 	mov    0x17a41(%rip),%rdi        # 20e18 <moon>
}
    93d7:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (moon);
    93db:	e9 e0 e6 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
  if (blink)  wattron (moon, A_BLINK);
    93e0:	31 d2                	xor    %edx,%edx
    93e2:	be 00 00 08 00       	mov    $0x80000,%esi
    93e7:	e8 64 e5 ff ff       	callq  7950 <wattr_on@plt>
  mvwaddstr (moon, LINES-11, car_base-1, "GAME OVER");
    93ec:	8b 05 06 7a 01 00    	mov    0x17a06(%rip),%eax        # 20df8 <car_base>
    93f2:	48 8b 3d 1f 7a 01 00 	mov    0x17a1f(%rip),%rdi        # 20e18 <moon>
    93f9:	8d 50 ff             	lea    -0x1(%rax),%edx
    93fc:	8b 05 82 5e 01 00    	mov    0x15e82(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    9402:	8d 70 f5             	lea    -0xb(%rax),%esi
    9405:	e8 c6 e7 ff ff       	callq  7bd0 <wmove@plt>
    940a:	83 f8 ff             	cmp    $0xffffffff,%eax
    940d:	75 29                	jne    9438 <print_game_over+0xc8>
  if (blink)  wattroff (moon, A_BLINK);
    940f:	48 8b 3d 02 7a 01 00 	mov    0x17a02(%rip),%rdi        # 20e18 <moon>
    9416:	31 d2                	xor    %edx,%edx
    9418:	be 00 00 08 00       	mov    $0x80000,%esi
    941d:	e8 9e e8 ff ff       	callq  7cc0 <wattr_off@plt>
  wnoutrefresh (moon);
    9422:	48 8b 3d ef 79 01 00 	mov    0x179ef(%rip),%rdi        # 20e18 <moon>
}
    9429:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (moon);
    942d:	e9 8e e6 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    9432:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  mvwaddstr (moon, LINES-11, car_base-1, "GAME OVER");
    9438:	48 8b 3d d9 79 01 00 	mov    0x179d9(%rip),%rdi        # 20e18 <moon>
    943f:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    9444:	48 8d 35 33 03 01 00 	lea    0x10333(%rip),%rsi        # 1977e <_IO_stdin_used+0x977e>
    944b:	e8 50 e8 ff ff       	callq  7ca0 <waddnstr@plt>
  if (blink)  wattroff (moon, A_BLINK);
    9450:	eb bd                	jmp    940f <print_game_over+0x9f>
    9452:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    9459:	00 00 00 00 
    945d:	0f 1f 00             	nopl   (%rax)

0000000000009460 <crash_enter>:
{
    9460:	f3 0f 1e fa          	endbr64 
    9464:	48 83 ec 08          	sub    $0x8,%rsp
  clock_reset ();
    9468:	e8 e3 41 00 00       	callq  d650 <clock_reset>
  add_event (1.2, print_lives_h, NULL);
    946d:	f2 0f 10 05 3b 03 01 	movsd  0x1033b(%rip),%xmm0        # 197b0 <_IO_stdin_used+0x97b0>
    9474:	00 
    9475:	31 f6                	xor    %esi,%esi
    9477:	48 8d 3d 92 fe ff ff 	lea    -0x16e(%rip),%rdi        # 9310 <print_lives_h>
  lives_flag = 0;
    947e:	c7 05 48 5e 01 00 00 	movl   $0x0,0x15e48(%rip)        # 1f2d0 <lives_flag>
    9485:	00 00 00 
  add_event (1.2, print_lives_h, NULL);
    9488:	e8 13 43 00 00       	callq  d7a0 <add_event>
  add_event (2.0, leave_crash_mode, NULL);
    948d:	f2 0f 10 05 23 03 01 	movsd  0x10323(%rip),%xmm0        # 197b8 <_IO_stdin_used+0x97b8>
    9494:	00 
    9495:	31 f6                	xor    %esi,%esi
    9497:	48 8d 3d f2 fb ff ff 	lea    -0x40e(%rip),%rdi        # 9090 <leave_crash_mode>
    949e:	e8 fd 42 00 00       	callq  d7a0 <add_event>
  print_buggy ();
    94a3:	e8 18 15 00 00       	callq  a9c0 <print_buggy>
  if (lives <= 0)  print_game_over (1);
    94a8:	8b 05 2a 5e 01 00    	mov    0x15e2a(%rip),%eax        # 1f2d8 <lives>
    94ae:	85 c0                	test   %eax,%eax
    94b0:	7e 0e                	jle    94c0 <crash_enter+0x60>
}
    94b2:	48 83 c4 08          	add    $0x8,%rsp
    94b6:	c3                   	retq   
    94b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    94be:	00 00 
  if (lives <= 0)  print_game_over (1);
    94c0:	bf 01 00 00 00       	mov    $0x1,%edi
}
    94c5:	48 83 c4 08          	add    $0x8,%rsp
  if (lives <= 0)  print_game_over (1);
    94c9:	e9 a2 fe ff ff       	jmpq   9370 <print_game_over>
    94ce:	66 90                	xchg   %ax,%ax

00000000000094d0 <setup_game_mode>:

void
setup_game_mode (void)
{
    94d0:	f3 0f 1e fa          	endbr64 
    94d4:	48 83 ec 08          	sub    $0x8,%rsp
  game_mode = new_mode ();
    94d8:	e8 83 f1 ff ff       	callq  8660 <new_mode>
  game_mode->enter = game_enter;
  game_mode->leave = game_leave;
  game_mode->redraw = game_redraw;
  game_mode->keypress = key_handler;
  game_mode->signal = signal_handler;
  mode_add_key (game_mode, mbk_jump, "jump", 1);
    94dd:	b9 01 00 00 00       	mov    $0x1,%ecx
    94e2:	be 20 00 00 00       	mov    $0x20,%esi
    94e7:	48 8d 15 9a 02 01 00 	lea    0x1029a(%rip),%rdx        # 19788 <_IO_stdin_used+0x9788>
  game_mode = new_mode ();
    94ee:	48 89 c7             	mov    %rax,%rdi
    94f1:	48 89 05 48 79 01 00 	mov    %rax,0x17948(%rip)        # 20e40 <game_mode>
  game_mode->enter = game_enter;
    94f8:	48 8d 05 01 fb ff ff 	lea    -0x4ff(%rip),%rax        # 9000 <game_enter>
    94ff:	48 89 07             	mov    %rax,(%rdi)
  game_mode->leave = game_leave;
    9502:	48 8d 05 c7 fa ff ff 	lea    -0x539(%rip),%rax        # 8fd0 <game_leave>
    9509:	48 89 47 08          	mov    %rax,0x8(%rdi)
  game_mode->redraw = game_redraw;
    950d:	48 8d 05 1c fe ff ff 	lea    -0x1e4(%rip),%rax        # 9330 <game_redraw>
    9514:	48 89 47 10          	mov    %rax,0x10(%rdi)
  game_mode->keypress = key_handler;
    9518:	48 8d 05 51 fc ff ff 	lea    -0x3af(%rip),%rax        # 9170 <key_handler>
    951f:	48 89 47 30          	mov    %rax,0x30(%rdi)
  game_mode->signal = signal_handler;
    9523:	48 8d 05 f6 fb ff ff 	lea    -0x40a(%rip),%rax        # 9120 <signal_handler>
    952a:	48 89 47 18          	mov    %rax,0x18(%rdi)
  mode_add_key (game_mode, mbk_jump, "jump", 1);
    952e:	e8 8d f1 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (game_mode, mbk_fire, "fire", 2);
    9533:	b9 02 00 00 00       	mov    $0x2,%ecx
    9538:	be 08 00 00 00       	mov    $0x8,%esi
    953d:	48 8b 3d fc 78 01 00 	mov    0x178fc(%rip),%rdi        # 20e40 <game_mode>
    9544:	48 8d 15 42 02 01 00 	lea    0x10242(%rip),%rdx        # 1978d <_IO_stdin_used+0x978d>
    954b:	e8 70 f1 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (game_mode, mbk_end, "abort game", 3);
    9550:	b9 03 00 00 00       	mov    $0x3,%ecx
    9555:	be 04 00 00 00       	mov    $0x4,%esi
    955a:	48 8b 3d df 78 01 00 	mov    0x178df(%rip),%rdi        # 20e40 <game_mode>
    9561:	48 8d 15 2a 02 01 00 	lea    0x1022a(%rip),%rdx        # 19792 <_IO_stdin_used+0x9792>
    9568:	e8 53 f1 ff ff       	callq  86c0 <mode_add_key>
  mode_complete (game_mode);
    956d:	48 8b 3d cc 78 01 00 	mov    0x178cc(%rip),%rdi        # 20e40 <game_mode>
    9574:	e8 c7 f1 ff ff       	callq  8740 <mode_complete>

  crash_mode = new_mode ();
    9579:	e8 e2 f0 ff ff       	callq  8660 <new_mode>
  crash_mode->enter = crash_enter;
  crash_mode->redraw = crash_redraw;
  crash_mode->keypress = crash_key_handler;
  mode_add_key (crash_mode, mbk_start, "continue", 1);
    957e:	b9 01 00 00 00       	mov    $0x1,%ecx
    9583:	be 00 02 00 00       	mov    $0x200,%esi
    9588:	48 8d 15 0e 02 01 00 	lea    0x1020e(%rip),%rdx        # 1979d <_IO_stdin_used+0x979d>
  crash_mode = new_mode ();
    958f:	48 89 c7             	mov    %rax,%rdi
    9592:	48 89 05 9f 78 01 00 	mov    %rax,0x1789f(%rip)        # 20e38 <crash_mode>
  crash_mode->enter = crash_enter;
    9599:	48 8d 05 c0 fe ff ff 	lea    -0x140(%rip),%rax        # 9460 <crash_enter>
    95a0:	48 89 07             	mov    %rax,(%rdi)
  crash_mode->redraw = crash_redraw;
    95a3:	48 8d 05 16 fd ff ff 	lea    -0x2ea(%rip),%rax        # 92c0 <crash_redraw>
    95aa:	48 89 47 10          	mov    %rax,0x10(%rdi)
  crash_mode->keypress = crash_key_handler;
    95ae:	48 8d 05 2b fb ff ff 	lea    -0x4d5(%rip),%rax        # 90e0 <crash_key_handler>
    95b5:	48 89 47 30          	mov    %rax,0x30(%rdi)
  mode_add_key (crash_mode, mbk_start, "continue", 1);
    95b9:	e8 02 f1 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (crash_mode, mbk_end, "abort game", 3);
    95be:	b9 03 00 00 00       	mov    $0x3,%ecx
    95c3:	be 04 00 00 00       	mov    $0x4,%esi
    95c8:	48 8b 3d 69 78 01 00 	mov    0x17869(%rip),%rdi        # 20e38 <crash_mode>
    95cf:	48 8d 15 bc 01 01 00 	lea    0x101bc(%rip),%rdx        # 19792 <_IO_stdin_used+0x9792>
    95d6:	e8 e5 f0 ff ff       	callq  86c0 <mode_add_key>
  mode_complete (crash_mode);
    95db:	48 8b 3d 56 78 01 00 	mov    0x17856(%rip),%rdi        # 20e38 <crash_mode>
}
    95e2:	48 83 c4 08          	add    $0x8,%rsp
  mode_complete (crash_mode);
    95e6:	e9 55 f1 ff ff       	jmpq   8740 <mode_complete>
    95eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000095f0 <level0_init>:
} data;


static void
level0_init (void)
{
    95f0:	f3 0f 1e fa          	endbr64 
  hole = 2;
    95f4:	c7 05 0e 5d 01 00 02 	movl   $0x2,0x15d0e(%rip)        # 1f30c <hole>
    95fb:	00 00 00 
  data.l0.state = 0;
    95fe:	c7 05 d8 5c 01 00 00 	movl   $0x0,0x15cd8(%rip)        # 1f2e0 <data>
    9605:	00 00 00 
}
    9608:	c3                   	retq   
    9609:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000009610 <level1_init>:
}


static void
level1_init (void)
{
    9610:	f3 0f 1e fa          	endbr64 
  hole = 5;
    9614:	c7 05 ee 5c 01 00 05 	movl   $0x5,0x15cee(%rip)        # 1f30c <hole>
    961b:	00 00 00 
  data.l1.state = 0;
    961e:	c7 05 b8 5c 01 00 00 	movl   $0x0,0x15cb8(%rip)        # 1f2e0 <data>
    9625:	00 00 00 
}
    9628:	c3                   	retq   
    9629:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000009630 <level2_init>:
}


static void
level2_init (void)
{
    9630:	f3 0f 1e fa          	endbr64 
  hole = 2;
    9634:	c7 05 ce 5c 01 00 02 	movl   $0x2,0x15cce(%rip)        # 1f30c <hole>
    963b:	00 00 00 
  data.l2.state = 0;
    963e:	c7 05 98 5c 01 00 00 	movl   $0x0,0x15c98(%rip)        # 1f2e0 <data>
    9645:	00 00 00 
}
    9648:	c3                   	retq   
    9649:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000009650 <level3_init>:
}


static void
level3_init (void)
{
    9650:	f3 0f 1e fa          	endbr64 
  data.l3.state = -1;
    9654:	c7 05 82 5c 01 00 ff 	movl   $0xffffffff,0x15c82(%rip)        # 1f2e0 <data>
    965b:	ff ff ff 
}
    965e:	c3                   	retq   
    965f:	90                   	nop

0000000000009660 <level_fin_init>:
}


static void
level_fin_init (void)
{
    9660:	f3 0f 1e fa          	endbr64 
    9664:	48 83 ec 08          	sub    $0x8,%rsp
  data.l_fin.state = uniform_rnd (10);
    9668:	bf 0a 00 00 00       	mov    $0xa,%edi
    966d:	e8 8e 5e 00 00       	callq  f500 <uniform_rnd>
  hole = 2;
    9672:	c7 05 90 5c 01 00 02 	movl   $0x2,0x15c90(%rip)        # 1f30c <hole>
    9679:	00 00 00 
  data.l_fin.state = uniform_rnd (10);
    967c:	89 05 5e 5c 01 00    	mov    %eax,0x15c5e(%rip)        # 1f2e0 <data>
  data.l_fin.next_gap = 7;
    9682:	48 c7 05 5b 5c 01 00 	movq   $0x7,0x15c5b(%rip)        # 1f2e8 <data+0x8>
    9689:	07 00 00 00 
  data.l_fin.spare_time = 0;
}
    968d:	48 83 c4 08          	add    $0x8,%rsp
    9691:	c3                   	retq   
    9692:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    9699:	00 00 00 00 
    969d:	0f 1f 00             	nopl   (%rax)

00000000000096a0 <level6_init>:
{
    96a0:	f3 0f 1e fa          	endbr64 
    96a4:	48 83 ec 08          	sub    $0x8,%rsp
  data.l6.next_gap = 8 + uniform_rnd (10);
    96a8:	bf 0a 00 00 00       	mov    $0xa,%edi
  hole = 5;
    96ad:	c7 05 55 5c 01 00 05 	movl   $0x5,0x15c55(%rip)        # 1f30c <hole>
    96b4:	00 00 00 
  data.l6.next_gap = 8 + uniform_rnd (10);
    96b7:	e8 44 5e 00 00       	callq  f500 <uniform_rnd>
  data.l6.state = 3;
    96bc:	c7 05 1a 5c 01 00 03 	movl   $0x3,0x15c1a(%rip)        # 1f2e0 <data>
    96c3:	00 00 00 
  data.l6.spare_time = 6;
    96c6:	c7 05 1c 5c 01 00 06 	movl   $0x6,0x15c1c(%rip)        # 1f2ec <data+0xc>
    96cd:	00 00 00 
  data.l6.next_gap = 8 + uniform_rnd (10);
    96d0:	83 c0 08             	add    $0x8,%eax
    96d3:	89 05 0f 5c 01 00    	mov    %eax,0x15c0f(%rip)        # 1f2e8 <data+0x8>
}
    96d9:	48 83 c4 08          	add    $0x8,%rsp
    96dd:	c3                   	retq   
    96de:	66 90                	xchg   %ax,%ax

00000000000096e0 <level4_init>:
{
    96e0:	f3 0f 1e fa          	endbr64 
    96e4:	48 83 ec 08          	sub    $0x8,%rsp
  data.l4.next_gap = 8 + uniform_rnd (10);
    96e8:	bf 0a 00 00 00       	mov    $0xa,%edi
  hole = 6;
    96ed:	c7 05 15 5c 01 00 06 	movl   $0x6,0x15c15(%rip)        # 1f30c <hole>
    96f4:	00 00 00 
  data.l4.next_gap = 8 + uniform_rnd (10);
    96f7:	e8 04 5e 00 00       	callq  f500 <uniform_rnd>
  data.l4.state = 3;
    96fc:	c7 05 da 5b 01 00 03 	movl   $0x3,0x15bda(%rip)        # 1f2e0 <data>
    9703:	00 00 00 
  data.l4.next_gap = 8 + uniform_rnd (10);
    9706:	83 c0 08             	add    $0x8,%eax
    9709:	89 05 d9 5b 01 00    	mov    %eax,0x15bd9(%rip)        # 1f2e8 <data+0x8>
}
    970f:	48 83 c4 08          	add    $0x8,%rsp
    9713:	c3                   	retq   
    9714:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    971b:	00 00 00 00 
    971f:	90                   	nop

0000000000009720 <level2>:
{
    9720:	f3 0f 1e fa          	endbr64 
  if (is_edge) {
    9724:	8b 15 da 5b 01 00    	mov    0x15bda(%rip),%edx        # 1f304 <is_edge>
    972a:	8b 05 b0 5b 01 00    	mov    0x15bb0(%rip),%eax        # 1f2e0 <data>
    9730:	85 d2                	test   %edx,%edx
    9732:	74 74                	je     97a8 <level2+0x88>
{
    9734:	48 83 ec 08          	sub    $0x8,%rsp
    if (data.l2.state == 0) {
    9738:	85 c0                	test   %eax,%eax
    973a:	0f 85 98 00 00 00    	jne    97d8 <level2+0xb8>
      data.l2.gap = 8;
    9740:	c7 05 9a 5b 01 00 08 	movl   $0x8,0x15b9a(%rip)        # 1f2e4 <data+0x4>
    9747:	00 00 00 
      if (ticks >= 310) {
    974a:	8b 05 a0 5b 01 00    	mov    0x15ba0(%rip),%eax        # 1f2f0 <ticks>
    9750:	3d 35 01 00 00       	cmp    $0x135,%eax
    9755:	0f 8f bd 00 00 00    	jg     9818 <level2+0xf8>
        data.l2.state = 2 + uniform_rnd (3 + (ticks < 190));
    975b:	31 ff                	xor    %edi,%edi
    975d:	3d be 00 00 00       	cmp    $0xbe,%eax
    9762:	40 0f 9c c7          	setl   %dil
    9766:	83 c7 03             	add    $0x3,%edi
    9769:	e8 92 5d 00 00       	callq  f500 <uniform_rnd>
    976e:	8b 35 70 5b 01 00    	mov    0x15b70(%rip),%esi        # 1f2e4 <data+0x4>
    9774:	83 c0 02             	add    $0x2,%eax
    9777:	89 05 63 5b 01 00    	mov    %eax,0x15b63(%rip)        # 1f2e0 <data>
    977d:	8d 56 ff             	lea    -0x1(%rsi),%edx
  --data.l2.gap;
    9780:	89 15 5e 5b 01 00    	mov    %edx,0x15b5e(%rip)        # 1f2e4 <data+0x4>
  if (data.l2.gap <= 0)  hole = 2;
    9786:	85 d2                	test   %edx,%edx
    9788:	7f 0a                	jg     9794 <level2+0x74>
    978a:	c7 05 78 5b 01 00 02 	movl   $0x2,0x15b78(%rip)        # 1f30c <hole>
    9791:	00 00 00 
  if (data.l2.state < -6)  ++level;
    9794:	83 f8 fa             	cmp    $0xfffffffa,%eax
    9797:	7d 07                	jge    97a0 <level2+0x80>
    9799:	83 05 5c 5b 01 00 01 	addl   $0x1,0x15b5c(%rip)        # 1f2fc <level>
}
    97a0:	48 83 c4 08          	add    $0x8,%rsp
    97a4:	c3                   	retq   
    97a5:	0f 1f 00             	nopl   (%rax)
    97a8:	8b 0d 36 5b 01 00    	mov    0x15b36(%rip),%ecx        # 1f2e4 <data+0x4>
    97ae:	8d 51 ff             	lea    -0x1(%rcx),%edx
  --data.l2.gap;
    97b1:	89 15 2d 5b 01 00    	mov    %edx,0x15b2d(%rip)        # 1f2e4 <data+0x4>
  if (data.l2.gap <= 0)  hole = 2;
    97b7:	85 d2                	test   %edx,%edx
    97b9:	7f 0a                	jg     97c5 <level2+0xa5>
    97bb:	c7 05 47 5b 01 00 02 	movl   $0x2,0x15b47(%rip)        # 1f30c <hole>
    97c2:	00 00 00 
  if (data.l2.state < -6)  ++level;
    97c5:	83 f8 fa             	cmp    $0xfffffffa,%eax
    97c8:	7d 46                	jge    9810 <level2+0xf0>
    97ca:	83 05 2b 5b 01 00 01 	addl   $0x1,0x15b2b(%rip)        # 1f2fc <level>
    97d1:	c3                   	retq   
    97d2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    } else if (data.l2.state > 0) {
    97d8:	7f 56                	jg     9830 <level2+0x110>
      switch (data.l2.state) {
    97da:	83 f8 fe             	cmp    $0xfffffffe,%eax
    97dd:	74 79                	je     9858 <level2+0x138>
    97df:	83 f8 ff             	cmp    $0xffffffff,%eax
    97e2:	0f 84 a8 00 00 00    	je     9890 <level2+0x170>
    97e8:	83 f8 fc             	cmp    $0xfffffffc,%eax
    97eb:	0f 84 7f 00 00 00    	je     9870 <level2+0x150>
  --data.l2.gap;
    97f1:	c7 05 e9 5a 01 00 06 	movl   $0x6,0x15ae9(%rip)        # 1f2e4 <data+0x4>
    97f8:	00 00 00 
      --data.l2.state;
    97fb:	83 e8 01             	sub    $0x1,%eax
    97fe:	89 05 dc 5a 01 00    	mov    %eax,0x15adc(%rip)        # 1f2e0 <data>
  if (data.l2.gap <= 0)  hole = 2;
    9804:	eb 8e                	jmp    9794 <level2+0x74>
    9806:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    980d:	00 00 00 
    9810:	c3                   	retq   
    9811:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
        data.l2.state = -1;
    9818:	48 b8 ff ff ff ff 07 	movabs $0x7ffffffff,%rax
    981f:	00 00 00 
    9822:	48 89 05 b7 5a 01 00 	mov    %rax,0x15ab7(%rip)        # 1f2e0 <data>
}
    9829:	48 83 c4 08          	add    $0x8,%rsp
    982d:	c3                   	retq   
    982e:	66 90                	xchg   %ax,%ax
      data.l2.gap = 12 + uniform_rnd (6);
    9830:	bf 06 00 00 00       	mov    $0x6,%edi
    9835:	e8 c6 5c 00 00       	callq  f500 <uniform_rnd>
    983a:	41 89 c0             	mov    %eax,%r8d
      --data.l2.state;
    983d:	8b 05 9d 5a 01 00    	mov    0x15a9d(%rip),%eax        # 1f2e0 <data>
    9843:	41 8d 50 0b          	lea    0xb(%r8),%edx
    9847:	83 e8 01             	sub    $0x1,%eax
    984a:	89 05 90 5a 01 00    	mov    %eax,0x15a90(%rip)        # 1f2e0 <data>
    9850:	e9 2b ff ff ff       	jmpq   9780 <level2+0x60>
    9855:	0f 1f 00             	nopl   (%rax)
      --data.l2.state;
    9858:	48 b8 fd ff ff ff 0c 	movabs $0xcfffffffd,%rax
    985f:	00 00 00 
    9862:	48 89 05 77 5a 01 00 	mov    %rax,0x15a77(%rip)        # 1f2e0 <data>
  if (data.l2.gap <= 0)  hole = 2;
    9869:	e9 32 ff ff ff       	jmpq   97a0 <level2+0x80>
    986e:	66 90                	xchg   %ax,%ax
      --data.l2.state;
    9870:	48 b8 fb ff ff ff 0d 	movabs $0xdfffffffb,%rax
    9877:	00 00 00 
    987a:	48 89 05 5f 5a 01 00 	mov    %rax,0x15a5f(%rip)        # 1f2e0 <data>
  if (data.l2.gap <= 0)  hole = 2;
    9881:	e9 1a ff ff ff       	jmpq   97a0 <level2+0x80>
    9886:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    988d:	00 00 00 
      --data.l2.state;
    9890:	48 b8 fe ff ff ff 0f 	movabs $0xffffffffe,%rax
    9897:	00 00 00 
    989a:	48 89 05 3f 5a 01 00 	mov    %rax,0x15a3f(%rip)        # 1f2e0 <data>
  if (data.l2.gap <= 0)  hole = 2;
    98a1:	e9 fa fe ff ff       	jmpq   97a0 <level2+0x80>
    98a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    98ad:	00 00 00 

00000000000098b0 <level1>:
{
    98b0:	f3 0f 1e fa          	endbr64 
  if (is_edge) {
    98b4:	8b 05 4a 5a 01 00    	mov    0x15a4a(%rip),%eax        # 1f304 <is_edge>
{
    98ba:	53                   	push   %rbx
  if (is_edge) {
    98bb:	85 c0                	test   %eax,%eax
    98bd:	75 49                	jne    9908 <level1+0x58>
    98bf:	8b 05 1f 5a 01 00    	mov    0x15a1f(%rip),%eax        # 1f2e4 <data+0x4>
    98c5:	83 e8 01             	sub    $0x1,%eax
  --data.l1.gap;
    98c8:	89 05 16 5a 01 00    	mov    %eax,0x15a16(%rip)        # 1f2e4 <data+0x4>
  if (data.l1.gap <= 0) {
    98ce:	85 c0                	test   %eax,%eax
    98d0:	7f 2f                	jg     9901 <level1+0x51>
    switch (data.l1.state) {
    98d2:	8b 05 08 5a 01 00    	mov    0x15a08(%rip),%eax        # 1f2e0 <data>
    98d8:	83 f8 02             	cmp    $0x2,%eax
    98db:	7f 6b                	jg     9948 <level1+0x98>
    98dd:	85 c0                	test   %eax,%eax
    98df:	0f 8f db 00 00 00    	jg     99c0 <level1+0x110>
      hole = table [uniform_rnd (11)];
    98e5:	bf 0b 00 00 00       	mov    $0xb,%edi
    98ea:	e8 11 5c 00 00       	callq  f500 <uniform_rnd>
    98ef:	48 8d 15 4a ff 00 00 	lea    0xff4a(%rip),%rdx        # 19840 <table.4488>
    98f6:	48 98                	cltq   
    98f8:	8b 04 82             	mov    (%rdx,%rax,4),%eax
    98fb:	89 05 0b 5a 01 00    	mov    %eax,0x15a0b(%rip)        # 1f30c <hole>
}
    9901:	5b                   	pop    %rbx
    9902:	c3                   	retq   
    9903:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    if (ticks < 300) {
    9908:	8b 1d e2 59 01 00    	mov    0x159e2(%rip),%ebx        # 1f2f0 <ticks>
    990e:	81 fb 2b 01 00 00    	cmp    $0x12b,%ebx
    9914:	7e 62                	jle    9978 <level1+0xc8>
      switch (data.l1.state) {
    9916:	8b 05 c4 59 01 00    	mov    0x159c4(%rip),%eax        # 1f2e0 <data>
    991c:	83 f8 01             	cmp    $0x1,%eax
    991f:	0f 84 ab 00 00 00    	je     99d0 <level1+0x120>
    9925:	83 f8 02             	cmp    $0x2,%eax
    9928:	74 36                	je     9960 <level1+0xb0>
      if (data.l1.state > 2) {
    992a:	0f 8e b3 00 00 00    	jle    99e3 <level1+0x133>
        ++level;
    9930:	83 05 c5 59 01 00 01 	addl   $0x1,0x159c5(%rip)        # 1f2fc <level>
}
    9937:	5b                   	pop    %rbx
  --data.l1.gap;
    9938:	c7 05 a2 59 01 00 0b 	movl   $0xb,0x159a2(%rip)        # 1f2e4 <data+0x4>
    993f:	00 00 00 
}
    9942:	c3                   	retq   
    9943:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    switch (data.l1.state) {
    9948:	83 f8 03             	cmp    $0x3,%eax
    994b:	75 98                	jne    98e5 <level1+0x35>
      hole = 5;
    994d:	c7 05 b5 59 01 00 05 	movl   $0x5,0x159b5(%rip)        # 1f30c <hole>
    9954:	00 00 00 
}
    9957:	5b                   	pop    %rbx
    9958:	c3                   	retq   
    9959:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
        ++data.l1.state;
    9960:	48 b8 03 00 00 00 07 	movabs $0x700000003,%rax
    9967:	00 00 00 
}
    996a:	5b                   	pop    %rbx
        ++data.l1.state;
    996b:	48 89 05 6e 59 01 00 	mov    %rax,0x1596e(%rip)        # 1f2e0 <data>
}
    9972:	c3                   	retq   
    9973:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      data.l1.gap = 14.5 - ticks*4.0/300 + uniform_rnd (3);
    9978:	bf 03 00 00 00       	mov    $0x3,%edi
    997d:	e8 7e 5b 00 00       	callq  f500 <uniform_rnd>
    9982:	f2 0f 10 05 e6 ff 00 	movsd  0xffe6(%rip),%xmm0        # 19970 <__PRETTY_FUNCTION__.4560+0x100>
    9989:	00 
    998a:	66 0f ef c9          	pxor   %xmm1,%xmm1
    998e:	f2 0f 2a cb          	cvtsi2sd %ebx,%xmm1
    9992:	f2 0f 59 0d c6 ff 00 	mulsd  0xffc6(%rip),%xmm1        # 19960 <__PRETTY_FUNCTION__.4560+0xf0>
    9999:	00 
    999a:	f2 0f 5e 0d c6 ff 00 	divsd  0xffc6(%rip),%xmm1        # 19968 <__PRETTY_FUNCTION__.4560+0xf8>
    99a1:	00 
    99a2:	f2 0f 5c c1          	subsd  %xmm1,%xmm0
    99a6:	66 0f ef c9          	pxor   %xmm1,%xmm1
    99aa:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    99ae:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
    99b2:	f2 0f 2c c0          	cvttsd2si %xmm0,%eax
    99b6:	83 e8 01             	sub    $0x1,%eax
    99b9:	e9 0a ff ff ff       	jmpq   98c8 <level1+0x18>
    99be:	66 90                	xchg   %ax,%ax
      hole = 4;
    99c0:	c7 05 42 59 01 00 04 	movl   $0x4,0x15942(%rip)        # 1f30c <hole>
    99c7:	00 00 00 
}
    99ca:	5b                   	pop    %rbx
    99cb:	c3                   	retq   
    99cc:	0f 1f 40 00          	nopl   0x0(%rax)
        ++data.l1.state;
    99d0:	48 b8 02 00 00 00 06 	movabs $0x600000002,%rax
    99d7:	00 00 00 
}
    99da:	5b                   	pop    %rbx
        ++data.l1.state;
    99db:	48 89 05 fe 58 01 00 	mov    %rax,0x158fe(%rip)        # 1f2e0 <data>
}
    99e2:	c3                   	retq   
  --data.l1.gap;
    99e3:	c7 05 f7 58 01 00 0b 	movl   $0xb,0x158f7(%rip)        # 1f2e4 <data+0x4>
    99ea:	00 00 00 
        ++data.l1.state;
    99ed:	83 c0 01             	add    $0x1,%eax
}
    99f0:	5b                   	pop    %rbx
        ++data.l1.state;
    99f1:	89 05 e9 58 01 00    	mov    %eax,0x158e9(%rip)        # 1f2e0 <data>
}
    99f7:	c3                   	retq   
    99f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    99ff:	00 

0000000000009a00 <level0>:
{
    9a00:	f3 0f 1e fa          	endbr64 
  if (is_edge) {
    9a04:	8b 05 fa 58 01 00    	mov    0x158fa(%rip),%eax        # 1f304 <is_edge>
    9a0a:	85 c0                	test   %eax,%eax
    9a0c:	75 2a                	jne    9a38 <level0+0x38>
    9a0e:	8b 05 d0 58 01 00    	mov    0x158d0(%rip),%eax        # 1f2e4 <data+0x4>
    9a14:	83 e8 01             	sub    $0x1,%eax
  --data.l0.gap;
    9a17:	89 05 c7 58 01 00    	mov    %eax,0x158c7(%rip)        # 1f2e4 <data+0x4>
  if (data.l0.gap <= 0)  hole = 2;
    9a1d:	85 c0                	test   %eax,%eax
    9a1f:	7f 0f                	jg     9a30 <level0+0x30>
    9a21:	c7 05 e1 58 01 00 02 	movl   $0x2,0x158e1(%rip)        # 1f30c <hole>
    9a28:	00 00 00 
    9a2b:	c3                   	retq   
    9a2c:	0f 1f 40 00          	nopl   0x0(%rax)
    9a30:	c3                   	retq   
    9a31:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    if (ticks < 345) {
    9a38:	8b 05 b2 58 01 00    	mov    0x158b2(%rip),%eax        # 1f2f0 <ticks>
    9a3e:	3d 58 01 00 00       	cmp    $0x158,%eax
    9a43:	7e 3b                	jle    9a80 <level0+0x80>
      switch (data.l0.state) {
    9a45:	8b 15 95 58 01 00    	mov    0x15895(%rip),%edx        # 1f2e0 <data>
    9a4b:	83 fa 01             	cmp    $0x1,%edx
    9a4e:	0f 84 dc 00 00 00    	je     9b30 <level0+0x130>
    9a54:	83 fa 02             	cmp    $0x2,%edx
    9a57:	0f 84 bb 00 00 00    	je     9b18 <level0+0x118>
    9a5d:	85 d2                	test   %edx,%edx
    9a5f:	0f 84 9b 00 00 00    	je     9b00 <level0+0x100>
        ++level;
    9a65:	8b 05 79 58 01 00    	mov    0x15879(%rip),%eax        # 1f2e4 <data+0x4>
      ++data.l0.state;
    9a6b:	83 c2 01             	add    $0x1,%edx
        ++level;
    9a6e:	83 05 87 58 01 00 01 	addl   $0x1,0x15887(%rip)        # 1f2fc <level>
      ++data.l0.state;
    9a75:	89 15 65 58 01 00    	mov    %edx,0x15865(%rip)        # 1f2e0 <data>
    9a7b:	83 e8 01             	sub    $0x1,%eax
    9a7e:	eb 97                	jmp    9a17 <level0+0x17>
      data.l0.gap = 14.5 - ticks*4.0/345 + uniform_rnd (4.5 + ticks*4.0/345);
    9a80:	66 0f ef c9          	pxor   %xmm1,%xmm1
{
    9a84:	48 83 ec 18          	sub    $0x18,%rsp
      data.l0.gap = 14.5 - ticks*4.0/345 + uniform_rnd (4.5 + ticks*4.0/345);
    9a88:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    9a8c:	f2 0f 59 0d cc fe 00 	mulsd  0xfecc(%rip),%xmm1        # 19960 <__PRETTY_FUNCTION__.4560+0xf0>
    9a93:	00 
    9a94:	f2 0f 5e 0d dc fe 00 	divsd  0xfedc(%rip),%xmm1        # 19978 <__PRETTY_FUNCTION__.4560+0x108>
    9a9b:	00 
    9a9c:	66 0f 28 c1          	movapd %xmm1,%xmm0
    9aa0:	f2 0f 58 05 d8 fe 00 	addsd  0xfed8(%rip),%xmm0        # 19980 <__PRETTY_FUNCTION__.4560+0x110>
    9aa7:	00 
    9aa8:	f2 0f 11 4c 24 08    	movsd  %xmm1,0x8(%rsp)
    9aae:	f2 48 0f 2c f8       	cvttsd2si %xmm0,%rdi
    9ab3:	e8 48 5a 00 00       	callq  f500 <uniform_rnd>
    9ab8:	f2 0f 10 4c 24 08    	movsd  0x8(%rsp),%xmm1
    9abe:	f2 0f 10 05 aa fe 00 	movsd  0xfeaa(%rip),%xmm0        # 19970 <__PRETTY_FUNCTION__.4560+0x100>
    9ac5:	00 
    9ac6:	f2 0f 5c c1          	subsd  %xmm1,%xmm0
    9aca:	66 0f ef c9          	pxor   %xmm1,%xmm1
    9ace:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    9ad2:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
    9ad6:	f2 0f 2c c0          	cvttsd2si %xmm0,%eax
    9ada:	83 e8 01             	sub    $0x1,%eax
  --data.l0.gap;
    9add:	89 05 01 58 01 00    	mov    %eax,0x15801(%rip)        # 1f2e4 <data+0x4>
  if (data.l0.gap <= 0)  hole = 2;
    9ae3:	85 c0                	test   %eax,%eax
    9ae5:	7f 0a                	jg     9af1 <level0+0xf1>
    9ae7:	c7 05 1b 58 01 00 02 	movl   $0x2,0x1581b(%rip)        # 1f30c <hole>
    9aee:	00 00 00 
}
    9af1:	48 83 c4 18          	add    $0x18,%rsp
    9af5:	c3                   	retq   
    9af6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    9afd:	00 00 00 
      ++data.l0.state;
    9b00:	48 b8 01 00 00 00 0c 	movabs $0xc00000001,%rax
    9b07:	00 00 00 
    9b0a:	48 89 05 cf 57 01 00 	mov    %rax,0x157cf(%rip)        # 1f2e0 <data>
  if (data.l0.gap <= 0)  hole = 2;
    9b11:	c3                   	retq   
    9b12:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      ++data.l0.state;
    9b18:	48 b8 03 00 00 00 0a 	movabs $0xa00000003,%rax
    9b1f:	00 00 00 
    9b22:	48 89 05 b7 57 01 00 	mov    %rax,0x157b7(%rip)        # 1f2e0 <data>
  if (data.l0.gap <= 0)  hole = 2;
    9b29:	c3                   	retq   
    9b2a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      ++data.l0.state;
    9b30:	48 b8 02 00 00 00 09 	movabs $0x900000002,%rax
    9b37:	00 00 00 
    9b3a:	48 89 05 9f 57 01 00 	mov    %rax,0x1579f(%rip)        # 1f2e0 <data>
  if (data.l0.gap <= 0)  hole = 2;
    9b41:	c3                   	retq   
    9b42:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    9b49:	00 00 00 00 
    9b4d:	0f 1f 00             	nopl   (%rax)

0000000000009b50 <level_fin>:

static void
level_fin (double t)
{
    9b50:	f3 0f 1e fa          	endbr64 
    9b54:	48 83 ec 08          	sub    $0x8,%rsp
  if (is_edge) {
    9b58:	8b 15 a6 57 01 00    	mov    0x157a6(%rip),%edx        # 1f304 <is_edge>
    9b5e:	85 d2                	test   %edx,%edx
    9b60:	74 39                	je     9b9b <level_fin+0x4b>
    data.l_fin.gap = data.l_fin.next_gap;
    9b62:	8b 05 80 57 01 00    	mov    0x15780(%rip),%eax        # 1f2e8 <data+0x8>
    if (data.l_fin.state == 0) {
    9b68:	8b 15 72 57 01 00    	mov    0x15772(%rip),%edx        # 1f2e0 <data>
    data.l_fin.gap = data.l_fin.next_gap;
    9b6e:	89 05 70 57 01 00    	mov    %eax,0x15770(%rip)        # 1f2e4 <data+0x4>
    if (data.l_fin.state == 0) {
    9b74:	85 d2                	test   %edx,%edx
    9b76:	74 10                	je     9b88 <level_fin+0x38>
      data.l_fin.state = 3 + uniform_rnd (6);
    } else {
      --data.l_fin.state;
    9b78:	83 ea 01             	sub    $0x1,%edx
    9b7b:	89 15 5f 57 01 00    	mov    %edx,0x1575f(%rip)        # 1f2e0 <data>
    9b81:	eb 1e                	jmp    9ba1 <level_fin+0x51>
    9b83:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      data.l_fin.state = 3 + uniform_rnd (6);
    9b88:	bf 06 00 00 00       	mov    $0x6,%edi
    9b8d:	e8 6e 59 00 00       	callq  f500 <uniform_rnd>
    9b92:	83 c0 03             	add    $0x3,%eax
    9b95:	89 05 45 57 01 00    	mov    %eax,0x15745(%rip)        # 1f2e0 <data>
    9b9b:	8b 05 43 57 01 00    	mov    0x15743(%rip),%eax        # 1f2e4 <data+0x4>
    }
  }
  --data.l_fin.gap;
  ++data.l_fin.spare_time;
    9ba1:	8b 0d 45 57 01 00    	mov    0x15745(%rip),%ecx        # 1f2ec <data+0xc>
  --data.l_fin.gap;
    9ba7:	83 e8 01             	sub    $0x1,%eax
    9baa:	89 05 34 57 01 00    	mov    %eax,0x15734(%rip)        # 1f2e4 <data+0x4>
  ++data.l_fin.spare_time;
    9bb0:	8d 79 01             	lea    0x1(%rcx),%edi
    9bb3:	89 3d 33 57 01 00    	mov    %edi,0x15733(%rip)        # 1f2ec <data+0xc>
  if (data.l_fin.gap <= 0) {
    9bb9:	85 c0                	test   %eax,%eax
    9bbb:	7e 13                	jle    9bd0 <level_fin+0x80>
      }
    }
    data.l_fin.spare_time -= 11;
  }

  if (data.l_fin.spare_time >= 5) {
    9bbd:	83 ff 04             	cmp    $0x4,%edi
    9bc0:	7f 58                	jg     9c1a <level_fin+0xca>
    if (uniform_rnd (data.l_fin.spare_time) > 2) {
      place_meteor ();
      data.l_fin.spare_time -= 5;
    }
  }
}
    9bc2:	48 83 c4 08          	add    $0x8,%rsp
    9bc6:	c3                   	retq   
    9bc7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    9bce:	00 00 
    if (data.l_fin.state) {
    9bd0:	8b 05 0a 57 01 00    	mov    0x1570a(%rip),%eax        # 1f2e0 <data>
      hole = 2 + uniform_rnd (3);
    9bd6:	bf 03 00 00 00       	mov    $0x3,%edi
    if (data.l_fin.state) {
    9bdb:	85 c0                	test   %eax,%eax
    9bdd:	74 59                	je     9c38 <level_fin+0xe8>
      hole = 2 + uniform_rnd (3);
    9bdf:	e8 1c 59 00 00       	callq  f500 <uniform_rnd>
      data.l_fin.next_gap = 15 + uniform_rnd (6) - hole;
    9be4:	bf 06 00 00 00       	mov    $0x6,%edi
      hole = 2 + uniform_rnd (3);
    9be9:	83 c0 02             	add    $0x2,%eax
    9bec:	89 05 1a 57 01 00    	mov    %eax,0x1571a(%rip)        # 1f30c <hole>
      data.l_fin.next_gap = 15 + uniform_rnd (6) - hole;
    9bf2:	e8 09 59 00 00       	callq  f500 <uniform_rnd>
    9bf7:	83 c0 0f             	add    $0xf,%eax
    9bfa:	2b 05 0c 57 01 00    	sub    0x1570c(%rip),%eax        # 1f30c <hole>
    9c00:	89 05 e2 56 01 00    	mov    %eax,0x156e2(%rip)        # 1f2e8 <data+0x8>
    data.l_fin.spare_time -= 11;
    9c06:	8b 05 e0 56 01 00    	mov    0x156e0(%rip),%eax        # 1f2ec <data+0xc>
    9c0c:	8d 78 f5             	lea    -0xb(%rax),%edi
    9c0f:	89 3d d7 56 01 00    	mov    %edi,0x156d7(%rip)        # 1f2ec <data+0xc>
  if (data.l_fin.spare_time >= 5) {
    9c15:	83 ff 04             	cmp    $0x4,%edi
    9c18:	7e a8                	jle    9bc2 <level_fin+0x72>
    if (uniform_rnd (data.l_fin.spare_time) > 2) {
    9c1a:	e8 e1 58 00 00       	callq  f500 <uniform_rnd>
    9c1f:	83 f8 02             	cmp    $0x2,%eax
    9c22:	7e 9e                	jle    9bc2 <level_fin+0x72>
      place_meteor ();
    9c24:	e8 37 1b 00 00       	callq  b760 <place_meteor>
      data.l_fin.spare_time -= 5;
    9c29:	83 2d bc 56 01 00 05 	subl   $0x5,0x156bc(%rip)        # 1f2ec <data+0xc>
}
    9c30:	48 83 c4 08          	add    $0x8,%rsp
    9c34:	c3                   	retq   
    9c35:	0f 1f 00             	nopl   (%rax)
      if (uniform_rnd (3)) {
    9c38:	e8 c3 58 00 00       	callq  f500 <uniform_rnd>
    9c3d:	85 c0                	test   %eax,%eax
    9c3f:	74 2f                	je     9c70 <level_fin+0x120>
        hole = 5 + uniform_rnd (2);
    9c41:	bf 02 00 00 00       	mov    $0x2,%edi
    9c46:	e8 b5 58 00 00       	callq  f500 <uniform_rnd>
        data.l_fin.next_gap = 9 + uniform_rnd (10);
    9c4b:	bf 0a 00 00 00       	mov    $0xa,%edi
        hole = 5 + uniform_rnd (2);
    9c50:	83 c0 05             	add    $0x5,%eax
    9c53:	89 05 b3 56 01 00    	mov    %eax,0x156b3(%rip)        # 1f30c <hole>
        data.l_fin.next_gap = 9 + uniform_rnd (10);
    9c59:	e8 a2 58 00 00       	callq  f500 <uniform_rnd>
    9c5e:	83 c0 09             	add    $0x9,%eax
    9c61:	89 05 81 56 01 00    	mov    %eax,0x15681(%rip)        # 1f2e8 <data+0x8>
    9c67:	eb 9d                	jmp    9c06 <level_fin+0xb6>
    9c69:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
        hole = 2 + uniform_rnd (3);
    9c70:	bf 03 00 00 00       	mov    $0x3,%edi
    9c75:	e8 86 58 00 00       	callq  f500 <uniform_rnd>
        data.l_fin.next_gap = 9;
    9c7a:	c7 05 64 56 01 00 09 	movl   $0x9,0x15664(%rip)        # 1f2e8 <data+0x8>
    9c81:	00 00 00 
        hole = 2 + uniform_rnd (3);
    9c84:	83 c0 02             	add    $0x2,%eax
    9c87:	89 05 7f 56 01 00    	mov    %eax,0x1567f(%rip)        # 1f30c <hole>
        data.l_fin.next_gap = 9;
    9c8d:	e9 74 ff ff ff       	jmpq   9c06 <level_fin+0xb6>
    9c92:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    9c99:	00 00 00 00 
    9c9d:	0f 1f 00             	nopl   (%rax)

0000000000009ca0 <level6>:
{
    9ca0:	f3 0f 1e fa          	endbr64 
  if (is_edge) {
    9ca4:	8b 15 5a 56 01 00    	mov    0x1565a(%rip),%edx        # 1f304 <is_edge>
{
    9caa:	53                   	push   %rbx
  if (is_edge) {
    9cab:	85 d2                	test   %edx,%edx
    9cad:	74 51                	je     9d00 <level6+0x60>
    data.l6.gap = data.l6.next_gap;
    9caf:	8b 05 33 56 01 00    	mov    0x15633(%rip),%eax        # 1f2e8 <data+0x8>
    if (data.l6.state == 0) {
    9cb5:	8b 15 25 56 01 00    	mov    0x15625(%rip),%edx        # 1f2e0 <data>
    data.l6.gap = data.l6.next_gap;
    9cbb:	89 05 23 56 01 00    	mov    %eax,0x15623(%rip)        # 1f2e4 <data+0x4>
    if (data.l6.state == 0) {
    9cc1:	85 d2                	test   %edx,%edx
    9cc3:	74 0b                	je     9cd0 <level6+0x30>
      --data.l6.state;
    9cc5:	83 ea 01             	sub    $0x1,%edx
    9cc8:	89 15 12 56 01 00    	mov    %edx,0x15612(%rip)        # 1f2e0 <data>
    9cce:	eb 36                	jmp    9d06 <level6+0x66>
      data.l6.state = 3 + uniform_rnd (5);
    9cd0:	bf 05 00 00 00       	mov    $0x5,%edi
    9cd5:	e8 26 58 00 00       	callq  f500 <uniform_rnd>
    9cda:	83 c0 03             	add    $0x3,%eax
      if (ticks >= 375)  ++level;
    9cdd:	81 3d 09 56 01 00 76 	cmpl   $0x176,0x15609(%rip)        # 1f2f0 <ticks>
    9ce4:	01 00 00 
      data.l6.state = 3 + uniform_rnd (5);
    9ce7:	89 05 f3 55 01 00    	mov    %eax,0x155f3(%rip)        # 1f2e0 <data>
      if (ticks >= 375)  ++level;
    9ced:	7e 11                	jle    9d00 <level6+0x60>
    9cef:	83 05 06 56 01 00 01 	addl   $0x1,0x15606(%rip)        # 1f2fc <level>
    9cf6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    9cfd:	00 00 00 
    9d00:	8b 05 de 55 01 00    	mov    0x155de(%rip),%eax        # 1f2e4 <data+0x4>
  ++data.l6.spare_time;
    9d06:	8b 0d e0 55 01 00    	mov    0x155e0(%rip),%ecx        # 1f2ec <data+0xc>
  --data.l6.gap;
    9d0c:	83 e8 01             	sub    $0x1,%eax
    9d0f:	89 05 cf 55 01 00    	mov    %eax,0x155cf(%rip)        # 1f2e4 <data+0x4>
  ++data.l6.spare_time;
    9d15:	8d 79 01             	lea    0x1(%rcx),%edi
    9d18:	89 3d ce 55 01 00    	mov    %edi,0x155ce(%rip)        # 1f2ec <data+0xc>
  if (data.l6.gap <= 0) {
    9d1e:	85 c0                	test   %eax,%eax
    9d20:	7e 5e                	jle    9d80 <level6+0xe0>
  slip = (380-ticks)*3.0/374 + 1.5;
    9d22:	b8 7c 01 00 00       	mov    $0x17c,%eax
    9d27:	66 0f ef c0          	pxor   %xmm0,%xmm0
    9d2b:	2b 05 bf 55 01 00    	sub    0x155bf(%rip),%eax        # 1f2f0 <ticks>
    9d31:	f2 0f 2a c0          	cvtsi2sd %eax,%xmm0
    9d35:	f2 0f 59 05 eb 69 00 	mulsd  0x69eb(%rip),%xmm0        # 10728 <_IO_stdin_used+0x728>
    9d3c:	00 
    9d3d:	f2 0f 5e 05 43 fc 00 	divsd  0xfc43(%rip),%xmm0        # 19988 <__PRETTY_FUNCTION__.4560+0x118>
    9d44:	00 
    9d45:	f2 0f 58 05 43 fc 00 	addsd  0xfc43(%rip),%xmm0        # 19990 <__PRETTY_FUNCTION__.4560+0x120>
    9d4c:	00 
    9d4d:	f2 0f 2c d8          	cvttsd2si %xmm0,%ebx
  if (data.l6.spare_time >= 3+slip) {
    9d51:	8d 43 02             	lea    0x2(%rbx),%eax
    9d54:	39 f8                	cmp    %edi,%eax
    9d56:	7c 08                	jl     9d60 <level6+0xc0>
}
    9d58:	5b                   	pop    %rbx
    9d59:	c3                   	retq   
    9d5a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    if (uniform_rnd (data.l6.spare_time) > 2) {
    9d60:	e8 9b 57 00 00       	callq  f500 <uniform_rnd>
    9d65:	83 f8 02             	cmp    $0x2,%eax
    9d68:	7e ee                	jle    9d58 <level6+0xb8>
      place_meteor ();
    9d6a:	e8 f1 19 00 00       	callq  b760 <place_meteor>
      data.l6.spare_time -= 3+slip;
    9d6f:	83 c3 03             	add    $0x3,%ebx
    9d72:	29 1d 74 55 01 00    	sub    %ebx,0x15574(%rip)        # 1f2ec <data+0xc>
}
    9d78:	5b                   	pop    %rbx
    9d79:	c3                   	retq   
    9d7a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    if (data.l6.state) {
    9d80:	8b 05 5a 55 01 00    	mov    0x1555a(%rip),%eax        # 1f2e0 <data>
      hole = 2 + uniform_rnd (3);
    9d86:	bf 03 00 00 00       	mov    $0x3,%edi
    if (data.l6.state) {
    9d8b:	85 c0                	test   %eax,%eax
    9d8d:	74 41                	je     9dd0 <level6+0x130>
      hole = 2 + uniform_rnd (3);
    9d8f:	e8 6c 57 00 00       	callq  f500 <uniform_rnd>
      data.l6.next_gap = 15 + uniform_rnd (6) - hole;
    9d94:	bf 06 00 00 00       	mov    $0x6,%edi
      hole = 2 + uniform_rnd (3);
    9d99:	83 c0 02             	add    $0x2,%eax
    9d9c:	89 05 6a 55 01 00    	mov    %eax,0x1556a(%rip)        # 1f30c <hole>
      data.l6.next_gap = 15 + uniform_rnd (6) - hole;
    9da2:	e8 59 57 00 00       	callq  f500 <uniform_rnd>
    9da7:	83 c0 0f             	add    $0xf,%eax
    9daa:	2b 05 5c 55 01 00    	sub    0x1555c(%rip),%eax        # 1f30c <hole>
    9db0:	89 05 32 55 01 00    	mov    %eax,0x15532(%rip)        # 1f2e8 <data+0x8>
    data.l6.spare_time -= 11;
    9db6:	8b 05 30 55 01 00    	mov    0x15530(%rip),%eax        # 1f2ec <data+0xc>
    9dbc:	8d 78 f5             	lea    -0xb(%rax),%edi
    9dbf:	89 3d 27 55 01 00    	mov    %edi,0x15527(%rip)        # 1f2ec <data+0xc>
    9dc5:	e9 58 ff ff ff       	jmpq   9d22 <level6+0x82>
    9dca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      if (uniform_rnd (3)) {
    9dd0:	e8 2b 57 00 00       	callq  f500 <uniform_rnd>
    9dd5:	85 c0                	test   %eax,%eax
    9dd7:	74 27                	je     9e00 <level6+0x160>
        hole = 5;
    9dd9:	c7 05 29 55 01 00 05 	movl   $0x5,0x15529(%rip)        # 1f30c <hole>
    9de0:	00 00 00 
        data.l6.next_gap = 9 + uniform_rnd (10);
    9de3:	bf 0a 00 00 00       	mov    $0xa,%edi
    9de8:	e8 13 57 00 00       	callq  f500 <uniform_rnd>
    9ded:	83 c0 09             	add    $0x9,%eax
    9df0:	89 05 f2 54 01 00    	mov    %eax,0x154f2(%rip)        # 1f2e8 <data+0x8>
    9df6:	eb be                	jmp    9db6 <level6+0x116>
    9df8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    9dff:	00 
        hole = 2 + uniform_rnd (2);
    9e00:	bf 02 00 00 00       	mov    $0x2,%edi
    9e05:	e8 f6 56 00 00       	callq  f500 <uniform_rnd>
        data.l6.next_gap = 9;
    9e0a:	c7 05 d4 54 01 00 09 	movl   $0x9,0x154d4(%rip)        # 1f2e8 <data+0x8>
    9e11:	00 00 00 
        hole = 2 + uniform_rnd (2);
    9e14:	83 c0 02             	add    $0x2,%eax
    9e17:	89 05 ef 54 01 00    	mov    %eax,0x154ef(%rip)        # 1f30c <hole>
        data.l6.next_gap = 9;
    9e1d:	eb 97                	jmp    9db6 <level6+0x116>
    9e1f:	90                   	nop

0000000000009e20 <level3>:
{
    9e20:	f3 0f 1e fa          	endbr64 
  if (data.l3.state < 0) {
    9e24:	8b 15 b6 54 01 00    	mov    0x154b6(%rip),%edx        # 1f2e0 <data>
{
    9e2a:	53                   	push   %rbx
  if (data.l3.state < 0) {
    9e2b:	85 d2                	test   %edx,%edx
    9e2d:	0f 88 8d 00 00 00    	js     9ec0 <level3+0xa0>
  if (is_edge) {
    9e33:	8b 05 cb 54 01 00    	mov    0x154cb(%rip),%eax        # 1f304 <is_edge>
    9e39:	85 c0                	test   %eax,%eax
    9e3b:	75 33                	jne    9e70 <level3+0x50>
    9e3d:	8b 1d a1 54 01 00    	mov    0x154a1(%rip),%ebx        # 1f2e4 <data+0x4>
    9e43:	8b 15 9f 54 01 00    	mov    0x1549f(%rip),%edx        # 1f2e8 <data+0x8>
  --data.l3.gap;
    9e49:	8d 43 ff             	lea    -0x1(%rbx),%eax
    9e4c:	89 05 92 54 01 00    	mov    %eax,0x15492(%rip)        # 1f2e4 <data+0x4>
  if (data.l3.gap == data.l3.pos)  place_meteor ();
    9e52:	39 d0                	cmp    %edx,%eax
    9e54:	0f 84 7e 00 00 00    	je     9ed8 <level3+0xb8>
  if (data.l3.gap <= 0)  hole = 2;
    9e5a:	85 c0                	test   %eax,%eax
    9e5c:	7e 02                	jle    9e60 <level3+0x40>
}
    9e5e:	5b                   	pop    %rbx
    9e5f:	c3                   	retq   
  if (data.l3.gap <= 0)  hole = 2;
    9e60:	c7 05 a2 54 01 00 02 	movl   $0x2,0x154a2(%rip)        # 1f30c <hole>
    9e67:	00 00 00 
}
    9e6a:	5b                   	pop    %rbx
    9e6b:	c3                   	retq   
    9e6c:	0f 1f 40 00          	nopl   0x0(%rax)
    data.l3.gap = 20 + uniform_rnd (10);
    9e70:	bf 0a 00 00 00       	mov    $0xa,%edi
    9e75:	e8 86 56 00 00       	callq  f500 <uniform_rnd>
    if (ticks > 160)  ++data.l3.state;
    9e7a:	81 3d 6c 54 01 00 a0 	cmpl   $0xa0,0x1546c(%rip)        # 1f2f0 <ticks>
    9e81:	00 00 00 
    data.l3.gap = 20 + uniform_rnd (10);
    9e84:	8d 58 14             	lea    0x14(%rax),%ebx
    if (ticks > 160)  ++data.l3.state;
    9e87:	8b 05 53 54 01 00    	mov    0x15453(%rip),%eax        # 1f2e0 <data>
    data.l3.gap = 20 + uniform_rnd (10);
    9e8d:	89 1d 51 54 01 00    	mov    %ebx,0x15451(%rip)        # 1f2e4 <data+0x4>
    if (ticks > 160)  ++data.l3.state;
    9e93:	7f 5b                	jg     9ef0 <level3+0xd0>
    switch (data.l3.state) {
    9e95:	83 f8 01             	cmp    $0x1,%eax
    9e98:	0f 84 a2 00 00 00    	je     9f40 <level3+0x120>
    9e9e:	83 f8 02             	cmp    $0x2,%eax
    9ea1:	74 7d                	je     9f20 <level3+0x100>
    9ea3:	85 c0                	test   %eax,%eax
    9ea5:	74 59                	je     9f00 <level3+0xe0>
      bonus[0] += 20;
    9ea7:	48 8b 05 b2 6f 01 00 	mov    0x16fb2(%rip),%rax        # 20e60 <bonus>
      ++level;
    9eae:	83 05 47 54 01 00 01 	addl   $0x1,0x15447(%rip)        # 1f2fc <level>
    9eb5:	8b 15 2d 54 01 00    	mov    0x1542d(%rip),%edx        # 1f2e8 <data+0x8>
      bonus[0] += 20;
    9ebb:	83 00 14             	addl   $0x14,(%rax)
      break;
    9ebe:	eb 89                	jmp    9e49 <level3+0x29>
    place_meteor ();
    9ec0:	e8 9b 18 00 00       	callq  b760 <place_meteor>
    data.l3.state = 0;
    9ec5:	c7 05 11 54 01 00 00 	movl   $0x0,0x15411(%rip)        # 1f2e0 <data>
    9ecc:	00 00 00 
    9ecf:	e9 5f ff ff ff       	jmpq   9e33 <level3+0x13>
    9ed4:	0f 1f 40 00          	nopl   0x0(%rax)
  if (data.l3.gap == data.l3.pos)  place_meteor ();
    9ed8:	e8 83 18 00 00       	callq  b760 <place_meteor>
    9edd:	8b 05 01 54 01 00    	mov    0x15401(%rip),%eax        # 1f2e4 <data+0x4>
    9ee3:	e9 72 ff ff ff       	jmpq   9e5a <level3+0x3a>
    9ee8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    9eef:	00 
    if (ticks > 160)  ++data.l3.state;
    9ef0:	83 c0 01             	add    $0x1,%eax
    9ef3:	89 05 e7 53 01 00    	mov    %eax,0x153e7(%rip)        # 1f2e0 <data>
    9ef9:	eb 9a                	jmp    9e95 <level3+0x75>
    9efb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      data.l3.pos = uniform_rnd (5)+1;
    9f00:	bf 05 00 00 00       	mov    $0x5,%edi
    9f05:	e8 f6 55 00 00       	callq  f500 <uniform_rnd>
    9f0a:	8b 1d d4 53 01 00    	mov    0x153d4(%rip),%ebx        # 1f2e4 <data+0x4>
    9f10:	8d 50 01             	lea    0x1(%rax),%edx
    9f13:	89 15 cf 53 01 00    	mov    %edx,0x153cf(%rip)        # 1f2e8 <data+0x8>
      break;
    9f19:	e9 2b ff ff ff       	jmpq   9e49 <level3+0x29>
    9f1e:	66 90                	xchg   %ax,%ax
      data.l3.pos = data.l3.gap - uniform_rnd (2) - 1;
    9f20:	bf 02 00 00 00       	mov    $0x2,%edi
    9f25:	e8 d6 55 00 00       	callq  f500 <uniform_rnd>
    9f2a:	29 c3                	sub    %eax,%ebx
    9f2c:	8d 53 ff             	lea    -0x1(%rbx),%edx
    9f2f:	8b 1d af 53 01 00    	mov    0x153af(%rip),%ebx        # 1f2e4 <data+0x4>
    9f35:	89 15 ad 53 01 00    	mov    %edx,0x153ad(%rip)        # 1f2e8 <data+0x8>
      break;
    9f3b:	e9 09 ff ff ff       	jmpq   9e49 <level3+0x29>
      data.l3.pos = data.l3.gap - uniform_rnd (7) - 1;
    9f40:	bf 07 00 00 00       	mov    $0x7,%edi
    9f45:	eb de                	jmp    9f25 <level3+0x105>
    9f47:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    9f4e:	00 00 

0000000000009f50 <level4>:
{
    9f50:	f3 0f 1e fa          	endbr64 
    9f54:	48 83 ec 08          	sub    $0x8,%rsp
  if (is_edge) {
    9f58:	8b 05 a6 53 01 00    	mov    0x153a6(%rip),%eax        # 1f304 <is_edge>
    9f5e:	85 c0                	test   %eax,%eax
    9f60:	75 1e                	jne    9f80 <level4+0x30>
    9f62:	8b 05 7c 53 01 00    	mov    0x1537c(%rip),%eax        # 1f2e4 <data+0x4>
  --data.l4.gap;
    9f68:	83 e8 01             	sub    $0x1,%eax
    9f6b:	89 05 73 53 01 00    	mov    %eax,0x15373(%rip)        # 1f2e4 <data+0x4>
  if (data.l4.gap <= 0) {
    9f71:	85 c0                	test   %eax,%eax
    9f73:	7e 51                	jle    9fc6 <level4+0x76>
}
    9f75:	48 83 c4 08          	add    $0x8,%rsp
    9f79:	c3                   	retq   
    9f7a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    data.l4.gap = data.l4.next_gap;
    9f80:	8b 05 62 53 01 00    	mov    0x15362(%rip),%eax        # 1f2e8 <data+0x8>
    if (data.l4.state == 0 && ticks < 700) {
    9f86:	8b 15 54 53 01 00    	mov    0x15354(%rip),%edx        # 1f2e0 <data>
    data.l4.gap = data.l4.next_gap;
    9f8c:	89 05 52 53 01 00    	mov    %eax,0x15352(%rip)        # 1f2e4 <data+0x4>
    if (data.l4.state == 0 && ticks < 700) {
    9f92:	85 d2                	test   %edx,%edx
    9f94:	75 0e                	jne    9fa4 <level4+0x54>
    9f96:	8b 0d 54 53 01 00    	mov    0x15354(%rip),%ecx        # 1f2f0 <ticks>
    9f9c:	81 f9 bb 02 00 00    	cmp    $0x2bb,%ecx
    9fa2:	7e 4c                	jle    9ff0 <level4+0xa0>
      --data.l4.state;
    9fa4:	83 ea 01             	sub    $0x1,%edx
    9fa7:	89 15 33 53 01 00    	mov    %edx,0x15333(%rip)        # 1f2e0 <data>
    if (data.l4.state < -5)  ++level;
    9fad:	83 fa fb             	cmp    $0xfffffffb,%edx
    9fb0:	7d b6                	jge    9f68 <level4+0x18>
  --data.l4.gap;
    9fb2:	83 e8 01             	sub    $0x1,%eax
    if (data.l4.state < -5)  ++level;
    9fb5:	83 05 40 53 01 00 01 	addl   $0x1,0x15340(%rip)        # 1f2fc <level>
  --data.l4.gap;
    9fbc:	89 05 22 53 01 00    	mov    %eax,0x15322(%rip)        # 1f2e4 <data+0x4>
  if (data.l4.gap <= 0) {
    9fc2:	85 c0                	test   %eax,%eax
    9fc4:	7f af                	jg     9f75 <level4+0x25>
    switch (data.l4.state) {
    9fc6:	8b 05 14 53 01 00    	mov    0x15314(%rip),%eax        # 1f2e0 <data>
    9fcc:	83 c0 05             	add    $0x5,%eax
    9fcf:	83 f8 05             	cmp    $0x5,%eax
    9fd2:	0f 87 17 01 00 00    	ja     a0ef <level4+0x19f>
    9fd8:	48 8d 15 e1 f7 00 00 	lea    0xf7e1(%rip),%rdx        # 197c0 <_IO_stdin_used+0x97c0>
    9fdf:	48 63 04 82          	movslq (%rdx,%rax,4),%rax
    9fe3:	48 01 d0             	add    %rdx,%rax
    9fe6:	3e ff e0             	notrack jmpq *%rax
    9fe9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      data.l4.state = 3 + uniform_rnd (3 + 2*(ticks < 350));
    9ff0:	31 ff                	xor    %edi,%edi
    9ff2:	81 f9 5e 01 00 00    	cmp    $0x15e,%ecx
    9ff8:	40 0f 9c c7          	setl   %dil
    9ffc:	8d 7c 3f 03          	lea    0x3(%rdi,%rdi,1),%edi
    a000:	e8 fb 54 00 00       	callq  f500 <uniform_rnd>
    a005:	8d 50 03             	lea    0x3(%rax),%edx
    a008:	8b 05 d6 52 01 00    	mov    0x152d6(%rip),%eax        # 1f2e4 <data+0x4>
    a00e:	89 15 cc 52 01 00    	mov    %edx,0x152cc(%rip)        # 1f2e0 <data>
    a014:	eb 97                	jmp    9fad <level4+0x5d>
    a016:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    a01d:	00 00 00 
      hole = 3;
    a020:	c7 05 e2 52 01 00 03 	movl   $0x3,0x152e2(%rip)        # 1f30c <hole>
    a027:	00 00 00 
      data.l4.next_gap = 14;
    a02a:	c7 05 b4 52 01 00 0e 	movl   $0xe,0x152b4(%rip)        # 1f2e8 <data+0x8>
    a031:	00 00 00 
      break;
    a034:	e9 3c ff ff ff       	jmpq   9f75 <level4+0x25>
    a039:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      hole = 6;
    a040:	c7 05 c2 52 01 00 06 	movl   $0x6,0x152c2(%rip)        # 1f30c <hole>
    a047:	00 00 00 
      data.l4.next_gap = 6;
    a04a:	c7 05 94 52 01 00 06 	movl   $0x6,0x15294(%rip)        # 1f2e8 <data+0x8>
    a051:	00 00 00 
      break;
    a054:	e9 1c ff ff ff       	jmpq   9f75 <level4+0x25>
    a059:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      hole = 4;
    a060:	c7 05 a2 52 01 00 04 	movl   $0x4,0x152a2(%rip)        # 1f30c <hole>
    a067:	00 00 00 
      data.l4.next_gap = 16 + uniform_rnd (6);
    a06a:	bf 06 00 00 00       	mov    $0x6,%edi
    a06f:	e8 8c 54 00 00       	callq  f500 <uniform_rnd>
    a074:	83 c0 10             	add    $0x10,%eax
    a077:	89 05 6b 52 01 00    	mov    %eax,0x1526b(%rip)        # 1f2e8 <data+0x8>
      break;
    a07d:	e9 f3 fe ff ff       	jmpq   9f75 <level4+0x25>
    a082:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      hole = 2;
    a088:	c7 05 7a 52 01 00 02 	movl   $0x2,0x1527a(%rip)        # 1f30c <hole>
    a08f:	00 00 00 
      data.l4.next_gap = 7;
    a092:	c7 05 4c 52 01 00 07 	movl   $0x7,0x1524c(%rip)        # 1f2e8 <data+0x8>
    a099:	00 00 00 
      break;
    a09c:	e9 d4 fe ff ff       	jmpq   9f75 <level4+0x25>
    a0a1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      hole = 5;
    a0a8:	c7 05 5a 52 01 00 05 	movl   $0x5,0x1525a(%rip)        # 1f30c <hole>
    a0af:	00 00 00 
      data.l4.next_gap = 12;
    a0b2:	c7 05 2c 52 01 00 0c 	movl   $0xc,0x1522c(%rip)        # 1f2e8 <data+0x8>
    a0b9:	00 00 00 
}
    a0bc:	e9 b4 fe ff ff       	jmpq   9f75 <level4+0x25>
    a0c1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      if (uniform_rnd (2)) {
    a0c8:	bf 02 00 00 00       	mov    $0x2,%edi
    a0cd:	e8 2e 54 00 00       	callq  f500 <uniform_rnd>
    a0d2:	85 c0                	test   %eax,%eax
    a0d4:	75 4a                	jne    a120 <level4+0x1d0>
        hole = 2;
    a0d6:	c7 05 2c 52 01 00 02 	movl   $0x2,0x1522c(%rip)        # 1f30c <hole>
    a0dd:	00 00 00 
        data.l4.next_gap = 8;
    a0e0:	c7 05 fe 51 01 00 08 	movl   $0x8,0x151fe(%rip)        # 1f2e8 <data+0x8>
    a0e7:	00 00 00 
    a0ea:	e9 86 fe ff ff       	jmpq   9f75 <level4+0x25>
      hole = 2 + uniform_rnd (3);
    a0ef:	bf 03 00 00 00       	mov    $0x3,%edi
    a0f4:	e8 07 54 00 00       	callq  f500 <uniform_rnd>
      data.l4.next_gap = 14 + uniform_rnd (6) - hole;
    a0f9:	bf 06 00 00 00       	mov    $0x6,%edi
      hole = 2 + uniform_rnd (3);
    a0fe:	83 c0 02             	add    $0x2,%eax
    a101:	89 05 05 52 01 00    	mov    %eax,0x15205(%rip)        # 1f30c <hole>
      data.l4.next_gap = 14 + uniform_rnd (6) - hole;
    a107:	e8 f4 53 00 00       	callq  f500 <uniform_rnd>
    a10c:	83 c0 0e             	add    $0xe,%eax
    a10f:	2b 05 f7 51 01 00    	sub    0x151f7(%rip),%eax        # 1f30c <hole>
    a115:	89 05 cd 51 01 00    	mov    %eax,0x151cd(%rip)        # 1f2e8 <data+0x8>
      break;
    a11b:	e9 55 fe ff ff       	jmpq   9f75 <level4+0x25>
        hole = 5;
    a120:	c7 05 e2 51 01 00 05 	movl   $0x5,0x151e2(%rip)        # 1f30c <hole>
    a127:	00 00 00 
        data.l4.next_gap = 9 + uniform_rnd (10);
    a12a:	bf 0a 00 00 00       	mov    $0xa,%edi
    a12f:	e8 cc 53 00 00       	callq  f500 <uniform_rnd>
    a134:	83 c0 09             	add    $0x9,%eax
    a137:	89 05 ab 51 01 00    	mov    %eax,0x151ab(%rip)        # 1f2e8 <data+0x8>
    a13d:	e9 33 fe ff ff       	jmpq   9f75 <level4+0x25>
    a142:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    a149:	00 00 00 00 
    a14d:	0f 1f 00             	nopl   (%rax)

000000000000a150 <level5>:
{
    a150:	f3 0f 1e fa          	endbr64 
    a154:	48 83 ec 08          	sub    $0x8,%rsp
  if (uniform_rnd (ticks % 20 < 8 ? 4 : 8) == 0)  place_meteor ();
    a158:	48 63 05 91 51 01 00 	movslq 0x15191(%rip),%rax        # 1f2f0 <ticks>
    a15f:	31 ff                	xor    %edi,%edi
    a161:	48 89 c2             	mov    %rax,%rdx
    a164:	48 69 c0 67 66 66 66 	imul   $0x66666667,%rax,%rax
    a16b:	89 d1                	mov    %edx,%ecx
    a16d:	c1 f9 1f             	sar    $0x1f,%ecx
    a170:	48 c1 f8 23          	sar    $0x23,%rax
    a174:	29 c8                	sub    %ecx,%eax
    a176:	8d 04 80             	lea    (%rax,%rax,4),%eax
    a179:	c1 e0 02             	shl    $0x2,%eax
    a17c:	29 c2                	sub    %eax,%edx
    a17e:	83 fa 08             	cmp    $0x8,%edx
    a181:	40 0f 9d c7          	setge  %dil
    a185:	8d 3c bd 04 00 00 00 	lea    0x4(,%rdi,4),%edi
    a18c:	e8 6f 53 00 00       	callq  f500 <uniform_rnd>
    a191:	85 c0                	test   %eax,%eax
    a193:	74 1b                	je     a1b0 <level5+0x60>
  if (ticks >= 125)  ++level;
    a195:	83 3d 54 51 01 00 7c 	cmpl   $0x7c,0x15154(%rip)        # 1f2f0 <ticks>
    a19c:	7e 07                	jle    a1a5 <level5+0x55>
    a19e:	83 05 57 51 01 00 01 	addl   $0x1,0x15157(%rip)        # 1f2fc <level>
}
    a1a5:	48 83 c4 08          	add    $0x8,%rsp
    a1a9:	c3                   	retq   
    a1aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  if (uniform_rnd (ticks % 20 < 8 ? 4 : 8) == 0)  place_meteor ();
    a1b0:	e8 ab 15 00 00       	callq  b760 <place_meteor>
    a1b5:	eb de                	jmp    a195 <level5+0x45>
    a1b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    a1be:	00 00 

000000000000a1c0 <level_start>:
};

void
level_start (int initial)
/* Start the game anew with level INITIAL.  */
{
    a1c0:	f3 0f 1e fa          	endbr64 
  assert (initial >= 0 && initial < LEVEL_COUNT);
    a1c4:	83 ff 07             	cmp    $0x7,%edi
    a1c7:	77 21                	ja     a1ea <level_start+0x2a>
  level = initial_level = initial;
    a1c9:	89 3d 29 51 01 00    	mov    %edi,0x15129(%rip)        # 1f2f8 <initial_level>
    a1cf:	89 3d 27 51 01 00    	mov    %edi,0x15127(%rip)        # 1f2fc <level>
  last_level = -1;
    a1d5:	c7 05 15 51 01 00 ff 	movl   $0xffffffff,0x15115(%rip)        # 1f2f4 <last_level>
    a1dc:	ff ff ff 
  ticks = 0;
    a1df:	c7 05 07 51 01 00 00 	movl   $0x0,0x15107(%rip)        # 1f2f0 <ticks>
    a1e6:	00 00 00 
    a1e9:	c3                   	retq   
{
    a1ea:	50                   	push   %rax
  assert (initial >= 0 && initial < LEVEL_COUNT);
    a1eb:	48 8d 0d 7e f6 00 00 	lea    0xf67e(%rip),%rcx        # 19870 <__PRETTY_FUNCTION__.4560>
    a1f2:	ba 99 01 00 00       	mov    $0x199,%edx
    a1f7:	48 8d 35 7e f6 00 00 	lea    0xf67e(%rip),%rsi        # 1987c <__PRETTY_FUNCTION__.4560+0xc>
    a1fe:	48 8d 3d bb f6 00 00 	lea    0xf6bb(%rip),%rdi        # 198c0 <__PRETTY_FUNCTION__.4560+0x50>
    a205:	e8 d6 d6 ff ff       	callq  78e0 <__assert_fail@plt>
    a20a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000a210 <level_tick>:
level_tick (double t)
/* Advance the current level's state by one.
 * The function must be called every time the ground moved.  It fills
 * in the new values of `ground2[0]' and `bonus[0]'.  The parameter T
 * must be the current game time.  */
{
    a210:	f3 0f 1e fa          	endbr64 
    a214:	53                   	push   %rbx
    a215:	66 0f 28 c8          	movapd %xmm0,%xmm1
    a219:	48 83 ec 10          	sub    $0x10,%rsp
  int  ground;

  bonus[0] = 0;
    a21d:	48 8b 05 3c 6c 01 00 	mov    0x16c3c(%rip),%rax        # 20e60 <bonus>
  if (level != last_level) {
    a224:	8b 0d ca 50 01 00    	mov    0x150ca(%rip),%ecx        # 1f2f4 <last_level>
  bonus[0] = 0;
    a22a:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
  if (level != last_level) {
    a230:	8b 05 c6 50 01 00    	mov    0x150c6(%rip),%eax        # 1f2fc <level>
    a236:	39 c8                	cmp    %ecx,%eax
    a238:	0f 84 c4 00 00 00    	je     a302 <level_tick+0xf2>
    double  msg_t;
    level = level % LEVEL_COUNT;
    a23e:	99                   	cltd   
    hole = 0;
    if (levels[level].init_fn)  levels[level].init_fn ();
    a23f:	48 8d 1d fa 45 01 00 	lea    0x145fa(%rip),%rbx        # 1e840 <levels>
    hole = 0;
    a246:	c7 05 bc 50 01 00 00 	movl   $0x0,0x150bc(%rip)        # 1f30c <hole>
    a24d:	00 00 00 
    level = level % LEVEL_COUNT;
    a250:	c1 ea 1d             	shr    $0x1d,%edx
    a253:	01 d0                	add    %edx,%eax
    a255:	83 e0 07             	and    $0x7,%eax
    a258:	29 d0                	sub    %edx,%eax
    if (levels[level].init_fn)  levels[level].init_fn ();
    a25a:	48 63 d0             	movslq %eax,%rdx
    level = level % LEVEL_COUNT;
    a25d:	89 05 99 50 01 00    	mov    %eax,0x15099(%rip)        # 1f2fc <level>
    if (levels[level].init_fn)  levels[level].init_fn ();
    a263:	48 8d 14 52          	lea    (%rdx,%rdx,2),%rdx
    a267:	48 8b 14 d3          	mov    (%rbx,%rdx,8),%rdx
    a26b:	48 85 d2             	test   %rdx,%rdx
    a26e:	74 1a                	je     a28a <level_tick+0x7a>
    a270:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
    a276:	ff d2                	callq  *%rdx
    a278:	8b 0d 76 50 01 00    	mov    0x15076(%rip),%ecx        # 1f2f4 <last_level>
    a27e:	8b 05 78 50 01 00    	mov    0x15078(%rip),%eax        # 1f2fc <level>
    a284:	f2 0f 10 4c 24 08    	movsd  0x8(%rsp),%xmm1
    if (last_level >= 0) {
      ticks = -PAUSE;
      msg_t = t + TICK(car_x + PAUSE/5);
    } else {
      msg_t = t;
    a28a:	66 0f 28 c1          	movapd %xmm1,%xmm0
    if (last_level >= 0) {
    a28e:	85 c9                	test   %ecx,%ecx
    a290:	78 27                	js     a2b9 <level_tick+0xa9>
      msg_t = t + TICK(car_x + PAUSE/5);
    a292:	8b 3d d0 6b 01 00    	mov    0x16bd0(%rip),%edi        # 20e68 <car_x>
    a298:	66 0f ef c0          	pxor   %xmm0,%xmm0
      ticks = -PAUSE;
    a29c:	c7 05 4a 50 01 00 d8 	movl   $0xffffffd8,0x1504a(%rip)        # 1f2f0 <ticks>
    a2a3:	ff ff ff 
      msg_t = t + TICK(car_x + PAUSE/5);
    a2a6:	8d 57 08             	lea    0x8(%rdi),%edx
    a2a9:	f2 0f 2a c2          	cvtsi2sd %edx,%xmm0
    a2ad:	f2 0f 59 05 e3 f6 00 	mulsd  0xf6e3(%rip),%xmm0        # 19998 <__PRETTY_FUNCTION__.4560+0x128>
    a2b4:	00 
    a2b5:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
    }
    if (levels[level].msg) {
    a2b9:	48 63 d0             	movslq %eax,%rdx
    a2bc:	48 8d 14 52          	lea    (%rdx,%rdx,2),%rdx
    a2c0:	48 8b 74 d3 10       	mov    0x10(%rbx,%rdx,8),%rsi
    a2c5:	48 85 f6             	test   %rsi,%rsi
    a2c8:	74 1e                	je     a2e8 <level_tick+0xd8>
      add_event (msg_t, print_hint_h, (void *)levels[level].msg);
    a2ca:	48 8d 3d 9f 38 00 00 	lea    0x389f(%rip),%rdi        # db70 <print_hint_h>
    a2d1:	f2 0f 11 4c 24 08    	movsd  %xmm1,0x8(%rsp)
    a2d7:	e8 c4 34 00 00       	callq  d7a0 <add_event>
    a2dc:	8b 05 1a 50 01 00    	mov    0x1501a(%rip),%eax        # 1f2fc <level>
    a2e2:	f2 0f 10 4c 24 08    	movsd  0x8(%rsp),%xmm1
    }
    last_level = level;
    a2e8:	89 05 06 50 01 00    	mov    %eax,0x15006(%rip)        # 1f2f4 <last_level>
    is_edge = 1;
    a2ee:	c7 05 0c 50 01 00 01 	movl   $0x1,0x1500c(%rip)        # 1f304 <is_edge>
    a2f5:	00 00 00 
    crater_seen = 0;
    a2f8:	c7 05 fe 4f 01 00 00 	movl   $0x0,0x14ffe(%rip)        # 1f300 <crater_seen>
    a2ff:	00 00 00 
  }
  if (ticks < 0) {
    a302:	8b 35 e8 4f 01 00    	mov    0x14fe8(%rip),%esi        # 1f2f0 <ticks>
    a308:	85 f6                	test   %esi,%esi
    a30a:	0f 88 98 00 00 00    	js     a3a8 <level_tick+0x198>
    ground = '#';
  } else if (hole > 0) {
    a310:	8b 05 f6 4f 01 00    	mov    0x14ff6(%rip),%eax        # 1f30c <hole>
    a316:	85 c0                	test   %eax,%eax
    a318:	7e 26                	jle    a340 <level_tick+0x130>
    if (! crater_seen) {
    a31a:	8b 0d e0 4f 01 00    	mov    0x14fe0(%rip),%ecx        # 1f300 <crater_seen>
    a320:	85 c9                	test   %ecx,%ecx
    a322:	0f 84 a8 00 00 00    	je     a3d0 <level_tick+0x1c0>
      crater_seen = 1;
      plateau = 0;
    }

    ground = ' ';
    --hole;
    a328:	83 e8 01             	sub    $0x1,%eax
    a32b:	ba 20 00 00 00       	mov    $0x20,%edx
    a330:	89 05 d6 4f 01 00    	mov    %eax,0x14fd6(%rip)        # 1f30c <hole>
    a336:	eb 75                	jmp    a3ad <level_tick+0x19d>
    a338:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    a33f:	00 
  } else {
    levels[level].fn (t);
    a340:	48 63 05 b5 4f 01 00 	movslq 0x14fb5(%rip),%rax        # 1f2fc <level>
    a347:	66 0f 28 c1          	movapd %xmm1,%xmm0
    a34b:	48 8d 14 40          	lea    (%rax,%rax,2),%rdx
    a34f:	48 8d 05 ea 44 01 00 	lea    0x144ea(%rip),%rax        # 1e840 <levels>
    a356:	ff 54 d0 08          	callq  *0x8(%rax,%rdx,8)
    is_edge = 0;
    crater_seen = 0;

    ground = '#';
    ++plateau;
    a35a:	8b 05 a8 4f 01 00    	mov    0x14fa8(%rip),%eax        # 1f308 <plateau>
  if (width > 8)  return;
    a360:	8b 15 a6 4f 01 00    	mov    0x14fa6(%rip),%edx        # 1f30c <hole>
    is_edge = 0;
    a366:	c7 05 94 4f 01 00 00 	movl   $0x0,0x14f94(%rip)        # 1f304 <is_edge>
    a36d:	00 00 00 
    crater_seen = 0;
    a370:	c7 05 86 4f 01 00 00 	movl   $0x0,0x14f86(%rip)        # 1f300 <crater_seen>
    a377:	00 00 00 
    ++plateau;
    a37a:	83 c0 01             	add    $0x1,%eax
    a37d:	89 05 85 4f 01 00    	mov    %eax,0x14f85(%rip)        # 1f308 <plateau>
  if (width > 8)  return;
    a383:	85 d2                	test   %edx,%edx
    a385:	7e 21                	jle    a3a8 <level_tick+0x198>
    a387:	83 f8 08             	cmp    $0x8,%eax
    a38a:	7f 1c                	jg     a3a8 <level_tick+0x198>
  bonus[0] += score_table [width];
    a38c:	48 8b 15 cd 6a 01 00 	mov    0x16acd(%rip),%rdx        # 20e60 <bonus>
    a393:	48 98                	cltq   
    a395:	48 8d 0d 44 f4 00 00 	lea    0xf444(%rip),%rcx        # 197e0 <score_table.4569>
    a39c:	8b 04 81             	mov    (%rcx,%rax,4),%eax
    a39f:	01 02                	add    %eax,(%rdx)
    a3a1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    a3a8:	ba 23 00 00 00       	mov    $0x23,%edx
    if (hole > 0)  score_plateau (plateau);
  }

  ground2[0] = ground;
    a3ad:	48 8b 05 a4 6a 01 00 	mov    0x16aa4(%rip),%rax        # 20e58 <ground2>
    a3b4:	88 10                	mov    %dl,(%rax)
  print_buggy(); /* ++pg now the refresh of the car is needed here. */
    a3b6:	e8 05 06 00 00       	callq  a9c0 <print_buggy>

  ++ticks;
    a3bb:	83 05 2e 4f 01 00 01 	addl   $0x1,0x14f2e(%rip)        # 1f2f0 <ticks>
}
    a3c2:	48 83 c4 10          	add    $0x10,%rsp
    a3c6:	5b                   	pop    %rbx
    a3c7:	c3                   	retq   
    a3c8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    a3cf:	00 
  assert (width < 7);
    a3d0:	83 f8 06             	cmp    $0x6,%eax
    a3d3:	7f 39                	jg     a40e <level_tick+0x1fe>
  bonus[0] += score_table [width];
    a3d5:	48 8b 0d 84 6a 01 00 	mov    0x16a84(%rip),%rcx        # 20e60 <bonus>
    a3dc:	48 63 d0             	movslq %eax,%rdx
    a3df:	48 8d 35 2a f4 00 00 	lea    0xf42a(%rip),%rsi        # 19810 <score_table.4564>
      is_edge = 1;
    a3e6:	c7 05 14 4f 01 00 01 	movl   $0x1,0x14f14(%rip)        # 1f304 <is_edge>
    a3ed:	00 00 00 
      crater_seen = 1;
    a3f0:	c7 05 06 4f 01 00 01 	movl   $0x1,0x14f06(%rip)        # 1f300 <crater_seen>
    a3f7:	00 00 00 
  bonus[0] += score_table [width];
    a3fa:	8b 14 96             	mov    (%rsi,%rdx,4),%edx
      plateau = 0;
    a3fd:	c7 05 01 4f 01 00 00 	movl   $0x0,0x14f01(%rip)        # 1f308 <plateau>
    a404:	00 00 00 
  bonus[0] += score_table [width];
    a407:	01 11                	add    %edx,(%rcx)
      plateau = 0;
    a409:	e9 1a ff ff ff       	jmpq   a328 <level_tick+0x118>
  assert (width < 7);
    a40e:	48 8d 0d 1b f4 00 00 	lea    0xf41b(%rip),%rcx        # 19830 <__PRETTY_FUNCTION__.4565>
    a415:	ba a3 01 00 00       	mov    $0x1a3,%edx
    a41a:	48 8d 35 5b f4 00 00 	lea    0xf45b(%rip),%rsi        # 1987c <__PRETTY_FUNCTION__.4560+0xc>
    a421:	48 8d 3d 5c f4 00 00 	lea    0xf45c(%rip),%rdi        # 19884 <__PRETTY_FUNCTION__.4560+0x14>
    a428:	e8 b3 d4 ff ff       	callq  78e0 <__assert_fail@plt>
    a42d:	0f 1f 00             	nopl   (%rax)

000000000000a430 <current_level>:

int
current_level (void)
/* Return the current level's number as the car sees it.  */
{
    a430:	f3 0f 1e fa          	endbr64 
  int  res = (ticks+PAUSE/2 >= car_x) ? level : level - 1;
    a434:	8b 0d b6 4e 01 00    	mov    0x14eb6(%rip),%ecx        # 1f2f0 <ticks>
    a43a:	8b 05 bc 4e 01 00    	mov    0x14ebc(%rip),%eax        # 1f2fc <level>
    a440:	8d 51 14             	lea    0x14(%rcx),%edx
    a443:	3b 15 1f 6a 01 00    	cmp    0x16a1f(%rip),%edx        # 20e68 <car_x>
    a449:	0f 9c c2             	setl   %dl
    a44c:	0f b6 d2             	movzbl %dl,%edx
    a44f:	29 d0                	sub    %edx,%eax
  if (res < initial_level)  res = initial_level;
  return  res;
    a451:	39 05 a1 4e 01 00    	cmp    %eax,0x14ea1(%rip)        # 1f2f8 <initial_level>
    a457:	0f 4d 05 9a 4e 01 00 	cmovge 0x14e9a(%rip),%eax        # 1f2f8 <initial_level>
}
    a45e:	c3                   	retq   
    a45f:	90                   	nop

000000000000a460 <resize_ground>:
static int  ground_width;


void
resize_ground (int clear_it)
{
    a460:	f3 0f 1e fa          	endbr64 
    a464:	41 54                	push   %r12
    a466:	55                   	push   %rbp
    a467:	89 fd                	mov    %edi,%ebp
    a469:	53                   	push   %rbx
  int  cols, i, old;

  cols = COLS;
    a46a:	8b 1d 10 4e 01 00    	mov    0x14e10(%rip),%ebx        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
  if (ground_width != cols) {
    a470:	39 1d 9a 4e 01 00    	cmp    %ebx,0x14e9a(%rip)        # 1f310 <ground_width>
    a476:	74 4a                	je     a4c2 <resize_ground+0x62>
    bonus = xrealloc (bonus, cols*sizeof(int));
    a478:	4c 63 e3             	movslq %ebx,%r12
    a47b:	48 8b 3d de 69 01 00 	mov    0x169de(%rip),%rdi        # 20e60 <bonus>
    a482:	4a 8d 34 a5 00 00 00 	lea    0x0(,%r12,4),%rsi
    a489:	00 
    a48a:	e8 01 52 00 00       	callq  f690 <xrealloc>
    ground1 = xrealloc (ground1, cols);
    a48f:	48 8b 3d ba 69 01 00 	mov    0x169ba(%rip),%rdi        # 20e50 <ground1>
    a496:	4c 89 e6             	mov    %r12,%rsi
    bonus = xrealloc (bonus, cols*sizeof(int));
    a499:	48 89 05 c0 69 01 00 	mov    %rax,0x169c0(%rip)        # 20e60 <bonus>
    ground1 = xrealloc (ground1, cols);
    a4a0:	e8 eb 51 00 00       	callq  f690 <xrealloc>
    ground2 = xrealloc (ground2, cols);
    a4a5:	48 8b 3d ac 69 01 00 	mov    0x169ac(%rip),%rdi        # 20e58 <ground2>
    a4ac:	4c 89 e6             	mov    %r12,%rsi
    ground1 = xrealloc (ground1, cols);
    a4af:	48 89 05 9a 69 01 00 	mov    %rax,0x1699a(%rip)        # 20e50 <ground1>
    ground2 = xrealloc (ground2, cols);
    a4b6:	e8 d5 51 00 00       	callq  f690 <xrealloc>
    a4bb:	48 89 05 96 69 01 00 	mov    %rax,0x16996(%rip)        # 20e58 <ground2>
  }
  for (i=(clear_it ? 0 : ground_width); i<cols; ++i) {
    a4c2:	85 ed                	test   %ebp,%ebp
    a4c4:	ba 00 00 00 00       	mov    $0x0,%edx
    a4c9:	0f 44 15 40 4e 01 00 	cmove  0x14e40(%rip),%edx        # 1f310 <ground_width>
    a4d0:	39 da                	cmp    %ebx,%edx
    a4d2:	7d 44                	jge    a518 <resize_ground+0xb8>
    a4d4:	48 63 c2             	movslq %edx,%rax
    a4d7:	8d 73 ff             	lea    -0x1(%rbx),%esi
    a4da:	29 d6                	sub    %edx,%esi
    a4dc:	48 8d 50 01          	lea    0x1(%rax),%rdx
    a4e0:	48 01 d6             	add    %rdx,%rsi
    a4e3:	eb 07                	jmp    a4ec <resize_ground+0x8c>
    a4e5:	0f 1f 00             	nopl   (%rax)
    a4e8:	48 83 c2 01          	add    $0x1,%rdx
    bonus[i] = 0;
    a4ec:	48 8b 0d 6d 69 01 00 	mov    0x1696d(%rip),%rcx        # 20e60 <bonus>
    a4f3:	c7 04 81 00 00 00 00 	movl   $0x0,(%rcx,%rax,4)
    ground1[i] = '#';
    a4fa:	48 8b 0d 4f 69 01 00 	mov    0x1694f(%rip),%rcx        # 20e50 <ground1>
    a501:	c6 04 01 23          	movb   $0x23,(%rcx,%rax,1)
    ground2[i] = '#';
    a505:	48 8b 0d 4c 69 01 00 	mov    0x1694c(%rip),%rcx        # 20e58 <ground2>
    a50c:	c6 04 01 23          	movb   $0x23,(%rcx,%rax,1)
  for (i=(clear_it ? 0 : ground_width); i<cols; ++i) {
    a510:	48 89 d0             	mov    %rdx,%rax
    a513:	48 39 d6             	cmp    %rdx,%rsi
    a516:	75 d0                	jne    a4e8 <resize_ground+0x88>
  }
  ground_width = cols;
  old = car_base;
  car_base = (cols > 80 ? 80 : cols) - 12;
    a518:	83 fb 50             	cmp    $0x50,%ebx
    a51b:	ba 50 00 00 00       	mov    $0x50,%edx
  ground_width = cols;
    a520:	89 1d ea 4d 01 00    	mov    %ebx,0x14dea(%rip)        # 1f310 <ground_width>
  old = car_base;
    a526:	8b 05 cc 68 01 00    	mov    0x168cc(%rip),%eax        # 20df8 <car_base>
  car_base = (cols > 80 ? 80 : cols) - 12;
    a52c:	0f 4f da             	cmovg  %edx,%ebx
    a52f:	83 eb 0c             	sub    $0xc,%ebx
    a532:	89 1d c0 68 01 00    	mov    %ebx,0x168c0(%rip)        # 20df8 <car_base>
  car_x += (car_base-old);
    a538:	29 c3                	sub    %eax,%ebx
    a53a:	01 1d 28 69 01 00    	add    %ebx,0x16928(%rip)        # 20e68 <car_x>
}
    a540:	5b                   	pop    %rbx
    a541:	5d                   	pop    %rbp
    a542:	41 5c                	pop    %r12
    a544:	c3                   	retq   
    a545:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    a54c:	00 00 00 00 

000000000000a550 <print_ground>:

void
print_ground (void)
{
    a550:	f3 0f 1e fa          	endbr64 
    a554:	48 83 ec 08          	sub    $0x8,%rsp
  mvwaddnstr (moon, LINES-4, 0, ground2, ground_width);
    a558:	8b 05 26 4d 01 00    	mov    0x14d26(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    a55e:	48 8b 3d b3 68 01 00 	mov    0x168b3(%rip),%rdi        # 20e18 <moon>
    a565:	31 d2                	xor    %edx,%edx
    a567:	8d 70 fc             	lea    -0x4(%rax),%esi
    a56a:	e8 61 d6 ff ff       	callq  7bd0 <wmove@plt>
    a56f:	83 f8 ff             	cmp    $0xffffffff,%eax
    a572:	74 19                	je     a58d <print_ground+0x3d>
    a574:	8b 15 96 4d 01 00    	mov    0x14d96(%rip),%edx        # 1f310 <ground_width>
    a57a:	48 8b 35 d7 68 01 00 	mov    0x168d7(%rip),%rsi        # 20e58 <ground2>
    a581:	48 8b 3d 90 68 01 00 	mov    0x16890(%rip),%rdi        # 20e18 <moon>
    a588:	e8 13 d7 ff ff       	callq  7ca0 <waddnstr@plt>
  mvwaddnstr (moon, LINES-3, 0, ground1, ground_width);
    a58d:	8b 05 f1 4c 01 00    	mov    0x14cf1(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    a593:	48 8b 3d 7e 68 01 00 	mov    0x1687e(%rip),%rdi        # 20e18 <moon>
    a59a:	31 d2                	xor    %edx,%edx
    a59c:	8d 70 fd             	lea    -0x3(%rax),%esi
    a59f:	e8 2c d6 ff ff       	callq  7bd0 <wmove@plt>
    a5a4:	83 f8 ff             	cmp    $0xffffffff,%eax
    a5a7:	74 19                	je     a5c2 <print_ground+0x72>
    a5a9:	8b 15 61 4d 01 00    	mov    0x14d61(%rip),%edx        # 1f310 <ground_width>
    a5af:	48 8b 35 9a 68 01 00 	mov    0x1689a(%rip),%rsi        # 20e50 <ground1>
    a5b6:	48 8b 3d 5b 68 01 00 	mov    0x1685b(%rip),%rdi        # 20e18 <moon>
    a5bd:	e8 de d6 ff ff       	callq  7ca0 <waddnstr@plt>
  wnoutrefresh (moon);
    a5c2:	48 8b 3d 4f 68 01 00 	mov    0x1684f(%rip),%rdi        # 20e18 <moon>
}
    a5c9:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (moon);
    a5cd:	e9 ee d4 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    a5d2:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    a5d9:	00 00 00 00 
    a5dd:	0f 1f 00             	nopl   (%rax)

000000000000a5e0 <scroll_handler>:
  wnoutrefresh (status);
}

static void
scroll_handler (game_time t, void *client_data)
{
    a5e0:	f3 0f 1e fa          	endbr64 
    a5e4:	41 54                	push   %r12
    a5e6:	48 83 ec 10          	sub    $0x10,%rsp
  if (crash_detected <= 2) {
    a5ea:	8b 05 40 68 01 00    	mov    0x16840(%rip),%eax        # 20e30 <crash_detected>
{
    a5f0:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
  if (crash_detected <= 2) {
    a5f6:	83 f8 02             	cmp    $0x2,%eax
    a5f9:	7e 55                	jle    a650 <scroll_handler+0x70>

    if (crash_detected)  shift_buggy (1);
  }

  if (crash_detected || crash_check ()) {
    ++crash_detected;
    a5fb:	83 c0 01             	add    $0x1,%eax
    a5fe:	89 05 2c 68 01 00    	mov    %eax,0x1682c(%rip)        # 20e30 <crash_detected>
    if (crash_detected > 35)  mode_change (crash_mode, 1);
    a604:	83 f8 23             	cmp    $0x23,%eax
    a607:	0f 8f 13 01 00 00    	jg     a720 <scroll_handler+0x140>
  }

  if (can_jump () && stakes) {
    a60d:	e8 1e 08 00 00       	callq  ae30 <can_jump>
    a612:	85 c0                	test   %eax,%eax
    a614:	74 0e                	je     a624 <scroll_handler+0x44>
    a616:	8b 3d 2c 68 01 00    	mov    0x1682c(%rip),%edi        # 20e48 <stakes>
    a61c:	85 ff                	test   %edi,%edi
    a61e:	0f 85 1c 01 00 00    	jne    a740 <scroll_handler+0x160>
    adjust_score (stakes);
    stakes = 0;
  }

  add_event (t+TICK(1), scroll_handler, NULL);
    a624:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    a62a:	f2 0f 58 05 66 f3 00 	addsd  0xf366(%rip),%xmm0        # 19998 <__PRETTY_FUNCTION__.4560+0x128>
    a631:	00 
    a632:	31 f6                	xor    %esi,%esi
}
    a634:	48 83 c4 10          	add    $0x10,%rsp
  add_event (t+TICK(1), scroll_handler, NULL);
    a638:	48 8d 3d a1 ff ff ff 	lea    -0x5f(%rip),%rdi        # a5e0 <scroll_handler>
}
    a63f:	41 5c                	pop    %r12
  add_event (t+TICK(1), scroll_handler, NULL);
    a641:	e9 5a 31 00 00       	jmpq   d7a0 <add_event>
    a646:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    a64d:	00 00 00 
    scroll_meteors ();
    a650:	e8 6b 0f 00 00       	callq  b5c0 <scroll_meteors>
    memmove (bonus+1, bonus, (ground_width-1)*sizeof(int));
    a655:	8b 05 b5 4c 01 00    	mov    0x14cb5(%rip),%eax        # 1f310 <ground_width>
    a65b:	48 8b 35 fe 67 01 00 	mov    0x167fe(%rip),%rsi        # 20e60 <bonus>
    a662:	44 8d 60 ff          	lea    -0x1(%rax),%r12d
    a666:	48 8d 7e 04          	lea    0x4(%rsi),%rdi
    a66a:	4d 63 e4             	movslq %r12d,%r12
    a66d:	4a 8d 14 a5 00 00 00 	lea    0x0(,%r12,4),%rdx
    a674:	00 
}

__fortify_function void *
__NTH (memmove (void *__dest, const void *__src, size_t __len))
{
  return __builtin___memmove_chk (__dest, __src, __len, __bos0 (__dest));
    a675:	e8 f6 d4 ff ff       	callq  7b70 <memmove@plt>
    memmove (ground2+1, ground2, ground_width-1);
    a67a:	48 8b 35 d7 67 01 00 	mov    0x167d7(%rip),%rsi        # 20e58 <ground2>
    a681:	4c 89 e2             	mov    %r12,%rdx
    a684:	48 8d 7e 01          	lea    0x1(%rsi),%rdi
    a688:	e8 e3 d4 ff ff       	callq  7b70 <memmove@plt>
    level_tick (t);
    a68d:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    a693:	e8 78 fb ff ff       	callq  a210 <level_tick>
    print_ground ();
    a698:	e8 b3 fe ff ff       	callq  a550 <print_ground>
  mvwprintw (status, 0, car_base-32, "level: %d", current_level () + 1);
    a69d:	e8 8e fd ff ff       	callq  a430 <current_level>
    a6a2:	8b 0d 50 67 01 00    	mov    0x16750(%rip),%ecx        # 20df8 <car_base>
    a6a8:	48 8b 3d 61 67 01 00 	mov    0x16761(%rip),%rdi        # 20e10 <status>
    a6af:	31 f6                	xor    %esi,%esi
    a6b1:	44 8d 40 01          	lea    0x1(%rax),%r8d
    a6b5:	31 c0                	xor    %eax,%eax
    a6b7:	8d 51 e0             	lea    -0x20(%rcx),%edx
    a6ba:	48 8d 0d df f2 00 00 	lea    0xf2df(%rip),%rcx        # 199a0 <__PRETTY_FUNCTION__.4560+0x130>
    a6c1:	e8 4a d2 ff ff       	callq  7910 <mvwprintw@plt>
  wnoutrefresh (status);
    a6c6:	48 8b 3d 43 67 01 00 	mov    0x16743(%rip),%rdi        # 20e10 <status>
    a6cd:	e8 ee d3 ff ff       	callq  7ac0 <wnoutrefresh@plt>
    stakes += bonus[car_x + 7];
    a6d2:	48 63 15 8f 67 01 00 	movslq 0x1678f(%rip),%rdx        # 20e68 <car_x>
    a6d9:	48 8b 05 80 67 01 00 	mov    0x16780(%rip),%rax        # 20e60 <bonus>
    a6e0:	8b 44 90 1c          	mov    0x1c(%rax,%rdx,4),%eax
    a6e4:	01 05 5e 67 01 00    	add    %eax,0x1675e(%rip)        # 20e48 <stakes>
    if (crash_detected)  shift_buggy (1);
    a6ea:	8b 05 40 67 01 00    	mov    0x16740(%rip),%eax        # 20e30 <crash_detected>
    a6f0:	85 c0                	test   %eax,%eax
    a6f2:	75 64                	jne    a758 <scroll_handler+0x178>
  if (crash_detected || crash_check ()) {
    a6f4:	e8 47 07 00 00       	callq  ae40 <crash_check>
    a6f9:	85 c0                	test   %eax,%eax
    a6fb:	0f 84 0c ff ff ff    	je     a60d <scroll_handler+0x2d>
    a701:	8b 05 29 67 01 00    	mov    0x16729(%rip),%eax        # 20e30 <crash_detected>
    ++crash_detected;
    a707:	83 c0 01             	add    $0x1,%eax
    a70a:	89 05 20 67 01 00    	mov    %eax,0x16720(%rip)        # 20e30 <crash_detected>
    if (crash_detected > 35)  mode_change (crash_mode, 1);
    a710:	83 f8 23             	cmp    $0x23,%eax
    a713:	0f 8e f4 fe ff ff    	jle    a60d <scroll_handler+0x2d>
    a719:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    a720:	48 8b 3d 11 67 01 00 	mov    0x16711(%rip),%rdi        # 20e38 <crash_mode>
    a727:	be 01 00 00 00       	mov    $0x1,%esi
    a72c:	e8 2f e0 ff ff       	callq  8760 <mode_change>
    a731:	e9 d7 fe ff ff       	jmpq   a60d <scroll_handler+0x2d>
    a736:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    a73d:	00 00 00 
    adjust_score (stakes);
    a740:	e8 1b eb ff ff       	callq  9260 <adjust_score>
    stakes = 0;
    a745:	c7 05 f9 66 01 00 00 	movl   $0x0,0x166f9(%rip)        # 20e48 <stakes>
    a74c:	00 00 00 
    a74f:	e9 d0 fe ff ff       	jmpq   a624 <scroll_handler+0x44>
    a754:	0f 1f 40 00          	nopl   0x0(%rax)
    if (crash_detected)  shift_buggy (1);
    a758:	bf 01 00 00 00       	mov    $0x1,%edi
    a75d:	e8 ce 05 00 00       	callq  ad30 <shift_buggy>
    a762:	8b 05 c8 66 01 00    	mov    0x166c8(%rip),%eax        # 20e30 <crash_detected>
  if (crash_detected || crash_check ()) {
    a768:	85 c0                	test   %eax,%eax
    a76a:	74 88                	je     a6f4 <scroll_handler+0x114>
    a76c:	e9 8a fe ff ff       	jmpq   a5fb <scroll_handler+0x1b>
    a771:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    a778:	00 00 00 00 
    a77c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000a780 <start_scrolling>:

void
start_scrolling (double t)
{
    a780:	f3 0f 1e fa          	endbr64 
  add_event (t, scroll_handler, NULL);
    a784:	31 f6                	xor    %esi,%esi
    a786:	48 8d 3d 53 fe ff ff 	lea    -0x1ad(%rip),%rdi        # a5e0 <scroll_handler>
    a78d:	e9 0e 30 00 00       	jmpq   d7a0 <add_event>
    a792:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    a799:	00 00 00 
    a79c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000a7a0 <wheel_handler>:

static int wheel_x, wheel_y;

static void
wheel_handler (game_time t, void *client_data)
{
    a7a0:	f3 0f 1e fa          	endbr64 
    a7a4:	53                   	push   %rbx
    a7a5:	bb 01 00 00 00       	mov    $0x1,%ebx
    a7aa:	48 83 ec 10          	sub    $0x10,%rsp
  int  wheel_crash;

  wheel_crash = (wheel_x<car_x && wheel_y==LINES-5 && ground2[wheel_x]==' ');
    a7ae:	8b 15 68 4b 01 00    	mov    0x14b68(%rip),%edx        # 1f31c <wheel_x>
    a7b4:	8b 05 ae 66 01 00    	mov    0x166ae(%rip),%eax        # 20e68 <car_x>
    a7ba:	8b 0d c4 4a 01 00    	mov    0x14ac4(%rip),%ecx        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
{
    a7c0:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
  wheel_crash = (wheel_x<car_x && wheel_y==LINES-5 && ground2[wheel_x]==' ');
    a7c6:	39 c2                	cmp    %eax,%edx
    a7c8:	7d 38                	jge    a802 <wheel_handler+0x62>
    a7ca:	8b 35 48 4b 01 00    	mov    0x14b48(%rip),%esi        # 1f318 <wheel_y>
    a7d0:	83 e9 05             	sub    $0x5,%ecx
    a7d3:	39 f1                	cmp    %esi,%ecx
    a7d5:	0f 84 e5 00 00 00    	je     a8c0 <wheel_handler+0x120>
  if (wheel_x < car_x)  mvwaddch (moon, wheel_y, wheel_x, ' ');
    a7db:	48 8b 3d 36 66 01 00 	mov    0x16636(%rip),%rdi        # 20e18 <moon>
    a7e2:	e8 e9 d3 ff ff       	callq  7bd0 <wmove@plt>
    a7e7:	83 f8 ff             	cmp    $0xffffffff,%eax
    a7ea:	0f 85 f0 00 00 00    	jne    a8e0 <wheel_handler+0x140>
    a7f0:	8b 15 26 4b 01 00    	mov    0x14b26(%rip),%edx        # 1f31c <wheel_x>
    a7f6:	8b 05 6c 66 01 00    	mov    0x1666c(%rip),%eax        # 20e68 <car_x>
    a7fc:	8b 0d 82 4a 01 00    	mov    0x14a82(%rip),%ecx        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
  wheel_x -= 1;
    a802:	83 ea 01             	sub    $0x1,%edx
  switch (car_x - wheel_x) {
    a805:	29 d0                	sub    %edx,%eax
  wheel_x -= 1;
    a807:	89 15 0f 4b 01 00    	mov    %edx,0x14b0f(%rip)        # 1f31c <wheel_x>
  switch (car_x - wheel_x) {
    a80d:	83 f8 04             	cmp    $0x4,%eax
    a810:	7f 36                	jg     a848 <wheel_handler+0xa8>
    a812:	83 f8 01             	cmp    $0x1,%eax
    a815:	7f 49                	jg     a860 <wheel_handler+0xc0>
    a817:	74 3c                	je     a855 <wheel_handler+0xb5>
  case 3:
  case 4:
    wheel_y = LINES - 7;
    break;
  default:
    wheel_y = LINES - 5;
    a819:	83 e9 05             	sub    $0x5,%ecx
    a81c:	89 0d f6 4a 01 00    	mov    %ecx,0x14af6(%rip)        # 1f318 <wheel_y>
    break;
  }
  if (wheel_x >= 0 && ! wheel_crash) {
    a822:	48 8b 3d ef 65 01 00 	mov    0x165ef(%rip),%rdi        # 20e18 <moon>
    a829:	85 d2                	test   %edx,%edx
    a82b:	78 04                	js     a831 <wheel_handler+0x91>
    a82d:	84 db                	test   %bl,%bl
    a82f:	75 3f                	jne    a870 <wheel_handler+0xd0>
    mvwaddch (moon, wheel_y, wheel_x, 'o');
    add_event (t+TICK(2.3), wheel_handler, NULL);
  } else {
    crash_detected = 1000;
    a831:	c7 05 f5 65 01 00 e8 	movl   $0x3e8,0x165f5(%rip)        # 20e30 <crash_detected>
    a838:	03 00 00 
  }
  wnoutrefresh (moon);
}
    a83b:	48 83 c4 10          	add    $0x10,%rsp
    a83f:	5b                   	pop    %rbx
  wnoutrefresh (moon);
    a840:	e9 7b d2 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    a845:	0f 1f 00             	nopl   (%rax)
  switch (car_x - wheel_x) {
    a848:	83 f8 05             	cmp    $0x5,%eax
    a84b:	74 08                	je     a855 <wheel_handler+0xb5>
    a84d:	83 e8 07             	sub    $0x7,%eax
    a850:	83 f8 02             	cmp    $0x2,%eax
    a853:	77 c4                	ja     a819 <wheel_handler+0x79>
    wheel_y = LINES - 6;
    a855:	83 e9 06             	sub    $0x6,%ecx
    a858:	89 0d ba 4a 01 00    	mov    %ecx,0x14aba(%rip)        # 1f318 <wheel_y>
    break;
    a85e:	eb c2                	jmp    a822 <wheel_handler+0x82>
    wheel_y = LINES - 7;
    a860:	83 e9 07             	sub    $0x7,%ecx
    a863:	89 0d af 4a 01 00    	mov    %ecx,0x14aaf(%rip)        # 1f318 <wheel_y>
    break;
    a869:	eb b7                	jmp    a822 <wheel_handler+0x82>
    a86b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    mvwaddch (moon, wheel_y, wheel_x, 'o');
    a870:	8b 35 a2 4a 01 00    	mov    0x14aa2(%rip),%esi        # 1f318 <wheel_y>
    a876:	e8 55 d3 ff ff       	callq  7bd0 <wmove@plt>
    a87b:	83 f8 ff             	cmp    $0xffffffff,%eax
    a87e:	74 11                	je     a891 <wheel_handler+0xf1>
    a880:	48 8b 3d 91 65 01 00 	mov    0x16591(%rip),%rdi        # 20e18 <moon>
    a887:	be 6f 00 00 00       	mov    $0x6f,%esi
    a88c:	e8 5f d3 ff ff       	callq  7bf0 <waddch@plt>
    add_event (t+TICK(2.3), wheel_handler, NULL);
    a891:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    a897:	f2 0f 58 05 d9 f1 00 	addsd  0xf1d9(%rip),%xmm0        # 19a78 <__PRETTY_FUNCTION__.4499+0xc>
    a89e:	00 
    a89f:	48 8d 3d fa fe ff ff 	lea    -0x106(%rip),%rdi        # a7a0 <wheel_handler>
    a8a6:	31 f6                	xor    %esi,%esi
    a8a8:	e8 f3 2e 00 00       	callq  d7a0 <add_event>
    a8ad:	48 8b 3d 64 65 01 00 	mov    0x16564(%rip),%rdi        # 20e18 <moon>
}
    a8b4:	48 83 c4 10          	add    $0x10,%rsp
    a8b8:	5b                   	pop    %rbx
  wnoutrefresh (moon);
    a8b9:	e9 02 d2 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    a8be:	66 90                	xchg   %ax,%ax
  wheel_crash = (wheel_x<car_x && wheel_y==LINES-5 && ground2[wheel_x]==' ');
    a8c0:	48 8b 0d 91 65 01 00 	mov    0x16591(%rip),%rcx        # 20e58 <ground2>
    a8c7:	48 63 c2             	movslq %edx,%rax
    a8ca:	80 3c 01 20          	cmpb   $0x20,(%rcx,%rax,1)
    a8ce:	0f 95 c3             	setne  %bl
    a8d1:	e9 05 ff ff ff       	jmpq   a7db <wheel_handler+0x3b>
    a8d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    a8dd:	00 00 00 
  if (wheel_x < car_x)  mvwaddch (moon, wheel_y, wheel_x, ' ');
    a8e0:	48 8b 3d 31 65 01 00 	mov    0x16531(%rip),%rdi        # 20e18 <moon>
    a8e7:	be 20 00 00 00       	mov    $0x20,%esi
    a8ec:	e8 ff d2 ff ff       	callq  7bf0 <waddch@plt>
    a8f1:	e9 fa fe ff ff       	jmpq   a7f0 <wheel_handler+0x50>
    a8f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    a8fd:	00 00 00 

000000000000a900 <start_wheel>:

static void
start_wheel (void)
{
    a900:	48 83 ec 08          	sub    $0x8,%rsp
  wheel_x = car_x;
    a904:	8b 05 5e 65 01 00    	mov    0x1655e(%rip),%eax        # 20e68 <car_x>
    a90a:	89 05 0c 4a 01 00    	mov    %eax,0x14a0c(%rip)        # 1f31c <wheel_x>
  add_event (current_time()+TICK(0.5), wheel_handler, NULL);
    a910:	e8 1b 2d 00 00       	callq  d630 <current_time>
    a915:	f2 0f 58 05 63 f1 00 	addsd  0xf163(%rip),%xmm0        # 19a80 <__PRETTY_FUNCTION__.4499+0x14>
    a91c:	00 
    a91d:	31 f6                	xor    %esi,%esi
    a91f:	48 8d 3d 7a fe ff ff 	lea    -0x186(%rip),%rdi        # a7a0 <wheel_handler>
}
    a926:	48 83 c4 08          	add    $0x8,%rsp
  add_event (current_time()+TICK(0.5), wheel_handler, NULL);
    a92a:	e9 71 2e 00 00       	jmpq   d7a0 <add_event>
    a92f:	90                   	nop

000000000000a930 <initialise_buggy>:
{
    a930:	f3 0f 1e fa          	endbr64 
    a934:	55                   	push   %rbp
  state = sz_empty;
    a935:	48 8d 05 a4 48 01 00 	lea    0x148a4(%rip),%rax        # 1f1e0 <sz_empty>
  for (y=5; y<9; ++y)  mvwaddstr (moon, LINES-y, car_x, "       ");
    a93c:	48 8d 2d 67 f0 00 00 	lea    0xf067(%rip),%rbp        # 199aa <__PRETTY_FUNCTION__.4560+0x13a>
{
    a943:	53                   	push   %rbx
  for (y=5; y<9; ++y)  mvwaddstr (moon, LINES-y, car_x, "       ");
    a944:	bb 05 00 00 00       	mov    $0x5,%ebx
{
    a949:	48 83 ec 08          	sub    $0x8,%rsp
  state = sz_empty;
    a94d:	48 89 05 d4 49 01 00 	mov    %rax,0x149d4(%rip)        # 1f328 <state>
  for (y=5; y<9; ++y)  mvwaddstr (moon, LINES-y, car_x, "       ");
    a954:	8b 35 2a 49 01 00    	mov    0x1492a(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    a95a:	8b 15 08 65 01 00    	mov    0x16508(%rip),%edx        # 20e68 <car_x>
    a960:	48 8b 3d b1 64 01 00 	mov    0x164b1(%rip),%rdi        # 20e18 <moon>
    a967:	29 de                	sub    %ebx,%esi
    a969:	e8 62 d2 ff ff       	callq  7bd0 <wmove@plt>
    a96e:	83 f8 ff             	cmp    $0xffffffff,%eax
    a971:	74 14                	je     a987 <initialise_buggy+0x57>
    a973:	48 8b 3d 9e 64 01 00 	mov    0x1649e(%rip),%rdi        # 20e18 <moon>
    a97a:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    a97f:	48 89 ee             	mov    %rbp,%rsi
    a982:	e8 19 d3 ff ff       	callq  7ca0 <waddnstr@plt>
    a987:	83 c3 01             	add    $0x1,%ebx
    a98a:	83 fb 09             	cmp    $0x9,%ebx
    a98d:	75 c5                	jne    a954 <initialise_buggy+0x24>
  car_x = car_base;
    a98f:	8b 05 63 64 01 00    	mov    0x16463(%rip),%eax        # 20df8 <car_base>
  wnoutrefresh (moon);
    a995:	48 8b 3d 7c 64 01 00 	mov    0x1647c(%rip),%rdi        # 20e18 <moon>
  car_x = car_base;
    a99c:	89 05 c6 64 01 00    	mov    %eax,0x164c6(%rip)        # 20e68 <car_x>
  car_y = state->y;
    a9a2:	48 8b 05 7f 49 01 00 	mov    0x1497f(%rip),%rax        # 1f328 <state>
    a9a9:	8b 40 04             	mov    0x4(%rax),%eax
    a9ac:	89 05 ba 64 01 00    	mov    %eax,0x164ba(%rip)        # 20e6c <car_y>
}
    a9b2:	48 83 c4 08          	add    $0x8,%rsp
    a9b6:	5b                   	pop    %rbx
    a9b7:	5d                   	pop    %rbp
  wnoutrefresh (moon);
    a9b8:	e9 03 d1 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    a9bd:	0f 1f 00             	nopl   (%rax)

000000000000a9c0 <print_buggy>:
{
    a9c0:	f3 0f 1e fa          	endbr64 
    a9c4:	55                   	push   %rbp
    a9c5:	53                   	push   %rbx
    a9c6:	48 83 ec 08          	sub    $0x8,%rsp
    a9ca:	8b 15 98 64 01 00    	mov    0x16498(%rip),%edx        # 20e68 <car_x>
  enum car_state  n = state->n;
    a9d0:	48 8b 05 51 49 01 00 	mov    0x14951(%rip),%rax        # 1f328 <state>
    a9d7:	8b 35 a7 48 01 00    	mov    0x148a7(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    a9dd:	48 8b 3d 34 64 01 00 	mov    0x16434(%rip),%rdi        # 20e18 <moon>
    a9e4:	8b 28                	mov    (%rax),%ebp
  int  y = state->y;
    a9e6:	8b 58 04             	mov    0x4(%rax),%ebx
  if (y < car_y) {
    a9e9:	8b 05 7d 64 01 00    	mov    0x1647d(%rip),%eax        # 20e6c <car_y>
    a9ef:	39 d8                	cmp    %ebx,%eax
    a9f1:	0f 8f f1 01 00 00    	jg     abe8 <print_buggy+0x228>
  } else if (y > car_y) {
    a9f7:	0f 8c d3 00 00 00    	jl     aad0 <print_buggy+0x110>
  car_y = y;
    a9fd:	29 de                	sub    %ebx,%esi
    a9ff:	89 1d 67 64 01 00    	mov    %ebx,0x16467(%rip)        # 20e6c <car_y>
  if (n==car_NORMAL)  {
    aa05:	83 ee 01             	sub    $0x1,%esi
    aa08:	85 ed                	test   %ebp,%ebp
    aa0a:	0f 85 f6 00 00 00    	jne    ab06 <print_buggy+0x146>
    mvwaddstr (moon, LINES-y-1, car_x, image[n+nextG][0]);
    aa10:	e8 bb d1 ff ff       	callq  7bd0 <wmove@plt>
    aa15:	83 f8 ff             	cmp    $0xffffffff,%eax
    aa18:	0f 85 82 00 00 00    	jne    aaa0 <print_buggy+0xe0>
    mvwaddstr (moon, LINES-y, car_x, image[n+nextG][1]);
    aa1e:	8b 35 60 48 01 00    	mov    0x14860(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    aa24:	8b 15 3e 64 01 00    	mov    0x1643e(%rip),%edx        # 20e68 <car_x>
    aa2a:	48 8b 3d e7 63 01 00 	mov    0x163e7(%rip),%rdi        # 20e18 <moon>
    aa31:	29 de                	sub    %ebx,%esi
    aa33:	e8 98 d1 ff ff       	callq  7bd0 <wmove@plt>
    aa38:	83 f8 ff             	cmp    $0xffffffff,%eax
    aa3b:	74 27                	je     aa64 <print_buggy+0xa4>
    aa3d:	8b 05 dd 48 01 00    	mov    0x148dd(%rip),%eax        # 1f320 <nextG>
    aa43:	48 8d 0d b6 3e 01 00 	lea    0x13eb6(%rip),%rcx        # 1e900 <image>
    aa4a:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    aa4f:	48 8b 3d c2 63 01 00 	mov    0x163c2(%rip),%rdi        # 20e18 <moon>
    aa56:	48 c1 e0 04          	shl    $0x4,%rax
    aa5a:	48 8b 74 01 08       	mov    0x8(%rcx,%rax,1),%rsi
    aa5f:	e8 3c d2 ff ff       	callq  7ca0 <waddnstr@plt>
  nextG++; if (nextG>3) nextG=0;
    aa64:	8b 05 b6 48 01 00    	mov    0x148b6(%rip),%eax        # 1f320 <nextG>
    aa6a:	48 8b 3d a7 63 01 00 	mov    0x163a7(%rip),%rdi        # 20e18 <moon>
    aa71:	83 c0 01             	add    $0x1,%eax
    aa74:	89 05 a6 48 01 00    	mov    %eax,0x148a6(%rip)        # 1f320 <nextG>
    aa7a:	83 f8 03             	cmp    $0x3,%eax
    aa7d:	7e 13                	jle    aa92 <print_buggy+0xd2>
    aa7f:	c7 05 97 48 01 00 00 	movl   $0x0,0x14897(%rip)        # 1f320 <nextG>
    aa86:	00 00 00 
  if (n == car_BROKEN) {
    aa89:	83 fd 08             	cmp    $0x8,%ebp
    aa8c:	0f 84 0a 01 00 00    	je     ab9c <print_buggy+0x1dc>
}
    aa92:	48 83 c4 08          	add    $0x8,%rsp
    aa96:	5b                   	pop    %rbx
    aa97:	5d                   	pop    %rbp
  wnoutrefresh (moon);
    aa98:	e9 23 d0 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    aa9d:	0f 1f 00             	nopl   (%rax)
    mvwaddstr (moon, LINES-y-1, car_x, image[n+nextG][0]);
    aaa0:	8b 05 7a 48 01 00    	mov    0x1487a(%rip),%eax        # 1f320 <nextG>
    aaa6:	48 8d 0d 53 3e 01 00 	lea    0x13e53(%rip),%rcx        # 1e900 <image>
    aaad:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    aab2:	48 8b 3d 5f 63 01 00 	mov    0x1635f(%rip),%rdi        # 20e18 <moon>
    aab9:	48 c1 e0 04          	shl    $0x4,%rax
    aabd:	48 8b 34 01          	mov    (%rcx,%rax,1),%rsi
    aac1:	e8 da d1 ff ff       	callq  7ca0 <waddnstr@plt>
    aac6:	e9 53 ff ff ff       	jmpq   aa1e <print_buggy+0x5e>
    aacb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    mvwaddstr (moon, LINES-car_y, car_x, "       ");
    aad0:	29 c6                	sub    %eax,%esi
    aad2:	e8 f9 d0 ff ff       	callq  7bd0 <wmove@plt>
    aad7:	83 f8 ff             	cmp    $0xffffffff,%eax
    aada:	0f 85 1b 01 00 00    	jne    abfb <print_buggy+0x23b>
    aae0:	8b 35 9e 47 01 00    	mov    0x1479e(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
  car_y = y;
    aae6:	89 1d 80 63 01 00    	mov    %ebx,0x16380(%rip)        # 20e6c <car_y>
    aaec:	8b 15 76 63 01 00    	mov    0x16376(%rip),%edx        # 20e68 <car_x>
    aaf2:	48 8b 3d 1f 63 01 00 	mov    0x1631f(%rip),%rdi        # 20e18 <moon>
  if (n==car_NORMAL)  {
    aaf9:	29 de                	sub    %ebx,%esi
    aafb:	83 ee 01             	sub    $0x1,%esi
    aafe:	85 ed                	test   %ebp,%ebp
    ab00:	0f 84 0a ff ff ff    	je     aa10 <print_buggy+0x50>
    mvwaddstr (moon, LINES-y-1, car_x, image[n][0]);
    ab06:	e8 c5 d0 ff ff       	callq  7bd0 <wmove@plt>
    ab0b:	83 f8 ff             	cmp    $0xffffffff,%eax
    ab0e:	74 22                	je     ab32 <print_buggy+0x172>
    ab10:	89 e8                	mov    %ebp,%eax
    ab12:	48 8d 0d e7 3d 01 00 	lea    0x13de7(%rip),%rcx        # 1e900 <image>
    ab19:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    ab1e:	48 8b 3d f3 62 01 00 	mov    0x162f3(%rip),%rdi        # 20e18 <moon>
    ab25:	48 c1 e0 04          	shl    $0x4,%rax
    ab29:	48 8b 34 01          	mov    (%rcx,%rax,1),%rsi
    ab2d:	e8 6e d1 ff ff       	callq  7ca0 <waddnstr@plt>
    mvwaddstr (moon, LINES-y, car_x, image[n][1]);
    ab32:	8b 35 4c 47 01 00    	mov    0x1474c(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    ab38:	8b 15 2a 63 01 00    	mov    0x1632a(%rip),%edx        # 20e68 <car_x>
    ab3e:	48 8b 3d d3 62 01 00 	mov    0x162d3(%rip),%rdi        # 20e18 <moon>
    ab45:	29 de                	sub    %ebx,%esi
    ab47:	e8 84 d0 ff ff       	callq  7bd0 <wmove@plt>
    ab4c:	83 f8 ff             	cmp    $0xffffffff,%eax
    ab4f:	74 23                	je     ab74 <print_buggy+0x1b4>
    ab51:	89 e8                	mov    %ebp,%eax
    ab53:	48 8d 0d a6 3d 01 00 	lea    0x13da6(%rip),%rcx        # 1e900 <image>
    ab5a:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    ab5f:	48 8b 3d b2 62 01 00 	mov    0x162b2(%rip),%rdi        # 20e18 <moon>
    ab66:	48 c1 e0 04          	shl    $0x4,%rax
    ab6a:	48 8b 74 01 08       	mov    0x8(%rcx,%rax,1),%rsi
    ab6f:	e8 2c d1 ff ff       	callq  7ca0 <waddnstr@plt>
  nextG++; if (nextG>3) nextG=0;
    ab74:	8b 05 a6 47 01 00    	mov    0x147a6(%rip),%eax        # 1f320 <nextG>
    ab7a:	48 8b 3d 97 62 01 00 	mov    0x16297(%rip),%rdi        # 20e18 <moon>
    ab81:	83 c0 01             	add    $0x1,%eax
    ab84:	89 05 96 47 01 00    	mov    %eax,0x14796(%rip)        # 1f320 <nextG>
    ab8a:	83 f8 03             	cmp    $0x3,%eax
    ab8d:	0f 8f ec fe ff ff    	jg     aa7f <print_buggy+0xbf>
  if (n == car_BROKEN) {
    ab93:	83 fd 08             	cmp    $0x8,%ebp
    ab96:	0f 85 f6 fe ff ff    	jne    aa92 <print_buggy+0xd2>
    if (ground2[car_x+1] == ' ')  mvwaddch (moon, LINES-4, car_x+1, 'o');
    ab9c:	48 63 05 c5 62 01 00 	movslq 0x162c5(%rip),%rax        # 20e68 <car_x>
    aba3:	48 8b 0d ae 62 01 00 	mov    0x162ae(%rip),%rcx        # 20e58 <ground2>
    abaa:	80 7c 01 01 20       	cmpb   $0x20,0x1(%rcx,%rax,1)
    abaf:	48 89 c2             	mov    %rax,%rdx
    abb2:	74 6c                	je     ac20 <print_buggy+0x260>
    if (ground2[car_x+5] == ' ')  mvwaddch (moon, LINES-4, car_x+5, 'o');
    abb4:	80 7c 01 05 20       	cmpb   $0x20,0x5(%rcx,%rax,1)
    abb9:	0f 85 d3 fe ff ff    	jne    aa92 <print_buggy+0xd2>
    abbf:	8b 05 bf 46 01 00    	mov    0x146bf(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    abc5:	83 c2 05             	add    $0x5,%edx
    abc8:	8d 70 fc             	lea    -0x4(%rax),%esi
    abcb:	e8 00 d0 ff ff       	callq  7bd0 <wmove@plt>
    abd0:	83 f8 ff             	cmp    $0xffffffff,%eax
    abd3:	0f 85 97 00 00 00    	jne    ac70 <print_buggy+0x2b0>
    abd9:	48 8b 3d 38 62 01 00 	mov    0x16238(%rip),%rdi        # 20e18 <moon>
    abe0:	e9 ad fe ff ff       	jmpq   aa92 <print_buggy+0xd2>
    abe5:	0f 1f 00             	nopl   (%rax)
    mvwaddstr (moon, LINES-car_y-1, car_x, "       ");
    abe8:	29 c6                	sub    %eax,%esi
    abea:	83 ee 01             	sub    $0x1,%esi
    abed:	e8 de cf ff ff       	callq  7bd0 <wmove@plt>
    abf2:	83 f8 ff             	cmp    $0xffffffff,%eax
    abf5:	0f 84 e5 fe ff ff    	je     aae0 <print_buggy+0x120>
    mvwaddstr (moon, LINES-car_y, car_x, "       ");
    abfb:	48 8b 3d 16 62 01 00 	mov    0x16216(%rip),%rdi        # 20e18 <moon>
    ac02:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    ac07:	48 8d 35 9c ed 00 00 	lea    0xed9c(%rip),%rsi        # 199aa <__PRETTY_FUNCTION__.4560+0x13a>
    ac0e:	e8 8d d0 ff ff       	callq  7ca0 <waddnstr@plt>
    ac13:	e9 c8 fe ff ff       	jmpq   aae0 <print_buggy+0x120>
    ac18:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    ac1f:	00 
    if (ground2[car_x+1] == ' ')  mvwaddch (moon, LINES-4, car_x+1, 'o');
    ac20:	8b 05 5e 46 01 00    	mov    0x1465e(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    ac26:	83 c2 01             	add    $0x1,%edx
    ac29:	8d 70 fc             	lea    -0x4(%rax),%esi
    ac2c:	e8 9f cf ff ff       	callq  7bd0 <wmove@plt>
    ac31:	83 f8 ff             	cmp    $0xffffffff,%eax
    ac34:	75 22                	jne    ac58 <print_buggy+0x298>
    ac36:	48 63 05 2b 62 01 00 	movslq 0x1622b(%rip),%rax        # 20e68 <car_x>
    ac3d:	48 8b 0d 14 62 01 00 	mov    0x16214(%rip),%rcx        # 20e58 <ground2>
    ac44:	48 8b 3d cd 61 01 00 	mov    0x161cd(%rip),%rdi        # 20e18 <moon>
    ac4b:	48 89 c2             	mov    %rax,%rdx
    ac4e:	e9 61 ff ff ff       	jmpq   abb4 <print_buggy+0x1f4>
    ac53:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    ac58:	48 8b 3d b9 61 01 00 	mov    0x161b9(%rip),%rdi        # 20e18 <moon>
    ac5f:	be 6f 00 00 00       	mov    $0x6f,%esi
    ac64:	e8 87 cf ff ff       	callq  7bf0 <waddch@plt>
    ac69:	eb cb                	jmp    ac36 <print_buggy+0x276>
    ac6b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    if (ground2[car_x+5] == ' ')  mvwaddch (moon, LINES-4, car_x+5, 'o');
    ac70:	48 8b 3d a1 61 01 00 	mov    0x161a1(%rip),%rdi        # 20e18 <moon>
    ac77:	be 6f 00 00 00       	mov    $0x6f,%esi
    ac7c:	e8 6f cf ff ff       	callq  7bf0 <waddch@plt>
    ac81:	e9 53 ff ff ff       	jmpq   abd9 <print_buggy+0x219>
    ac86:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    ac8d:	00 00 00 

000000000000ac90 <jump_handler>:
 * handle the jumps
 */

static void
jump_handler (game_time t, void *client_data)
{
    ac90:	f3 0f 1e fa          	endbr64 
    ac94:	48 83 ec 18          	sub    $0x18,%rsp
  state = client_data;
  if (car_y > 5 && state->y == 5) {
    ac98:	83 3d cd 61 01 00 05 	cmpl   $0x5,0x161cd(%rip)        # 20e6c <car_y>
  state = client_data;
    ac9f:	48 89 3d 82 46 01 00 	mov    %rdi,0x14682(%rip)        # 1f328 <state>
{
    aca6:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
  if (car_y > 5 && state->y == 5) {
    acac:	7e 06                	jle    acb4 <jump_handler+0x24>
    acae:	83 7f 04 05          	cmpl   $0x5,0x4(%rdi)
    acb2:	74 44                	je     acf8 <jump_handler+0x68>
      state = sz_sit;
      start_wheel ();
      crash_detected = 1;
    }
  }
  print_buggy ();
    acb4:	e8 07 fd ff ff       	callq  a9c0 <print_buggy>
  if (state->dt >= -0.5) {
    acb9:	48 8b 35 68 46 01 00 	mov    0x14668(%rip),%rsi        # 1f328 <state>
    acc0:	f2 0f 10 46 08       	movsd  0x8(%rsi),%xmm0
    acc5:	66 0f 2f 05 bb ed 00 	comisd 0xedbb(%rip),%xmm0        # 19a88 <__PRETTY_FUNCTION__.4499+0x1c>
    accc:	00 
    accd:	73 09                	jae    acd8 <jump_handler+0x48>
    add_event (t+state->dt, jump_handler, state+1);
  }
}
    accf:	48 83 c4 18          	add    $0x18,%rsp
    acd3:	c3                   	retq   
    acd4:	0f 1f 40 00          	nopl   0x0(%rax)
    add_event (t+state->dt, jump_handler, state+1);
    acd8:	f2 0f 58 44 24 08    	addsd  0x8(%rsp),%xmm0
    acde:	48 83 c6 18          	add    $0x18,%rsi
}
    ace2:	48 83 c4 18          	add    $0x18,%rsp
    add_event (t+state->dt, jump_handler, state+1);
    ace6:	48 8d 3d a3 ff ff ff 	lea    -0x5d(%rip),%rdi        # ac90 <jump_handler>
    aced:	e9 ae 2a 00 00       	jmpq   d7a0 <add_event>
    acf2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    if (meteor_car_hit (car_x, car_x+7)) {
    acf8:	8b 3d 6a 61 01 00    	mov    0x1616a(%rip),%edi        # 20e68 <car_x>
    acfe:	8d 77 07             	lea    0x7(%rdi),%esi
    ad01:	e8 3a 0d 00 00       	callq  ba40 <meteor_car_hit>
    ad06:	85 c0                	test   %eax,%eax
    ad08:	74 aa                	je     acb4 <jump_handler+0x24>
      state = sz_sit;
    ad0a:	48 8d 05 8f 43 01 00 	lea    0x1438f(%rip),%rax        # 1f0a0 <sz_sit>
    ad11:	48 89 05 10 46 01 00 	mov    %rax,0x14610(%rip)        # 1f328 <state>
      start_wheel ();
    ad18:	e8 e3 fb ff ff       	callq  a900 <start_wheel>
      crash_detected = 1;
    ad1d:	c7 05 09 61 01 00 01 	movl   $0x1,0x16109(%rip)        # 20e30 <crash_detected>
    ad24:	00 00 00 
    ad27:	eb 8b                	jmp    acb4 <jump_handler+0x24>
    ad29:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

000000000000ad30 <shift_buggy>:
{
    ad30:	f3 0f 1e fa          	endbr64 
  mvwaddstr (moon, LINES-car_y-1, car_x, "       ");
    ad34:	8b 35 4a 45 01 00    	mov    0x1454a(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    ad3a:	8b 15 28 61 01 00    	mov    0x16128(%rip),%edx        # 20e68 <car_x>
{
    ad40:	53                   	push   %rbx
    ad41:	89 fb                	mov    %edi,%ebx
  mvwaddstr (moon, LINES-car_y-1, car_x, "       ");
    ad43:	2b 35 23 61 01 00    	sub    0x16123(%rip),%esi        # 20e6c <car_y>
    ad49:	48 8b 3d c8 60 01 00 	mov    0x160c8(%rip),%rdi        # 20e18 <moon>
    ad50:	83 ee 01             	sub    $0x1,%esi
    ad53:	e8 78 ce ff ff       	callq  7bd0 <wmove@plt>
    ad58:	83 f8 ff             	cmp    $0xffffffff,%eax
    ad5b:	74 18                	je     ad75 <shift_buggy+0x45>
    ad5d:	48 8b 3d b4 60 01 00 	mov    0x160b4(%rip),%rdi        # 20e18 <moon>
    ad64:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    ad69:	48 8d 35 3a ec 00 00 	lea    0xec3a(%rip),%rsi        # 199aa <__PRETTY_FUNCTION__.4560+0x13a>
    ad70:	e8 2b cf ff ff       	callq  7ca0 <waddnstr@plt>
  mvwaddstr (moon, LINES-car_y, car_x, "       ");
    ad75:	8b 15 ed 60 01 00    	mov    0x160ed(%rip),%edx        # 20e68 <car_x>
    ad7b:	48 8b 3d 96 60 01 00 	mov    0x16096(%rip),%rdi        # 20e18 <moon>
    ad82:	8b 35 fc 44 01 00    	mov    0x144fc(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    ad88:	2b 35 de 60 01 00    	sub    0x160de(%rip),%esi        # 20e6c <car_y>
    ad8e:	e8 3d ce ff ff       	callq  7bd0 <wmove@plt>
    ad93:	83 f8 ff             	cmp    $0xffffffff,%eax
    ad96:	74 18                	je     adb0 <shift_buggy+0x80>
    ad98:	48 8b 3d 79 60 01 00 	mov    0x16079(%rip),%rdi        # 20e18 <moon>
    ad9f:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    ada4:	48 8d 35 ff eb 00 00 	lea    0xebff(%rip),%rsi        # 199aa <__PRETTY_FUNCTION__.4560+0x13a>
    adab:	e8 f0 ce ff ff       	callq  7ca0 <waddnstr@plt>
  car_x += dx;
    adb0:	01 1d b2 60 01 00    	add    %ebx,0x160b2(%rip)        # 20e68 <car_x>
}
    adb6:	5b                   	pop    %rbx
  print_buggy ();
    adb7:	e9 04 fc ff ff       	jmpq   a9c0 <print_buggy>
    adbc:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000adc0 <jump>:

void
jump (game_time t)
{
    adc0:	f3 0f 1e fa          	endbr64 
    adc4:	48 83 ec 18          	sub    $0x18,%rsp
  assert (state->has_ground);
    adc8:	48 8b 05 59 45 01 00 	mov    0x14559(%rip),%rax        # 1f328 <state>
    adcf:	8b 40 10             	mov    0x10(%rax),%eax
    add2:	85 c0                	test   %eax,%eax
    add4:	74 2f                	je     ae05 <jump+0x45>
  remove_event (jump_handler);	/* only one jump at a time */
    add6:	48 8d 3d b3 fe ff ff 	lea    -0x14d(%rip),%rdi        # ac90 <jump_handler>
    addd:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
    ade3:	e8 38 2a 00 00       	callq  d820 <remove_event>
  add_event (t, jump_handler, sz_jump);
    ade8:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
}
    adee:	48 83 c4 18          	add    $0x18,%rsp
  add_event (t, jump_handler, sz_jump);
    adf2:	48 8d 35 47 43 01 00 	lea    0x14347(%rip),%rsi        # 1f140 <sz_jump>
    adf9:	48 8d 3d 90 fe ff ff 	lea    -0x170(%rip),%rdi        # ac90 <jump_handler>
    ae00:	e9 9b 29 00 00       	jmpq   d7a0 <add_event>
  assert (state->has_ground);
    ae05:	48 8d 0d 60 ec 00 00 	lea    0xec60(%rip),%rcx        # 19a6c <__PRETTY_FUNCTION__.4499>
    ae0c:	ba bf 00 00 00       	mov    $0xbf,%edx
    ae11:	48 8d 35 9a eb 00 00 	lea    0xeb9a(%rip),%rsi        # 199b2 <__PRETTY_FUNCTION__.4560+0x142>
    ae18:	48 8d 3d 9b eb 00 00 	lea    0xeb9b(%rip),%rdi        # 199ba <__PRETTY_FUNCTION__.4560+0x14a>
    ae1f:	e8 bc ca ff ff       	callq  78e0 <__assert_fail@plt>
    ae24:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    ae2b:	00 00 00 00 
    ae2f:	90                   	nop

000000000000ae30 <can_jump>:

int
can_jump (void)
{
    ae30:	f3 0f 1e fa          	endbr64 
  return  state->has_ground;
    ae34:	48 8b 05 ed 44 01 00 	mov    0x144ed(%rip),%rax        # 1f328 <state>
    ae3b:	8b 40 10             	mov    0x10(%rax),%eax
}
    ae3e:	c3                   	retq   
    ae3f:	90                   	nop

000000000000ae40 <crash_check>:
 */

int
crash_check (void)
/* Return true, if the car crashed.  */
{
    ae40:	f3 0f 1e fa          	endbr64 
	//return 0;
  if (! state->has_ground)  return 0;
    ae44:	48 8b 05 dd 44 01 00 	mov    0x144dd(%rip),%rax        # 1f328 <state>
    ae4b:	8b 40 10             	mov    0x10(%rax),%eax
    ae4e:	85 c0                	test   %eax,%eax
    ae50:	74 1e                	je     ae70 <crash_check+0x30>
  if (ground2[car_x+1] == ' ' || ground2[car_x+5] == ' ') {
    ae52:	48 8b 0d ff 5f 01 00 	mov    0x15fff(%rip),%rcx        # 20e58 <ground2>
    ae59:	48 63 15 08 60 01 00 	movslq 0x16008(%rip),%rdx        # 20e68 <car_x>
    ae60:	80 7c 11 01 20       	cmpb   $0x20,0x1(%rcx,%rdx,1)
    ae65:	74 11                	je     ae78 <crash_check+0x38>
  if (! state->has_ground)  return 0;
    ae67:	31 c0                	xor    %eax,%eax
  if (ground2[car_x+1] == ' ' || ground2[car_x+5] == ' ') {
    ae69:	80 7c 11 05 20       	cmpb   $0x20,0x5(%rcx,%rdx,1)
    ae6e:	74 08                	je     ae78 <crash_check+0x38>
    start_wheel ();
    return 1;
  }

  return  0;
}
    ae70:	c3                   	retq   
    ae71:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
{
    ae78:	48 83 ec 08          	sub    $0x8,%rsp
    remove_event (jump_handler);
    ae7c:	48 8d 3d 0d fe ff ff 	lea    -0x1f3(%rip),%rdi        # ac90 <jump_handler>
    ae83:	e8 98 29 00 00       	callq  d820 <remove_event>
    state = sz_crash;
    ae88:	48 8d 05 81 42 01 00 	lea    0x14281(%rip),%rax        # 1f110 <sz_crash>
    ae8f:	48 89 05 92 44 01 00 	mov    %rax,0x14492(%rip)        # 1f328 <state>
    print_buggy ();
    ae96:	e8 25 fb ff ff       	callq  a9c0 <print_buggy>
    start_wheel ();
    ae9b:	e8 60 fa ff ff       	callq  a900 <start_wheel>
    return 1;
    aea0:	b8 01 00 00 00       	mov    $0x1,%eax
}
    aea5:	48 83 c4 08          	add    $0x8,%rsp
    aea9:	c3                   	retq   
    aeaa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000aeb0 <car_meteor_hit>:

int
car_meteor_hit (int x)
/* Return true, if the car is down and occupies position X.
 * Then the car crashes immediately.  */
{
    aeb0:	f3 0f 1e fa          	endbr64 
    start_wheel ();
    crash_detected = 1;
    return 1;
  }

  return  0;
    aeb4:	31 c0                	xor    %eax,%eax
  if (car_y == 5 && x >= car_x && x < car_x+7) {
    aeb6:	83 3d af 5f 01 00 05 	cmpl   $0x5,0x15faf(%rip)        # 20e6c <car_y>
    aebd:	74 01                	je     aec0 <car_meteor_hit+0x10>
}
    aebf:	c3                   	retq   
  if (car_y == 5 && x >= car_x && x < car_x+7) {
    aec0:	8b 15 a2 5f 01 00    	mov    0x15fa2(%rip),%edx        # 20e68 <car_x>
    aec6:	39 fa                	cmp    %edi,%edx
    aec8:	7f f5                	jg     aebf <car_meteor_hit+0xf>
    aeca:	83 c2 06             	add    $0x6,%edx
    aecd:	39 fa                	cmp    %edi,%edx
    aecf:	7c ee                	jl     aebf <car_meteor_hit+0xf>
{
    aed1:	48 83 ec 08          	sub    $0x8,%rsp
    remove_event (jump_handler);
    aed5:	48 8d 3d b4 fd ff ff 	lea    -0x24c(%rip),%rdi        # ac90 <jump_handler>
    aedc:	e8 3f 29 00 00       	callq  d820 <remove_event>
    add_event (current_time (), jump_handler, sz_ram);
    aee1:	e8 4a 27 00 00       	callq  d630 <current_time>
    aee6:	48 8d 35 d3 41 01 00 	lea    0x141d3(%rip),%rsi        # 1f0c0 <sz_ram>
    aeed:	48 8d 3d 9c fd ff ff 	lea    -0x264(%rip),%rdi        # ac90 <jump_handler>
    aef4:	e8 a7 28 00 00       	callq  d7a0 <add_event>
    print_buggy ();
    aef9:	e8 c2 fa ff ff       	callq  a9c0 <print_buggy>
    start_wheel ();
    aefe:	e8 fd f9 ff ff       	callq  a900 <start_wheel>
    return 1;
    af03:	b8 01 00 00 00       	mov    $0x1,%eax
    crash_detected = 1;
    af08:	c7 05 1e 5f 01 00 01 	movl   $0x1,0x15f1e(%rip)        # 20e30 <crash_detected>
    af0f:	00 00 00 
}
    af12:	48 83 c4 08          	add    $0x8,%rsp
    af16:	c3                   	retq   
    af17:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    af1e:	00 00 

000000000000af20 <beam_handler>:
} beam_table;


static void
beam_handler (game_time t, void *client_data)
{
    af20:	f3 0f 1e fa          	endbr64 
    af24:	41 55                	push   %r13
    af26:	41 54                	push   %r12
    af28:	55                   	push   %rbp
    af29:	48 89 fd             	mov    %rdi,%rbp
    af2c:	53                   	push   %rbx
    af2d:	48 83 ec 18          	sub    $0x18,%rsp
  struct beam *b = client_data;
  int  i, x;

  switch (b->state) {
    af31:	8b 07                	mov    (%rdi),%eax
{
    af33:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
  switch (b->state) {
    af39:	83 f8 01             	cmp    $0x1,%eax
    af3c:	74 2a                	je     af68 <beam_handler+0x48>
    af3e:	83 f8 02             	cmp    $0x2,%eax
    af41:	0f 84 29 01 00 00    	je     b070 <beam_handler+0x150>
    af47:	85 c0                	test   %eax,%eax
    af49:	0f 84 a1 00 00 00    	je     aff0 <beam_handler+0xd0>
      DA_REMOVE_VALUE (beam_table, struct beam *, b);
      free (b);
    }
    break;
  }
  wnoutrefresh (moon);
    af4f:	48 8b 3d c2 5e 01 00 	mov    0x15ec2(%rip),%rdi        # 20e18 <moon>
}
    af56:	48 83 c4 18          	add    $0x18,%rsp
    af5a:	5b                   	pop    %rbx
    af5b:	5d                   	pop    %rbp
    af5c:	41 5c                	pop    %r12
    af5e:	41 5d                	pop    %r13
  wnoutrefresh (moon);
    af60:	e9 5b cb ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    af65:	0f 1f 00             	nopl   (%rax)
    if (b->count > 0) {
    af68:	8b 45 10             	mov    0x10(%rbp),%eax
    af6b:	8b 57 04             	mov    0x4(%rdi),%edx
    af6e:	8b 35 10 43 01 00    	mov    0x14310(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    af74:	2b 77 0c             	sub    0xc(%rdi),%esi
    af77:	48 8b 3d 9a 5e 01 00 	mov    0x15e9a(%rip),%rdi        # 20e18 <moon>
    af7e:	85 c0                	test   %eax,%eax
    af80:	0f 8e 1a 02 00 00    	jle    b1a0 <beam_handler+0x280>
      b->left -= 1;
    af86:	83 ea 01             	sub    $0x1,%edx
      b->right -= 1;
    af89:	83 6d 08 01          	subl   $0x1,0x8(%rbp)
      b->left -= 1;
    af8d:	89 55 04             	mov    %edx,0x4(%rbp)
      mvwaddch (moon, LINES-b->y, b->left, '-');
    af90:	e8 3b cc ff ff       	callq  7bd0 <wmove@plt>
    af95:	83 f8 ff             	cmp    $0xffffffff,%eax
    af98:	74 11                	je     afab <beam_handler+0x8b>
    af9a:	48 8b 3d 77 5e 01 00 	mov    0x15e77(%rip),%rdi        # 20e18 <moon>
    afa1:	be 2d 00 00 00       	mov    $0x2d,%esi
    afa6:	e8 45 cc ff ff       	callq  7bf0 <waddch@plt>
      mvwaddch (moon, LINES-b->y, b->right, ' ');
    afab:	8b 55 08             	mov    0x8(%rbp),%edx
    afae:	48 8b 3d 63 5e 01 00 	mov    0x15e63(%rip),%rdi        # 20e18 <moon>
    afb5:	8b 35 c9 42 01 00    	mov    0x142c9(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    afbb:	2b 75 0c             	sub    0xc(%rbp),%esi
    afbe:	e8 0d cc ff ff       	callq  7bd0 <wmove@plt>
    afc3:	83 f8 ff             	cmp    $0xffffffff,%eax
    afc6:	74 11                	je     afd9 <beam_handler+0xb9>
    afc8:	48 8b 3d 49 5e 01 00 	mov    0x15e49(%rip),%rdi        # 20e18 <moon>
    afcf:	be 20 00 00 00       	mov    $0x20,%esi
    afd4:	e8 17 cc ff ff       	callq  7bf0 <waddch@plt>
      if (b->y == 5 && meteor_laser_hit (b->left, b->right)) {
    afd9:	83 7d 0c 05          	cmpl   $0x5,0xc(%rbp)
    afdd:	0f 84 2d 03 00 00    	je     b310 <beam_handler+0x3f0>
        b->count -= 1;
    afe3:	8b 45 10             	mov    0x10(%rbp),%eax
    afe6:	83 e8 01             	sub    $0x1,%eax
    afe9:	89 45 10             	mov    %eax,0x10(%rbp)
    afec:	eb 57                	jmp    b045 <beam_handler+0x125>
    afee:	66 90                	xchg   %ax,%ax
    if (b->y == 5 && (x = meteor_laser_hit (b->left, b->right))) {
    aff0:	8b 47 0c             	mov    0xc(%rdi),%eax
    aff3:	8b 57 04             	mov    0x4(%rdi),%edx
    aff6:	83 f8 05             	cmp    $0x5,%eax
    aff9:	0f 84 39 02 00 00    	je     b238 <beam_handler+0x318>
    wmove (moon, LINES-b->y, b->left);
    afff:	8b 35 7f 42 01 00    	mov    0x1427f(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b005:	48 8b 3d 0c 5e 01 00 	mov    0x15e0c(%rip),%rdi        # 20e18 <moon>
    for (i=0; i<b->right-b->left; ++i)  waddch (moon, '-');
    b00c:	31 db                	xor    %ebx,%ebx
    wmove (moon, LINES-b->y, b->left);
    b00e:	29 c6                	sub    %eax,%esi
    b010:	e8 bb cb ff ff       	callq  7bd0 <wmove@plt>
    for (i=0; i<b->right-b->left; ++i)  waddch (moon, '-');
    b015:	8b 45 08             	mov    0x8(%rbp),%eax
    b018:	2b 45 04             	sub    0x4(%rbp),%eax
    b01b:	85 c0                	test   %eax,%eax
    b01d:	7e 1f                	jle    b03e <beam_handler+0x11e>
    b01f:	90                   	nop
    b020:	48 8b 3d f1 5d 01 00 	mov    0x15df1(%rip),%rdi        # 20e18 <moon>
    b027:	be 2d 00 00 00       	mov    $0x2d,%esi
    b02c:	83 c3 01             	add    $0x1,%ebx
    b02f:	e8 bc cb ff ff       	callq  7bf0 <waddch@plt>
    b034:	8b 45 08             	mov    0x8(%rbp),%eax
    b037:	2b 45 04             	sub    0x4(%rbp),%eax
    b03a:	39 d8                	cmp    %ebx,%eax
    b03c:	7f e2                	jg     b020 <beam_handler+0x100>
    b->state = bs_RUN;
    b03e:	c7 45 00 01 00 00 00 	movl   $0x1,0x0(%rbp)
      add_event (t+TICK(0.25), beam_handler, client_data);
    b045:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    b04b:	48 89 ee             	mov    %rbp,%rsi
    b04e:	f2 0f 58 05 3a ea 00 	addsd  0xea3a(%rip),%xmm0        # 19a90 <__PRETTY_FUNCTION__.4499+0x24>
    b055:	00 
    b056:	48 8d 3d c3 fe ff ff 	lea    -0x13d(%rip),%rdi        # af20 <beam_handler>
    b05d:	e8 3e 27 00 00       	callq  d7a0 <add_event>
    b062:	e9 e8 fe ff ff       	jmpq   af4f <beam_handler+0x2f>
    b067:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    b06e:	00 00 
    if (b->count > 1) {
    b070:	8b 35 0e 42 01 00    	mov    0x1420e(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b076:	2b 77 0c             	sub    0xc(%rdi),%esi
    b079:	83 7d 10 01          	cmpl   $0x1,0x10(%rbp)
    b07d:	8b 57 04             	mov    0x4(%rdi),%edx
    b080:	48 8b 3d 91 5d 01 00 	mov    0x15d91(%rip),%rdi        # 20e18 <moon>
    b087:	0f 8f 9b 00 00 00    	jg     b128 <beam_handler+0x208>
    } else if (b->count > 0) {
    b08d:	0f 84 05 02 00 00    	je     b298 <beam_handler+0x378>
      wmove (moon, LINES-b->y, b->left);
    b093:	e8 38 cb ff ff       	callq  7bd0 <wmove@plt>
      for (i=0; i<2; ++i)  waddch (moon, ' ');
    b098:	48 8b 3d 79 5d 01 00 	mov    0x15d79(%rip),%rdi        # 20e18 <moon>
    b09f:	be 20 00 00 00       	mov    $0x20,%esi
      DA_REMOVE_VALUE (beam_table, struct beam *, b);
    b0a4:	31 db                	xor    %ebx,%ebx
      for (i=0; i<2; ++i)  waddch (moon, ' ');
    b0a6:	e8 45 cb ff ff       	callq  7bf0 <waddch@plt>
    b0ab:	48 8b 3d 66 5d 01 00 	mov    0x15d66(%rip),%rdi        # 20e18 <moon>
    b0b2:	be 20 00 00 00       	mov    $0x20,%esi
    b0b7:	e8 34 cb ff ff       	callq  7bf0 <waddch@plt>
      DA_REMOVE_VALUE (beam_table, struct beam *, b);
    b0bc:	44 8b 25 79 42 01 00 	mov    0x14279(%rip),%r12d        # 1f33c <beam_table+0xc>
    b0c3:	4c 8b 2d 66 42 01 00 	mov    0x14266(%rip),%r13        # 1f330 <beam_table>
    b0ca:	45 85 e4             	test   %r12d,%r12d
    b0cd:	7f 1c                	jg     b0eb <beam_handler+0x1cb>
    b0cf:	e9 a4 01 00 00       	jmpq   b278 <beam_handler+0x358>
    b0d4:	0f 1f 40 00          	nopl   0x0(%rax)
    b0d8:	44 8b 25 5d 42 01 00 	mov    0x1425d(%rip),%r12d        # 1f33c <beam_table+0xc>
    b0df:	83 c3 01             	add    $0x1,%ebx
    b0e2:	44 39 e3             	cmp    %r12d,%ebx
    b0e5:	0f 8d 8d 01 00 00    	jge    b278 <beam_handler+0x358>
    b0eb:	48 63 c3             	movslq %ebx,%rax
    b0ee:	48 c1 e0 03          	shl    $0x3,%rax
    b0f2:	49 8d 7c 05 00       	lea    0x0(%r13,%rax,1),%rdi
    b0f7:	48 39 2f             	cmp    %rbp,(%rdi)
    b0fa:	75 dc                	jne    b0d8 <beam_handler+0x1b8>
    b0fc:	44 89 e2             	mov    %r12d,%edx
    b0ff:	49 8d 74 05 08       	lea    0x8(%r13,%rax,1),%rsi
    b104:	41 83 ec 01          	sub    $0x1,%r12d
    b108:	29 da                	sub    %ebx,%edx
    b10a:	83 ea 01             	sub    $0x1,%edx
    b10d:	48 63 d2             	movslq %edx,%rdx
    b110:	48 c1 e2 03          	shl    $0x3,%rdx
    b114:	e8 57 ca ff ff       	callq  7b70 <memmove@plt>
    b119:	44 89 25 1c 42 01 00 	mov    %r12d,0x1421c(%rip)        # 1f33c <beam_table+0xc>
    b120:	eb c0                	jmp    b0e2 <beam_handler+0x1c2>
    b122:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      mvwaddch (moon, LINES-b->y, b->left, ' ');
    b128:	e8 a3 ca ff ff       	callq  7bd0 <wmove@plt>
    b12d:	83 f8 ff             	cmp    $0xffffffff,%eax
    b130:	74 11                	je     b143 <beam_handler+0x223>
    b132:	48 8b 3d df 5c 01 00 	mov    0x15cdf(%rip),%rdi        # 20e18 <moon>
    b139:	be 20 00 00 00       	mov    $0x20,%esi
    b13e:	e8 ad ca ff ff       	callq  7bf0 <waddch@plt>
      mvwaddch (moon, LINES-b->y, b->right, '*');
    b143:	8b 55 08             	mov    0x8(%rbp),%edx
    b146:	48 8b 3d cb 5c 01 00 	mov    0x15ccb(%rip),%rdi        # 20e18 <moon>
    b14d:	8b 35 31 41 01 00    	mov    0x14131(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b153:	2b 75 0c             	sub    0xc(%rbp),%esi
    b156:	e8 75 ca ff ff       	callq  7bd0 <wmove@plt>
    b15b:	83 f8 ff             	cmp    $0xffffffff,%eax
    b15e:	74 11                	je     b171 <beam_handler+0x251>
    b160:	48 8b 3d b1 5c 01 00 	mov    0x15cb1(%rip),%rdi        # 20e18 <moon>
    b167:	be 2a 00 00 00       	mov    $0x2a,%esi
    b16c:	e8 7f ca ff ff       	callq  7bf0 <waddch@plt>
      b->left += 1;
    b171:	83 45 04 01          	addl   $0x1,0x4(%rbp)
      b->right += 1;
    b175:	83 45 08 01          	addl   $0x1,0x8(%rbp)
      b->count -= 1;
    b179:	83 6d 10 01          	subl   $0x1,0x10(%rbp)
      add_event (t+TICK(1), beam_handler, client_data);
    b17d:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    b183:	48 89 ee             	mov    %rbp,%rsi
    b186:	f2 0f 58 05 0a e8 00 	addsd  0xe80a(%rip),%xmm0        # 19998 <__PRETTY_FUNCTION__.4560+0x128>
    b18d:	00 
    b18e:	48 8d 3d 8b fd ff ff 	lea    -0x275(%rip),%rdi        # af20 <beam_handler>
    b195:	e8 06 26 00 00       	callq  d7a0 <add_event>
    b19a:	e9 b0 fd ff ff       	jmpq   af4f <beam_handler+0x2f>
    b19f:	90                   	nop
      wmove (moon, LINES-b->y, b->left);
    b1a0:	e8 2b ca ff ff       	callq  7bd0 <wmove@plt>
      for (i=0; i<2; ++i)  waddch (moon, '*');
    b1a5:	48 8b 3d 6c 5c 01 00 	mov    0x15c6c(%rip),%rdi        # 20e18 <moon>
    b1ac:	be 2a 00 00 00       	mov    $0x2a,%esi
    b1b1:	e8 3a ca ff ff       	callq  7bf0 <waddch@plt>
    b1b6:	48 8b 3d 5b 5c 01 00 	mov    0x15c5b(%rip),%rdi        # 20e18 <moon>
    b1bd:	be 2a 00 00 00       	mov    $0x2a,%esi
    b1c2:	e8 29 ca ff ff       	callq  7bf0 <waddch@plt>
      for (i=2; i<b->right-b->left; ++i)  waddch (moon, ' ');
    b1c7:	8b 55 04             	mov    0x4(%rbp),%edx
    b1ca:	8b 45 08             	mov    0x8(%rbp),%eax
    b1cd:	29 d0                	sub    %edx,%eax
    b1cf:	83 f8 02             	cmp    $0x2,%eax
    b1d2:	7e 2c                	jle    b200 <beam_handler+0x2e0>
    b1d4:	bb 02 00 00 00       	mov    $0x2,%ebx
    b1d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    b1e0:	48 8b 3d 31 5c 01 00 	mov    0x15c31(%rip),%rdi        # 20e18 <moon>
    b1e7:	be 20 00 00 00       	mov    $0x20,%esi
    b1ec:	83 c3 01             	add    $0x1,%ebx
    b1ef:	e8 fc c9 ff ff       	callq  7bf0 <waddch@plt>
    b1f4:	8b 55 04             	mov    0x4(%rbp),%edx
    b1f7:	8b 45 08             	mov    0x8(%rbp),%eax
    b1fa:	29 d0                	sub    %edx,%eax
    b1fc:	39 d8                	cmp    %ebx,%eax
    b1fe:	7f e0                	jg     b1e0 <beam_handler+0x2c0>
      if (b->right + b->count >= car_x)  b->count = car_x - b->right - 1;
    b200:	8b 0d 62 5c 01 00    	mov    0x15c62(%rip),%ecx        # 20e68 <car_x>
      b->right = b->left+2;
    b206:	8d 42 02             	lea    0x2(%rdx),%eax
      if (b->right + b->count >= car_x)  b->count = car_x - b->right - 1;
    b209:	83 c2 05             	add    $0x5,%edx
      b->state = bs_CLOUD;
    b20c:	c7 45 00 02 00 00 00 	movl   $0x2,0x0(%rbp)
      b->right = b->left+2;
    b213:	89 45 08             	mov    %eax,0x8(%rbp)
      if (b->right + b->count >= car_x)  b->count = car_x - b->right - 1;
    b216:	89 cb                	mov    %ecx,%ebx
    b218:	29 c3                	sub    %eax,%ebx
    b21a:	89 d8                	mov    %ebx,%eax
    b21c:	83 e8 01             	sub    $0x1,%eax
    b21f:	39 ca                	cmp    %ecx,%edx
    b221:	ba 03 00 00 00       	mov    $0x3,%edx
    b226:	0f 4c c2             	cmovl  %edx,%eax
    b229:	89 45 10             	mov    %eax,0x10(%rbp)
      add_event (t+TICK(1), beam_handler, client_data);
    b22c:	e9 4c ff ff ff       	jmpq   b17d <beam_handler+0x25d>
    b231:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    if (b->y == 5 && (x = meteor_laser_hit (b->left, b->right))) {
    b238:	8b 77 08             	mov    0x8(%rdi),%esi
    b23b:	89 d7                	mov    %edx,%edi
    b23d:	e8 8e 06 00 00       	callq  b8d0 <meteor_laser_hit>
    b242:	89 c2                	mov    %eax,%edx
    b244:	85 c0                	test   %eax,%eax
    b246:	74 40                	je     b288 <beam_handler+0x368>
      if (b->left > car_x - 2)  b->left = car_x - 2;
    b248:	8b 0d 1a 5c 01 00    	mov    0x15c1a(%rip),%ecx        # 20e68 <car_x>
      b->left = x;
    b24e:	89 45 04             	mov    %eax,0x4(%rbp)
      b->count = 0;
    b251:	c7 45 10 00 00 00 00 	movl   $0x0,0x10(%rbp)
      if (b->left > car_x - 2)  b->left = car_x - 2;
    b258:	8b 45 0c             	mov    0xc(%rbp),%eax
    b25b:	8d 71 ff             	lea    -0x1(%rcx),%esi
    b25e:	39 d6                	cmp    %edx,%esi
    b260:	0f 8f 99 fd ff ff    	jg     afff <beam_handler+0xdf>
    b266:	8d 51 fe             	lea    -0x2(%rcx),%edx
    b269:	89 55 04             	mov    %edx,0x4(%rbp)
    b26c:	e9 8e fd ff ff       	jmpq   afff <beam_handler+0xdf>
    b271:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      free (b);
    b278:	48 89 ef             	mov    %rbp,%rdi
    b27b:	e8 70 c4 ff ff       	callq  76f0 <free@plt>
    b280:	e9 ca fc ff ff       	jmpq   af4f <beam_handler+0x2f>
    b285:	0f 1f 00             	nopl   (%rax)
    b288:	8b 55 04             	mov    0x4(%rbp),%edx
    b28b:	8b 45 0c             	mov    0xc(%rbp),%eax
    b28e:	e9 6c fd ff ff       	jmpq   afff <beam_handler+0xdf>
    b293:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      mvwaddch (moon, LINES-b->y, b->left, ' ');
    b298:	e8 33 c9 ff ff       	callq  7bd0 <wmove@plt>
    b29d:	83 f8 ff             	cmp    $0xffffffff,%eax
    b2a0:	74 11                	je     b2b3 <beam_handler+0x393>
    b2a2:	48 8b 3d 6f 5b 01 00 	mov    0x15b6f(%rip),%rdi        # 20e18 <moon>
    b2a9:	be 20 00 00 00       	mov    $0x20,%esi
    b2ae:	e8 3d c9 ff ff       	callq  7bf0 <waddch@plt>
      b->left += 1;
    b2b3:	8b 55 04             	mov    0x4(%rbp),%edx
      b->right += 1;
    b2b6:	8b 45 08             	mov    0x8(%rbp),%eax
      b->left += 1;
    b2b9:	8d 5a 01             	lea    0x1(%rdx),%ebx
      b->right += 1;
    b2bc:	8d 48 01             	lea    0x1(%rax),%ecx
      b->left += 1;
    b2bf:	89 5d 04             	mov    %ebx,0x4(%rbp)
      b->right += 1;
    b2c2:	89 4d 08             	mov    %ecx,0x8(%rbp)
      for (i=b->left; i<b->right; ++i)  mvwaddch (moon, LINES-b->y, i, '.');
    b2c5:	39 c2                	cmp    %eax,%edx
    b2c7:	0f 8d ac fe ff ff    	jge    b179 <beam_handler+0x259>
    b2cd:	0f 1f 00             	nopl   (%rax)
    b2d0:	48 8b 3d 41 5b 01 00 	mov    0x15b41(%rip),%rdi        # 20e18 <moon>
    b2d7:	8b 35 a7 3f 01 00    	mov    0x13fa7(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b2dd:	89 da                	mov    %ebx,%edx
    b2df:	2b 75 0c             	sub    0xc(%rbp),%esi
    b2e2:	e8 e9 c8 ff ff       	callq  7bd0 <wmove@plt>
    b2e7:	83 f8 ff             	cmp    $0xffffffff,%eax
    b2ea:	74 11                	je     b2fd <beam_handler+0x3dd>
    b2ec:	48 8b 3d 25 5b 01 00 	mov    0x15b25(%rip),%rdi        # 20e18 <moon>
    b2f3:	be 2e 00 00 00       	mov    $0x2e,%esi
    b2f8:	e8 f3 c8 ff ff       	callq  7bf0 <waddch@plt>
    b2fd:	83 c3 01             	add    $0x1,%ebx
    b300:	39 5d 08             	cmp    %ebx,0x8(%rbp)
    b303:	7f cb                	jg     b2d0 <beam_handler+0x3b0>
    b305:	e9 6f fe ff ff       	jmpq   b179 <beam_handler+0x259>
    b30a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      if (b->y == 5 && meteor_laser_hit (b->left, b->right)) {
    b310:	8b 75 08             	mov    0x8(%rbp),%esi
    b313:	8b 7d 04             	mov    0x4(%rbp),%edi
    b316:	e8 b5 05 00 00       	callq  b8d0 <meteor_laser_hit>
    b31b:	85 c0                	test   %eax,%eax
    b31d:	0f 84 c0 fc ff ff    	je     afe3 <beam_handler+0xc3>
        b->count = 0;
    b323:	31 c0                	xor    %eax,%eax
    b325:	e9 bf fc ff ff       	jmpq   afe9 <beam_handler+0xc9>
    b32a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000b330 <fire_laser>:

void
fire_laser (double t)
{
    b330:	f3 0f 1e fa          	endbr64 
    b334:	55                   	push   %rbp
    b335:	48 83 ec 10          	sub    $0x10,%rsp
  struct beam *b;

  if (! beam_table.data)  DA_INIT (beam_table, struct beam *);
    b339:	48 83 3d ef 3f 01 00 	cmpq   $0x0,0x13fef(%rip)        # 1f330 <beam_table>
    b340:	00 
{
    b341:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
  if (! beam_table.data)  DA_INIT (beam_table, struct beam *);
    b347:	0f 84 bb 00 00 00    	je     b408 <fire_laser+0xd8>
  b = xmalloc (sizeof (struct beam));
    b34d:	bf 14 00 00 00       	mov    $0x14,%edi
    b352:	e8 09 43 00 00       	callq  f660 <xmalloc>
  b->state = bs_START;
  b->count = 40;
  b->left = car_x-8;
  b->right = car_x;
  b->y = car_y;
  DA_ADD (beam_table, struct beam *, b);
    b357:	8b 35 db 3f 01 00    	mov    0x13fdb(%rip),%esi        # 1f338 <beam_table+0x8>
  b->state = bs_START;
    b35d:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
  b = xmalloc (sizeof (struct beam));
    b363:	48 89 c5             	mov    %rax,%rbp
  b->count = 40;
    b366:	c7 40 10 28 00 00 00 	movl   $0x28,0x10(%rax)
  b->left = car_x-8;
    b36d:	8b 05 f5 5a 01 00    	mov    0x15af5(%rip),%eax        # 20e68 <car_x>
    b373:	8d 50 f8             	lea    -0x8(%rax),%edx
  b->right = car_x;
    b376:	89 45 08             	mov    %eax,0x8(%rbp)
  b->y = car_y;
    b379:	8b 05 ed 5a 01 00    	mov    0x15aed(%rip),%eax        # 20e6c <car_y>
  b->left = car_x-8;
    b37f:	89 55 04             	mov    %edx,0x4(%rbp)
  DA_ADD (beam_table, struct beam *, b);
    b382:	8b 15 b4 3f 01 00    	mov    0x13fb4(%rip),%edx        # 1f33c <beam_table+0xc>
  b->y = car_y;
    b388:	89 45 0c             	mov    %eax,0xc(%rbp)
  DA_ADD (beam_table, struct beam *, b);
    b38b:	48 8b 05 9e 3f 01 00 	mov    0x13f9e(%rip),%rax        # 1f330 <beam_table>
    b392:	39 f2                	cmp    %esi,%edx
    b394:	7d 42                	jge    b3d8 <fire_laser+0xa8>
    b396:	48 63 ca             	movslq %edx,%rcx
  add_event (t+TICK(0.25), beam_handler, b);
    b399:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
  DA_ADD (beam_table, struct beam *, b);
    b39f:	83 c2 01             	add    $0x1,%edx
  add_event (t+TICK(0.25), beam_handler, b);
    b3a2:	48 89 ee             	mov    %rbp,%rsi
  DA_ADD (beam_table, struct beam *, b);
    b3a5:	48 89 2c c8          	mov    %rbp,(%rax,%rcx,8)
  add_event (t+TICK(0.25), beam_handler, b);
    b3a9:	f2 0f 58 05 df e6 00 	addsd  0xe6df(%rip),%xmm0        # 19a90 <__PRETTY_FUNCTION__.4499+0x24>
    b3b0:	00 
    b3b1:	48 8d 3d 68 fb ff ff 	lea    -0x498(%rip),%rdi        # af20 <beam_handler>
  DA_ADD (beam_table, struct beam *, b);
    b3b8:	89 15 7e 3f 01 00    	mov    %edx,0x13f7e(%rip)        # 1f33c <beam_table+0xc>
  add_event (t+TICK(0.25), beam_handler, b);
    b3be:	e8 dd 23 00 00       	callq  d7a0 <add_event>
  adjust_score (-1);
}
    b3c3:	48 83 c4 10          	add    $0x10,%rsp
  adjust_score (-1);
    b3c7:	bf ff ff ff ff       	mov    $0xffffffff,%edi
}
    b3cc:	5d                   	pop    %rbp
  adjust_score (-1);
    b3cd:	e9 8e de ff ff       	jmpq   9260 <adjust_score>
    b3d2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  DA_ADD (beam_table, struct beam *, b);
    b3d8:	83 c6 04             	add    $0x4,%esi
    b3db:	48 8b 3d 4e 3f 01 00 	mov    0x13f4e(%rip),%rdi        # 1f330 <beam_table>
    b3e2:	89 35 50 3f 01 00    	mov    %esi,0x13f50(%rip)        # 1f338 <beam_table+0x8>
    b3e8:	48 63 f6             	movslq %esi,%rsi
    b3eb:	48 c1 e6 03          	shl    $0x3,%rsi
    b3ef:	e8 9c 42 00 00       	callq  f690 <xrealloc>
    b3f4:	8b 15 42 3f 01 00    	mov    0x13f42(%rip),%edx        # 1f33c <beam_table+0xc>
    b3fa:	48 89 05 2f 3f 01 00 	mov    %rax,0x13f2f(%rip)        # 1f330 <beam_table>
    b401:	eb 93                	jmp    b396 <fire_laser+0x66>
    b403:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  if (! beam_table.data)  DA_INIT (beam_table, struct beam *);
    b408:	c7 05 26 3f 01 00 04 	movl   $0x4,0x13f26(%rip)        # 1f338 <beam_table+0x8>
    b40f:	00 00 00 
    b412:	bf 20 00 00 00       	mov    $0x20,%edi
    b417:	e8 44 42 00 00       	callq  f660 <xmalloc>
    b41c:	c7 05 16 3f 01 00 00 	movl   $0x0,0x13f16(%rip)        # 1f33c <beam_table+0xc>
    b423:	00 00 00 
    b426:	48 89 05 03 3f 01 00 	mov    %rax,0x13f03(%rip)        # 1f330 <beam_table>
    b42d:	e9 1b ff ff ff       	jmpq   b34d <fire_laser+0x1d>
    b432:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    b439:	00 00 00 00 
    b43d:	0f 1f 00             	nopl   (%rax)

000000000000b440 <extinguish_laser>:

void
extinguish_laser (void)
/* Clear all laser beams from the screen.  */
{
    b440:	f3 0f 1e fa          	endbr64 
    b444:	41 55                	push   %r13
  int  j;

  remove_event (beam_handler);
    b446:	48 8d 3d d3 fa ff ff 	lea    -0x52d(%rip),%rdi        # af20 <beam_handler>
{
    b44d:	41 54                	push   %r12
    b44f:	55                   	push   %rbp
    b450:	53                   	push   %rbx
    b451:	48 83 ec 08          	sub    $0x8,%rsp
  remove_event (beam_handler);
    b455:	e8 c6 23 00 00       	callq  d820 <remove_event>
  for (j=0; j<beam_table.used; ++j) {
    b45a:	8b 05 dc 3e 01 00    	mov    0x13edc(%rip),%eax        # 1f33c <beam_table+0xc>
    b460:	85 c0                	test   %eax,%eax
    b462:	7e 66                	jle    b4ca <extinguish_laser+0x8a>
    b464:	45 31 e4             	xor    %r12d,%r12d
    b467:	4c 8d 2d c2 3e 01 00 	lea    0x13ec2(%rip),%r13        # 1f330 <beam_table>
    b46e:	66 90                	xchg   %ax,%ax
    struct beam *b = beam_table.data[j];
    b470:	49 8b 45 00          	mov    0x0(%r13),%rax
    b474:	4a 8b 2c e0          	mov    (%rax,%r12,8),%rbp
    int  i;

    for (i=b->left; i<b->right; ++i)  mvwaddch (moon, LINES-b->y, i, ' ');
    b478:	8b 5d 04             	mov    0x4(%rbp),%ebx
    b47b:	3b 5d 08             	cmp    0x8(%rbp),%ebx
    b47e:	7d 35                	jge    b4b5 <extinguish_laser+0x75>
    b480:	48 8b 3d 91 59 01 00 	mov    0x15991(%rip),%rdi        # 20e18 <moon>
    b487:	8b 35 f7 3d 01 00    	mov    0x13df7(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b48d:	89 da                	mov    %ebx,%edx
    b48f:	2b 75 0c             	sub    0xc(%rbp),%esi
    b492:	e8 39 c7 ff ff       	callq  7bd0 <wmove@plt>
    b497:	83 f8 ff             	cmp    $0xffffffff,%eax
    b49a:	74 11                	je     b4ad <extinguish_laser+0x6d>
    b49c:	48 8b 3d 75 59 01 00 	mov    0x15975(%rip),%rdi        # 20e18 <moon>
    b4a3:	be 20 00 00 00       	mov    $0x20,%esi
    b4a8:	e8 43 c7 ff ff       	callq  7bf0 <waddch@plt>
    b4ad:	83 c3 01             	add    $0x1,%ebx
    b4b0:	39 5d 08             	cmp    %ebx,0x8(%rbp)
    b4b3:	7f cb                	jg     b480 <extinguish_laser+0x40>
    free (b);
    b4b5:	48 89 ef             	mov    %rbp,%rdi
    b4b8:	49 83 c4 01          	add    $0x1,%r12
    b4bc:	e8 2f c2 ff ff       	callq  76f0 <free@plt>
  for (j=0; j<beam_table.used; ++j) {
    b4c1:	44 39 25 74 3e 01 00 	cmp    %r12d,0x13e74(%rip)        # 1f33c <beam_table+0xc>
    b4c8:	7f a6                	jg     b470 <extinguish_laser+0x30>
  }
  DA_CLEAR (beam_table);
    b4ca:	c7 05 68 3e 01 00 00 	movl   $0x0,0x13e68(%rip)        # 1f33c <beam_table+0xc>
    b4d1:	00 00 00 
  wnoutrefresh (moon);
    b4d4:	48 8b 3d 3d 59 01 00 	mov    0x1593d(%rip),%rdi        # 20e18 <moon>
}
    b4db:	48 83 c4 08          	add    $0x8,%rsp
    b4df:	5b                   	pop    %rbx
    b4e0:	5d                   	pop    %rbp
    b4e1:	41 5c                	pop    %r12
    b4e3:	41 5d                	pop    %r13
  wnoutrefresh (moon);
    b4e5:	e9 d6 c5 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    b4ea:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000b4f0 <laser_hit>:

int
laser_hit (int x)
/* Return true, if a beam covers location X of the baseline.
 * These beams hit a meteor and stop immediately.  */
{
    b4f0:	f3 0f 1e fa          	endbr64 
  int  j;
  int  res = 0;

  for (j=0; j<beam_table.used; ++j) {
    b4f4:	8b 05 42 3e 01 00    	mov    0x13e42(%rip),%eax        # 1f33c <beam_table+0xc>
    b4fa:	85 c0                	test   %eax,%eax
    b4fc:	7e 5a                	jle    b558 <laser_hit+0x68>
    b4fe:	48 8b 15 2b 3e 01 00 	mov    0x13e2b(%rip),%rdx        # 1f330 <beam_table>
    b505:	8d 48 ff             	lea    -0x1(%rax),%ecx
  int  res = 0;
    b508:	45 31 c0             	xor    %r8d,%r8d
    b50b:	48 8d 42 08          	lea    0x8(%rdx),%rax
    b50f:	48 8d 0c c8          	lea    (%rax,%rcx,8),%rcx
    b513:	eb 0f                	jmp    b524 <laser_hit+0x34>
    b515:	0f 1f 00             	nopl   (%rax)
  for (j=0; j<beam_table.used; ++j) {
    b518:	48 89 c2             	mov    %rax,%rdx
    b51b:	48 39 c8             	cmp    %rcx,%rax
    b51e:	74 31                	je     b551 <laser_hit+0x61>
    b520:	48 83 c0 08          	add    $0x8,%rax
    struct beam *b = beam_table.data[j];
    b524:	48 8b 12             	mov    (%rdx),%rdx
    if (b->y == 5 && b->left >= x && b->right < x) {
    b527:	83 7a 0c 05          	cmpl   $0x5,0xc(%rdx)
    b52b:	75 eb                	jne    b518 <laser_hit+0x28>
    b52d:	39 7a 04             	cmp    %edi,0x4(%rdx)
    b530:	7c e6                	jl     b518 <laser_hit+0x28>
    b532:	39 7a 08             	cmp    %edi,0x8(%rdx)
    b535:	7d e1                	jge    b518 <laser_hit+0x28>
      if (b->state < bs_CLOUD)  b->count = 0;
    b537:	83 3a 01             	cmpl   $0x1,(%rdx)
      res = 1;
    b53a:	41 b8 01 00 00 00    	mov    $0x1,%r8d
      if (b->state < bs_CLOUD)  b->count = 0;
    b540:	77 d6                	ja     b518 <laser_hit+0x28>
    b542:	c7 42 10 00 00 00 00 	movl   $0x0,0x10(%rdx)
  for (j=0; j<beam_table.used; ++j) {
    b549:	48 89 c2             	mov    %rax,%rdx
    b54c:	48 39 c8             	cmp    %rcx,%rax
    b54f:	75 cf                	jne    b520 <laser_hit+0x30>
    }
  }
  return  res;
}
    b551:	44 89 c0             	mov    %r8d,%eax
    b554:	c3                   	retq   
    b555:	0f 1f 00             	nopl   (%rax)
  int  res = 0;
    b558:	45 31 c0             	xor    %r8d,%r8d
}
    b55b:	44 89 c0             	mov    %r8d,%eax
    b55e:	c3                   	retq   
    b55f:	90                   	nop

000000000000b560 <resize_laser>:

void
resize_laser (void)
/* Clear all laser beams from the screen.  */
{
    b560:	f3 0f 1e fa          	endbr64 
    b564:	55                   	push   %rbp
  int  j;

  remove_event (beam_handler);
    b565:	48 8d 3d b4 f9 ff ff 	lea    -0x64c(%rip),%rdi        # af20 <beam_handler>
{
    b56c:	53                   	push   %rbx
    b56d:	48 83 ec 08          	sub    $0x8,%rsp
  remove_event (beam_handler);
    b571:	e8 aa 22 00 00       	callq  d820 <remove_event>
  for (j=0; j<beam_table.used; ++j)  free (beam_table.data[j]);
    b576:	8b 15 c0 3d 01 00    	mov    0x13dc0(%rip),%edx        # 1f33c <beam_table+0xc>
    b57c:	85 d2                	test   %edx,%edx
    b57e:	7e 2c                	jle    b5ac <resize_laser+0x4c>
    b580:	48 8b 05 a9 3d 01 00 	mov    0x13da9(%rip),%rax        # 1f330 <beam_table>
    b587:	83 ea 01             	sub    $0x1,%edx
    b58a:	48 8d 58 08          	lea    0x8(%rax),%rbx
    b58e:	48 8d 2c d3          	lea    (%rbx,%rdx,8),%rbp
    b592:	eb 08                	jmp    b59c <resize_laser+0x3c>
    b594:	0f 1f 40 00          	nopl   0x0(%rax)
    b598:	48 83 c3 08          	add    $0x8,%rbx
    b59c:	48 8b 38             	mov    (%rax),%rdi
    b59f:	e8 4c c1 ff ff       	callq  76f0 <free@plt>
    b5a4:	48 89 d8             	mov    %rbx,%rax
    b5a7:	48 39 eb             	cmp    %rbp,%rbx
    b5aa:	75 ec                	jne    b598 <resize_laser+0x38>
  DA_CLEAR (beam_table);
    b5ac:	c7 05 86 3d 01 00 00 	movl   $0x0,0x13d86(%rip)        # 1f33c <beam_table+0xc>
    b5b3:	00 00 00 
}
    b5b6:	48 83 c4 08          	add    $0x8,%rsp
    b5ba:	5b                   	pop    %rbx
    b5bb:	5d                   	pop    %rbp
    b5bc:	c3                   	retq   
    b5bd:	0f 1f 00             	nopl   (%rax)

000000000000b5c0 <scroll_meteors>:

void
scroll_meteors (void)
/* Move the meteors along with the ground.
 * Handle collisions with the car or with laser beams. */
{
    b5c0:	f3 0f 1e fa          	endbr64 
    b5c4:	41 57                	push   %r15
    b5c6:	41 56                	push   %r14
    b5c8:	41 55                	push   %r13
    b5ca:	41 54                	push   %r12
    b5cc:	55                   	push   %rbp
    b5cd:	53                   	push   %rbx
    b5ce:	48 83 ec 08          	sub    $0x8,%rsp
  int  j;

  if (meteor_table.used > 0)  wnoutrefresh (moon);
    b5d2:	8b 1d 74 3d 01 00    	mov    0x13d74(%rip),%ebx        # 1f34c <meteor_table+0xc>
    b5d8:	85 db                	test   %ebx,%ebx
    b5da:	7e 12                	jle    b5ee <scroll_meteors+0x2e>
    b5dc:	48 8b 3d 35 58 01 00 	mov    0x15835(%rip),%rdi        # 20e18 <moon>
    b5e3:	e8 d8 c4 ff ff       	callq  7ac0 <wnoutrefresh@plt>
    b5e8:	8b 1d 5e 3d 01 00    	mov    0x13d5e(%rip),%ebx        # 1f34c <meteor_table+0xc>
  for (j=meteor_table.used-1; j>=0; --j) {
    b5ee:	83 eb 01             	sub    $0x1,%ebx
    b5f1:	4c 8d 2d 48 3d 01 00 	lea    0x13d48(%rip),%r13        # 1f340 <meteor_table>
  mvwaddch (moon, BASELINE, m->x, m_image[m->state]);
    b5f8:	4c 8d 35 99 e4 00 00 	lea    0xe499(%rip),%r14        # 19a98 <m_image>
    b5ff:	4c 63 e3             	movslq %ebx,%r12
    b602:	49 c1 e4 03          	shl    $0x3,%r12
  for (j=meteor_table.used-1; j>=0; --j) {
    b606:	85 db                	test   %ebx,%ebx
    b608:	79 50                	jns    b65a <scroll_meteors+0x9a>
    b60a:	e9 e6 00 00 00       	jmpq   b6f5 <scroll_meteors+0x135>
    b60f:	90                   	nop
    struct meteor *m = meteor_table.data[j];
    int  res;

    res = scroll_one_meteor (m);
    if (res) {
      DA_REMOVE (meteor_table, struct meteor *, j);
    b610:	44 8b 3d 35 3d 01 00 	mov    0x13d35(%rip),%r15d        # 1f34c <meteor_table+0xc>
    b617:	49 8b 7d 00          	mov    0x0(%r13),%rdi
    b61b:	44 89 fa             	mov    %r15d,%edx
    b61e:	4a 8d 74 27 08       	lea    0x8(%rdi,%r12,1),%rsi
    b623:	4c 01 e7             	add    %r12,%rdi
    b626:	41 83 ef 01          	sub    $0x1,%r15d
    b62a:	29 da                	sub    %ebx,%edx
    b62c:	83 ea 01             	sub    $0x1,%edx
    b62f:	48 63 d2             	movslq %edx,%rdx
    b632:	48 c1 e2 03          	shl    $0x3,%rdx
    b636:	e8 35 c5 ff ff       	callq  7b70 <memmove@plt>
      free (m);
    b63b:	48 89 ef             	mov    %rbp,%rdi
      DA_REMOVE (meteor_table, struct meteor *, j);
    b63e:	44 89 3d 07 3d 01 00 	mov    %r15d,0x13d07(%rip)        # 1f34c <meteor_table+0xc>
      free (m);
    b645:	e8 a6 c0 ff ff       	callq  76f0 <free@plt>
  for (j=meteor_table.used-1; j>=0; --j) {
    b64a:	83 eb 01             	sub    $0x1,%ebx
    b64d:	49 83 ec 08          	sub    $0x8,%r12
    b651:	83 fb ff             	cmp    $0xffffffff,%ebx
    b654:	0f 84 9b 00 00 00    	je     b6f5 <scroll_meteors+0x135>
    struct meteor *m = meteor_table.data[j];
    b65a:	49 8b 45 00          	mov    0x0(%r13),%rax
    b65e:	4a 8b 2c 20          	mov    (%rax,%r12,1),%rbp
  if (m->state == ms_START) {
    b662:	8b 45 00             	mov    0x0(%rbp),%eax
    b665:	8b 55 04             	mov    0x4(%rbp),%edx
    b668:	85 c0                	test   %eax,%eax
    b66a:	0f 85 98 00 00 00    	jne    b708 <scroll_meteors+0x148>
    m->state = ms_BIG;
    b670:	c7 45 00 01 00 00 00 	movl   $0x1,0x0(%rbp)
  m->x += 1;
    b677:	8d 7a 01             	lea    0x1(%rdx),%edi
  if (m->x >= COLS )  return 1;
    b67a:	3b 3d 00 3c 01 00    	cmp    0x13c00(%rip),%edi        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
  m->x += 1;
    b680:	89 7d 04             	mov    %edi,0x4(%rbp)
  if (m->x >= COLS )  return 1;
    b683:	7d 8b                	jge    b610 <scroll_meteors+0x50>
  if (laser_hit (m->x)) {
    b685:	e8 66 fe ff ff       	callq  b4f0 <laser_hit>
    b68a:	85 c0                	test   %eax,%eax
    b68c:	74 12                	je     b6a0 <scroll_meteors+0xe0>
    m->state += 1;
    b68e:	8b 45 00             	mov    0x0(%rbp),%eax
    b691:	83 c0 01             	add    $0x1,%eax
    b694:	89 45 00             	mov    %eax,0x0(%rbp)
    if (m->state > ms_SMALL) {
    b697:	83 f8 03             	cmp    $0x3,%eax
    b69a:	0f 87 a0 00 00 00    	ja     b740 <scroll_meteors+0x180>
  if (car_meteor_hit (m->x))  return  1;
    b6a0:	8b 7d 04             	mov    0x4(%rbp),%edi
    b6a3:	e8 08 f8 ff ff       	callq  aeb0 <car_meteor_hit>
    b6a8:	85 c0                	test   %eax,%eax
    b6aa:	0f 85 60 ff ff ff    	jne    b610 <scroll_meteors+0x50>
  mvwaddch (moon, BASELINE, m->x, m_image[m->state]);
    b6b0:	8b 05 ce 3b 01 00    	mov    0x13bce(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b6b6:	8b 55 04             	mov    0x4(%rbp),%edx
    b6b9:	48 8b 3d 58 57 01 00 	mov    0x15758(%rip),%rdi        # 20e18 <moon>
    b6c0:	8d 70 fb             	lea    -0x5(%rax),%esi
    b6c3:	e8 08 c5 ff ff       	callq  7bd0 <wmove@plt>
    b6c8:	83 f8 ff             	cmp    $0xffffffff,%eax
    b6cb:	0f 84 79 ff ff ff    	je     b64a <scroll_meteors+0x8a>
    b6d1:	8b 45 00             	mov    0x0(%rbp),%eax
    b6d4:	48 8b 3d 3d 57 01 00 	mov    0x1573d(%rip),%rdi        # 20e18 <moon>
  for (j=meteor_table.used-1; j>=0; --j) {
    b6db:	83 eb 01             	sub    $0x1,%ebx
    b6de:	49 83 ec 08          	sub    $0x8,%r12
  mvwaddch (moon, BASELINE, m->x, m_image[m->state]);
    b6e2:	41 0f be 34 06       	movsbl (%r14,%rax,1),%esi
    b6e7:	e8 04 c5 ff ff       	callq  7bf0 <waddch@plt>
  for (j=meteor_table.used-1; j>=0; --j) {
    b6ec:	83 fb ff             	cmp    $0xffffffff,%ebx
    b6ef:	0f 85 65 ff ff ff    	jne    b65a <scroll_meteors+0x9a>
    }
  }
}
    b6f5:	48 83 c4 08          	add    $0x8,%rsp
    b6f9:	5b                   	pop    %rbx
    b6fa:	5d                   	pop    %rbp
    b6fb:	41 5c                	pop    %r12
    b6fd:	41 5d                	pop    %r13
    b6ff:	41 5e                	pop    %r14
    b701:	41 5f                	pop    %r15
    b703:	c3                   	retq   
    b704:	0f 1f 40 00          	nopl   0x0(%rax)
    mvwaddch (moon, BASELINE, m->x, ' ');
    b708:	8b 05 76 3b 01 00    	mov    0x13b76(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b70e:	48 8b 3d 03 57 01 00 	mov    0x15703(%rip),%rdi        # 20e18 <moon>
    b715:	8d 70 fb             	lea    -0x5(%rax),%esi
    b718:	e8 b3 c4 ff ff       	callq  7bd0 <wmove@plt>
    b71d:	83 f8 ff             	cmp    $0xffffffff,%eax
    b720:	74 11                	je     b733 <scroll_meteors+0x173>
    b722:	48 8b 3d ef 56 01 00 	mov    0x156ef(%rip),%rdi        # 20e18 <moon>
    b729:	be 20 00 00 00       	mov    $0x20,%esi
    b72e:	e8 bd c4 ff ff       	callq  7bf0 <waddch@plt>
    b733:	8b 55 04             	mov    0x4(%rbp),%edx
    b736:	e9 3c ff ff ff       	jmpq   b677 <scroll_meteors+0xb7>
    b73b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  adjust_score (13);
    b740:	bf 0d 00 00 00       	mov    $0xd,%edi
    b745:	e8 16 db ff ff       	callq  9260 <adjust_score>
  bonus[m->x] -= 20;
    b74a:	48 63 55 04          	movslq 0x4(%rbp),%rdx
    b74e:	48 8b 05 0b 57 01 00 	mov    0x1570b(%rip),%rax        # 20e60 <bonus>
    b755:	83 2c 90 14          	subl   $0x14,(%rax,%rdx,4)
    if (res) {
    b759:	e9 b2 fe ff ff       	jmpq   b610 <scroll_meteors+0x50>
    b75e:	66 90                	xchg   %ax,%ax

000000000000b760 <place_meteor>:

void
place_meteor (void)
/* Place a new meteor on the ground.  */
{
    b760:	f3 0f 1e fa          	endbr64 
  struct meteor *m;

  if (! meteor_table.data)  DA_INIT (meteor_table, struct meteor *);
    b764:	48 83 3d d4 3b 01 00 	cmpq   $0x0,0x13bd4(%rip)        # 1f340 <meteor_table>
    b76b:	00 
{
    b76c:	53                   	push   %rbx
  if (! meteor_table.data)  DA_INIT (meteor_table, struct meteor *);
    b76d:	0f 84 7d 00 00 00    	je     b7f0 <place_meteor+0x90>
  m = xmalloc (sizeof (struct meteor));
    b773:	bf 08 00 00 00       	mov    $0x8,%edi
    b778:	e8 e3 3e 00 00       	callq  f660 <xmalloc>
  m->state = ms_START;
  m->x = 0;
  bonus[0] += 20;
  DA_ADD (meteor_table, struct meteor *, m);
    b77d:	8b 15 c9 3b 01 00    	mov    0x13bc9(%rip),%edx        # 1f34c <meteor_table+0xc>
    b783:	8b 35 bf 3b 01 00    	mov    0x13bbf(%rip),%esi        # 1f348 <meteor_table+0x8>
  m->state = ms_START;
    b789:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
  m = xmalloc (sizeof (struct meteor));
    b790:	48 89 c3             	mov    %rax,%rbx
  bonus[0] += 20;
    b793:	48 8b 05 c6 56 01 00 	mov    0x156c6(%rip),%rax        # 20e60 <bonus>
    b79a:	83 00 14             	addl   $0x14,(%rax)
  DA_ADD (meteor_table, struct meteor *, m);
    b79d:	48 8b 05 9c 3b 01 00 	mov    0x13b9c(%rip),%rax        # 1f340 <meteor_table>
    b7a4:	39 f2                	cmp    %esi,%edx
    b7a6:	7d 18                	jge    b7c0 <place_meteor+0x60>
    b7a8:	48 63 ca             	movslq %edx,%rcx
    b7ab:	83 c2 01             	add    $0x1,%edx
    b7ae:	48 89 1c c8          	mov    %rbx,(%rax,%rcx,8)
}
    b7b2:	5b                   	pop    %rbx
  DA_ADD (meteor_table, struct meteor *, m);
    b7b3:	89 15 93 3b 01 00    	mov    %edx,0x13b93(%rip)        # 1f34c <meteor_table+0xc>
}
    b7b9:	c3                   	retq   
    b7ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  DA_ADD (meteor_table, struct meteor *, m);
    b7c0:	83 c6 04             	add    $0x4,%esi
    b7c3:	48 8b 3d 76 3b 01 00 	mov    0x13b76(%rip),%rdi        # 1f340 <meteor_table>
    b7ca:	89 35 78 3b 01 00    	mov    %esi,0x13b78(%rip)        # 1f348 <meteor_table+0x8>
    b7d0:	48 63 f6             	movslq %esi,%rsi
    b7d3:	48 c1 e6 03          	shl    $0x3,%rsi
    b7d7:	e8 b4 3e 00 00       	callq  f690 <xrealloc>
    b7dc:	8b 15 6a 3b 01 00    	mov    0x13b6a(%rip),%edx        # 1f34c <meteor_table+0xc>
    b7e2:	48 89 05 57 3b 01 00 	mov    %rax,0x13b57(%rip)        # 1f340 <meteor_table>
    b7e9:	eb bd                	jmp    b7a8 <place_meteor+0x48>
    b7eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  if (! meteor_table.data)  DA_INIT (meteor_table, struct meteor *);
    b7f0:	c7 05 4e 3b 01 00 04 	movl   $0x4,0x13b4e(%rip)        # 1f348 <meteor_table+0x8>
    b7f7:	00 00 00 
    b7fa:	bf 20 00 00 00       	mov    $0x20,%edi
    b7ff:	e8 5c 3e 00 00       	callq  f660 <xmalloc>
    b804:	c7 05 3e 3b 01 00 00 	movl   $0x0,0x13b3e(%rip)        # 1f34c <meteor_table+0xc>
    b80b:	00 00 00 
    b80e:	48 89 05 2b 3b 01 00 	mov    %rax,0x13b2b(%rip)        # 1f340 <meteor_table>
    b815:	e9 59 ff ff ff       	jmpq   b773 <place_meteor+0x13>
    b81a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000b820 <remove_meteors>:

void
remove_meteors (void)
/* Remove all meteors from the ground.
 * Free any resources used by the internal representation.  */
{
    b820:	f3 0f 1e fa          	endbr64 
  int  j;

  if (meteor_table.used > 0)  wnoutrefresh (moon);
    b824:	8b 15 22 3b 01 00    	mov    0x13b22(%rip),%edx        # 1f34c <meteor_table+0xc>
    b82a:	85 d2                	test   %edx,%edx
    b82c:	7f 12                	jg     b840 <remove_meteors+0x20>
  for (j=0; j<meteor_table.used; ++j) {
    struct meteor *m = meteor_table.data[j];
    mvwaddch (moon, BASELINE, m->x, ' ');
    free (m);
  }
  DA_CLEAR (meteor_table);
    b82e:	c7 05 14 3b 01 00 00 	movl   $0x0,0x13b14(%rip)        # 1f34c <meteor_table+0xc>
    b835:	00 00 00 
    b838:	c3                   	retq   
    b839:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
{
    b840:	41 54                	push   %r12
  if (meteor_table.used > 0)  wnoutrefresh (moon);
    b842:	48 8b 3d cf 55 01 00 	mov    0x155cf(%rip),%rdi        # 20e18 <moon>
{
    b849:	55                   	push   %rbp
    b84a:	53                   	push   %rbx
  if (meteor_table.used > 0)  wnoutrefresh (moon);
    b84b:	e8 70 c2 ff ff       	callq  7ac0 <wnoutrefresh@plt>
  for (j=0; j<meteor_table.used; ++j) {
    b850:	8b 05 f6 3a 01 00    	mov    0x13af6(%rip),%eax        # 1f34c <meteor_table+0xc>
    b856:	85 c0                	test   %eax,%eax
    b858:	7e 58                	jle    b8b2 <remove_meteors+0x92>
    b85a:	31 db                	xor    %ebx,%ebx
    b85c:	4c 8d 25 dd 3a 01 00 	lea    0x13add(%rip),%r12        # 1f340 <meteor_table>
    b863:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    struct meteor *m = meteor_table.data[j];
    b868:	49 8b 04 24          	mov    (%r12),%rax
    mvwaddch (moon, BASELINE, m->x, ' ');
    b86c:	48 8b 3d a5 55 01 00 	mov    0x155a5(%rip),%rdi        # 20e18 <moon>
    struct meteor *m = meteor_table.data[j];
    b873:	48 8b 2c d8          	mov    (%rax,%rbx,8),%rbp
    mvwaddch (moon, BASELINE, m->x, ' ');
    b877:	8b 05 07 3a 01 00    	mov    0x13a07(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    b87d:	8b 55 04             	mov    0x4(%rbp),%edx
    b880:	8d 70 fb             	lea    -0x5(%rax),%esi
    b883:	e8 48 c3 ff ff       	callq  7bd0 <wmove@plt>
    b888:	83 f8 ff             	cmp    $0xffffffff,%eax
    b88b:	74 11                	je     b89e <remove_meteors+0x7e>
    b88d:	48 8b 3d 84 55 01 00 	mov    0x15584(%rip),%rdi        # 20e18 <moon>
    b894:	be 20 00 00 00       	mov    $0x20,%esi
    b899:	e8 52 c3 ff ff       	callq  7bf0 <waddch@plt>
    free (m);
    b89e:	48 89 ef             	mov    %rbp,%rdi
    b8a1:	48 83 c3 01          	add    $0x1,%rbx
    b8a5:	e8 46 be ff ff       	callq  76f0 <free@plt>
  for (j=0; j<meteor_table.used; ++j) {
    b8aa:	39 1d 9c 3a 01 00    	cmp    %ebx,0x13a9c(%rip)        # 1f34c <meteor_table+0xc>
    b8b0:	7f b6                	jg     b868 <remove_meteors+0x48>
  DA_CLEAR (meteor_table);
    b8b2:	c7 05 90 3a 01 00 00 	movl   $0x0,0x13a90(%rip)        # 1f34c <meteor_table+0xc>
    b8b9:	00 00 00 
}
    b8bc:	5b                   	pop    %rbx
    b8bd:	5d                   	pop    %rbp
    b8be:	41 5c                	pop    %r12
    b8c0:	c3                   	retq   
    b8c1:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    b8c8:	00 00 00 00 
    b8cc:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000b8d0 <meteor_laser_hit>:
int
meteor_laser_hit (int x0, int x1)
/* Check for meteors at positions >=x0 and <x1.
 * All these are hit by the laser.
 * Return true, if there are any hits.  */
{
    b8d0:	f3 0f 1e fa          	endbr64 
  int  j;

  for (j=0; j<meteor_table.used; ++j) {
    b8d4:	8b 15 72 3a 01 00    	mov    0x13a72(%rip),%edx        # 1f34c <meteor_table+0xc>
{
    b8da:	41 56                	push   %r14
    b8dc:	41 55                	push   %r13
    b8de:	41 54                	push   %r12
    b8e0:	55                   	push   %rbp
    b8e1:	53                   	push   %rbx
  for (j=0; j<meteor_table.used; ++j) {
    b8e2:	85 d2                	test   %edx,%edx
    b8e4:	7e 2c                	jle    b912 <meteor_laser_hit+0x42>
    b8e6:	48 8b 05 53 3a 01 00 	mov    0x13a53(%rip),%rax        # 1f340 <meteor_table>
    b8ed:	83 ea 01             	sub    $0x1,%edx
    b8f0:	48 8d 54 d0 08       	lea    0x8(%rax,%rdx,8),%rdx
    b8f5:	0f 1f 00             	nopl   (%rax)
    struct meteor *m = meteor_table.data[j];
    b8f8:	48 8b 28             	mov    (%rax),%rbp
    if (m->x >= x0 && m->x < x1) {
    b8fb:	44 8b 65 04          	mov    0x4(%rbp),%r12d
    b8ff:	41 39 fc             	cmp    %edi,%r12d
    b902:	7c 05                	jl     b909 <meteor_laser_hit+0x39>
    b904:	41 39 f4             	cmp    %esi,%r12d
    b907:	7c 1f                	jl     b928 <meteor_laser_hit+0x58>
  for (j=0; j<meteor_table.used; ++j) {
    b909:	48 83 c0 08          	add    $0x8,%rax
    b90d:	48 39 c2             	cmp    %rax,%rdx
    b910:	75 e6                	jne    b8f8 <meteor_laser_hit+0x28>
        mvwaddch (moon, BASELINE, m->x, m_image[m->state]);
      }
      return  x;
    }
  }
  return  0;
    b912:	45 31 e4             	xor    %r12d,%r12d
}
    b915:	5b                   	pop    %rbx
    b916:	44 89 e0             	mov    %r12d,%eax
    b919:	5d                   	pop    %rbp
    b91a:	41 5c                	pop    %r12
    b91c:	41 5d                	pop    %r13
    b91e:	41 5e                	pop    %r14
    b920:	c3                   	retq   
    b921:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      m->state += 1;
    b928:	83 45 00 01          	addl   $0x1,0x0(%rbp)
      wnoutrefresh (moon);
    b92c:	48 8b 3d e5 54 01 00 	mov    0x154e5(%rip),%rdi        # 20e18 <moon>
    b933:	e8 88 c1 ff ff       	callq  7ac0 <wnoutrefresh@plt>
        mvwaddch (moon, BASELINE, m->x, ' ');
    b938:	8b 05 46 39 01 00    	mov    0x13946(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
      if (m->state > ms_SMALL) {
    b93e:	83 7d 00 03          	cmpl   $0x3,0x0(%rbp)
        mvwaddch (moon, BASELINE, m->x, ' ');
    b942:	8b 55 04             	mov    0x4(%rbp),%edx
    b945:	48 8b 3d cc 54 01 00 	mov    0x154cc(%rip),%rdi        # 20e18 <moon>
    b94c:	8d 70 fb             	lea    -0x5(%rax),%esi
      if (m->state > ms_SMALL) {
    b94f:	0f 86 bb 00 00 00    	jbe    ba10 <meteor_laser_hit+0x140>
        mvwaddch (moon, BASELINE, m->x, ' ');
    b955:	e8 76 c2 ff ff       	callq  7bd0 <wmove@plt>
    b95a:	83 f8 ff             	cmp    $0xffffffff,%eax
    b95d:	74 11                	je     b970 <meteor_laser_hit+0xa0>
    b95f:	48 8b 3d b2 54 01 00 	mov    0x154b2(%rip),%rdi        # 20e18 <moon>
    b966:	be 20 00 00 00       	mov    $0x20,%esi
    b96b:	e8 80 c2 ff ff       	callq  7bf0 <waddch@plt>
  adjust_score (13);
    b970:	bf 0d 00 00 00       	mov    $0xd,%edi
        DA_REMOVE_VALUE (meteor_table, struct meteor *, m);
    b975:	31 db                	xor    %ebx,%ebx
  adjust_score (13);
    b977:	e8 e4 d8 ff ff       	callq  9260 <adjust_score>
  bonus[m->x] -= 20;
    b97c:	48 63 55 04          	movslq 0x4(%rbp),%rdx
    b980:	48 8b 05 d9 54 01 00 	mov    0x154d9(%rip),%rax        # 20e60 <bonus>
        remove_client_data (m);
    b987:	48 89 ef             	mov    %rbp,%rdi
  bonus[m->x] -= 20;
    b98a:	83 2c 90 14          	subl   $0x14,(%rax,%rdx,4)
        remove_client_data (m);
    b98e:	e8 5d 1f 00 00       	callq  d8f0 <remove_client_data>
        DA_REMOVE_VALUE (meteor_table, struct meteor *, m);
    b993:	44 8b 2d b2 39 01 00 	mov    0x139b2(%rip),%r13d        # 1f34c <meteor_table+0xc>
    b99a:	4c 8b 35 9f 39 01 00 	mov    0x1399f(%rip),%r14        # 1f340 <meteor_table>
    b9a1:	45 85 ed             	test   %r13d,%r13d
    b9a4:	7f 19                	jg     b9bf <meteor_laser_hit+0xef>
    b9a6:	eb 50                	jmp    b9f8 <meteor_laser_hit+0x128>
    b9a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    b9af:	00 
    b9b0:	44 8b 2d 95 39 01 00 	mov    0x13995(%rip),%r13d        # 1f34c <meteor_table+0xc>
    b9b7:	83 c3 01             	add    $0x1,%ebx
    b9ba:	44 39 eb             	cmp    %r13d,%ebx
    b9bd:	7d 39                	jge    b9f8 <meteor_laser_hit+0x128>
    b9bf:	48 63 c3             	movslq %ebx,%rax
    b9c2:	48 c1 e0 03          	shl    $0x3,%rax
    b9c6:	49 8d 3c 06          	lea    (%r14,%rax,1),%rdi
    b9ca:	48 39 2f             	cmp    %rbp,(%rdi)
    b9cd:	75 e1                	jne    b9b0 <meteor_laser_hit+0xe0>
    b9cf:	44 89 ea             	mov    %r13d,%edx
    b9d2:	49 8d 74 06 08       	lea    0x8(%r14,%rax,1),%rsi
    b9d7:	41 83 ed 01          	sub    $0x1,%r13d
    b9db:	29 da                	sub    %ebx,%edx
    b9dd:	83 ea 01             	sub    $0x1,%edx
    b9e0:	48 63 d2             	movslq %edx,%rdx
    b9e3:	48 c1 e2 03          	shl    $0x3,%rdx
    b9e7:	e8 84 c1 ff ff       	callq  7b70 <memmove@plt>
    b9ec:	44 89 2d 59 39 01 00 	mov    %r13d,0x13959(%rip)        # 1f34c <meteor_table+0xc>
    b9f3:	44 39 eb             	cmp    %r13d,%ebx
    b9f6:	7c c7                	jl     b9bf <meteor_laser_hit+0xef>
        free (m);
    b9f8:	48 89 ef             	mov    %rbp,%rdi
    b9fb:	e8 f0 bc ff ff       	callq  76f0 <free@plt>
}
    ba00:	5b                   	pop    %rbx
    ba01:	44 89 e0             	mov    %r12d,%eax
    ba04:	5d                   	pop    %rbp
    ba05:	41 5c                	pop    %r12
    ba07:	41 5d                	pop    %r13
    ba09:	41 5e                	pop    %r14
    ba0b:	c3                   	retq   
    ba0c:	0f 1f 40 00          	nopl   0x0(%rax)
        mvwaddch (moon, BASELINE, m->x, m_image[m->state]);
    ba10:	e8 bb c1 ff ff       	callq  7bd0 <wmove@plt>
    ba15:	83 f8 ff             	cmp    $0xffffffff,%eax
    ba18:	0f 84 f7 fe ff ff    	je     b915 <meteor_laser_hit+0x45>
    ba1e:	8b 45 00             	mov    0x0(%rbp),%eax
    ba21:	48 8d 15 70 e0 00 00 	lea    0xe070(%rip),%rdx        # 19a98 <m_image>
    ba28:	48 8b 3d e9 53 01 00 	mov    0x153e9(%rip),%rdi        # 20e18 <moon>
    ba2f:	0f be 34 02          	movsbl (%rdx,%rax,1),%esi
    ba33:	e8 b8 c1 ff ff       	callq  7bf0 <waddch@plt>
    ba38:	e9 d8 fe ff ff       	jmpq   b915 <meteor_laser_hit+0x45>
    ba3d:	0f 1f 00             	nopl   (%rax)

000000000000ba40 <meteor_car_hit>:
int
meteor_car_hit (int x0, int x1)
/* Check for meteors at positions >=x0 and <x1.
 * All these are destroyed by the landing car.
 * Return true, if there are any hits.  */
{
    ba40:	f3 0f 1e fa          	endbr64 
    ba44:	41 57                	push   %r15
    ba46:	41 56                	push   %r14
    ba48:	41 55                	push   %r13
    ba4a:	41 54                	push   %r12
    ba4c:	55                   	push   %rbp
    ba4d:	53                   	push   %rbx
    ba4e:	48 83 ec 18          	sub    $0x18,%rsp
  int  j;
  int  res = 0;

  for (j=meteor_table.used-1; j>=0; --j) {
    ba52:	48 63 05 f3 38 01 00 	movslq 0x138f3(%rip),%rax        # 1f34c <meteor_table+0xc>
{
    ba59:	89 7c 24 08          	mov    %edi,0x8(%rsp)
  for (j=meteor_table.used-1; j>=0; --j) {
    ba5d:	89 c2                	mov    %eax,%edx
    ba5f:	83 ea 01             	sub    $0x1,%edx
    ba62:	0f 88 48 01 00 00    	js     bbb0 <meteor_car_hit+0x170>
    ba68:	48 63 da             	movslq %edx,%rbx
    ba6b:	89 d2                	mov    %edx,%edx
    ba6d:	41 89 f6             	mov    %esi,%r14d
  int  res = 0;
    ba70:	45 31 ed             	xor    %r13d,%r13d
    ba73:	48 29 d0             	sub    %rdx,%rax
    ba76:	48 c1 e3 03          	shl    $0x3,%rbx
    ba7a:	4c 8d 3d bf 38 01 00 	lea    0x138bf(%rip),%r15        # 1f340 <meteor_table>
    ba81:	4c 8d 24 c5 f0 ff ff 	lea    -0x10(,%rax,8),%r12
    ba88:	ff 
    ba89:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    struct meteor *m = meteor_table.data[j];
    ba90:	49 8b 07             	mov    (%r15),%rax
    ba93:	48 8b 2c 18          	mov    (%rax,%rbx,1),%rbp
    if (m->x >= x0 && m->x < x1) {
    ba97:	8b 55 04             	mov    0x4(%rbp),%edx
    ba9a:	44 39 f2             	cmp    %r14d,%edx
    ba9d:	7d 06                	jge    baa5 <meteor_car_hit+0x65>
    ba9f:	3b 54 24 08          	cmp    0x8(%rsp),%edx
    baa3:	7d 33                	jge    bad8 <meteor_car_hit+0x98>
  for (j=meteor_table.used-1; j>=0; --j) {
    baa5:	48 83 eb 08          	sub    $0x8,%rbx
    baa9:	49 39 dc             	cmp    %rbx,%r12
    baac:	75 e2                	jne    ba90 <meteor_car_hit+0x50>
      DA_REMOVE_VALUE (meteor_table, struct meteor *, m);
      free (m);
      res = 1;
    }
  }
  if (res)  wnoutrefresh (moon);
    baae:	45 85 ed             	test   %r13d,%r13d
    bab1:	74 0c                	je     babf <meteor_car_hit+0x7f>
    bab3:	48 8b 3d 5e 53 01 00 	mov    0x1535e(%rip),%rdi        # 20e18 <moon>
    baba:	e8 01 c0 ff ff       	callq  7ac0 <wnoutrefresh@plt>
  return  res;
}
    babf:	48 83 c4 18          	add    $0x18,%rsp
    bac3:	44 89 e8             	mov    %r13d,%eax
    bac6:	5b                   	pop    %rbx
    bac7:	5d                   	pop    %rbp
    bac8:	41 5c                	pop    %r12
    baca:	41 5d                	pop    %r13
    bacc:	41 5e                	pop    %r14
    bace:	41 5f                	pop    %r15
    bad0:	c3                   	retq   
    bad1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      mvwaddch (moon, BASELINE, m->x, ' ');
    bad8:	8b 05 a6 37 01 00    	mov    0x137a6(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    bade:	48 8b 3d 33 53 01 00 	mov    0x15333(%rip),%rdi        # 20e18 <moon>
    bae5:	8d 70 fb             	lea    -0x5(%rax),%esi
    bae8:	e8 e3 c0 ff ff       	callq  7bd0 <wmove@plt>
    baed:	83 f8 ff             	cmp    $0xffffffff,%eax
    baf0:	0f 85 9a 00 00 00    	jne    bb90 <meteor_car_hit+0x150>
      remove_client_data (m);
    baf6:	48 89 ef             	mov    %rbp,%rdi
    baf9:	e8 f2 1d 00 00       	callq  d8f0 <remove_client_data>
      DA_REMOVE_VALUE (meteor_table, struct meteor *, m);
    bafe:	44 8b 05 47 38 01 00 	mov    0x13847(%rip),%r8d        # 1f34c <meteor_table+0xc>
    bb05:	45 85 c0             	test   %r8d,%r8d
    bb08:	7e 6e                	jle    bb78 <meteor_car_hit+0x138>
    bb0a:	4d 8b 0f             	mov    (%r15),%r9
    bb0d:	45 31 ed             	xor    %r13d,%r13d
    bb10:	eb 16                	jmp    bb28 <meteor_car_hit+0xe8>
    bb12:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    bb18:	44 8b 05 2d 38 01 00 	mov    0x1382d(%rip),%r8d        # 1f34c <meteor_table+0xc>
    bb1f:	41 83 c5 01          	add    $0x1,%r13d
    bb23:	45 39 c5             	cmp    %r8d,%r13d
    bb26:	7d 50                	jge    bb78 <meteor_car_hit+0x138>
    bb28:	49 63 c5             	movslq %r13d,%rax
    bb2b:	48 c1 e0 03          	shl    $0x3,%rax
    bb2f:	49 8d 3c 01          	lea    (%r9,%rax,1),%rdi
    bb33:	48 39 2f             	cmp    %rbp,(%rdi)
    bb36:	75 e0                	jne    bb18 <meteor_car_hit+0xd8>
    bb38:	44 89 c2             	mov    %r8d,%edx
    bb3b:	49 8d 74 01 08       	lea    0x8(%r9,%rax,1),%rsi
    bb40:	44 89 44 24 0c       	mov    %r8d,0xc(%rsp)
    bb45:	44 29 ea             	sub    %r13d,%edx
    bb48:	4c 89 0c 24          	mov    %r9,(%rsp)
    bb4c:	83 ea 01             	sub    $0x1,%edx
    bb4f:	48 63 d2             	movslq %edx,%rdx
    bb52:	48 c1 e2 03          	shl    $0x3,%rdx
    bb56:	e8 15 c0 ff ff       	callq  7b70 <memmove@plt>
    bb5b:	44 8b 44 24 0c       	mov    0xc(%rsp),%r8d
    bb60:	4c 8b 0c 24          	mov    (%rsp),%r9
    bb64:	41 83 e8 01          	sub    $0x1,%r8d
    bb68:	44 89 05 dd 37 01 00 	mov    %r8d,0x137dd(%rip)        # 1f34c <meteor_table+0xc>
    bb6f:	45 39 c5             	cmp    %r8d,%r13d
    bb72:	7c b4                	jl     bb28 <meteor_car_hit+0xe8>
    bb74:	0f 1f 40 00          	nopl   0x0(%rax)
      free (m);
    bb78:	48 89 ef             	mov    %rbp,%rdi
      res = 1;
    bb7b:	41 bd 01 00 00 00    	mov    $0x1,%r13d
      free (m);
    bb81:	e8 6a bb ff ff       	callq  76f0 <free@plt>
      res = 1;
    bb86:	e9 1a ff ff ff       	jmpq   baa5 <meteor_car_hit+0x65>
    bb8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      mvwaddch (moon, BASELINE, m->x, ' ');
    bb90:	48 8b 3d 81 52 01 00 	mov    0x15281(%rip),%rdi        # 20e18 <moon>
    bb97:	be 20 00 00 00       	mov    $0x20,%esi
    bb9c:	e8 4f c0 ff ff       	callq  7bf0 <waddch@plt>
    bba1:	e9 50 ff ff ff       	jmpq   baf6 <meteor_car_hit+0xb6>
    bba6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    bbad:	00 00 00 
  int  res = 0;
    bbb0:	45 31 ed             	xor    %r13d,%r13d
  return  res;
    bbb3:	e9 07 ff ff ff       	jmpq   babf <meteor_car_hit+0x7f>
    bbb8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    bbbf:	00 

000000000000bbc0 <resize_meteors>:

void
resize_meteors (void)
/* Silently remove all meteors, which are no longer visible.  */
{
    bbc0:	f3 0f 1e fa          	endbr64 
  int  j;

  j = 0;
  while (j<meteor_table.used) {
    bbc4:	8b 05 82 37 01 00    	mov    0x13782(%rip),%eax        # 1f34c <meteor_table+0xc>
    bbca:	85 c0                	test   %eax,%eax
    bbcc:	0f 8e ce 00 00 00    	jle    bca0 <resize_meteors+0xe0>
{
    bbd2:	41 57                	push   %r15
    bbd4:	41 56                	push   %r14
    bbd6:	4c 8d 35 63 37 01 00 	lea    0x13763(%rip),%r14        # 1f340 <meteor_table>
    bbdd:	41 55                	push   %r13
    bbdf:	41 54                	push   %r12
    bbe1:	45 31 e4             	xor    %r12d,%r12d
    bbe4:	55                   	push   %rbp
    bbe5:	53                   	push   %rbx
    bbe6:	48 83 ec 08          	sub    $0x8,%rsp
    bbea:	eb 17                	jmp    bc03 <resize_meteors+0x43>
    bbec:	0f 1f 40 00          	nopl   0x0(%rax)
    if (m->x >= COLS) {
      remove_client_data (m);
      DA_REMOVE_VALUE (meteor_table, struct meteor *, m);
      free (m);
    } else {
      ++j;
    bbf0:	8b 1d 56 37 01 00    	mov    0x13756(%rip),%ebx        # 1f34c <meteor_table+0xc>
    bbf6:	41 83 c4 01          	add    $0x1,%r12d
  while (j<meteor_table.used) {
    bbfa:	41 39 dc             	cmp    %ebx,%r12d
    bbfd:	0f 8d 8e 00 00 00    	jge    bc91 <resize_meteors+0xd1>
    struct meteor *m = meteor_table.data[j];
    bc03:	49 8b 16             	mov    (%r14),%rdx
    bc06:	49 63 c4             	movslq %r12d,%rax
    bc09:	4c 8b 2c c2          	mov    (%rdx,%rax,8),%r13
    if (m->x >= COLS) {
    bc0d:	8b 05 6d 36 01 00    	mov    0x1366d(%rip),%eax        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
    bc13:	41 39 45 04          	cmp    %eax,0x4(%r13)
    bc17:	7c d7                	jl     bbf0 <resize_meteors+0x30>
      remove_client_data (m);
    bc19:	4c 89 ef             	mov    %r13,%rdi
    bc1c:	e8 cf 1c 00 00       	callq  d8f0 <remove_client_data>
      DA_REMOVE_VALUE (meteor_table, struct meteor *, m);
    bc21:	8b 1d 25 37 01 00    	mov    0x13725(%rip),%ebx        # 1f34c <meteor_table+0xc>
    bc27:	85 db                	test   %ebx,%ebx
    bc29:	7e 55                	jle    bc80 <resize_meteors+0xc0>
    bc2b:	4d 8b 3e             	mov    (%r14),%r15
    bc2e:	31 ed                	xor    %ebp,%ebp
    bc30:	eb 13                	jmp    bc45 <resize_meteors+0x85>
    bc32:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    bc38:	8b 1d 0e 37 01 00    	mov    0x1370e(%rip),%ebx        # 1f34c <meteor_table+0xc>
    bc3e:	83 c5 01             	add    $0x1,%ebp
    bc41:	39 dd                	cmp    %ebx,%ebp
    bc43:	7d 3b                	jge    bc80 <resize_meteors+0xc0>
    bc45:	48 63 c5             	movslq %ebp,%rax
    bc48:	48 c1 e0 03          	shl    $0x3,%rax
    bc4c:	49 8d 3c 07          	lea    (%r15,%rax,1),%rdi
    bc50:	4c 39 2f             	cmp    %r13,(%rdi)
    bc53:	75 e3                	jne    bc38 <resize_meteors+0x78>
    bc55:	89 da                	mov    %ebx,%edx
    bc57:	49 8d 74 07 08       	lea    0x8(%r15,%rax,1),%rsi
    bc5c:	83 eb 01             	sub    $0x1,%ebx
    bc5f:	29 ea                	sub    %ebp,%edx
    bc61:	83 ea 01             	sub    $0x1,%edx
    bc64:	48 63 d2             	movslq %edx,%rdx
    bc67:	48 c1 e2 03          	shl    $0x3,%rdx
    bc6b:	e8 00 bf ff ff       	callq  7b70 <memmove@plt>
    bc70:	89 1d d6 36 01 00    	mov    %ebx,0x136d6(%rip)        # 1f34c <meteor_table+0xc>
    bc76:	39 dd                	cmp    %ebx,%ebp
    bc78:	7c cb                	jl     bc45 <resize_meteors+0x85>
    bc7a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      free (m);
    bc80:	4c 89 ef             	mov    %r13,%rdi
    bc83:	e8 68 ba ff ff       	callq  76f0 <free@plt>
  while (j<meteor_table.used) {
    bc88:	41 39 dc             	cmp    %ebx,%r12d
    bc8b:	0f 8c 72 ff ff ff    	jl     bc03 <resize_meteors+0x43>
    }
  }
}
    bc91:	48 83 c4 08          	add    $0x8,%rsp
    bc95:	5b                   	pop    %rbx
    bc96:	5d                   	pop    %rbp
    bc97:	41 5c                	pop    %r12
    bc99:	41 5d                	pop    %r13
    bc9b:	41 5e                	pop    %r14
    bc9d:	41 5f                	pop    %r15
    bc9f:	c3                   	retq   
    bca0:	c3                   	retq   
    bca1:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    bca8:	00 00 00 
    bcab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000bcb0 <compare_entries>:

static int
compare_entries (const void *a, const void *b)
/* Compare two score values.
 * This is a comparison function for the use with `qsort'.  */
{
    bcb0:	f3 0f 1e fa          	endbr64 
  const  struct score_entry *aa = a;
  const  struct score_entry *bb = b;
  if (aa->score > bb->score)  return -1;
    bcb4:	8b 16                	mov    (%rsi),%edx
    bcb6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    bcbb:	39 17                	cmp    %edx,(%rdi)
    bcbd:	7f 06                	jg     bcc5 <compare_entries+0x15>
  if (aa->score < bb->score)  return +1;
    bcbf:	0f 9c c0             	setl   %al
    bcc2:	0f b6 c0             	movzbl %al,%eax
  return  0;
}
    bcc5:	c3                   	retq   
    bcc6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    bccd:	00 00 00 

000000000000bcd0 <center_new>:
center_new (void)
/* Prepare `gap' in order to view values around `last_score'.  */
{
  int  i, pos;

  max_line = LINES-11;
    bcd0:	8b 35 ae 35 01 00    	mov    0x135ae(%rip),%esi        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    bcd6:	8d 56 f5             	lea    -0xb(%rsi),%edx
  if (max_line > 25)  max_line = 25;
    bcd9:	83 fa 19             	cmp    $0x19,%edx
    bcdc:	7f 62                	jg     bd40 <center_new+0x70>
    bcde:	8d 46 ef             	lea    -0x11(%rsi),%eax
  max_line = LINES-11;
    bce1:	89 15 79 36 01 00    	mov    %edx,0x13679(%rip)        # 1f360 <max_line>
    bce7:	bf 67 00 00 00       	mov    $0x67,%edi
    bcec:	89 c6                	mov    %eax,%esi
    bcee:	29 d7                	sub    %edx,%edi
    bcf0:	c1 ee 1f             	shr    $0x1f,%esi
    bcf3:	01 c6                	add    %eax,%esi
    bcf5:	d1 fe                	sar    %esi
    bcf7:	83 c6 07             	add    $0x7,%esi

  for (i=1; i<HIGHSCORE_SLOTS; ++i) {
    if (highscore[i].score < last_score)  break;
    bcfa:	8b 0d 6c 36 01 00    	mov    0x1366c(%rip),%ecx        # 1f36c <last_score>
    bd00:	48 8d 15 b9 36 01 00 	lea    0x136b9(%rip),%rdx        # 1f3c0 <highscore+0x40>
  for (i=1; i<HIGHSCORE_SLOTS; ++i) {
    bd07:	b8 01 00 00 00       	mov    $0x1,%eax
    bd0c:	eb 0e                	jmp    bd1c <center_new+0x4c>
    bd0e:	66 90                	xchg   %ax,%ax
    bd10:	83 c0 01             	add    $0x1,%eax
    bd13:	48 83 c2 40          	add    $0x40,%rdx
    bd17:	83 f8 64             	cmp    $0x64,%eax
    bd1a:	74 54                	je     bd70 <center_new+0xa0>
    if (highscore[i].score < last_score)  break;
    bd1c:	39 0a                	cmp    %ecx,(%rdx)
    bd1e:	7d f0                	jge    bd10 <center_new+0x40>
    bd20:	83 c0 04             	add    $0x4,%eax
  }
  --i;

  pos = 7+(max_line-6)/2;
  gap = 1 + (i+4) - pos;
    bd23:	29 f0                	sub    %esi,%eax
  if (gap > limit)  gap = limit;
    bd25:	39 f8                	cmp    %edi,%eax
    bd27:	7f 37                	jg     bd60 <center_new+0x90>
  if (gap < 2)  gap = 0;
    bd29:	83 f8 01             	cmp    $0x1,%eax
    bd2c:	ba 00 00 00 00       	mov    $0x0,%edx
    bd31:	0f 4e c2             	cmovle %edx,%eax
    bd34:	89 05 2a 36 01 00    	mov    %eax,0x1362a(%rip)        # 1f364 <gap>
    bd3a:	c3                   	retq   
    bd3b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  if (max_line > 25)  max_line = 25;
    bd40:	c7 05 16 36 01 00 19 	movl   $0x19,0x13616(%rip)        # 1f360 <max_line>
    bd47:	00 00 00 
    bd4a:	bf 4e 00 00 00       	mov    $0x4e,%edi
    bd4f:	be 10 00 00 00       	mov    $0x10,%esi
    bd54:	eb a4                	jmp    bcfa <center_new+0x2a>
    bd56:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    bd5d:	00 00 00 
  if (gap > limit)  gap = limit;
    bd60:	89 3d fe 35 01 00    	mov    %edi,0x135fe(%rip)        # 1f364 <gap>
  fix_gap ();
}
    bd66:	c3                   	retq   
    bd67:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    bd6e:	00 00 
    bd70:	b8 68 00 00 00       	mov    $0x68,%eax
    bd75:	eb ac                	jmp    bd23 <center_new+0x53>
    bd77:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    bd7e:	00 00 

000000000000bd80 <compose_filename>:
{
    bd80:	41 55                	push   %r13
    bd82:	49 89 f5             	mov    %rsi,%r13
    bd85:	41 54                	push   %r12
    bd87:	55                   	push   %rbp
  if (dir) {
    bd88:	48 85 ff             	test   %rdi,%rdi
    bd8b:	74 53                	je     bde0 <compose_filename+0x60>
    bd8d:	48 89 fd             	mov    %rdi,%rbp
    res = xmalloc (strlen(dir) + 1 + strlen(name) + 1);
    bd90:	e8 ab ba ff ff       	callq  7840 <strlen@plt>
    bd95:	4c 89 ef             	mov    %r13,%rdi
    bd98:	49 89 c4             	mov    %rax,%r12
    bd9b:	e8 a0 ba ff ff       	callq  7840 <strlen@plt>
    bda0:	49 8d 7c 04 02       	lea    0x2(%r12,%rax,1),%rdi
    bda5:	e8 b6 38 00 00       	callq  f660 <xmalloc>
#endif

__fortify_function char *
__NTH (strcpy (char *__restrict __dest, const char *__restrict __src))
{
  return __builtin___strcpy_chk (__dest, __src, __bos (__dest));
    bdaa:	48 89 ee             	mov    %rbp,%rsi
    bdad:	49 89 c4             	mov    %rax,%r12
    bdb0:	48 89 c7             	mov    %rax,%rdi
    bdb3:	e8 a8 b9 ff ff       	callq  7760 <strcpy@plt>


__fortify_function char *
__NTH (strcat (char *__restrict __dest, const char *__restrict __src))
{
  return __builtin___strcat_chk (__dest, __src, __bos (__dest));
    bdb8:	4c 89 e7             	mov    %r12,%rdi
    bdbb:	e8 80 ba ff ff       	callq  7840 <strlen@plt>
    bdc0:	4c 89 ee             	mov    %r13,%rsi
    bdc3:	41 c6 04 04 2f       	movb   $0x2f,(%r12,%rax,1)
    bdc8:	49 8d 7c 04 01       	lea    0x1(%r12,%rax,1),%rdi
    bdcd:	e8 8e b9 ff ff       	callq  7760 <strcpy@plt>
}
    bdd2:	4c 89 e0             	mov    %r12,%rax
    bdd5:	5d                   	pop    %rbp
    bdd6:	41 5c                	pop    %r12
    bdd8:	41 5d                	pop    %r13
    bdda:	c3                   	retq   
    bddb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    bde0:	5d                   	pop    %rbp
    res = xstrdup (name);
    bde1:	48 89 f7             	mov    %rsi,%rdi
}
    bde4:	41 5c                	pop    %r12
    bde6:	41 5d                	pop    %r13
    res = xstrdup (name);
    bde8:	e9 e3 38 00 00       	jmpq   f6d0 <xstrdup>
    bded:	0f 1f 00             	nopl   (%rax)

000000000000bdf0 <do_open>:
{
    bdf0:	41 57                	push   %r15
    bdf2:	41 89 cf             	mov    %ecx,%r15d
    bdf5:	41 56                	push   %r14
    bdf7:	41 55                	push   %r13
    bdf9:	41 89 f5             	mov    %esi,%r13d
    bdfc:	41 54                	push   %r12
    bdfe:	55                   	push   %rbp
    bdff:	48 89 fd             	mov    %rdi,%rbp
    be02:	53                   	push   %rbx
    be03:	48 83 ec 48          	sub    $0x48,%rsp
    be07:	89 54 24 0c          	mov    %edx,0xc(%rsp)
    be0b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    be12:	00 00 
    be14:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
    be19:	31 c0                	xor    %eax,%eax
  if ( is_setgid () )  mode |= S_IWGRP;
    be1b:	e8 40 21 00 00       	callq  df60 <is_setgid>
    be20:	83 f8 01             	cmp    $0x1,%eax
    be23:	19 db                	sbb    %ebx,%ebx
  mask = umask (0);
    be25:	31 ff                	xor    %edi,%edi
    be27:	e8 94 bb ff ff       	callq  79c0 <umask@plt>
  if ( is_setgid () )  mode |= S_IWGRP;
    be2c:	83 e3 f0             	and    $0xfffffff0,%ebx
    be2f:	81 c3 b4 01 00 00    	add    $0x1b4,%ebx
  mask = umask (0);
    be35:	41 89 c6             	mov    %eax,%r14d
    be38:	eb 16                	jmp    be50 <do_open+0x60>
    be3a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  } while (fd == -1 && errno == EINTR);
    be40:	e8 eb b8 ff ff       	callq  7730 <__errno_location@plt>
    be45:	8b 38                	mov    (%rax),%edi
    be47:	83 ff 04             	cmp    $0x4,%edi
    be4a:	0f 85 98 00 00 00    	jne    bee8 <do_open+0xf8>
    }

  if (__va_arg_pack_len () < 1)
    return __open_2 (__path, __oflag);

  return __open_alias (__path, __oflag, __va_arg_pack ());
    be50:	89 da                	mov    %ebx,%edx
    be52:	44 89 ee             	mov    %r13d,%esi
    be55:	48 89 ef             	mov    %rbp,%rdi
    be58:	31 c0                	xor    %eax,%eax
    be5a:	e8 61 bd ff ff       	callq  7bc0 <open@plt>
    be5f:	41 89 c4             	mov    %eax,%r12d
    be62:	83 f8 ff             	cmp    $0xffffffff,%eax
    be65:	74 d9                	je     be40 <do_open+0x50>
  umask (mask);
    be67:	44 89 f7             	mov    %r14d,%edi
    be6a:	48 8d 5c 24 10       	lea    0x10(%rsp),%rbx
    be6f:	e8 4c bb ff ff       	callq  79c0 <umask@plt>
    l.l_type = (lock == 1) ? F_RDLCK : F_WRLCK;
    be74:	31 c0                	xor    %eax,%eax
    be76:	83 7c 24 0c 01       	cmpl   $0x1,0xc(%rsp)
    l.l_start = 0;
    be7b:	48 c7 44 24 18 00 00 	movq   $0x0,0x18(%rsp)
    be82:	00 00 
    l.l_len = 0;
    be84:	48 c7 44 24 20 00 00 	movq   $0x0,0x20(%rsp)
    be8b:	00 00 
    l.l_type = (lock == 1) ? F_RDLCK : F_WRLCK;
    be8d:	0f 95 c0             	setne  %al
    be90:	66 89 44 24 10       	mov    %ax,0x10(%rsp)
    l.l_whence = SEEK_SET;
    be95:	31 c0                	xor    %eax,%eax
    be97:	66 89 44 24 12       	mov    %ax,0x12(%rsp)
    l.l_len = 0;
    be9c:	eb 0e                	jmp    beac <do_open+0xbc>
    be9e:	66 90                	xchg   %ax,%ax
    } while (res == -1 && errno == EINTR);
    bea0:	e8 8b b8 ff ff       	callq  7730 <__errno_location@plt>
    bea5:	8b 38                	mov    (%rax),%edi
    bea7:	83 ff 04             	cmp    $0x4,%edi
    beaa:	75 5c                	jne    bf08 <do_open+0x118>
      res = fcntl (fd, F_SETLKW, &l);
    beac:	31 c0                	xor    %eax,%eax
    beae:	48 89 da             	mov    %rbx,%rdx
    beb1:	be 07 00 00 00       	mov    $0x7,%esi
    beb6:	44 89 e7             	mov    %r12d,%edi
    beb9:	e8 22 b9 ff ff       	callq  77e0 <fcntl@plt>
    } while (res == -1 && errno == EINTR);
    bebe:	83 f8 ff             	cmp    $0xffffffff,%eax
    bec1:	74 dd                	je     bea0 <do_open+0xb0>
}
    bec3:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    bec8:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    becf:	00 00 
    bed1:	75 4e                	jne    bf21 <do_open+0x131>
    bed3:	48 83 c4 48          	add    $0x48,%rsp
    bed7:	44 89 e0             	mov    %r12d,%eax
    beda:	5b                   	pop    %rbx
    bedb:	5d                   	pop    %rbp
    bedc:	41 5c                	pop    %r12
    bede:	41 5d                	pop    %r13
    bee0:	41 5e                	pop    %r14
    bee2:	41 5f                	pop    %r15
    bee4:	c3                   	retq   
    bee5:	0f 1f 00             	nopl   (%rax)
  if (fd == -1 && (must_succeed || (errno != EACCES && errno != ENOENT))) {
    bee8:	45 85 ff             	test   %r15d,%r15d
    beeb:	75 39                	jne    bf26 <do_open+0x136>
    beed:	83 ff 0d             	cmp    $0xd,%edi
    bef0:	74 05                	je     bef7 <do_open+0x107>
    bef2:	83 ff 02             	cmp    $0x2,%edi
    bef5:	75 2f                	jne    bf26 <do_open+0x136>
  umask (mask);
    bef7:	44 89 f7             	mov    %r14d,%edi
    befa:	e8 c1 ba ff ff       	callq  79c0 <umask@plt>
  if (fd != -1 && ! lock_done) {
    beff:	eb c2                	jmp    bec3 <do_open+0xd3>
    bf01:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
      fatal ("Cannot lock score file \"%s\": %s", name, strerror (errno));
    bf08:	e8 83 bd ff ff       	callq  7c90 <strerror@plt>
    bf0d:	48 89 ee             	mov    %rbp,%rsi
    bf10:	48 8d 3d a9 db 00 00 	lea    0xdba9(%rip),%rdi        # 19ac0 <m_image+0x28>
    bf17:	48 89 c2             	mov    %rax,%rdx
    bf1a:	31 c0                	xor    %eax,%eax
    bf1c:	e8 3f 36 00 00       	callq  f560 <fatal>
}
    bf21:	e8 3a b9 ff ff       	callq  7860 <__stack_chk_fail@plt>
    fatal ("Cannot open score file \"%s\": %s", name, strerror (errno));
    bf26:	e8 65 bd ff ff       	callq  7c90 <strerror@plt>
    bf2b:	48 89 ee             	mov    %rbp,%rsi
    bf2e:	48 8d 3d 6b db 00 00 	lea    0xdb6b(%rip),%rdi        # 19aa0 <m_image+0x8>
    bf35:	48 89 c2             	mov    %rax,%rdx
    bf38:	31 c0                	xor    %eax,%eax
    bf3a:	e8 21 36 00 00       	callq  f560 <fatal>
    bf3f:	90                   	nop

000000000000bf40 <randomize_entry>:
  highscore[n].score = 10*(HIGHSCORE_SLOTS-n);
    bf40:	b8 64 00 00 00       	mov    $0x64,%eax
{
    bf45:	41 54                	push   %r12
  highscore[n].score = 10*(HIGHSCORE_SLOTS-n);
    bf47:	4c 8d 25 32 34 01 00 	lea    0x13432(%rip),%r12        # 1f380 <highscore>
{
    bf4e:	55                   	push   %rbp
  highscore[n].score = 10*(HIGHSCORE_SLOTS-n);
    bf4f:	29 f8                	sub    %edi,%eax
    bf51:	48 63 ef             	movslq %edi,%rbp
  highscore[n].date = time (NULL);
    bf54:	31 ff                	xor    %edi,%edi
  highscore[n].score = 10*(HIGHSCORE_SLOTS-n);
    bf56:	48 c1 e5 06          	shl    $0x6,%rbp
    bf5a:	8d 04 80             	lea    (%rax,%rax,4),%eax
{
    bf5d:	53                   	push   %rbx
  highscore[n].score = 10*(HIGHSCORE_SLOTS-n);
    bf5e:	01 c0                	add    %eax,%eax
    bf60:	49 8d 1c 2c          	lea    (%r12,%rbp,1),%rbx
    bf64:	89 03                	mov    %eax,(%rbx)
  highscore[n].level = 1;
    bf66:	c7 43 04 01 00 00 00 	movl   $0x1,0x4(%rbx)
  highscore[n].date = time (NULL);
    bf6d:	e8 6e ba ff ff       	callq  79e0 <time@plt>
  strcpy (highscore[n].name, names[uniform_rnd(13)]);
    bf72:	bf 0d 00 00 00       	mov    $0xd,%edi
  highscore[n].date = time (NULL);
    bf77:	48 89 43 08          	mov    %rax,0x8(%rbx)
  strcpy (highscore[n].name, names[uniform_rnd(13)]);
    bf7b:	e8 80 35 00 00       	callq  f500 <uniform_rnd>
  return __builtin___strcpy_chk (__dest, __src, __bos (__dest));
    bf80:	48 8d 15 59 2a 01 00 	lea    0x12a59(%rip),%rdx        # 1e9e0 <names.6451>
    bf87:	49 8d 7c 2c 10       	lea    0x10(%r12,%rbp,1),%rdi
    bf8c:	48 98                	cltq   
    bf8e:	48 8b 34 c2          	mov    (%rdx,%rax,8),%rsi
    bf92:	ba 28 00 00 00       	mov    $0x28,%edx
    bf97:	e8 74 bb ff ff       	callq  7b10 <__strcpy_chk@plt>
  highscore[n].new = 0;
    bf9c:	c7 43 38 00 00 00 00 	movl   $0x0,0x38(%rbx)
}
    bfa3:	5b                   	pop    %rbx
  highscore_changed = 1;
    bfa4:	c7 05 c6 33 01 00 01 	movl   $0x1,0x133c6(%rip)        # 1f374 <highscore_changed>
    bfab:	00 00 00 
}
    bfae:	5d                   	pop    %rbp
    bfaf:	41 5c                	pop    %r12
    bfb1:	c3                   	retq   
    bfb2:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    bfb9:	00 00 00 00 
    bfbd:	0f 1f 00             	nopl   (%rax)

000000000000bfc0 <refill_old_entries>:
{
    bfc0:	41 55                	push   %r13
  now = time (NULL);
    bfc2:	31 ff                	xor    %edi,%edi
  return  date + 14*day + (HIGHSCORE_SLOTS-1-rank)*rate;
    bfc4:	41 bd 63 00 00 00    	mov    $0x63,%r13d
{
    bfca:	41 54                	push   %r12
    bfcc:	55                   	push   %rbp
    bfcd:	48 8d 2d 74 34 01 00 	lea    0x13474(%rip),%rbp        # 1f448 <highscore+0xc8>
    bfd4:	53                   	push   %rbx
  for (i=3; i<HIGHSCORE_SLOTS; ++i) {
    bfd5:	bb 03 00 00 00       	mov    $0x3,%ebx
{
    bfda:	48 83 ec 08          	sub    $0x8,%rsp
  now = time (NULL);
    bfde:	e8 fd b9 ff ff       	callq  79e0 <time@plt>
    bfe3:	f2 0f 10 1d 7d dd 00 	movsd  0xdd7d(%rip),%xmm3        # 19d68 <__PRETTY_FUNCTION__.6560+0x18>
    bfea:	00 
    bfeb:	f2 0f 10 15 7d dd 00 	movsd  0xdd7d(%rip),%xmm2        # 19d70 <__PRETTY_FUNCTION__.6560+0x20>
    bff2:	00 
    bff3:	49 89 c4             	mov    %rax,%r12
  for (i=3; i<HIGHSCORE_SLOTS; ++i) {
    bff6:	eb 14                	jmp    c00c <refill_old_entries+0x4c>
    bff8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    bfff:	00 
    c000:	83 c3 01             	add    $0x1,%ebx
    c003:	48 83 c5 40          	add    $0x40,%rbp
    c007:	83 fb 64             	cmp    $0x64,%ebx
    c00a:	74 58                	je     c064 <refill_old_entries+0xa4>
  return  date + 14*day + (HIGHSCORE_SLOTS-1-rank)*rate;
    c00c:	44 89 ea             	mov    %r13d,%edx
    c00f:	66 0f ef c9          	pxor   %xmm1,%xmm1
    c013:	66 0f ef c0          	pxor   %xmm0,%xmm0
    c017:	29 da                	sub    %ebx,%edx
    c019:	f2 48 0f 2a 45 00    	cvtsi2sdq 0x0(%rbp),%xmm0
    c01f:	f2 0f 2a ca          	cvtsi2sd %edx,%xmm1
    c023:	f2 0f 58 c3          	addsd  %xmm3,%xmm0
    c027:	f2 0f 59 ca          	mulsd  %xmm2,%xmm1
    c02b:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
    c02f:	f2 48 0f 2c d0       	cvttsd2si %xmm0,%rdx
    if (expire_date (i, highscore[i].date) < now)  randomize_entry (i);
    c034:	49 39 d4             	cmp    %rdx,%r12
    c037:	7e c7                	jle    c000 <refill_old_entries+0x40>
    c039:	89 df                	mov    %ebx,%edi
  for (i=3; i<HIGHSCORE_SLOTS; ++i) {
    c03b:	83 c3 01             	add    $0x1,%ebx
    c03e:	48 83 c5 40          	add    $0x40,%rbp
    if (expire_date (i, highscore[i].date) < now)  randomize_entry (i);
    c042:	e8 f9 fe ff ff       	callq  bf40 <randomize_entry>
    c047:	48 8b 05 22 dd 00 00 	mov    0xdd22(%rip),%rax        # 19d70 <__PRETTY_FUNCTION__.6560+0x20>
    c04e:	66 48 0f 6e d0       	movq   %rax,%xmm2
    c053:	48 8b 05 0e dd 00 00 	mov    0xdd0e(%rip),%rax        # 19d68 <__PRETTY_FUNCTION__.6560+0x18>
    c05a:	66 48 0f 6e d8       	movq   %rax,%xmm3
  for (i=3; i<HIGHSCORE_SLOTS; ++i) {
    c05f:	83 fb 64             	cmp    $0x64,%ebx
    c062:	75 a8                	jne    c00c <refill_old_entries+0x4c>
}
    c064:	48 83 c4 08          	add    $0x8,%rsp
  qsort (highscore, HIGHSCORE_SLOTS, sizeof (struct score_entry),
    c068:	ba 40 00 00 00       	mov    $0x40,%edx
    c06d:	48 8d 0d 3c fc ff ff 	lea    -0x3c4(%rip),%rcx        # bcb0 <compare_entries>
    c074:	be 64 00 00 00       	mov    $0x64,%esi
}
    c079:	5b                   	pop    %rbx
  qsort (highscore, HIGHSCORE_SLOTS, sizeof (struct score_entry),
    c07a:	48 8d 3d ff 32 01 00 	lea    0x132ff(%rip),%rdi        # 1f380 <highscore>
}
    c081:	5d                   	pop    %rbp
    c082:	41 5c                	pop    %r12
    c084:	41 5d                	pop    %r13
  qsort (highscore, HIGHSCORE_SLOTS, sizeof (struct score_entry),
    c086:	e9 25 b7 ff ff       	jmpq   77b0 <qsort@plt>
    c08b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000c090 <highscore_leave>:
  }
}

static void
highscore_leave (void)
{
    c090:	f3 0f 1e fa          	endbr64 
    c094:	48 83 ec 08          	sub    $0x8,%rsp
  print_game_over (0);
    c098:	31 ff                	xor    %edi,%edi
    c09a:	e8 d1 d2 ff ff       	callq  9370 <print_game_over>
  last_score = last_level = 0;
    c09f:	c7 05 bf 32 01 00 00 	movl   $0x0,0x132bf(%rip)        # 1f368 <last_level>
    c0a6:	00 00 00 
    c0a9:	c7 05 b9 32 01 00 00 	movl   $0x0,0x132b9(%rip)        # 1f36c <last_score>
    c0b0:	00 00 00 
}
    c0b3:	48 83 c4 08          	add    $0x8,%rsp
    c0b7:	c3                   	retq   
    c0b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    c0bf:	00 

000000000000c0c0 <update_score_file>:
{
    c0c0:	41 57                	push   %r15
  return  compose_filename (score_dir, SCORE_FILE);
    c0c2:	48 8d 35 b4 da 00 00 	lea    0xdab4(%rip),%rsi        # 19b7d <m_image+0xe5>
{
    c0c9:	41 56                	push   %r14
    c0cb:	41 55                	push   %r13
    c0cd:	41 54                	push   %r12
    c0cf:	55                   	push   %rbp
    c0d0:	53                   	push   %rbx
    c0d1:	48 81 ec 08 01 00 00 	sub    $0x108,%rsp
    c0d8:	48 89 7c 24 50       	mov    %rdi,0x50(%rsp)
  return  compose_filename (score_dir, SCORE_FILE);
    c0dd:	48 8b 3d 5c 31 01 00 	mov    0x1315c(%rip),%rdi        # 1f240 <score_dir>
{
    c0e4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    c0eb:	00 00 
    c0ed:	48 89 84 24 f8 00 00 	mov    %rax,0xf8(%rsp)
    c0f4:	00 
    c0f5:	31 c0                	xor    %eax,%eax
  return  compose_filename (score_dir, SCORE_FILE);
    c0f7:	e8 84 fc ff ff       	callq  bd80 <compose_filename>
    c0fc:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
  uid_t  me = getuid ();
    c101:	e8 6a b7 ff ff       	callq  7870 <getuid@plt>
    c106:	89 c7                	mov    %eax,%edi
  struct passwd *my_passwd = getpwuid (me);
    c108:	e8 23 b7 ff ff       	callq  7830 <getpwuid@plt>
  if (my_passwd && my_passwd->pw_dir) {
    c10d:	48 85 c0             	test   %rax,%rax
    c110:	74 1e                	je     c130 <update_score_file+0x70>
    c112:	48 8b 78 20          	mov    0x20(%rax),%rdi
    c116:	48 85 ff             	test   %rdi,%rdi
    c119:	74 15                	je     c130 <update_score_file+0x70>
    return  compose_filename (my_passwd->pw_dir, "." SCORE_FILE);
    c11b:	48 8d 35 5a da 00 00 	lea    0xda5a(%rip),%rsi        # 19b7c <m_image+0xe4>
    c122:	e8 59 fc ff ff       	callq  bd80 <compose_filename>
    c127:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
    c12c:	eb 13                	jmp    c141 <update_score_file+0x81>
    c12e:	66 90                	xchg   %ax,%ax
    res = xstrdup (name);
    c130:	48 8d 3d 45 da 00 00 	lea    0xda45(%rip),%rdi        # 19b7c <m_image+0xe4>
    c137:	e8 94 35 00 00       	callq  f6d0 <xstrdup>
    c13c:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
  for (method=1; method<=4; ++method) {
    c141:	41 bd 01 00 00 00    	mov    $0x1,%r13d
    switch (method) {
    c147:	41 83 fd 03          	cmp    $0x3,%r13d
    c14b:	0f 84 fd 01 00 00    	je     c34e <update_score_file+0x28e>
    c151:	41 83 fd 04          	cmp    $0x4,%r13d
    c155:	0f 84 26 02 00 00    	je     c381 <update_score_file+0x2c1>
      set_persona (pers_GAME);
    c15b:	31 ff                	xor    %edi,%edi
    switch (method) {
    c15d:	41 83 fd 02          	cmp    $0x2,%r13d
    c161:	0f 84 b9 01 00 00    	je     c320 <update_score_file+0x260>
      set_persona (pers_GAME);
    c167:	e8 24 1e 00 00       	callq  df90 <set_persona>
      in_fd = out_fd = do_open (global_name, O_RDWR, 2, 0);
    c16c:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    c171:	31 c9                	xor    %ecx,%ecx
    c173:	ba 02 00 00 00       	mov    $0x2,%edx
    c178:	be 02 00 00 00       	mov    $0x2,%esi
    c17d:	e8 6e fc ff ff       	callq  bdf0 <do_open>
      in_pers = out_pers = pers_GAME;
    c182:	c7 44 24 4c 00 00 00 	movl   $0x0,0x4c(%rsp)
    c189:	00 
      in_fd = out_fd = do_open (global_name, O_RDWR, 2, 0);
    c18a:	89 44 24 0c          	mov    %eax,0xc(%rsp)
    if (in_fd != -1) {
    c18e:	83 f8 ff             	cmp    $0xffffffff,%eax
    c191:	0f 85 31 03 00 00    	jne    c4c8 <update_score_file+0x408>
  for (method=1; method<=4; ++method) {
    c197:	41 83 c5 01          	add    $0x1,%r13d
    c19b:	41 83 fd 05          	cmp    $0x5,%r13d
    c19f:	75 a6                	jne    c147 <update_score_file+0x87>
    c1a1:	c7 44 24 48 ff ff ff 	movl   $0xffffffff,0x48(%rsp)
    c1a8:	ff 
  if (in_fd == -1)  generate_data ();
    c1a9:	83 7c 24 0c ff       	cmpl   $0xffffffff,0xc(%rsp)
    c1ae:	0f 84 b5 06 00 00    	je     c869 <update_score_file+0x7a9>
  refill_old_entries ();
    c1b4:	e8 07 fe ff ff       	callq  bfc0 <refill_old_entries>
  if (entry)  merge_entry (entry);
    c1b9:	48 83 7c 24 50 00    	cmpq   $0x0,0x50(%rsp)
    c1bf:	74 13                	je     c1d4 <update_score_file+0x114>
  if (entry->score > last->score) {
    c1c1:	48 8b 44 24 50       	mov    0x50(%rsp),%rax
    c1c6:	8b 15 74 4a 01 00    	mov    0x14a74(%rip),%edx        # 20c40 <highscore+0x18c0>
    c1cc:	39 10                	cmp    %edx,(%rax)
    c1ce:	0f 8f b0 06 00 00    	jg     c884 <update_score_file+0x7c4>
  refill_old_entries ();
    c1d4:	e8 e7 fd ff ff       	callq  bfc0 <refill_old_entries>
  assert (out_fd != -1);
    c1d9:	83 7c 24 48 ff       	cmpl   $0xffffffff,0x48(%rsp)
    c1de:	0f 84 33 07 00 00    	je     c917 <update_score_file+0x857>
  if (in_fd != out_fd || highscore_changed) {
    c1e4:	8b 54 24 48          	mov    0x48(%rsp),%edx
    c1e8:	39 54 24 0c          	cmp    %edx,0xc(%rsp)
    c1ec:	0f 85 46 06 00 00    	jne    c838 <update_score_file+0x778>
    c1f2:	8b 35 7c 31 01 00    	mov    0x1317c(%rip),%esi        # 1f374 <highscore_changed>
    c1f8:	85 f6                	test   %esi,%esi
    c1fa:	0f 84 c3 00 00 00    	je     c2c3 <update_score_file+0x203>
    set_persona (out_pers);
    c200:	8b 7c 24 4c          	mov    0x4c(%rsp),%edi
    c204:	e8 87 1d 00 00       	callq  df90 <set_persona>
    c209:	31 c0                	xor    %eax,%eax
    c20b:	48 8d 15 16 d9 00 00 	lea    0xd916(%rip),%rdx        # 19b28 <m_image+0x90>
    c212:	be 01 00 00 00       	mov    $0x1,%esi
    c217:	4c 89 f7             	mov    %r14,%rdi
    c21a:	e8 21 ba ff ff       	callq  7c40 <__fprintf_chk@plt>
  if (res < 0)  fatal ("Score file write error (%s)", strerror (errno));
    c21f:	85 c0                	test   %eax,%eax
    c221:	0f 88 ce 06 00 00    	js     c8f5 <update_score_file+0x835>
    c227:	4c 8d 2d 62 31 01 00 	lea    0x13162(%rip),%r13        # 1f390 <highscore+0x10>
    c22e:	48 8d 9c 24 a0 00 00 	lea    0xa0(%rsp),%rbx
    c235:	00 
    c236:	4d 8d a5 00 19 00 00 	lea    0x1900(%r13),%r12
    c23d:	48 8d 2d 12 da 00 00 	lea    0xda12(%rip),%rbp        # 19c56 <m_image+0x1be>
    c244:	0f 1f 40 00          	nopl   0x0(%rax)
    format_date (date, highscore[i].date);
    c248:	49 8b 75 f8          	mov    -0x8(%r13),%rsi
    c24c:	48 89 df             	mov    %rbx,%rdi
    c24f:	e8 9c 1a 00 00       	callq  dcf0 <format_date>
    c254:	48 83 ec 08          	sub    $0x8,%rsp
    c258:	41 8b 4d f0          	mov    -0x10(%r13),%ecx
    c25c:	48 89 ea             	mov    %rbp,%rdx
    c25f:	41 55                	push   %r13
    c261:	45 8b 45 f4          	mov    -0xc(%r13),%r8d
    c265:	49 89 d9             	mov    %rbx,%r9
    c268:	be 01 00 00 00       	mov    $0x1,%esi
    c26d:	4c 89 f7             	mov    %r14,%rdi
    c270:	31 c0                	xor    %eax,%eax
    c272:	e8 c9 b9 ff ff       	callq  7c40 <__fprintf_chk@plt>
    if (res < 0)  fatal ("Score file write error (%s)", strerror (errno));
    c277:	5a                   	pop    %rdx
    c278:	59                   	pop    %rcx
    c279:	85 c0                	test   %eax,%eax
    c27b:	0f 88 74 06 00 00    	js     c8f5 <update_score_file+0x835>
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    c281:	49 83 c5 40          	add    $0x40,%r13
    c285:	4d 39 e5             	cmp    %r12,%r13
    c288:	75 be                	jne    c248 <update_score_file+0x188>
    int  fd = fileno (score_file);
    c28a:	4c 89 f7             	mov    %r14,%rdi
    c28d:	e8 5e b7 ff ff       	callq  79f0 <fileno@plt>
    long int  pos = ftell (score_file);
    c292:	4c 89 f7             	mov    %r14,%rdi
    int  fd = fileno (score_file);
    c295:	41 89 c4             	mov    %eax,%r12d
    long int  pos = ftell (score_file);
    c298:	e8 13 b7 ff ff       	callq  79b0 <ftell@plt>
    c29d:	48 89 c5             	mov    %rax,%rbp
    if (pos != -1) {
    c2a0:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
    c2a4:	74 13                	je     c2b9 <update_score_file+0x1f9>
      fflush (score_file);
    c2a6:	4c 89 f7             	mov    %r14,%rdi
    c2a9:	e8 b2 b7 ff ff       	callq  7a60 <fflush@plt>
      ftruncate (fd, pos);
    c2ae:	48 89 ee             	mov    %rbp,%rsi
    c2b1:	44 89 e7             	mov    %r12d,%edi
    c2b4:	e8 07 b6 ff ff       	callq  78c0 <ftruncate@plt>
  highscore_changed = 0;
    c2b9:	c7 05 b1 30 01 00 00 	movl   $0x0,0x130b1(%rip)        # 1f374 <highscore_changed>
    c2c0:	00 00 00 
  res = fclose (f);
    c2c3:	4c 89 f7             	mov    %r14,%rdi
    c2c6:	e8 55 b5 ff ff       	callq  7820 <fclose@plt>
  if (res == EOF)  fatal ("Score file write error (%s)", strerror (errno));
    c2cb:	83 f8 ff             	cmp    $0xffffffff,%eax
    c2ce:	0f 84 21 06 00 00    	je     c8f5 <update_score_file+0x835>
  set_persona (pers_USER);
    c2d4:	bf 01 00 00 00       	mov    $0x1,%edi
    c2d9:	e8 b2 1c 00 00       	callq  df90 <set_persona>
  free (local_name);
    c2de:	48 8b 7c 24 28       	mov    0x28(%rsp),%rdi
    c2e3:	e8 08 b4 ff ff       	callq  76f0 <free@plt>
  free (global_name);
    c2e8:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    c2ed:	e8 fe b3 ff ff       	callq  76f0 <free@plt>
}
    c2f2:	48 8b 84 24 f8 00 00 	mov    0xf8(%rsp),%rax
    c2f9:	00 
    c2fa:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    c301:	00 00 
    c303:	0f 85 09 06 00 00    	jne    c912 <update_score_file+0x852>
    c309:	48 81 c4 08 01 00 00 	add    $0x108,%rsp
    c310:	5b                   	pop    %rbx
    c311:	5d                   	pop    %rbp
    c312:	41 5c                	pop    %r12
    c314:	41 5d                	pop    %r13
    c316:	41 5e                	pop    %r14
    c318:	41 5f                	pop    %r15
    c31a:	c3                   	retq   
    c31b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      set_persona (pers_GAME);
    c320:	e8 6b 1c 00 00       	callq  df90 <set_persona>
      out_fd = do_open (global_name, O_WRONLY|O_CREAT, 2, 0);
    c325:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    c32a:	31 c9                	xor    %ecx,%ecx
    c32c:	ba 02 00 00 00       	mov    $0x2,%edx
    c331:	be 41 00 00 00       	mov    $0x41,%esi
    c336:	e8 b5 fa ff ff       	callq  bdf0 <do_open>
    c33b:	89 44 24 48          	mov    %eax,0x48(%rsp)
    if (out_fd != -1)  break;
    c33f:	83 f8 ff             	cmp    $0xffffffff,%eax
    c342:	0f 85 11 05 00 00    	jne    c859 <update_score_file+0x799>
  for (method=1; method<=4; ++method) {
    c348:	41 bd 03 00 00 00    	mov    $0x3,%r13d
      set_persona (pers_USER);
    c34e:	bf 01 00 00 00       	mov    $0x1,%edi
    c353:	e8 38 1c 00 00       	callq  df90 <set_persona>
      in_fd = out_fd = do_open (local_name, O_RDWR, 2, 0);
    c358:	48 8b 7c 24 28       	mov    0x28(%rsp),%rdi
    c35d:	31 c9                	xor    %ecx,%ecx
    c35f:	ba 02 00 00 00       	mov    $0x2,%edx
    c364:	be 02 00 00 00       	mov    $0x2,%esi
    c369:	e8 82 fa ff ff       	callq  bdf0 <do_open>
    c36e:	89 44 24 0c          	mov    %eax,0xc(%rsp)
    if (in_fd != -1) {
    c372:	83 f8 ff             	cmp    $0xffffffff,%eax
    c375:	0f 85 45 01 00 00    	jne    c4c0 <update_score_file+0x400>
  for (method=1; method<=4; ++method) {
    c37b:	41 bd 04 00 00 00    	mov    $0x4,%r13d
      set_persona (pers_USER);
    c381:	bf 01 00 00 00       	mov    $0x1,%edi
    c386:	e8 05 1c 00 00       	callq  df90 <set_persona>
      out_fd = do_open (local_name, O_WRONLY|O_CREAT, 2, 1);
    c38b:	48 8b 7c 24 28       	mov    0x28(%rsp),%rdi
    c390:	b9 01 00 00 00       	mov    $0x1,%ecx
    c395:	ba 02 00 00 00       	mov    $0x2,%edx
    c39a:	be 41 00 00 00       	mov    $0x41,%esi
    c39f:	e8 4c fa ff ff       	callq  bdf0 <do_open>
      set_persona (pers_GAME);
    c3a4:	31 ff                	xor    %edi,%edi
      out_fd = do_open (local_name, O_WRONLY|O_CREAT, 2, 1);
    c3a6:	89 44 24 48          	mov    %eax,0x48(%rsp)
    c3aa:	41 89 c7             	mov    %eax,%r15d
      set_persona (pers_GAME);
    c3ad:	e8 de 1b 00 00       	callq  df90 <set_persona>
      in_fd = do_open (global_name, O_RDONLY, 1, 0);
    c3b2:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    c3b7:	31 c9                	xor    %ecx,%ecx
    c3b9:	31 f6                	xor    %esi,%esi
    c3bb:	ba 01 00 00 00       	mov    $0x1,%edx
    c3c0:	e8 2b fa ff ff       	callq  bdf0 <do_open>
    c3c5:	89 44 24 0c          	mov    %eax,0xc(%rsp)
    c3c9:	89 c3                	mov    %eax,%ebx
    if (in_fd != -1) {
    c3cb:	83 f8 ff             	cmp    $0xffffffff,%eax
    c3ce:	0f 84 62 05 00 00    	je     c936 <update_score_file+0x876>
      set_persona (in_pers);
    c3d4:	31 ff                	xor    %edi,%edi
    c3d6:	e8 b5 1b 00 00       	callq  df90 <set_persona>
      out_pers = pers_USER;
    c3db:	41 39 df             	cmp    %ebx,%r15d
    c3de:	48 8d 35 c1 d4 00 00 	lea    0xd4c1(%rip),%rsi        # 198a6 <__PRETTY_FUNCTION__.4560+0x36>
    c3e5:	48 8d 05 8d d7 00 00 	lea    0xd78d(%rip),%rax        # 19b79 <m_image+0xe1>
    c3ec:	c7 44 24 4c 01 00 00 	movl   $0x1,0x4c(%rsp)
    c3f3:	00 
    c3f4:	48 0f 44 f0          	cmove  %rax,%rsi
      f = fdopen (in_fd, in_fd==out_fd ? "r+" : "r");
    c3f8:	8b 7c 24 0c          	mov    0xc(%rsp),%edi
    c3fc:	e8 1f b7 ff ff       	callq  7b20 <fdopen@plt>
  res = fscanf (score_file, "moon-buggy hiscore file (version %d)\n",
    c401:	48 8d 54 24 68       	lea    0x68(%rsp),%rdx
    c406:	48 8d 35 d3 d6 00 00 	lea    0xd6d3(%rip),%rsi        # 19ae0 <m_image+0x48>
    c40d:	48 89 c7             	mov    %rax,%rdi
      f = fdopen (in_fd, in_fd==out_fd ? "r+" : "r");
    c410:	49 89 c6             	mov    %rax,%r14
  res = fscanf (score_file, "moon-buggy hiscore file (version %d)\n",
    c413:	31 c0                	xor    %eax,%eax
    c415:	e8 56 b3 ff ff       	callq  7770 <__isoc99_fscanf@plt>
    c41a:	89 44 24 30          	mov    %eax,0x30(%rsp)
  if (res != 1) {
    c41e:	83 f8 01             	cmp    $0x1,%eax
    c421:	0f 85 c1 00 00 00    	jne    c4e8 <update_score_file+0x428>
  highscore_changed = 0;
    c427:	c7 05 43 2f 01 00 00 	movl   $0x0,0x12f43(%rip)        # 1f374 <highscore_changed>
    c42e:	00 00 00 
  switch (version) {
    c431:	44 8b 44 24 68       	mov    0x68(%rsp),%r8d
    c436:	41 83 f8 02          	cmp    $0x2,%r8d
    c43a:	0f 84 a0 02 00 00    	je     c6e0 <update_score_file+0x620>
    c440:	41 83 f8 03          	cmp    $0x3,%r8d
    c444:	0f 84 b6 00 00 00    	je     c500 <update_score_file+0x440>
  return __builtin___sprintf_chk (__s, __USE_FORTIFY_LEVEL - 1,
    c44a:	48 8d ac 24 a0 00 00 	lea    0xa0(%rsp),%rbp
    c451:	00 
    c452:	48 8d 0d 74 d7 00 00 	lea    0xd774(%rip),%rcx        # 19bcd <m_image+0x135>
    c459:	ba 50 00 00 00       	mov    $0x50,%edx
    c45e:	31 c0                	xor    %eax,%eax
    c460:	48 89 ef             	mov    %rbp,%rdi
    c463:	be 01 00 00 00       	mov    $0x1,%esi
    c468:	e8 a3 b8 ff ff       	callq  7d10 <__sprintf_chk@plt>
      print_message (buffer);
    c46d:	48 89 ef             	mov    %rbp,%rdi
    c470:	e8 fb be ff ff       	callq  8370 <print_message>
  if (ferror (score_file)) {
    c475:	4c 89 f7             	mov    %r14,%rdi
    c478:	e8 23 b3 ff ff       	callq  77a0 <ferror@plt>
    c47d:	85 c0                	test   %eax,%eax
    c47f:	74 0c                	je     c48d <update_score_file+0x3cd>
    print_message ("Error while reading score file");
    c481:	48 8d 3d 80 d6 00 00 	lea    0xd680(%rip),%rdi        # 19b08 <m_image+0x70>
    c488:	e8 e3 be ff ff       	callq  8370 <print_message>
        fclose (f);
    c48d:	4c 89 f7             	mov    %r14,%rdi
    c490:	e8 8b b3 ff ff       	callq  7820 <fclose@plt>
        if (out_fd == in_fd)
    c495:	8b 54 24 48          	mov    0x48(%rsp),%edx
    c499:	39 54 24 0c          	cmp    %edx,0xc(%rsp)
        in_fd = -1;
    c49d:	c7 44 24 0c ff ff ff 	movl   $0xffffffff,0xc(%rsp)
    c4a4:	ff 
        if (out_fd == in_fd)
    c4a5:	0f 84 ec fc ff ff    	je     c197 <update_score_file+0xd7>
    if (out_fd != -1)  break;
    c4ab:	83 7c 24 48 ff       	cmpl   $0xffffffff,0x48(%rsp)
    c4b0:	0f 84 e1 fc ff ff    	je     c197 <update_score_file+0xd7>
    c4b6:	e9 ee fc ff ff       	jmpq   c1a9 <update_score_file+0xe9>
    c4bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
      in_pers = out_pers = pers_USER;
    c4c0:	c7 44 24 4c 01 00 00 	movl   $0x1,0x4c(%rsp)
    c4c7:	00 
      set_persona (in_pers);
    c4c8:	8b 7c 24 4c          	mov    0x4c(%rsp),%edi
    c4cc:	e8 bf 1a 00 00       	callq  df90 <set_persona>
    c4d1:	8b 44 24 0c          	mov    0xc(%rsp),%eax
      f = fdopen (in_fd, in_fd==out_fd ? "r+" : "r");
    c4d5:	48 8d 35 9d d6 00 00 	lea    0xd69d(%rip),%rsi        # 19b79 <m_image+0xe1>
      set_persona (in_pers);
    c4dc:	89 44 24 48          	mov    %eax,0x48(%rsp)
    c4e0:	e9 13 ff ff ff       	jmpq   c3f8 <update_score_file+0x338>
    c4e5:	0f 1f 00             	nopl   (%rax)
    print_message ("Score file corrupted");
    c4e8:	48 8d 3d 96 d6 00 00 	lea    0xd696(%rip),%rdi        # 19b85 <m_image+0xed>
    c4ef:	e8 7c be ff ff       	callq  8370 <print_message>
      if (read_success) {
    c4f4:	eb 97                	jmp    c48d <update_score_file+0x3cd>
    c4f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    c4fd:	00 00 00 
    c500:	48 8d 44 24 78       	lea    0x78(%rsp),%rax
    c505:	4c 8d bc 24 80 00 00 	lea    0x80(%rsp),%r15
    c50c:	00 
    c50d:	44 89 6c 24 38       	mov    %r13d,0x38(%rsp)
  for (i=0; i<HIGHSCORE_SLOTS && ! err; ++i) {
    c512:	45 31 e4             	xor    %r12d,%r12d
    c515:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
    c51a:	48 8d 44 24 7c       	lea    0x7c(%rsp),%rax
    c51f:	48 8d 1d 6a 2e 01 00 	lea    0x12e6a(%rip),%rbx        # 1f390 <highscore+0x10>
    c526:	49 89 c5             	mov    %rax,%r13
    c529:	4c 89 f8             	mov    %r15,%rax
    c52c:	48 8d ac 24 a0 00 00 	lea    0xa0(%rsp),%rbp
    c533:	00 
    c534:	49 89 df             	mov    %rbx,%r15
    c537:	48 89 c3             	mov    %rax,%rbx
    c53a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    res = fscanf (score_file,
    c540:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
    c545:	31 c0                	xor    %eax,%eax
    c547:	49 89 e9             	mov    %rbp,%r9
    c54a:	49 89 d8             	mov    %rbx,%r8
    c54d:	4c 89 e9             	mov    %r13,%rcx
    c550:	48 8d 35 5d d6 00 00 	lea    0xd65d(%rip),%rsi        # 19bb4 <m_image+0x11c>
    c557:	4c 89 f7             	mov    %r14,%rdi
    c55a:	e8 11 b2 ff ff       	callq  7770 <__isoc99_fscanf@plt>
    if (res != 4) {
    c55f:	83 f8 04             	cmp    $0x4,%eax
    c562:	0f 84 d8 00 00 00    	je     c640 <update_score_file+0x580>
    c568:	48 89 d8             	mov    %rbx,%rax
    highscore[i].score = score;
    c56b:	4d 63 e4             	movslq %r12d,%r12
    c56e:	4c 89 fb             	mov    %r15,%rbx
    c571:	44 8b 6c 24 38       	mov    0x38(%rsp),%r13d
      print_message ("Score file corrupted");
    c576:	48 8d 3d 08 d6 00 00 	lea    0xd608(%rip),%rdi        # 19b85 <m_image+0xed>
    c57d:	49 89 c7             	mov    %rax,%r15
    highscore[i].score = score;
    c580:	49 c1 e4 06          	shl    $0x6,%r12
      print_message ("Score file corrupted");
    c584:	e8 e7 bd ff ff       	callq  8370 <print_message>
    highscore[i].score = score;
    c589:	48 8d 05 f0 2d 01 00 	lea    0x12df0(%rip),%rax        # 1f380 <highscore>
    highscore[i].date = parse_date (date);
    c590:	4c 89 ff             	mov    %r15,%rdi
    highscore[i].score = score;
    c593:	49 01 c4             	add    %rax,%r12
    c596:	8b 44 24 78          	mov    0x78(%rsp),%eax
    c59a:	41 89 04 24          	mov    %eax,(%r12)
    highscore[i].level = level;
    c59e:	8b 44 24 7c          	mov    0x7c(%rsp),%eax
    c5a2:	41 89 44 24 04       	mov    %eax,0x4(%r12)
    highscore[i].date = parse_date (date);
    c5a7:	e8 64 16 00 00       	callq  dc10 <parse_date>

__fortify_function char *
__NTH (strncat (char *__restrict __dest, const char *__restrict __src,
		size_t __len))
{
  return __builtin___strncat_chk (__dest, __src, __len, __bos (__dest));
    c5ac:	b9 28 00 00 00       	mov    $0x28,%ecx
    c5b1:	48 89 ee             	mov    %rbp,%rsi
    c5b4:	48 89 df             	mov    %rbx,%rdi
    c5b7:	49 89 44 24 08       	mov    %rax,0x8(%r12)
    c5bc:	ba 28 00 00 00       	mov    $0x28,%edx
    highscore[i].name[0] = '\0';
    c5c1:	41 c6 44 24 10 00    	movb   $0x0,0x10(%r12)
    highscore[i].new = 0;
    c5c7:	41 c7 44 24 38 00 00 	movl   $0x0,0x38(%r12)
    c5ce:	00 00 
    c5d0:	e8 7b b6 ff ff       	callq  7c50 <__strncat_chk@plt>
  if (ferror (score_file)) {
    c5d5:	4c 89 f7             	mov    %r14,%rdi
    c5d8:	e8 c3 b1 ff ff       	callq  77a0 <ferror@plt>
    c5dd:	85 c0                	test   %eax,%eax
    c5df:	0f 85 ff 02 00 00    	jne    c8e4 <update_score_file+0x824>
  if (ferror (score_file)) {
    c5e5:	4c 89 f7             	mov    %r14,%rdi
    c5e8:	e8 b3 b1 ff ff       	callq  77a0 <ferror@plt>
    c5ed:	85 c0                	test   %eax,%eax
    c5ef:	0f 85 8c fe ff ff    	jne    c481 <update_score_file+0x3c1>
      if (read_success) {
    c5f5:	83 7c 24 30 01       	cmpl   $0x1,0x30(%rsp)
    c5fa:	0f 84 8d fe ff ff    	je     c48d <update_score_file+0x3cd>
        if (in_fd != out_fd) {
    c600:	8b 54 24 48          	mov    0x48(%rsp),%edx
    c604:	39 54 24 0c          	cmp    %edx,0xc(%rsp)
    c608:	0f 84 9a 00 00 00    	je     c6a8 <update_score_file+0x5e8>
          res = fclose (f);
    c60e:	4c 89 f7             	mov    %r14,%rdi
    c611:	e8 0a b2 ff ff       	callq  7820 <fclose@plt>
          if (res == EOF)  fatal ("Score file read error (%s)", strerror (errno));
    c616:	83 f8 ff             	cmp    $0xffffffff,%eax
    c619:	0f 85 8c fe ff ff    	jne    c4ab <update_score_file+0x3eb>
    c61f:	e8 0c b1 ff ff       	callq  7730 <__errno_location@plt>
    c624:	8b 38                	mov    (%rax),%edi
    c626:	e8 65 b6 ff ff       	callq  7c90 <strerror@plt>
    c62b:	48 8d 3d b9 d5 00 00 	lea    0xd5b9(%rip),%rdi        # 19beb <m_image+0x153>
    c632:	48 89 c6             	mov    %rax,%rsi
    c635:	31 c0                	xor    %eax,%eax
    c637:	e8 24 2f 00 00       	callq  f560 <fatal>
    c63c:	0f 1f 40 00          	nopl   0x0(%rax)
    highscore[i].score = score;
    c640:	8b 44 24 78          	mov    0x78(%rsp),%eax
    highscore[i].date = parse_date (date);
    c644:	48 89 df             	mov    %rbx,%rdi
  for (i=0; i<HIGHSCORE_SLOTS && ! err; ++i) {
    c647:	41 83 c4 01          	add    $0x1,%r12d
    highscore[i].score = score;
    c64b:	41 89 47 f0          	mov    %eax,-0x10(%r15)
    highscore[i].level = level;
    c64f:	8b 44 24 7c          	mov    0x7c(%rsp),%eax
    c653:	41 89 47 f4          	mov    %eax,-0xc(%r15)
    highscore[i].date = parse_date (date);
    c657:	e8 b4 15 00 00       	callq  dc10 <parse_date>
    highscore[i].name[0] = '\0';
    c65c:	41 c6 07 00          	movb   $0x0,(%r15)
    c660:	4c 89 ff             	mov    %r15,%rdi
    c663:	48 89 ee             	mov    %rbp,%rsi
    highscore[i].date = parse_date (date);
    c666:	49 89 47 f8          	mov    %rax,-0x8(%r15)
    c66a:	b9 28 00 00 00       	mov    $0x28,%ecx
    c66f:	ba 28 00 00 00       	mov    $0x28,%edx
    c674:	49 83 c7 40          	add    $0x40,%r15
    highscore[i].new = 0;
    c678:	41 c7 47 e8 00 00 00 	movl   $0x0,-0x18(%r15)
    c67f:	00 
    c680:	e8 cb b5 ff ff       	callq  7c50 <__strncat_chk@plt>
  for (i=0; i<HIGHSCORE_SLOTS && ! err; ++i) {
    c685:	41 83 fc 64          	cmp    $0x64,%r12d
    c689:	0f 85 b1 fe ff ff    	jne    c540 <update_score_file+0x480>
    c68f:	c7 44 24 30 00 00 00 	movl   $0x0,0x30(%rsp)
    c696:	00 
    c697:	44 8b 6c 24 38       	mov    0x38(%rsp),%r13d
    c69c:	e9 34 ff ff ff       	jmpq   c5d5 <update_score_file+0x515>
    c6a1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
          res = fseek (f, 0, SEEK_SET);
    c6a8:	31 d2                	xor    %edx,%edx
    c6aa:	31 f6                	xor    %esi,%esi
    c6ac:	4c 89 f7             	mov    %r14,%rdi
    c6af:	e8 1c b4 ff ff       	callq  7ad0 <fseek@plt>
          if (res != 0)  fatal ("Score file seek error (%s)", strerror (errno));
    c6b4:	85 c0                	test   %eax,%eax
    c6b6:	0f 84 ed fa ff ff    	je     c1a9 <update_score_file+0xe9>
    c6bc:	e8 6f b0 ff ff       	callq  7730 <__errno_location@plt>
    c6c1:	8b 38                	mov    (%rax),%edi
    c6c3:	e8 c8 b5 ff ff       	callq  7c90 <strerror@plt>
    c6c8:	48 8d 3d 37 d5 00 00 	lea    0xd537(%rip),%rdi        # 19c06 <m_image+0x16e>
    c6cf:	48 89 c6             	mov    %rax,%rsi
    c6d2:	31 c0                	xor    %eax,%eax
    c6d4:	e8 87 2e 00 00       	callq  f560 <fatal>
    c6d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  switch (version) {
    c6e0:	31 db                	xor    %ebx,%ebx
    c6e2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  for (i=0; i<HIGHSCORE_SLOTS; ++i)  randomize_entry (i);
    c6e8:	89 df                	mov    %ebx,%edi
    c6ea:	83 c3 01             	add    $0x1,%ebx
    c6ed:	e8 4e f8 ff ff       	callq  bf40 <randomize_entry>
    c6f2:	83 fb 64             	cmp    $0x64,%ebx
    c6f5:	75 f1                	jne    c6e8 <update_score_file+0x628>
    c6f7:	48 8d 44 24 78       	lea    0x78(%rsp),%rax
    c6fc:	48 8d 54 24 6c       	lea    0x6c(%rsp),%rdx
    c701:	44 89 6c 24 5c       	mov    %r13d,0x5c(%rsp)
  for (i=0; i<10 && ! err; ++i) {
    c706:	31 db                	xor    %ebx,%ebx
    c708:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
    c70d:	48 8d 44 24 74       	lea    0x74(%rsp),%rax
    c712:	4c 8d 3d 77 2c 01 00 	lea    0x12c77(%rip),%r15        # 1f390 <highscore+0x10>
    c719:	48 89 44 24 30       	mov    %rax,0x30(%rsp)
    c71e:	48 8d 44 24 70       	lea    0x70(%rsp),%rax
    c723:	4d 89 fd             	mov    %r15,%r13
    c726:	48 8d ac 24 a0 00 00 	lea    0xa0(%rsp),%rbp
    c72d:	00 
    c72e:	48 89 54 24 40       	mov    %rdx,0x40(%rsp)
    c733:	48 8d 54 24 7c       	lea    0x7c(%rsp),%rdx
    c738:	49 89 c7             	mov    %rax,%r15
    c73b:	48 89 54 24 38       	mov    %rdx,0x38(%rsp)
    c740:	eb 65                	jmp    c7a7 <update_score_file+0x6e7>
    c742:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    if (res != 6) {
    c748:	c7 44 24 58 00 00 00 	movl   $0x0,0x58(%rsp)
    c74f:	00 
    c750:	83 fb 09             	cmp    $0x9,%ebx
    c753:	41 0f 9e c4          	setle  %r12b
    highscore[i].score = score;
    c757:	8b 44 24 6c          	mov    0x6c(%rsp),%eax
    highscore[i].date = convert_old_date (day, month, year);
    c75b:	8b 54 24 7c          	mov    0x7c(%rsp),%edx
    c75f:	8b 74 24 78          	mov    0x78(%rsp),%esi
    c763:	8b 7c 24 74          	mov    0x74(%rsp),%edi
    highscore[i].score = score;
    c767:	41 89 45 f0          	mov    %eax,-0x10(%r13)
    highscore[i].level = level;
    c76b:	8b 44 24 70          	mov    0x70(%rsp),%eax
    c76f:	41 89 45 f4          	mov    %eax,-0xc(%r13)
    highscore[i].date = convert_old_date (day, month, year);
    c773:	e8 18 15 00 00       	callq  dc90 <convert_old_date>
    highscore[i].name[0] = '\0';
    c778:	41 c6 45 00 00       	movb   $0x0,0x0(%r13)
    c77d:	4c 89 ef             	mov    %r13,%rdi
    c780:	48 89 ee             	mov    %rbp,%rsi
    highscore[i].date = convert_old_date (day, month, year);
    c783:	49 89 45 f8          	mov    %rax,-0x8(%r13)
    c787:	b9 28 00 00 00       	mov    $0x28,%ecx
    c78c:	ba 28 00 00 00       	mov    $0x28,%edx
    c791:	49 83 c5 40          	add    $0x40,%r13
    highscore[i].new = 0;
    c795:	41 c7 45 e8 00 00 00 	movl   $0x0,-0x18(%r13)
    c79c:	00 
    c79d:	e8 ae b4 ff ff       	callq  7c50 <__strncat_chk@plt>
  for (i=0; i<10 && ! err; ++i) {
    c7a2:	45 84 e4             	test   %r12b,%r12b
    c7a5:	74 59                	je     c800 <update_score_file+0x740>
    res = fscanf (score_file,
    c7a7:	55                   	push   %rbp
    c7a8:	4c 89 f7             	mov    %r14,%rdi
    c7ab:	4c 89 f9             	mov    %r15,%rcx
    c7ae:	48 8d 35 e5 d3 00 00 	lea    0xd3e5(%rip),%rsi        # 19b9a <m_image+0x102>
    c7b5:	ff 74 24 40          	pushq  0x40(%rsp)
    c7b9:	4c 8b 4c 24 20       	mov    0x20(%rsp),%r9
    c7be:	31 c0                	xor    %eax,%eax
    c7c0:	83 c3 01             	add    $0x1,%ebx
    c7c3:	4c 8b 44 24 40       	mov    0x40(%rsp),%r8
    c7c8:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
    c7cd:	e8 9e af ff ff       	callq  7770 <__isoc99_fscanf@plt>
    if (res != 6) {
    c7d2:	5f                   	pop    %rdi
    c7d3:	41 58                	pop    %r8
    c7d5:	83 f8 06             	cmp    $0x6,%eax
    c7d8:	0f 84 6a ff ff ff    	je     c748 <update_score_file+0x688>
      print_message ("Score file corrupted");
    c7de:	48 8d 3d a0 d3 00 00 	lea    0xd3a0(%rip),%rdi        # 19b85 <m_image+0xed>
    c7e5:	45 31 e4             	xor    %r12d,%r12d
    c7e8:	e8 83 bb ff ff       	callq  8370 <print_message>
      err = 1;
    c7ed:	c7 44 24 58 01 00 00 	movl   $0x1,0x58(%rsp)
    c7f4:	00 
    c7f5:	e9 5d ff ff ff       	jmpq   c757 <update_score_file+0x697>
    c7fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  qsort (highscore, HIGHSCORE_SLOTS, sizeof (struct score_entry),
    c800:	ba 40 00 00 00       	mov    $0x40,%edx
    c805:	48 8d 0d a4 f4 ff ff 	lea    -0xb5c(%rip),%rcx        # bcb0 <compare_entries>
    c80c:	be 64 00 00 00       	mov    $0x64,%esi
    c811:	44 8b 6c 24 5c       	mov    0x5c(%rsp),%r13d
    c816:	48 8d 3d 63 2b 01 00 	lea    0x12b63(%rip),%rdi        # 1f380 <highscore>
    c81d:	e8 8e af ff ff       	callq  77b0 <qsort@plt>
  refill_old_entries ();
    c822:	e8 99 f7 ff ff       	callq  bfc0 <refill_old_entries>
    break;
    c827:	8b 44 24 58          	mov    0x58(%rsp),%eax
    c82b:	89 44 24 30          	mov    %eax,0x30(%rsp)
    c82f:	e9 b1 fd ff ff       	jmpq   c5e5 <update_score_file+0x525>
    c834:	0f 1f 40 00          	nopl   0x0(%rax)
    set_persona (out_pers);
    c838:	8b 7c 24 4c          	mov    0x4c(%rsp),%edi
    c83c:	e8 4f 17 00 00       	callq  df90 <set_persona>
    if (in_fd != out_fd)  f = fdopen (out_fd, "w");
    c841:	8b 7c 24 48          	mov    0x48(%rsp),%edi
    c845:	48 8d 35 4d 3b 00 00 	lea    0x3b4d(%rip),%rsi        # 10399 <_IO_stdin_used+0x399>
    c84c:	e8 cf b2 ff ff       	callq  7b20 <fdopen@plt>
    c851:	49 89 c6             	mov    %rax,%r14
    c854:	e9 b0 f9 ff ff       	jmpq   c209 <update_score_file+0x149>
      out_pers = pers_GAME;
    c859:	c7 44 24 4c 00 00 00 	movl   $0x0,0x4c(%rsp)
    c860:	00 
  if (in_fd == -1)  generate_data ();
    c861:	c7 44 24 0c ff ff ff 	movl   $0xffffffff,0xc(%rsp)
    c868:	ff 
  for (i=0; i<HIGHSCORE_SLOTS; ++i)  randomize_entry (i);
    c869:	31 db                	xor    %ebx,%ebx
    c86b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    c870:	89 df                	mov    %ebx,%edi
    c872:	83 c3 01             	add    $0x1,%ebx
    c875:	e8 c6 f6 ff ff       	callq  bf40 <randomize_entry>
    c87a:	83 fb 64             	cmp    $0x64,%ebx
    c87d:	75 f1                	jne    c870 <update_score_file+0x7b0>
    c87f:	e9 30 f9 ff ff       	jmpq   c1b4 <update_score_file+0xf4>
  return __builtin___memcpy_chk (__dest, __src, __len, __bos0 (__dest));
    c884:	66 0f 6f 00          	movdqa (%rax),%xmm0
    qsort (highscore, HIGHSCORE_SLOTS, sizeof (struct score_entry),
    c888:	ba 40 00 00 00       	mov    $0x40,%edx
    c88d:	48 8d 0d 1c f4 ff ff 	lea    -0xbe4(%rip),%rcx        # bcb0 <compare_entries>
    c894:	be 64 00 00 00       	mov    $0x64,%esi
    c899:	48 8d 3d e0 2a 01 00 	lea    0x12ae0(%rip),%rdi        # 1f380 <highscore>
    c8a0:	0f 29 05 99 43 01 00 	movaps %xmm0,0x14399(%rip)        # 20c40 <highscore+0x18c0>
    c8a7:	66 0f 6f 50 10       	movdqa 0x10(%rax),%xmm2
    c8ac:	0f 29 15 9d 43 01 00 	movaps %xmm2,0x1439d(%rip)        # 20c50 <highscore+0x18d0>
    c8b3:	66 0f 6f 60 20       	movdqa 0x20(%rax),%xmm4
    c8b8:	0f 29 25 a1 43 01 00 	movaps %xmm4,0x143a1(%rip)        # 20c60 <highscore+0x18e0>
    c8bf:	66 0f 6f 70 30       	movdqa 0x30(%rax),%xmm6
    c8c4:	0f 29 64 24 10       	movaps %xmm4,0x10(%rsp)
    c8c9:	0f 29 35 a0 43 01 00 	movaps %xmm6,0x143a0(%rip)        # 20c70 <highscore+0x18f0>
    c8d0:	e8 db ae ff ff       	callq  77b0 <qsort@plt>
    highscore_changed = 1;
    c8d5:	c7 05 95 2a 01 00 01 	movl   $0x1,0x12a95(%rip)        # 1f374 <highscore_changed>
    c8dc:	00 00 00 
    c8df:	e9 f0 f8 ff ff       	jmpq   c1d4 <update_score_file+0x114>
    print_message ("Error while reading score file");
    c8e4:	48 8d 3d 1d d2 00 00 	lea    0xd21d(%rip),%rdi        # 19b08 <m_image+0x70>
    c8eb:	e8 80 ba ff ff       	callq  8370 <print_message>
    err = 1;
    c8f0:	e9 80 fb ff ff       	jmpq   c475 <update_score_file+0x3b5>
  if (res == EOF)  fatal ("Score file write error (%s)", strerror (errno));
    c8f5:	e8 36 ae ff ff       	callq  7730 <__errno_location@plt>
    c8fa:	8b 38                	mov    (%rax),%edi
    c8fc:	e8 8f b3 ff ff       	callq  7c90 <strerror@plt>
    c901:	48 8d 3d 32 d3 00 00 	lea    0xd332(%rip),%rdi        # 19c3a <m_image+0x1a2>
    c908:	48 89 c6             	mov    %rax,%rsi
    c90b:	31 c0                	xor    %eax,%eax
    c90d:	e8 4e 2c 00 00       	callq  f560 <fatal>
}
    c912:	e8 49 af ff ff       	callq  7860 <__stack_chk_fail@plt>
  assert (out_fd != -1);
    c917:	48 8d 0d 32 d4 00 00 	lea    0xd432(%rip),%rcx        # 19d50 <__PRETTY_FUNCTION__.6560>
    c91e:	ba d9 01 00 00       	mov    $0x1d9,%edx
    c923:	48 8d 35 f7 d2 00 00 	lea    0xd2f7(%rip),%rsi        # 19c21 <m_image+0x189>
    c92a:	48 8d 3d fc d2 00 00 	lea    0xd2fc(%rip),%rdi        # 19c2d <m_image+0x195>
    c931:	e8 aa af ff ff       	callq  78e0 <__assert_fail@plt>
    if (out_fd != -1)  break;
    c936:	83 7c 24 48 ff       	cmpl   $0xffffffff,0x48(%rsp)
      out_pers = pers_USER;
    c93b:	c7 44 24 4c 01 00 00 	movl   $0x1,0x4c(%rsp)
    c942:	00 
    if (out_fd != -1)  break;
    c943:	0f 84 20 ff ff ff    	je     c869 <update_score_file+0x7a9>
    c949:	e9 13 ff ff ff       	jmpq   c861 <update_score_file+0x7a1>
    c94e:	66 90                	xchg   %ax,%ax

000000000000c950 <enter_name_h>:
{
    c950:	f3 0f 1e fa          	endbr64 
    c954:	53                   	push   %rbx
  entry.date = time (NULL);
    c955:	31 ff                	xor    %edi,%edi
{
    c957:	48 83 ec 50          	sub    $0x50,%rsp
    c95b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    c962:	00 00 
    c964:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
    c969:	31 c0                	xor    %eax,%eax
  entry.score = last_score;
    c96b:	8b 05 fb 29 01 00    	mov    0x129fb(%rip),%eax        # 1f36c <last_score>
    c971:	48 8d 5c 24 10       	lea    0x10(%rsp),%rbx
    c976:	89 04 24             	mov    %eax,(%rsp)
  entry.level = last_level;
    c979:	8b 05 e9 29 01 00    	mov    0x129e9(%rip),%eax        # 1f368 <last_level>
    c97f:	89 44 24 04          	mov    %eax,0x4(%rsp)
  entry.date = time (NULL);
    c983:	e8 58 b0 ff ff       	callq  79e0 <time@plt>
    c988:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    c98d:	eb 06                	jmp    c995 <enter_name_h+0x45>
    c98f:	90                   	nop
    mode_redraw ();
    c990:	e8 ab be ff ff       	callq  8840 <mode_redraw>
  res = get_real_user_name (entry.name, MAX_NAME_CHARS);
    c995:	be 28 00 00 00       	mov    $0x28,%esi
    c99a:	48 89 df             	mov    %rbx,%rdi
  entry.name[0] = '\0';
    c99d:	c6 44 24 10 00       	movb   $0x0,0x10(%rsp)
  res = get_real_user_name (entry.name, MAX_NAME_CHARS);
    c9a2:	e8 09 09 00 00       	callq  d2b0 <get_real_user_name>
  if (res == ERR || ! entry.name[0]) {
    c9a7:	83 f8 ff             	cmp    $0xffffffff,%eax
    c9aa:	74 e4                	je     c990 <enter_name_h+0x40>
    c9ac:	80 7c 24 10 00       	cmpb   $0x0,0x10(%rsp)
    c9b1:	74 dd                	je     c990 <enter_name_h+0x40>
  print_message ("writing score file ...");
    c9b3:	48 8d 3d ae d2 00 00 	lea    0xd2ae(%rip),%rdi        # 19c68 <m_image+0x1d0>
  entry.new = 1;
    c9ba:	c7 44 24 38 01 00 00 	movl   $0x1,0x38(%rsp)
    c9c1:	00 
  print_message ("writing score file ...");
    c9c2:	e8 a9 b9 ff ff       	callq  8370 <print_message>
  doupdate ();
    c9c7:	e8 d4 b1 ff ff       	callq  7ba0 <doupdate@plt>
  block_all ();
    c9cc:	e8 ef 19 00 00       	callq  e3c0 <block_all>
  update_score_file (&entry);
    c9d1:	48 89 e7             	mov    %rsp,%rdi
    c9d4:	e8 e7 f6 ff ff       	callq  c0c0 <update_score_file>
  unblock ();
    c9d9:	e8 02 1a 00 00       	callq  e3e0 <unblock>
  mode_redraw ();
    c9de:	e8 5d be ff ff       	callq  8840 <mode_redraw>
}
    c9e3:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    c9e8:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    c9ef:	00 00 
    c9f1:	75 06                	jne    c9f9 <enter_name_h+0xa9>
    c9f3:	48 83 c4 50          	add    $0x50,%rsp
    c9f7:	5b                   	pop    %rbx
    c9f8:	c3                   	retq   
    c9f9:	e8 62 ae ff ff       	callq  7860 <__stack_chk_fail@plt>
    c9fe:	66 90                	xchg   %ax,%ax

000000000000ca00 <print_scores>:
{
    ca00:	41 57                	push   %r15
  now = time (NULL);
    ca02:	31 ff                	xor    %edi,%edi
{
    ca04:	41 56                	push   %r14
    ca06:	41 55                	push   %r13
    ca08:	41 54                	push   %r12
    ca0a:	55                   	push   %rbp
    ca0b:	53                   	push   %rbx
    ca0c:	48 83 ec 58          	sub    $0x58,%rsp
    ca10:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    ca17:	00 00 
    ca19:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
    ca1e:	31 c0                	xor    %eax,%eax
  now = time (NULL);
    ca20:	e8 bb af ff ff       	callq  79e0 <time@plt>
  mvwaddstr (moon, 1, 5, "rank   score lvl     date  expires  name");
    ca25:	ba 05 00 00 00       	mov    $0x5,%edx
    ca2a:	be 01 00 00 00       	mov    $0x1,%esi
    ca2f:	48 8b 3d e2 43 01 00 	mov    0x143e2(%rip),%rdi        # 20e18 <moon>
  now = time (NULL);
    ca36:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  mvwaddstr (moon, 1, 5, "rank   score lvl     date  expires  name");
    ca3b:	e8 90 b1 ff ff       	callq  7bd0 <wmove@plt>
    ca40:	83 f8 ff             	cmp    $0xffffffff,%eax
    ca43:	74 18                	je     ca5d <print_scores+0x5d>
    ca45:	48 8b 3d cc 43 01 00 	mov    0x143cc(%rip),%rdi        # 20e18 <moon>
    ca4c:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    ca51:	48 8d 35 f8 d0 00 00 	lea    0xd0f8(%rip),%rsi        # 19b50 <m_image+0xb8>
    ca58:	e8 43 b2 ff ff       	callq  7ca0 <waddnstr@plt>
    format_relative_time (expire, dt);
    ca5d:	48 8d 44 24 30       	lea    0x30(%rsp),%rax
{
    ca62:	c7 44 24 08 ff ff ff 	movl   $0xffffffff,0x8(%rsp)
    ca69:	ff 
    ca6a:	31 db                	xor    %ebx,%ebx
    ca6c:	41 bf 03 00 00 00    	mov    $0x3,%r15d
    format_relative_time (expire, dt);
    ca72:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
    ca77:	4c 8d 2d 12 29 01 00 	lea    0x12912(%rip),%r13        # 1f390 <highscore+0x10>
    ca7e:	eb 12                	jmp    ca92 <print_scores+0x92>
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    ca80:	48 83 c3 01          	add    $0x1,%rbx
    ca84:	49 83 c5 40          	add    $0x40,%r13
    ca88:	48 83 fb 64          	cmp    $0x64,%rbx
    ca8c:	0f 84 2f 01 00 00    	je     cbc1 <print_scores+0x1c1>
    if (highscore[i].new) {
    ca92:	41 8b 75 28          	mov    0x28(%r13),%esi
    ca96:	41 89 dc             	mov    %ebx,%r12d
    ca99:	8d 6b 01             	lea    0x1(%rbx),%ebp
    ca9c:	85 f6                	test   %esi,%esi
    ca9e:	74 15                	je     cab5 <print_scores+0xb5>
      if (highscore[i].score == last_score)  my_rank = i+1;
    caa0:	8b 05 c6 28 01 00    	mov    0x128c6(%rip),%eax        # 1f36c <last_score>
    caa6:	41 39 45 f0          	cmp    %eax,-0x10(%r13)
    caaa:	8b 44 24 08          	mov    0x8(%rsp),%eax
    caae:	0f 44 c5             	cmove  %ebp,%eax
    cab1:	89 44 24 08          	mov    %eax,0x8(%rsp)
    if ((i==3 && gap>0)
    cab5:	41 89 de             	mov    %ebx,%r14d
    cab8:	48 83 fb 03          	cmp    $0x3,%rbx
    cabc:	0f 84 86 01 00 00    	je     cc48 <print_scores+0x248>
        || (i<HIGHSCORE_SLOTS-1 && line==max_line)) {
    cac2:	83 fb 63             	cmp    $0x63,%ebx
    cac5:	74 17                	je     cade <print_scores+0xde>
    cac7:	44 39 3d 92 28 01 00 	cmp    %r15d,0x12892(%rip)        # 1f360 <max_line>
    cace:	0f 84 8c 01 00 00    	je     cc60 <print_scores+0x260>
    if ((i>=3 && i<3+gap) || line>max_line)  continue;
    cad4:	48 83 fb 02          	cmp    $0x2,%rbx
    cad8:	0f 86 c2 01 00 00    	jbe    cca0 <print_scores+0x2a0>
    cade:	8b 05 80 28 01 00    	mov    0x12880(%rip),%eax        # 1f364 <gap>
    cae4:	83 c0 02             	add    $0x2,%eax
    cae7:	44 39 f0             	cmp    %r14d,%eax
    caea:	7d 94                	jge    ca80 <print_scores+0x80>
    caec:	44 39 3d 6d 28 01 00 	cmp    %r15d,0x1286d(%rip)        # 1f360 <max_line>
    caf3:	7c 8b                	jl     ca80 <print_scores+0x80>
    format_display_date (date, highscore[i].date);
    caf5:	49 8b 75 f8          	mov    -0x8(%r13),%rsi
    caf9:	4c 8d 74 24 20       	lea    0x20(%rsp),%r14
    cafe:	4c 89 f7             	mov    %r14,%rdi
    cb01:	e8 7a 12 00 00       	callq  dd80 <format_display_date>
  return  date + 14*day + (HIGHSCORE_SLOTS-1-rank)*rate;
    cb06:	b8 63 00 00 00       	mov    $0x63,%eax
    cb0b:	66 0f ef c9          	pxor   %xmm1,%xmm1
    cb0f:	66 0f ef c0          	pxor   %xmm0,%xmm0
    cb13:	44 29 e0             	sub    %r12d,%eax
    cb16:	f2 49 0f 2a 45 f8    	cvtsi2sdq -0x8(%r13),%xmm0
    cb1c:	45 89 fc             	mov    %r15d,%r12d
    cb1f:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    cb23:	f2 0f 59 0d 45 d2 00 	mulsd  0xd245(%rip),%xmm1        # 19d70 <__PRETTY_FUNCTION__.6560+0x20>
    cb2a:	00 
    cb2b:	f2 0f 58 05 35 d2 00 	addsd  0xd235(%rip),%xmm0        # 19d68 <__PRETTY_FUNCTION__.6560+0x18>
    cb32:	00 
    cb33:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
    cb37:	f2 48 0f 2c f8       	cvttsd2si %xmm0,%rdi
    dt = difftime (expire_date (i, highscore[i].date), now);
    cb3c:	48 8b 74 24 18       	mov    0x18(%rsp),%rsi
    cb41:	e8 4a ad ff ff       	callq  7890 <difftime@plt>
    format_relative_time (expire, dt);
    cb46:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
    cb4b:	e8 b0 12 00 00       	callq  de00 <format_relative_time>
    if (highscore[i].new)  wstandout (moon);
    cb50:	41 8b 55 28          	mov    0x28(%r13),%edx
    cb54:	85 d2                	test   %edx,%edx
    cb56:	0f 85 8c 01 00 00    	jne    cce8 <print_scores+0x2e8>
    mvwprintw (moon, line++, 5,
    cb5c:	41 8b 45 f4          	mov    -0xc(%r13),%eax
    cb60:	41 55                	push   %r13
    cb62:	41 89 e8             	mov    %ebp,%r8d
    cb65:	48 8d 0d 19 d1 00 00 	lea    0xd119(%rip),%rcx        # 19c85 <m_image+0x1ed>
    cb6c:	ff 74 24 18          	pushq  0x18(%rsp)
    cb70:	45 8b 4d f0          	mov    -0x10(%r13),%r9d
    cb74:	ba 05 00 00 00       	mov    $0x5,%edx
    cb79:	44 89 e6             	mov    %r12d,%esi
    cb7c:	48 8b 3d 95 42 01 00 	mov    0x14295(%rip),%rdi        # 20e18 <moon>
    cb83:	41 56                	push   %r14
    cb85:	41 83 c7 01          	add    $0x1,%r15d
    cb89:	50                   	push   %rax
    cb8a:	31 c0                	xor    %eax,%eax
    cb8c:	e8 7f ad ff ff       	callq  7910 <mvwprintw@plt>
    if (highscore[i].new)  wstandend (moon);
    cb91:	41 8b 45 28          	mov    0x28(%r13),%eax
    cb95:	48 83 c4 20          	add    $0x20,%rsp
    cb99:	85 c0                	test   %eax,%eax
    cb9b:	0f 84 df fe ff ff    	je     ca80 <print_scores+0x80>
    cba1:	48 8b 3d 70 42 01 00 	mov    0x14270(%rip),%rdi        # 20e18 <moon>
    cba8:	31 f6                	xor    %esi,%esi
    cbaa:	48 83 c3 01          	add    $0x1,%rbx
    cbae:	49 83 c5 40          	add    $0x40,%r13
    cbb2:	e8 f9 aa ff ff       	callq  76b0 <wattrset@plt>
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    cbb7:	48 83 fb 64          	cmp    $0x64,%rbx
    cbbb:	0f 85 d1 fe ff ff    	jne    ca92 <print_scores+0x92>
  if (last_score > 0)
    cbc1:	44 8b 05 a4 27 01 00 	mov    0x127a4(%rip),%r8d        # 1f36c <last_score>
    cbc8:	48 8b 3d 49 42 01 00 	mov    0x14249(%rip),%rdi        # 20e18 <moon>
    cbcf:	41 8d 77 01          	lea    0x1(%r15),%esi
    cbd3:	45 85 c0             	test   %r8d,%r8d
    cbd6:	7e 20                	jle    cbf8 <print_scores+0x1f8>
    mvwprintw (moon, line++, 17, "your score: %d", last_score);
    cbd8:	48 8d 0d c2 d0 00 00 	lea    0xd0c2(%rip),%rcx        # 19ca1 <m_image+0x209>
    cbdf:	ba 11 00 00 00       	mov    $0x11,%edx
    cbe4:	41 8d 5f 02          	lea    0x2(%r15),%ebx
    cbe8:	31 c0                	xor    %eax,%eax
    cbea:	e8 21 ad ff ff       	callq  7910 <mvwprintw@plt>
    cbef:	48 8b 3d 22 42 01 00 	mov    0x14222(%rip),%rdi        # 20e18 <moon>
    cbf6:	89 de                	mov    %ebx,%esi
  if (my_rank > 0) mvwprintw (moon, line++, 17, "your rank: %d", my_rank);
    cbf8:	8b 44 24 08          	mov    0x8(%rsp),%eax
    cbfc:	85 c0                	test   %eax,%eax
    cbfe:	7e 1d                	jle    cc1d <print_scores+0x21d>
    cc00:	41 89 c0             	mov    %eax,%r8d
    cc03:	48 8d 0d a6 d0 00 00 	lea    0xd0a6(%rip),%rcx        # 19cb0 <m_image+0x218>
    cc0a:	ba 11 00 00 00       	mov    $0x11,%edx
    cc0f:	31 c0                	xor    %eax,%eax
    cc11:	e8 fa ac ff ff       	callq  7910 <mvwprintw@plt>
    cc16:	48 8b 3d fb 41 01 00 	mov    0x141fb(%rip),%rdi        # 20e18 <moon>
  wrefresh (moon);
    cc1d:	e8 de ac ff ff       	callq  7900 <wrefresh@plt>
}
    cc22:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    cc27:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    cc2e:	00 00 
    cc30:	0f 85 c8 00 00 00    	jne    ccfe <print_scores+0x2fe>
    cc36:	48 83 c4 58          	add    $0x58,%rsp
    cc3a:	5b                   	pop    %rbx
    cc3b:	5d                   	pop    %rbp
    cc3c:	41 5c                	pop    %r12
    cc3e:	41 5d                	pop    %r13
    cc40:	41 5e                	pop    %r14
    cc42:	41 5f                	pop    %r15
    cc44:	c3                   	retq   
    cc45:	0f 1f 00             	nopl   (%rax)
    if ((i==3 && gap>0)
    cc48:	8b 0d 16 27 01 00    	mov    0x12716(%rip),%ecx        # 1f364 <gap>
    cc4e:	85 c9                	test   %ecx,%ecx
    cc50:	7f 0e                	jg     cc60 <print_scores+0x260>
        || (i<HIGHSCORE_SLOTS-1 && line==max_line)) {
    cc52:	44 39 3d 07 27 01 00 	cmp    %r15d,0x12707(%rip)        # 1f360 <max_line>
    cc59:	0f 85 7f fe ff ff    	jne    cade <print_scores+0xde>
    cc5f:	90                   	nop
      mvwprintw (moon, line++, 5, "  ...");
    cc60:	41 8d 47 01          	lea    0x1(%r15),%eax
    cc64:	44 89 fe             	mov    %r15d,%esi
    cc67:	48 8b 3d aa 41 01 00 	mov    0x141aa(%rip),%rdi        # 20e18 <moon>
    cc6e:	48 8d 0d 0a d0 00 00 	lea    0xd00a(%rip),%rcx        # 19c7f <m_image+0x1e7>
    cc75:	89 44 24 0c          	mov    %eax,0xc(%rsp)
    cc79:	ba 05 00 00 00       	mov    $0x5,%edx
    cc7e:	31 c0                	xor    %eax,%eax
    cc80:	e8 8b ac ff ff       	callq  7910 <mvwprintw@plt>
      wclrtoeol (moon);
    cc85:	48 8b 3d 8c 41 01 00 	mov    0x1418c(%rip),%rdi        # 20e18 <moon>
    cc8c:	e8 4f af ff ff       	callq  7be0 <wclrtoeol@plt>
      mvwprintw (moon, line++, 5, "  ...");
    cc91:	44 8b 7c 24 0c       	mov    0xc(%rsp),%r15d
    if ((i>=3 && i<3+gap) || line>max_line)  continue;
    cc96:	48 83 fb 02          	cmp    $0x2,%rbx
    cc9a:	0f 87 3e fe ff ff    	ja     cade <print_scores+0xde>
    cca0:	44 3b 3d b9 26 01 00 	cmp    0x126b9(%rip),%r15d        # 1f360 <max_line>
    cca7:	0f 8f d3 fd ff ff    	jg     ca80 <print_scores+0x80>
    format_display_date (date, highscore[i].date);
    ccad:	49 8b 75 f8          	mov    -0x8(%r13),%rsi
    ccb1:	4c 8d 74 24 20       	lea    0x20(%rsp),%r14
  if (rank < 3)  return  time(NULL)+2000*day;
    ccb6:	45 89 fc             	mov    %r15d,%r12d
    format_display_date (date, highscore[i].date);
    ccb9:	4c 89 f7             	mov    %r14,%rdi
    ccbc:	e8 bf 10 00 00       	callq  dd80 <format_display_date>
  if (rank < 3)  return  time(NULL)+2000*day;
    ccc1:	31 ff                	xor    %edi,%edi
    ccc3:	e8 18 ad ff ff       	callq  79e0 <time@plt>
    ccc8:	66 0f ef c0          	pxor   %xmm0,%xmm0
    cccc:	f2 48 0f 2a c0       	cvtsi2sd %rax,%xmm0
    ccd1:	f2 0f 58 05 9f d0 00 	addsd  0xd09f(%rip),%xmm0        # 19d78 <__PRETTY_FUNCTION__.6560+0x28>
    ccd8:	00 
    ccd9:	f2 48 0f 2c f8       	cvttsd2si %xmm0,%rdi
    ccde:	e9 59 fe ff ff       	jmpq   cb3c <print_scores+0x13c>
    cce3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    if (highscore[i].new)  wstandout (moon);
    cce8:	48 8b 3d 29 41 01 00 	mov    0x14129(%rip),%rdi        # 20e18 <moon>
    ccef:	be 00 00 01 00       	mov    $0x10000,%esi
    ccf4:	e8 b7 a9 ff ff       	callq  76b0 <wattrset@plt>
    ccf9:	e9 5e fe ff ff       	jmpq   cb5c <print_scores+0x15c>
}
    ccfe:	e8 5d ab ff ff       	callq  7860 <__stack_chk_fail@plt>
    cd03:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    cd0a:	00 00 00 00 
    cd0e:	66 90                	xchg   %ax,%ax

000000000000cd10 <highscore_redraw>:

void
highscore_redraw (void)
{
    cd10:	f3 0f 1e fa          	endbr64 
    cd14:	48 83 ec 08          	sub    $0x8,%rsp
  resize_meteors ();
    cd18:	e8 a3 ee ff ff       	callq  bbc0 <resize_meteors>
  resize_ground (0);
    cd1d:	31 ff                	xor    %edi,%edi
    cd1f:	e8 3c d7 ff ff       	callq  a460 <resize_ground>

  max_line = LINES-11;
    cd24:	8b 05 5a 25 01 00    	mov    0x1255a(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    cd2a:	83 e8 0b             	sub    $0xb,%eax
  if (max_line > 25)  max_line = 25;
    cd2d:	83 f8 19             	cmp    $0x19,%eax
    cd30:	7f 66                	jg     cd98 <highscore_redraw+0x88>
    cd32:	ba 67 00 00 00       	mov    $0x67,%edx
  max_line = LINES-11;
    cd37:	89 05 23 26 01 00    	mov    %eax,0x12623(%rip)        # 1f360 <max_line>
    cd3d:	29 c2                	sub    %eax,%edx
  if (gap > limit)  gap = limit;
    cd3f:	8b 05 1f 26 01 00    	mov    0x1261f(%rip),%eax        # 1f364 <gap>
    cd45:	39 d0                	cmp    %edx,%eax
    cd47:	7f 77                	jg     cdc0 <highscore_redraw+0xb0>
  if (gap < 2)  gap = 0;
    cd49:	83 f8 01             	cmp    $0x1,%eax
    cd4c:	7f 0a                	jg     cd58 <highscore_redraw+0x48>
    cd4e:	c7 05 0c 26 01 00 00 	movl   $0x0,0x1260c(%rip)        # 1f364 <gap>
    cd55:	00 00 00 
  fix_gap ();

  print_ground ();
    cd58:	e8 f3 d7 ff ff       	callq  a550 <print_ground>
  adjust_score (0);
    cd5d:	31 ff                	xor    %edi,%edi
    cd5f:	e8 fc c4 ff ff       	callq  9260 <adjust_score>
  print_lives ();
    cd64:	e8 17 c5 ff ff       	callq  9280 <print_lives>
  print_buggy ();
    cd69:	e8 52 dc ff ff       	callq  a9c0 <print_buggy>
  if (last_level > 0)  print_game_over (1);
    cd6e:	8b 15 f4 25 01 00    	mov    0x125f4(%rip),%edx        # 1f368 <last_level>
    cd74:	85 d2                	test   %edx,%edx
    cd76:	7e 0a                	jle    cd82 <highscore_redraw+0x72>
    cd78:	bf 01 00 00 00       	mov    $0x1,%edi
    cd7d:	e8 ee c5 ff ff       	callq  9370 <print_game_over>
  if (highscore_valid)  print_scores ();
    cd82:	8b 05 e8 25 01 00    	mov    0x125e8(%rip),%eax        # 1f370 <highscore_valid>
    cd88:	85 c0                	test   %eax,%eax
    cd8a:	75 44                	jne    cdd0 <highscore_redraw+0xc0>
}
    cd8c:	48 83 c4 08          	add    $0x8,%rsp
    cd90:	c3                   	retq   
    cd91:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  if (max_line > 25)  max_line = 25;
    cd98:	c7 05 be 25 01 00 19 	movl   $0x19,0x125be(%rip)        # 1f360 <max_line>
    cd9f:	00 00 00 
  if (gap > limit)  gap = limit;
    cda2:	8b 05 bc 25 01 00    	mov    0x125bc(%rip),%eax        # 1f364 <gap>
    cda8:	83 f8 4e             	cmp    $0x4e,%eax
    cdab:	7e 9c                	jle    cd49 <highscore_redraw+0x39>
    cdad:	c7 05 ad 25 01 00 4e 	movl   $0x4e,0x125ad(%rip)        # 1f364 <gap>
    cdb4:	00 00 00 
  if (gap < 2)  gap = 0;
    cdb7:	eb 9f                	jmp    cd58 <highscore_redraw+0x48>
    cdb9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  if (gap > limit)  gap = limit;
    cdc0:	89 15 9e 25 01 00    	mov    %edx,0x1259e(%rip)        # 1f364 <gap>
  if (gap < 2)  gap = 0;
    cdc6:	eb 90                	jmp    cd58 <highscore_redraw+0x48>
    cdc8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    cdcf:	00 
}
    cdd0:	48 83 c4 08          	add    $0x8,%rsp
  if (highscore_valid)  print_scores ();
    cdd4:	e9 27 fc ff ff       	jmpq   ca00 <print_scores>
    cdd9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

000000000000cde0 <key_handler>:

static void
key_handler (game_time t, int val)
{
    cde0:	f3 0f 1e fa          	endbr64 
  switch (val) {
    cde4:	83 ff 07             	cmp    $0x7,%edi
    cde7:	77 17                	ja     ce00 <key_handler+0x20>
    cde9:	48 8d 15 40 cf 00 00 	lea    0xcf40(%rip),%rdx        # 19d30 <m_image+0x298>
    cdf0:	89 ff                	mov    %edi,%edi
    cdf2:	48 63 04 ba          	movslq (%rdx,%rdi,4),%rax
    cdf6:	48 01 d0             	add    %rdx,%rax
    cdf9:	3e ff e0             	notrack jmpq *%rax
    cdfc:	0f 1f 40 00          	nopl   0x0(%rax)
    ce00:	c3                   	retq   
    ce01:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
{
    ce08:	48 83 ec 08          	sub    $0x8,%rsp
      fix_gap ();
      print_scores ();
    }
    break;
  case 7:
    print_message ("reloading score file ...");
    ce0c:	48 8d 3d ab ce 00 00 	lea    0xceab(%rip),%rdi        # 19cbe <m_image+0x226>
    ce13:	e8 58 b5 ff ff       	callq  8370 <print_message>
    doupdate ();
    ce18:	e8 83 ad ff ff       	callq  7ba0 <doupdate@plt>
    block_all ();
    ce1d:	e8 9e 15 00 00       	callq  e3c0 <block_all>
    update_score_file (NULL);
    ce22:	31 ff                	xor    %edi,%edi
    ce24:	e8 97 f2 ff ff       	callq  c0c0 <update_score_file>
    highscore_valid = 1;
    ce29:	c7 05 3d 25 01 00 01 	movl   $0x1,0x1253d(%rip)        # 1f370 <highscore_valid>
    ce30:	00 00 00 
    unblock ();
    ce33:	e8 a8 15 00 00       	callq  e3e0 <unblock>
    center_new ();
    ce38:	e8 93 ee ff ff       	callq  bcd0 <center_new>
    mode_redraw ();
    break;
  }
}
    ce3d:	48 83 c4 08          	add    $0x8,%rsp
    mode_redraw ();
    ce41:	e9 fa b9 ff ff       	jmpq   8840 <mode_redraw>
    ce46:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    ce4d:	00 00 00 
    mode_change (game_mode, 0);
    ce50:	48 8b 3d e9 3f 01 00 	mov    0x13fe9(%rip),%rdi        # 20e40 <game_mode>
    ce57:	31 f6                	xor    %esi,%esi
    ce59:	e9 02 b9 ff ff       	jmpq   8760 <mode_change>
    ce5e:	66 90                	xchg   %ax,%ax
    quit_main_loop ();
    ce60:	e9 eb 0a 00 00       	jmpq   d950 <quit_main_loop>
    ce65:	0f 1f 00             	nopl   (%rax)
    if (highscore_valid) {
    ce68:	8b 35 02 25 01 00    	mov    0x12502(%rip),%esi        # 1f370 <highscore_valid>
    ce6e:	85 f6                	test   %esi,%esi
    ce70:	74 8e                	je     ce00 <key_handler+0x20>
      if (gap > 2) --gap; else gap = 0;
    ce72:	8b 15 ec 24 01 00    	mov    0x124ec(%rip),%edx        # 1f364 <gap>
    ce78:	8d 42 ff             	lea    -0x1(%rdx),%eax
    ce7b:	83 fa 02             	cmp    $0x2,%edx
    ce7e:	ba 00 00 00 00       	mov    $0x0,%edx
    ce83:	0f 4e c2             	cmovle %edx,%eax
    ce86:	89 05 d8 24 01 00    	mov    %eax,0x124d8(%rip)        # 1f364 <gap>
      print_scores ();
    ce8c:	e9 6f fb ff ff       	jmpq   ca00 <print_scores>
    ce91:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    if (highscore_valid) {
    ce98:	8b 0d d2 24 01 00    	mov    0x124d2(%rip),%ecx        # 1f370 <highscore_valid>
    ce9e:	85 c9                	test   %ecx,%ecx
    cea0:	0f 84 5a ff ff ff    	je     ce00 <key_handler+0x20>
      if (gap < 2) gap = 2; else ++gap;
    cea6:	8b 05 b8 24 01 00    	mov    0x124b8(%rip),%eax        # 1f364 <gap>
    ceac:	83 f8 01             	cmp    $0x1,%eax
    ceaf:	8d 50 01             	lea    0x1(%rax),%edx
    ceb2:	b8 02 00 00 00       	mov    $0x2,%eax
    ceb7:	0f 4e d0             	cmovle %eax,%edx
  int  limit = HIGHSCORE_SLOTS-(max_line-3);
    ceba:	b8 67 00 00 00       	mov    $0x67,%eax
    cebf:	2b 05 9b 24 01 00    	sub    0x1249b(%rip),%eax        # 1f360 <max_line>
    cec5:	89 15 99 24 01 00    	mov    %edx,0x12499(%rip)        # 1f364 <gap>
  if (gap > limit)  gap = limit;
    cecb:	39 d0                	cmp    %edx,%eax
    cecd:	7d 15                	jge    cee4 <key_handler+0x104>
    cecf:	89 05 8f 24 01 00    	mov    %eax,0x1248f(%rip)        # 1f364 <gap>
  if (gap < 2)  gap = 0;
    ced5:	83 f8 01             	cmp    $0x1,%eax
    ced8:	7f 0a                	jg     cee4 <key_handler+0x104>
    ceda:	c7 05 80 24 01 00 00 	movl   $0x0,0x12480(%rip)        # 1f364 <gap>
    cee1:	00 00 00 
      print_scores ();
    cee4:	e9 17 fb ff ff       	jmpq   ca00 <print_scores>
    cee9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    if (highscore_valid) {
    cef0:	8b 15 7a 24 01 00    	mov    0x1247a(%rip),%edx        # 1f370 <highscore_valid>
    cef6:	85 d2                	test   %edx,%edx
    cef8:	0f 84 02 ff ff ff    	je     ce00 <key_handler+0x20>
      gap -= max_line-7;
    cefe:	8b 0d 5c 24 01 00    	mov    0x1245c(%rip),%ecx        # 1f360 <max_line>
    cf04:	8b 15 5a 24 01 00    	mov    0x1245a(%rip),%edx        # 1f364 <gap>
    cf0a:	8d 41 f9             	lea    -0x7(%rcx),%eax
    cf0d:	29 c2                	sub    %eax,%edx
  int  limit = HIGHSCORE_SLOTS-(max_line-3);
    cf0f:	b8 67 00 00 00       	mov    $0x67,%eax
    cf14:	29 c8                	sub    %ecx,%eax
  if (gap > limit)  gap = limit;
    cf16:	39 c2                	cmp    %eax,%edx
    cf18:	7f b5                	jg     cecf <key_handler+0xef>
      gap += max_line-7;
    cf1a:	89 15 44 24 01 00    	mov    %edx,0x12444(%rip)        # 1f364 <gap>
    cf20:	89 d0                	mov    %edx,%eax
    cf22:	eb b1                	jmp    ced5 <key_handler+0xf5>
    cf24:	0f 1f 40 00          	nopl   0x0(%rax)
    if (highscore_valid) {
    cf28:	8b 05 42 24 01 00    	mov    0x12442(%rip),%eax        # 1f370 <highscore_valid>
    cf2e:	85 c0                	test   %eax,%eax
    cf30:	0f 84 ca fe ff ff    	je     ce00 <key_handler+0x20>
      gap += max_line-7;
    cf36:	8b 0d 24 24 01 00    	mov    0x12424(%rip),%ecx        # 1f360 <max_line>
    cf3c:	8b 05 22 24 01 00    	mov    0x12422(%rip),%eax        # 1f364 <gap>
    cf42:	8d 54 01 f9          	lea    -0x7(%rcx,%rax,1),%edx
  int  limit = HIGHSCORE_SLOTS-(max_line-3);
    cf46:	b8 67 00 00 00       	mov    $0x67,%eax
    cf4b:	29 c8                	sub    %ecx,%eax
  if (gap > limit)  gap = limit;
    cf4d:	39 c2                	cmp    %eax,%edx
    cf4f:	0f 8f 7a ff ff ff    	jg     cecf <key_handler+0xef>
    cf55:	eb c3                	jmp    cf1a <key_handler+0x13a>
    cf57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    cf5e:	00 00 

000000000000cf60 <highscore_enter>:
{
    cf60:	f3 0f 1e fa          	endbr64 
    cf64:	48 83 ec 08          	sub    $0x8,%rsp
  print_ground ();
    cf68:	e8 e3 d5 ff ff       	callq  a550 <print_ground>
  print_buggy ();
    cf6d:	e8 4e da ff ff       	callq  a9c0 <print_buggy>
  print_message ("loading score file ...");
    cf72:	48 8d 3d 47 cd 00 00 	lea    0xcd47(%rip),%rdi        # 19cc0 <m_image+0x228>
    cf79:	e8 f2 b3 ff ff       	callq  8370 <print_message>
  doupdate ();
    cf7e:	e8 1d ac ff ff       	callq  7ba0 <doupdate@plt>
  block_all ();
    cf83:	e8 38 14 00 00       	callq  e3c0 <block_all>
  update_score_file (NULL);
    cf88:	31 ff                	xor    %edi,%edi
    cf8a:	e8 31 f1 ff ff       	callq  c0c0 <update_score_file>
  highscore_valid = 1;
    cf8f:	c7 05 d7 23 01 00 01 	movl   $0x1,0x123d7(%rip)        # 1f370 <highscore_valid>
    cf96:	00 00 00 
  unblock ();
    cf99:	e8 42 14 00 00       	callq  e3e0 <unblock>
  center_new ();
    cf9e:	e8 2d ed ff ff       	callq  bcd0 <center_new>
  if (last_score > highscore[HIGHSCORE_SLOTS-1].score) {
    cfa3:	8b 05 c3 23 01 00    	mov    0x123c3(%rip),%eax        # 1f36c <last_score>
    cfa9:	39 05 91 3c 01 00    	cmp    %eax,0x13c91(%rip)        # 20c40 <highscore+0x18c0>
    cfaf:	7c 0f                	jl     cfc0 <highscore_enter+0x60>
}
    cfb1:	48 83 c4 08          	add    $0x8,%rsp
    cfb5:	c3                   	retq   
    cfb6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    cfbd:	00 00 00 
    add_event (0.0, enter_name_h, NULL);
    cfc0:	31 f6                	xor    %esi,%esi
    cfc2:	48 8d 3d 87 f9 ff ff 	lea    -0x679(%rip),%rdi        # c950 <enter_name_h>
    cfc9:	66 0f ef c0          	pxor   %xmm0,%xmm0
}
    cfcd:	48 83 c4 08          	add    $0x8,%rsp
    add_event (0.0, enter_name_h, NULL);
    cfd1:	e9 ca 07 00 00       	jmpq   d7a0 <add_event>
    cfd6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    cfdd:	00 00 00 

000000000000cfe0 <create_highscores>:
{
    cfe0:	f3 0f 1e fa          	endbr64 
    cfe4:	48 83 ec 08          	sub    $0x8,%rsp
  block_all ();
    cfe8:	e8 d3 13 00 00       	callq  e3c0 <block_all>
  update_score_file (NULL);
    cfed:	31 ff                	xor    %edi,%edi
    cfef:	e8 cc f0 ff ff       	callq  c0c0 <update_score_file>
}
    cff4:	48 83 c4 08          	add    $0x8,%rsp
  unblock ();
    cff8:	e9 e3 13 00 00       	jmpq   e3e0 <unblock>
    cffd:	0f 1f 00             	nopl   (%rax)

000000000000d000 <show_highscores>:
{
    d000:	f3 0f 1e fa          	endbr64 
    d004:	41 57                	push   %r15
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    d006:	45 31 ff             	xor    %r15d,%r15d
{
    d009:	41 56                	push   %r14
    d00b:	41 55                	push   %r13
    d00d:	41 54                	push   %r12
    d00f:	55                   	push   %rbp
    d010:	53                   	push   %rbx
    d011:	48 8d 1d 78 23 01 00 	lea    0x12378(%rip),%rbx        # 1f390 <highscore+0x10>
    d018:	48 83 ec 38          	sub    $0x38,%rsp
    d01c:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d023:	00 00 
    d025:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
    d02a:	31 c0                	xor    %eax,%eax
  block_all ();
    d02c:	48 89 e5             	mov    %rsp,%rbp
    d02f:	4c 8d 64 24 10       	lea    0x10(%rsp),%r12
    d034:	e8 87 13 00 00       	callq  e3c0 <block_all>
  update_score_file (NULL);
    d039:	31 ff                	xor    %edi,%edi
    d03b:	e8 80 f0 ff ff       	callq  c0c0 <update_score_file>
  unblock ();
    d040:	e8 9b 13 00 00       	callq  e3e0 <unblock>
  now = time (NULL);
    d045:	31 ff                	xor    %edi,%edi
    d047:	e8 94 a9 ff ff       	callq  79e0 <time@plt>
  puts ("rank   score lvl     date  expires  name");
    d04c:	48 8d 3d fd ca 00 00 	lea    0xcafd(%rip),%rdi        # 19b50 <m_image+0xb8>
  now = time (NULL);
    d053:	49 89 c5             	mov    %rax,%r13
  puts ("rank   score lvl     date  expires  name");
    d056:	e8 35 a7 ff ff       	callq  7790 <puts@plt>
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    d05b:	eb 78                	jmp    d0d5 <show_highscores+0xd5>
    d05d:	0f 1f 00             	nopl   (%rax)
  return  date + 14*day + (HIGHSCORE_SLOTS-1-rank)*rate;
    d060:	b8 64 00 00 00       	mov    $0x64,%eax
    d065:	66 0f ef c9          	pxor   %xmm1,%xmm1
    d069:	66 0f ef c0          	pxor   %xmm0,%xmm0
    dt = difftime (expire_date (i, highscore[i].date), now);
    d06d:	4c 89 ee             	mov    %r13,%rsi
  return  date + 14*day + (HIGHSCORE_SLOTS-1-rank)*rate;
    d070:	44 29 f0             	sub    %r14d,%eax
    d073:	f2 48 0f 2a 43 f8    	cvtsi2sdq -0x8(%rbx),%xmm0
    d079:	f2 0f 58 05 e7 cc 00 	addsd  0xcce7(%rip),%xmm0        # 19d68 <__PRETTY_FUNCTION__.6560+0x18>
    d080:	00 
    d081:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    d085:	f2 0f 59 0d e3 cc 00 	mulsd  0xcce3(%rip),%xmm1        # 19d70 <__PRETTY_FUNCTION__.6560+0x20>
    d08c:	00 
    d08d:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
    d091:	f2 48 0f 2c f8       	cvttsd2si %xmm0,%rdi
    dt = difftime (expire_date (i, highscore[i].date), now);
    d096:	e8 f5 a7 ff ff       	callq  7890 <difftime@plt>
    format_relative_time (expire, dt);
    d09b:	4c 89 e7             	mov    %r12,%rdi
    d09e:	e8 5d 0d 00 00       	callq  de00 <format_relative_time>
}

__fortify_function int
printf (const char *__restrict __fmt, ...)
{
  return __printf_chk (__USE_FORTIFY_LEVEL - 1, __fmt, __va_arg_pack ());
    d0a3:	53                   	push   %rbx
    d0a4:	8b 4b f0             	mov    -0x10(%rbx),%ecx
    d0a7:	44 89 f2             	mov    %r14d,%edx
    d0aa:	41 54                	push   %r12
    d0ac:	44 8b 43 f4          	mov    -0xc(%rbx),%r8d
    d0b0:	49 89 e9             	mov    %rbp,%r9
    d0b3:	48 8d 35 cb cb 00 00 	lea    0xcbcb(%rip),%rsi        # 19c85 <m_image+0x1ed>
    d0ba:	bf 01 00 00 00       	mov    $0x1,%edi
    d0bf:	31 c0                	xor    %eax,%eax
    d0c1:	e8 7a aa ff ff       	callq  7b40 <__printf_chk@plt>
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    d0c6:	58                   	pop    %rax
    d0c7:	5a                   	pop    %rdx
    d0c8:	41 83 fe 64          	cmp    $0x64,%r14d
    d0cc:	74 75                	je     d143 <show_highscores+0x143>
    d0ce:	48 83 c3 40          	add    $0x40,%rbx
    d0d2:	45 89 f7             	mov    %r14d,%r15d
    format_display_date (date, highscore[i].date);
    d0d5:	48 8b 73 f8          	mov    -0x8(%rbx),%rsi
    d0d9:	48 89 ef             	mov    %rbp,%rdi
    d0dc:	45 8d 77 01          	lea    0x1(%r15),%r14d
    d0e0:	e8 9b 0c 00 00       	callq  dd80 <format_display_date>
  if (rank < 3)  return  time(NULL)+2000*day;
    d0e5:	41 83 ff 02          	cmp    $0x2,%r15d
    d0e9:	0f 87 71 ff ff ff    	ja     d060 <show_highscores+0x60>
    d0ef:	31 ff                	xor    %edi,%edi
    d0f1:	e8 ea a8 ff ff       	callq  79e0 <time@plt>
    d0f6:	66 0f ef c0          	pxor   %xmm0,%xmm0
    dt = difftime (expire_date (i, highscore[i].date), now);
    d0fa:	4c 89 ee             	mov    %r13,%rsi
  if (rank < 3)  return  time(NULL)+2000*day;
    d0fd:	f2 48 0f 2a c0       	cvtsi2sd %rax,%xmm0
    d102:	f2 0f 58 05 6e cc 00 	addsd  0xcc6e(%rip),%xmm0        # 19d78 <__PRETTY_FUNCTION__.6560+0x28>
    d109:	00 
    d10a:	f2 48 0f 2c f8       	cvttsd2si %xmm0,%rdi
    dt = difftime (expire_date (i, highscore[i].date), now);
    d10f:	e8 7c a7 ff ff       	callq  7890 <difftime@plt>
    format_relative_time (expire, dt);
    d114:	4c 89 e7             	mov    %r12,%rdi
    d117:	e8 e4 0c 00 00       	callq  de00 <format_relative_time>
    d11c:	53                   	push   %rbx
    d11d:	8b 4b f0             	mov    -0x10(%rbx),%ecx
    d120:	48 8d 35 5e cb 00 00 	lea    0xcb5e(%rip),%rsi        # 19c85 <m_image+0x1ed>
    d127:	41 54                	push   %r12
    d129:	44 8b 43 f4          	mov    -0xc(%rbx),%r8d
    d12d:	49 89 e9             	mov    %rbp,%r9
    d130:	44 89 f2             	mov    %r14d,%edx
    d133:	bf 01 00 00 00       	mov    $0x1,%edi
    d138:	31 c0                	xor    %eax,%eax
    d13a:	e8 01 aa ff ff       	callq  7b40 <__printf_chk@plt>
  for (i=0; i<HIGHSCORE_SLOTS; ++i) {
    d13f:	59                   	pop    %rcx
    d140:	5e                   	pop    %rsi
    d141:	eb 8b                	jmp    d0ce <show_highscores+0xce>
}
    d143:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
    d148:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d14f:	00 00 
    d151:	75 0f                	jne    d162 <show_highscores+0x162>
    d153:	48 83 c4 38          	add    $0x38,%rsp
    d157:	5b                   	pop    %rbx
    d158:	5d                   	pop    %rbp
    d159:	41 5c                	pop    %r12
    d15b:	41 5d                	pop    %r13
    d15d:	41 5e                	pop    %r14
    d15f:	41 5f                	pop    %r15
    d161:	c3                   	retq   
    d162:	e8 f9 a6 ff ff       	callq  7860 <__stack_chk_fail@plt>
    d167:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    d16e:	00 00 

000000000000d170 <score_set>:
{
    d170:	f3 0f 1e fa          	endbr64 
  last_score = score;
    d174:	89 3d f2 21 01 00    	mov    %edi,0x121f2(%rip)        # 1f36c <last_score>
  last_level = level;
    d17a:	89 35 e8 21 01 00    	mov    %esi,0x121e8(%rip)        # 1f368 <last_level>
}
    d180:	c3                   	retq   
    d181:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    d188:	00 00 00 00 
    d18c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000d190 <setup_highscore_mode>:

void
setup_highscore_mode (void)
{
    d190:	f3 0f 1e fa          	endbr64 
    d194:	48 83 ec 08          	sub    $0x8,%rsp
  highscore_mode = new_mode ();
    d198:	e8 c3 b4 ff ff       	callq  8660 <new_mode>
  highscore_mode->enter = highscore_enter;
  highscore_mode->leave = highscore_leave;
  highscore_mode->redraw = highscore_redraw;
  highscore_mode->keypress = key_handler;
  mode_add_key (highscore_mode, mbk_start, "new game", 1);
    d19d:	b9 01 00 00 00       	mov    $0x1,%ecx
    d1a2:	be 00 02 00 00       	mov    $0x200,%esi
    d1a7:	48 8d 15 29 cb 00 00 	lea    0xcb29(%rip),%rdx        # 19cd7 <m_image+0x23f>
  highscore_mode = new_mode ();
    d1ae:	48 89 c7             	mov    %rax,%rdi
    d1b1:	48 89 05 b8 3c 01 00 	mov    %rax,0x13cb8(%rip)        # 20e70 <highscore_mode>
  highscore_mode->enter = highscore_enter;
    d1b8:	48 8d 05 a1 fd ff ff 	lea    -0x25f(%rip),%rax        # cf60 <highscore_enter>
    d1bf:	48 89 07             	mov    %rax,(%rdi)
  highscore_mode->leave = highscore_leave;
    d1c2:	48 8d 05 c7 ee ff ff 	lea    -0x1139(%rip),%rax        # c090 <highscore_leave>
    d1c9:	48 89 47 08          	mov    %rax,0x8(%rdi)
  highscore_mode->redraw = highscore_redraw;
    d1cd:	48 8d 05 3c fb ff ff 	lea    -0x4c4(%rip),%rax        # cd10 <highscore_redraw>
    d1d4:	48 89 47 10          	mov    %rax,0x10(%rdi)
  highscore_mode->keypress = key_handler;
    d1d8:	48 8d 05 01 fc ff ff 	lea    -0x3ff(%rip),%rax        # cde0 <key_handler>
    d1df:	48 89 47 30          	mov    %rax,0x30(%rdi)
  mode_add_key (highscore_mode, mbk_start, "new game", 1);
    d1e3:	e8 d8 b4 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (highscore_mode, mbk_end, "quit", 2);
    d1e8:	b9 02 00 00 00       	mov    $0x2,%ecx
    d1ed:	be 04 00 00 00       	mov    $0x4,%esi
    d1f2:	48 8b 3d 77 3c 01 00 	mov    0x13c77(%rip),%rdi        # 20e70 <highscore_mode>
    d1f9:	48 8d 15 f3 34 00 00 	lea    0x34f3(%rip),%rdx        # 106f3 <_IO_stdin_used+0x6f3>
    d200:	e8 bb b4 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (highscore_mode, mbk_up, "up", 3);
    d205:	b9 03 00 00 00       	mov    $0x3,%ecx
    d20a:	be 00 04 00 00       	mov    $0x400,%esi
    d20f:	48 8b 3d 5a 3c 01 00 	mov    0x13c5a(%rip),%rdi        # 20e70 <highscore_mode>
    d216:	48 8d 15 44 35 00 00 	lea    0x3544(%rip),%rdx        # 10761 <_IO_stdin_used+0x761>
    d21d:	e8 9e b4 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (highscore_mode, mbk_down, "down", 4);
    d222:	b9 04 00 00 00       	mov    $0x4,%ecx
    d227:	be 02 00 00 00       	mov    $0x2,%esi
    d22c:	48 8b 3d 3d 3c 01 00 	mov    0x13c3d(%rip),%rdi        # 20e70 <highscore_mode>
    d233:	48 8d 15 2d 35 00 00 	lea    0x352d(%rip),%rdx        # 10767 <_IO_stdin_used+0x767>
    d23a:	e8 81 b4 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (highscore_mode, mbk_pageup, "pg up", 5);
    d23f:	b9 05 00 00 00       	mov    $0x5,%ecx
    d244:	be 00 01 00 00       	mov    $0x100,%esi
    d249:	48 8b 3d 20 3c 01 00 	mov    0x13c20(%rip),%rdi        # 20e70 <highscore_mode>
    d250:	48 8d 15 07 35 00 00 	lea    0x3507(%rip),%rdx        # 1075e <_IO_stdin_used+0x75e>
    d257:	e8 64 b4 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (highscore_mode, mbk_pagedown, "pg down", 6);
    d25c:	b9 06 00 00 00       	mov    $0x6,%ecx
    d261:	be 80 00 00 00       	mov    $0x80,%esi
    d266:	48 8b 3d 03 3c 01 00 	mov    0x13c03(%rip),%rdi        # 20e70 <highscore_mode>
    d26d:	48 8d 15 f0 34 00 00 	lea    0x34f0(%rip),%rdx        # 10764 <_IO_stdin_used+0x764>
    d274:	e8 47 b4 ff ff       	callq  86c0 <mode_add_key>
  mode_add_key (highscore_mode, mbk_scores, "reload", 7);
    d279:	b9 07 00 00 00       	mov    $0x7,%ecx
    d27e:	be 00 10 00 00       	mov    $0x1000,%esi
    d283:	48 8b 3d e6 3b 01 00 	mov    0x13be6(%rip),%rdi        # 20e70 <highscore_mode>
    d28a:	48 8d 15 4f ca 00 00 	lea    0xca4f(%rip),%rdx        # 19ce0 <m_image+0x248>
    d291:	e8 2a b4 ff ff       	callq  86c0 <mode_add_key>
  mode_complete (highscore_mode);
    d296:	48 8b 3d d3 3b 01 00 	mov    0x13bd3(%rip),%rdi        # 20e70 <highscore_mode>
}
    d29d:	48 83 c4 08          	add    $0x8,%rsp
  mode_complete (highscore_mode);
    d2a1:	e9 9a b4 ff ff       	jmpq   8740 <mode_complete>
    d2a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    d2ad:	00 00 00 

000000000000d2b0 <get_real_user_name>:
int
get_real_user_name (char *buffer, size_t size)
/* Query the real user name.
 * Store the result into BUFFER, but do not write more then SIZE
 * characters.  */
{
    d2b0:	f3 0f 1e fa          	endbr64 
    d2b4:	41 57                	push   %r15
    d2b6:	41 56                	push   %r14
    d2b8:	41 55                	push   %r13
    d2ba:	41 54                	push   %r12
    d2bc:	55                   	push   %rbp
    d2bd:	48 89 f5             	mov    %rsi,%rbp
    d2c0:	53                   	push   %rbx
    d2c1:	48 81 ec 88 00 00 00 	sub    $0x88,%rsp
    d2c8:	48 89 3c 24          	mov    %rdi,(%rsp)
    d2cc:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d2d3:	00 00 
    d2d5:	48 89 44 24 78       	mov    %rax,0x78(%rsp)
    d2da:	31 c0                	xor    %eax,%eax
  int  res, start;
  char *tmp;

  if (buffer[0] == '\0') {
    d2dc:	80 3f 00             	cmpb   $0x0,(%rdi)
    d2df:	0f 84 5b 01 00 00    	je     d440 <get_real_user_name+0x190>
        }
      }
    }
  }

  werase (message);
    d2e5:	48 8b 3d 14 3b 01 00 	mov    0x13b14(%rip),%rdi        # 20e00 <message>
    d2ec:	e8 cf a3 ff ff       	callq  76c0 <werase@plt>
  if (buffer[0] == '\0') {
    d2f1:	48 8b 04 24          	mov    (%rsp),%rax
    d2f5:	80 38 00             	cmpb   $0x0,(%rax)
    d2f8:	0f 85 c2 00 00 00    	jne    d3c0 <get_real_user_name+0x110>
    waddstr (message, "please enter your name: ");
    d2fe:	48 8b 3d fb 3a 01 00 	mov    0x13afb(%rip),%rdi        # 20e00 <message>
    d305:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    d30a:	48 8d 35 6f ca 00 00 	lea    0xca6f(%rip),%rsi        # 19d80 <__PRETTY_FUNCTION__.6560+0x30>
    d311:	41 89 ec             	mov    %ebp,%r12d
    d314:	e8 87 a9 ff ff       	callq  7ca0 <waddnstr@plt>
               def_size);
    }
    wprintw (message, tmpl, buffer);
  }

  tmp = xmalloc (size+1);
    d319:	48 8d 7d 01          	lea    0x1(%rbp),%rdi
  res = wgetnstr (message, tmp, size);
  noecho ();
  hide_cursor ();

  start = 0;
  while (start < size && tmp[start] && isspace (tmp[start]))  ++start;
    d31d:	31 db                	xor    %ebx,%ebx
  tmp = xmalloc (size+1);
    d31f:	e8 3c 23 00 00       	callq  f660 <xmalloc>
    d324:	49 89 c7             	mov    %rax,%r15
  show_cursor ();
    d327:	e8 74 21 00 00       	callq  f4a0 <show_cursor>
  echo ();
    d32c:	e8 7f a7 ff ff       	callq  7ab0 <echo@plt>
  res = wgetnstr (message, tmp, size);
    d331:	48 8b 3d c8 3a 01 00 	mov    0x13ac8(%rip),%rdi        # 20e00 <message>
    d338:	44 89 e2             	mov    %r12d,%edx
    d33b:	4c 89 fe             	mov    %r15,%rsi
    d33e:	e8 1d a8 ff ff       	callq  7b60 <wgetnstr@plt>
    d343:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  noecho ();
    d347:	e8 04 a5 ff ff       	callq  7850 <noecho@plt>
  hide_cursor ();
    d34c:	e8 ff 20 00 00       	callq  f450 <hide_cursor>
  while (start < size && tmp[start] && isspace (tmp[start]))  ++start;
    d351:	48 85 ed             	test   %rbp,%rbp
    d354:	75 2a                	jne    d380 <get_real_user_name+0xd0>
    d356:	eb 36                	jmp    d38e <get_real_user_name+0xde>
    d358:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    d35f:	00 
    d360:	e8 9b a9 ff ff       	callq  7d00 <__ctype_b_loc@plt>
    d365:	49 0f be d6          	movsbq %r14b,%rdx
    d369:	48 8b 00             	mov    (%rax),%rax
    d36c:	f6 44 50 01 20       	testb  $0x20,0x1(%rax,%rdx,2)
    d371:	0f 84 59 01 00 00    	je     d4d0 <get_real_user_name+0x220>
    d377:	48 83 c3 01          	add    $0x1,%rbx
    d37b:	48 39 dd             	cmp    %rbx,%rbp
    d37e:	74 0e                	je     d38e <get_real_user_name+0xde>
    d380:	45 0f b6 34 1f       	movzbl (%r15,%rbx,1),%r14d
    d385:	4d 8d 2c 1f          	lea    (%r15,%rbx,1),%r13
    d389:	45 84 f6             	test   %r14b,%r14b
    d38c:	75 d2                	jne    d360 <get_real_user_name+0xb0>
  if (start<size && tmp[start]) {
    strncpy (buffer, tmp+start, size-start);
    if (start>0)  buffer[size-start] = '\0';
  }
  free (tmp);
    d38e:	4c 89 ff             	mov    %r15,%rdi
    d391:	e8 5a a3 ff ff       	callq  76f0 <free@plt>
  return  res;
}
    d396:	48 8b 44 24 78       	mov    0x78(%rsp),%rax
    d39b:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d3a2:	00 00 
    d3a4:	0f 85 6c 01 00 00    	jne    d516 <get_real_user_name+0x266>
    d3aa:	8b 44 24 0c          	mov    0xc(%rsp),%eax
    d3ae:	48 81 c4 88 00 00 00 	add    $0x88,%rsp
    d3b5:	5b                   	pop    %rbx
    d3b6:	5d                   	pop    %rbp
    d3b7:	41 5c                	pop    %r12
    d3b9:	41 5d                	pop    %r13
    d3bb:	41 5e                	pop    %r14
    d3bd:	41 5f                	pop    %r15
    d3bf:	c3                   	retq   
                - size
    d3c0:	8b 1d ba 1e 01 00    	mov    0x11eba(%rip),%ebx        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
    if (def_size >= (int)xstrnlen(buffer, size)) {
    d3c6:	48 8b 3c 24          	mov    (%rsp),%rdi
    d3ca:	48 89 ee             	mov    %rbp,%rsi
    d3cd:	e8 2e 23 00 00       	callq  f700 <xstrnlen>
                - size
    d3d2:	29 eb                	sub    %ebp,%ebx
                - strlen("please enter your name (default: \"\"): "));
    d3d4:	8d 53 da             	lea    -0x26(%rbx),%edx
    if (def_size >= (int)xstrnlen(buffer, size)) {
    d3d7:	39 c2                	cmp    %eax,%edx
    d3d9:	0f 8d c1 00 00 00    	jge    d4a0 <get_real_user_name+0x1f0>
      def_size -= 2;
    d3df:	83 eb 28             	sub    $0x28,%ebx
      if (def_size < 6)  def_size = 6;
    d3e2:	41 b8 06 00 00 00    	mov    $0x6,%r8d
    d3e8:	83 fb 06             	cmp    $0x6,%ebx
    d3eb:	44 0f 4d c3          	cmovge %ebx,%r8d
      assert (size >= 8);
    d3ef:	48 83 fd 07          	cmp    $0x7,%rbp
    d3f3:	0f 86 fe 00 00 00    	jbe    d4f7 <get_real_user_name+0x247>
  return __builtin___sprintf_chk (__s, __USE_FORTIFY_LEVEL - 1,
    d3f9:	4c 8d 6c 24 10       	lea    0x10(%rsp),%r13
    d3fe:	48 8d 0d db c9 00 00 	lea    0xc9db(%rip),%rcx        # 19de0 <__PRETTY_FUNCTION__.6560+0x90>
    d405:	ba 64 00 00 00       	mov    $0x64,%edx
    d40a:	be 01 00 00 00       	mov    $0x1,%esi
    d40f:	4c 89 ef             	mov    %r13,%rdi
    d412:	31 c0                	xor    %eax,%eax
    d414:	41 89 ec             	mov    %ebp,%r12d
    d417:	e8 f4 a8 ff ff       	callq  7d10 <__sprintf_chk@plt>
    wprintw (message, tmpl, buffer);
    d41c:	48 8b 14 24          	mov    (%rsp),%rdx
    d420:	48 8b 3d d9 39 01 00 	mov    0x139d9(%rip),%rdi        # 20e00 <message>
    d427:	4c 89 ee             	mov    %r13,%rsi
    d42a:	31 c0                	xor    %eax,%eax
    d42c:	e8 2f a8 ff ff       	callq  7c60 <wprintw@plt>
    d431:	e9 e3 fe ff ff       	jmpq   d319 <get_real_user_name+0x69>
    d436:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    d43d:	00 00 00 
    uid_t me = geteuid ();
    d440:	e8 db a4 ff ff       	callq  7920 <geteuid@plt>
    d445:	89 c7                	mov    %eax,%edi
    struct passwd *my_passwd = getpwuid (me);
    d447:	e8 e4 a3 ff ff       	callq  7830 <getpwuid@plt>
    if (my_passwd) {
    d44c:	48 85 c0             	test   %rax,%rax
    d44f:	0f 84 90 fe ff ff    	je     d2e5 <get_real_user_name+0x35>
  return __builtin___strncpy_chk (__dest, __src, __len, __bos (__dest));
    d455:	48 8b 1c 24          	mov    (%rsp),%rbx
    d459:	48 8b 70 18          	mov    0x18(%rax),%rsi
    d45d:	48 89 ea             	mov    %rbp,%rdx
    d460:	48 89 df             	mov    %rbx,%rdi
    d463:	e8 d8 a2 ff ff       	callq  7740 <strncpy@plt>
      for (i=0; i<size; ++i) {
    d468:	48 85 ed             	test   %rbp,%rbp
    d46b:	0f 84 74 fe ff ff    	je     d2e5 <get_real_user_name+0x35>
    d471:	48 8d 54 1d 00       	lea    0x0(%rbp,%rbx,1),%rdx
    d476:	eb 15                	jmp    d48d <get_real_user_name+0x1dd>
    d478:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    d47f:	00 
    d480:	48 83 c0 01          	add    $0x1,%rax
    d484:	48 39 d0             	cmp    %rdx,%rax
    d487:	0f 84 58 fe ff ff    	je     d2e5 <get_real_user_name+0x35>
        if (buffer[i] == ',') {
    d48d:	80 38 2c             	cmpb   $0x2c,(%rax)
    d490:	75 ee                	jne    d480 <get_real_user_name+0x1d0>
          buffer[i] = '\0';
    d492:	c6 00 00             	movb   $0x0,(%rax)
          break;
    d495:	e9 4b fe ff ff       	jmpq   d2e5 <get_real_user_name+0x35>
    d49a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    d4a0:	4c 8d 6c 24 10       	lea    0x10(%rsp),%r13
    d4a5:	41 89 e8             	mov    %ebp,%r8d
    d4a8:	ba 64 00 00 00       	mov    $0x64,%edx
    d4ad:	31 c0                	xor    %eax,%eax
    d4af:	48 8d 0d fa c8 00 00 	lea    0xc8fa(%rip),%rcx        # 19db0 <__PRETTY_FUNCTION__.6560+0x60>
    d4b6:	be 01 00 00 00       	mov    $0x1,%esi
    d4bb:	4c 89 ef             	mov    %r13,%rdi
      sprintf (tmpl, "please enter your name (default: \"%%.%ds\"): ", (int)size);
    d4be:	41 89 ec             	mov    %ebp,%r12d
    d4c1:	e8 4a a8 ff ff       	callq  7d10 <__sprintf_chk@plt>
    d4c6:	e9 51 ff ff ff       	jmpq   d41c <get_real_user_name+0x16c>
    d4cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    strncpy (buffer, tmp+start, size-start);
    d4d0:	48 29 dd             	sub    %rbx,%rbp
    d4d3:	48 8b 3c 24          	mov    (%rsp),%rdi
    d4d7:	4c 89 ee             	mov    %r13,%rsi
    d4da:	48 89 ea             	mov    %rbp,%rdx
    d4dd:	e8 5e a2 ff ff       	callq  7740 <strncpy@plt>
    if (start>0)  buffer[size-start] = '\0';
    d4e2:	85 db                	test   %ebx,%ebx
    d4e4:	0f 84 a4 fe ff ff    	je     d38e <get_real_user_name+0xde>
    d4ea:	48 8b 04 24          	mov    (%rsp),%rax
    d4ee:	c6 04 28 00          	movb   $0x0,(%rax,%rbp,1)
    d4f2:	e9 97 fe ff ff       	jmpq   d38e <get_real_user_name+0xde>
      assert (size >= 8);
    d4f7:	48 8d 0d 12 c9 00 00 	lea    0xc912(%rip),%rcx        # 19e10 <__PRETTY_FUNCTION__.6374>
    d4fe:	ba 43 00 00 00       	mov    $0x43,%edx
    d503:	48 8d 35 8f c8 00 00 	lea    0xc88f(%rip),%rsi        # 19d99 <__PRETTY_FUNCTION__.6560+0x49>
    d50a:	48 8d 3d 93 c8 00 00 	lea    0xc893(%rip),%rdi        # 19da4 <__PRETTY_FUNCTION__.6560+0x54>
    d511:	e8 ca a3 ff ff       	callq  78e0 <__assert_fail@plt>
}
    d516:	e8 45 a3 ff ff       	callq  7860 <__stack_chk_fail@plt>
    d51b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000d520 <dummy_h>:

static void
dummy_h (game_time t, void *client_data)
/* This function is a possible callback argument to `add_event'.
 * It does nothing.  */
{
    d520:	f3 0f 1e fa          	endbr64 
  return;
}
    d524:	c3                   	retq   
    d525:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    d52c:	00 00 00 00 

000000000000d530 <my_select>:
{
    d530:	41 54                	push   %r12
  FD_ZERO (&rfds);
    d532:	b9 10 00 00 00       	mov    $0x10,%ecx
{
    d537:	53                   	push   %rbx
    d538:	48 89 fb             	mov    %rdi,%rbx
    d53b:	48 81 ec 98 00 00 00 	sub    $0x98,%rsp
    d542:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d549:	00 00 
    d54b:	48 89 84 24 88 00 00 	mov    %rax,0x88(%rsp)
    d552:	00 
    d553:	31 c0                	xor    %eax,%eax
  FD_ZERO (&rfds);
    d555:	49 89 e4             	mov    %rsp,%r12
    d558:	4c 89 e7             	mov    %r12,%rdi
    d55b:	fc                   	cld    
    d55c:	f3 48 ab             	rep stos %rax,%es:(%rdi)
  FD_SET (0, &rfds);
    d55f:	48 83 0c 24 01       	orq    $0x1,(%rsp)
  if (handle_signals ())  return -1;
    d564:	e8 57 0f 00 00       	callq  e4c0 <handle_signals>
    d569:	85 c0                	test   %eax,%eax
    d56b:	75 5b                	jne    d5c8 <my_select+0x98>
  res = select (FD_SETSIZE, &rfds, NULL, NULL, timeout);
    d56d:	4c 89 e6             	mov    %r12,%rsi
    d570:	49 89 d8             	mov    %rbx,%r8
    d573:	31 c9                	xor    %ecx,%ecx
    d575:	31 d2                	xor    %edx,%edx
    d577:	bf 00 04 00 00       	mov    $0x400,%edi
    d57c:	e8 8f a4 ff ff       	callq  7a10 <select@plt>
    d581:	41 89 c4             	mov    %eax,%r12d
  if (res < 0) {
    d584:	85 c0                	test   %eax,%eax
    d586:	78 28                	js     d5b0 <my_select+0x80>
}
    d588:	48 8b 84 24 88 00 00 	mov    0x88(%rsp),%rax
    d58f:	00 
    d590:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d597:	00 00 
    d599:	75 35                	jne    d5d0 <my_select+0xa0>
    d59b:	48 81 c4 98 00 00 00 	add    $0x98,%rsp
    d5a2:	44 89 e0             	mov    %r12d,%eax
    d5a5:	5b                   	pop    %rbx
    d5a6:	41 5c                	pop    %r12
    d5a8:	c3                   	retq   
    d5a9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    if (errno == EINTR) {
    d5b0:	e8 7b a1 ff ff       	callq  7730 <__errno_location@plt>
    d5b5:	8b 38                	mov    (%rax),%edi
    d5b7:	83 ff 04             	cmp    $0x4,%edi
    d5ba:	75 19                	jne    d5d5 <my_select+0xa5>
      handle_signals ();
    d5bc:	e8 ff 0e 00 00       	callq  e4c0 <handle_signals>
    d5c1:	eb c5                	jmp    d588 <my_select+0x58>
    d5c3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  if (handle_signals ())  return -1;
    d5c8:	41 bc ff ff ff ff    	mov    $0xffffffff,%r12d
    d5ce:	eb b8                	jmp    d588 <my_select+0x58>
}
    d5d0:	e8 8b a2 ff ff       	callq  7860 <__stack_chk_fail@plt>
      fatal ("Select failed: %s", strerror (errno));
    d5d5:	e8 b6 a6 ff ff       	callq  7c90 <strerror@plt>
    d5da:	48 8d 3d 42 c8 00 00 	lea    0xc842(%rip),%rdi        # 19e23 <__PRETTY_FUNCTION__.6374+0x13>
    d5e1:	48 89 c6             	mov    %rax,%rsi
    d5e4:	31 c0                	xor    %eax,%eax
    d5e6:	e8 75 1f 00 00       	callq  f560 <fatal>
    d5eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000d5f0 <clear_hint_h>:
void
clear_hint_h (game_time t, void *client_data)
/* This function is a possible callback argument to `add_event'.
 * It causes the screen's hint area to be cleared.
 * The arguments T and CLIENT_DATA are ignored.  */
{
    d5f0:	f3 0f 1e fa          	endbr64 
    d5f4:	48 83 ec 08          	sub    $0x8,%rsp
  wmove (moon, LINES-11, 0);
    d5f8:	8b 05 86 1c 01 00    	mov    0x11c86(%rip),%eax        # 1f284 <LINES@@NCURSES6_TINFO_5.0.19991023>
    d5fe:	48 8b 3d 13 38 01 00 	mov    0x13813(%rip),%rdi        # 20e18 <moon>
    d605:	31 d2                	xor    %edx,%edx
    d607:	8d 70 f5             	lea    -0xb(%rax),%esi
    d60a:	e8 c1 a5 ff ff       	callq  7bd0 <wmove@plt>
  wclrtoeol (moon);
    d60f:	48 8b 3d 02 38 01 00 	mov    0x13802(%rip),%rdi        # 20e18 <moon>
    d616:	e8 c5 a5 ff ff       	callq  7be0 <wclrtoeol@plt>
  wnoutrefresh (moon);
    d61b:	48 8b 3d f6 37 01 00 	mov    0x137f6(%rip),%rdi        # 20e18 <moon>
}
    d622:	48 83 c4 08          	add    $0x8,%rsp
  wnoutrefresh (moon);
    d626:	e9 95 a4 ff ff       	jmpq   7ac0 <wnoutrefresh@plt>
    d62b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000d630 <current_time>:
{
    d630:	f3 0f 1e fa          	endbr64 
    d634:	48 83 ec 08          	sub    $0x8,%rsp
  return  to_game (vclock ());
    d638:	e8 73 05 00 00       	callq  dbb0 <vclock>
  return  t - time_base;
    d63d:	f2 0f 5c 05 43 36 01 	subsd  0x13643(%rip),%xmm0        # 20c88 <time_base>
    d644:	00 
}
    d645:	48 83 c4 08          	add    $0x8,%rsp
    d649:	c3                   	retq   
    d64a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000d650 <clock_reset>:
{
    d650:	f3 0f 1e fa          	endbr64 
    d654:	48 83 ec 08          	sub    $0x8,%rsp
  time_base = vclock ();
    d658:	e8 53 05 00 00       	callq  dbb0 <vclock>
    d65d:	f2 0f 11 05 23 36 01 	movsd  %xmm0,0x13623(%rip)        # 20c88 <time_base>
    d664:	00 
}
    d665:	48 83 c4 08          	add    $0x8,%rsp
    d669:	c3                   	retq   
    d66a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000d670 <clock_thaw>:
{
    d670:	f3 0f 1e fa          	endbr64 
    d674:	48 83 ec 08          	sub    $0x8,%rsp
  assert (queue);
    d678:	48 83 3d 10 36 01 00 	cmpq   $0x0,0x13610(%rip)        # 20c90 <queue>
    d67f:	00 
    d680:	74 1e                	je     d6a0 <clock_thaw+0x30>
  time_base = vclock () - queue->t;
    d682:	e8 29 05 00 00       	callq  dbb0 <vclock>
    d687:	48 8b 05 02 36 01 00 	mov    0x13602(%rip),%rax        # 20c90 <queue>
    d68e:	f2 0f 5c 40 08       	subsd  0x8(%rax),%xmm0
    d693:	f2 0f 11 05 ed 35 01 	movsd  %xmm0,0x135ed(%rip)        # 20c88 <time_base>
    d69a:	00 
}
    d69b:	48 83 c4 08          	add    $0x8,%rsp
    d69f:	c3                   	retq   
  assert (queue);
    d6a0:	48 8d 0d c9 c7 00 00 	lea    0xc7c9(%rip),%rcx        # 19e70 <__PRETTY_FUNCTION__.7358>
    d6a7:	ba d7 00 00 00       	mov    $0xd7,%edx
    d6ac:	48 8d 35 82 c7 00 00 	lea    0xc782(%rip),%rsi        # 19e35 <__PRETTY_FUNCTION__.6374+0x25>
    d6b3:	48 8d 3d 83 c7 00 00 	lea    0xc783(%rip),%rdi        # 19e3d <__PRETTY_FUNCTION__.6374+0x2d>
    d6ba:	e8 21 a2 ff ff       	callq  78e0 <__assert_fail@plt>
    d6bf:	90                   	nop

000000000000d6c0 <clear_queue>:
{
    d6c0:	f3 0f 1e fa          	endbr64 
    d6c4:	41 54                	push   %r12
    d6c6:	53                   	push   %rbx
    d6c7:	48 83 ec 28          	sub    $0x28,%rsp
  ev = queue, queue = NULL;
    d6cb:	48 8b 1d be 35 01 00 	mov    0x135be(%rip),%rbx        # 20c90 <queue>
{
    d6d2:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d6d9:	00 00 
    d6db:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    d6e0:	31 c0                	xor    %eax,%eax
  ev = queue, queue = NULL;
    d6e2:	48 c7 05 a3 35 01 00 	movq   $0x0,0x135a3(%rip)        # 20c90 <queue>
    d6e9:	00 00 00 00 
  while (ev) {
    d6ed:	48 85 db             	test   %rbx,%rbx
    d6f0:	74 16                	je     d708 <clear_queue+0x48>
    d6f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    ev = old->next;
    d6f8:	48 89 df             	mov    %rbx,%rdi
    d6fb:	48 8b 1b             	mov    (%rbx),%rbx
    free (old);
    d6fe:	e8 ed 9f ff ff       	callq  76f0 <free@plt>
  while (ev) {
    d703:	48 85 db             	test   %rbx,%rbx
    d706:	75 f0                	jne    d6f8 <clear_queue+0x38>
  oldflags = fcntl (0, F_GETFL, 0);
    d708:	31 d2                	xor    %edx,%edx
    d70a:	be 03 00 00 00       	mov    $0x3,%esi
    d70f:	31 ff                	xor    %edi,%edi
    d711:	31 c0                	xor    %eax,%eax
    d713:	e8 c8 a0 ff ff       	callq  77e0 <fcntl@plt>
    d718:	41 89 c4             	mov    %eax,%r12d
  if (oldflags < 0) {
    d71b:	85 c0                	test   %eax,%eax
    d71d:	78 57                	js     d776 <clear_queue+0xb6>
  fcntl (0, F_SETFL, oldflags|O_NONBLOCK);
    d71f:	89 c2                	mov    %eax,%edx
    d721:	be 04 00 00 00       	mov    $0x4,%esi
    d726:	31 ff                	xor    %edi,%edi
    d728:	31 c0                	xor    %eax,%eax
    d72a:	80 ce 08             	or     $0x8,%dh
    d72d:	48 89 e3             	mov    %rsp,%rbx
    d730:	e8 ab a0 ff ff       	callq  77e0 <fcntl@plt>
  while (read (0, buffer, 16) == 16)
    d735:	0f 1f 00             	nopl   (%rax)
	return __read_chk (__fd, __buf, __nbytes, __bos0 (__buf));

      if (__nbytes > __bos0 (__buf))
	return __read_chk_warn (__fd, __buf, __nbytes, __bos0 (__buf));
    }
  return __read_alias (__fd, __buf, __nbytes);
    d738:	31 ff                	xor    %edi,%edi
    d73a:	ba 10 00 00 00       	mov    $0x10,%edx
    d73f:	48 89 de             	mov    %rbx,%rsi
    d742:	e8 19 a2 ff ff       	callq  7960 <read@plt>
    d747:	48 83 f8 10          	cmp    $0x10,%rax
    d74b:	74 eb                	je     d738 <clear_queue+0x78>
  fcntl (0, F_SETFL, oldflags);
    d74d:	31 ff                	xor    %edi,%edi
    d74f:	31 c0                	xor    %eax,%eax
    d751:	44 89 e2             	mov    %r12d,%edx
    d754:	be 04 00 00 00       	mov    $0x4,%esi
    d759:	e8 82 a0 ff ff       	callq  77e0 <fcntl@plt>
}
    d75e:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
    d763:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    d76a:	00 00 
    d76c:	75 25                	jne    d793 <clear_queue+0xd3>
    d76e:	48 83 c4 28          	add    $0x28,%rsp
    d772:	5b                   	pop    %rbx
    d773:	41 5c                	pop    %r12
    d775:	c3                   	retq   
    fatal ("Cannot get file status flags (%s)", strerror (errno));
    d776:	e8 b5 9f ff ff       	callq  7730 <__errno_location@plt>
    d77b:	8b 38                	mov    (%rax),%edi
    d77d:	e8 0e a5 ff ff       	callq  7c90 <strerror@plt>
    d782:	48 8d 3d bf c6 00 00 	lea    0xc6bf(%rip),%rdi        # 19e48 <__PRETTY_FUNCTION__.6374+0x38>
    d789:	48 89 c6             	mov    %rax,%rsi
    d78c:	31 c0                	xor    %eax,%eax
    d78e:	e8 cd 1d 00 00       	callq  f560 <fatal>
}
    d793:	e8 c8 a0 ff ff       	callq  7860 <__stack_chk_fail@plt>
    d798:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    d79f:	00 

000000000000d7a0 <add_event>:
{
    d7a0:	f3 0f 1e fa          	endbr64 
    d7a4:	41 54                	push   %r12
    d7a6:	49 89 fc             	mov    %rdi,%r12
    d7a9:	55                   	push   %rbp
    d7aa:	48 89 f5             	mov    %rsi,%rbp
    d7ad:	53                   	push   %rbx
  evp = &queue;
    d7ae:	48 8d 1d db 34 01 00 	lea    0x134db(%rip),%rbx        # 20c90 <queue>
{
    d7b5:	48 83 ec 10          	sub    $0x10,%rsp
  evp = &queue;
    d7b9:	48 8b 05 d0 34 01 00 	mov    0x134d0(%rip),%rax        # 20c90 <queue>
  while (*evp && (*evp)->t <= t)  evp = &((*evp)->next);
    d7c0:	48 85 c0             	test   %rax,%rax
    d7c3:	75 16                	jne    d7db <add_event+0x3b>
    d7c5:	eb 1b                	jmp    d7e2 <add_event+0x42>
    d7c7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    d7ce:	00 00 
    d7d0:	48 89 c3             	mov    %rax,%rbx
    d7d3:	48 8b 00             	mov    (%rax),%rax
    d7d6:	48 85 c0             	test   %rax,%rax
    d7d9:	74 07                	je     d7e2 <add_event+0x42>
    d7db:	66 0f 2f 40 08       	comisd 0x8(%rax),%xmm0
    d7e0:	73 ee                	jae    d7d0 <add_event+0x30>
  ev = xmalloc (sizeof (struct event));
    d7e2:	bf 20 00 00 00       	mov    $0x20,%edi
    d7e7:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
    d7ed:	e8 6e 1e 00 00       	callq  f660 <xmalloc>
  ev->next = *evp;
    d7f2:	48 8b 13             	mov    (%rbx),%rdx
  ev->t = t;
    d7f5:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
  ev->callback = callback;
    d7fb:	4c 89 60 10          	mov    %r12,0x10(%rax)
  ev->next = *evp;
    d7ff:	48 89 10             	mov    %rdx,(%rax)
  ev->client_data = client_data;
    d802:	48 89 68 18          	mov    %rbp,0x18(%rax)
  ev->t = t;
    d806:	f2 0f 11 40 08       	movsd  %xmm0,0x8(%rax)
  *evp = ev;
    d80b:	48 89 03             	mov    %rax,(%rbx)
}
    d80e:	48 83 c4 10          	add    $0x10,%rsp
    d812:	5b                   	pop    %rbx
    d813:	5d                   	pop    %rbp
    d814:	41 5c                	pop    %r12
    d816:	c3                   	retq   
    d817:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    d81e:	00 00 

000000000000d820 <remove_event>:
{
    d820:	f3 0f 1e fa          	endbr64 
    d824:	55                   	push   %rbp
    d825:	53                   	push   %rbx
    d826:	48 89 fb             	mov    %rdi,%rbx
    d829:	48 83 ec 08          	sub    $0x8,%rsp
  while (*evp) {
    d82d:	48 8b 3d 5c 34 01 00 	mov    0x1345c(%rip),%rdi        # 20c90 <queue>
    d834:	48 85 ff             	test   %rdi,%rdi
    d837:	74 35                	je     d86e <remove_event+0x4e>
    d839:	48 8d 2d 50 34 01 00 	lea    0x13450(%rip),%rbp        # 20c90 <queue>
    d840:	eb 11                	jmp    d853 <remove_event+0x33>
    d842:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      evp = &((*evp)->next);
    d848:	48 89 fd             	mov    %rdi,%rbp
    d84b:	48 89 c7             	mov    %rax,%rdi
  while (*evp) {
    d84e:	48 85 ff             	test   %rdi,%rdi
    d851:	74 1b                	je     d86e <remove_event+0x4e>
    if (ev->callback == callback) {
    d853:	48 8b 07             	mov    (%rdi),%rax
    d856:	48 39 5f 10          	cmp    %rbx,0x10(%rdi)
    d85a:	75 ec                	jne    d848 <remove_event+0x28>
      *evp = (*evp)->next;
    d85c:	48 89 45 00          	mov    %rax,0x0(%rbp)
      free (ev);
    d860:	e8 8b 9e ff ff       	callq  76f0 <free@plt>
    d865:	48 8b 7d 00          	mov    0x0(%rbp),%rdi
  while (*evp) {
    d869:	48 85 ff             	test   %rdi,%rdi
    d86c:	75 e5                	jne    d853 <remove_event+0x33>
}
    d86e:	48 83 c4 08          	add    $0x8,%rsp
    d872:	5b                   	pop    %rbx
    d873:	5d                   	pop    %rbp
    d874:	c3                   	retq   
    d875:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    d87c:	00 00 00 00 

000000000000d880 <clock_freeze>:
{
    d880:	f3 0f 1e fa          	endbr64 
    d884:	48 83 ec 08          	sub    $0x8,%rsp
  remove_event (dummy_h);
    d888:	48 8d 3d 91 fc ff ff 	lea    -0x36f(%rip),%rdi        # d520 <dummy_h>
    d88f:	e8 8c ff ff ff       	callq  d820 <remove_event>
  return  to_game (vclock ());
    d894:	e8 17 03 00 00       	callq  dbb0 <vclock>
  if (queue && t >= queue->t - 0.1)  t = queue->t - 0.1;
    d899:	48 8b 05 f0 33 01 00 	mov    0x133f0(%rip),%rax        # 20c90 <queue>
  return  t - time_base;
    d8a0:	f2 0f 5c 05 e0 33 01 	subsd  0x133e0(%rip),%xmm0        # 20c88 <time_base>
    d8a7:	00 
  if (queue && t >= queue->t - 0.1)  t = queue->t - 0.1;
    d8a8:	48 85 c0             	test   %rax,%rax
    d8ab:	74 22                	je     d8cf <clock_freeze+0x4f>
    d8ad:	f2 0f 10 50 08       	movsd  0x8(%rax),%xmm2
    d8b2:	f2 0f 5c 15 c6 c5 00 	subsd  0xc5c6(%rip),%xmm2        # 19e80 <__PRETTY_FUNCTION__.7358+0x10>
    d8b9:	00 
    d8ba:	66 0f 28 ca          	movapd %xmm2,%xmm1
    d8be:	f2 0f c2 c8 06       	cmpnlesd %xmm0,%xmm1
    d8c3:	66 0f 54 c1          	andpd  %xmm1,%xmm0
    d8c7:	66 0f 55 ca          	andnpd %xmm2,%xmm1
    d8cb:	66 0f 56 c1          	orpd   %xmm1,%xmm0
  add_event (t, dummy_h, NULL);
    d8cf:	31 f6                	xor    %esi,%esi
    d8d1:	48 8d 3d 48 fc ff ff 	lea    -0x3b8(%rip),%rdi        # d520 <dummy_h>
}
    d8d8:	48 83 c4 08          	add    $0x8,%rsp
  add_event (t, dummy_h, NULL);
    d8dc:	e9 bf fe ff ff       	jmpq   d7a0 <add_event>
    d8e1:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    d8e8:	00 00 00 00 
    d8ec:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000d8f0 <remove_client_data>:
{
    d8f0:	f3 0f 1e fa          	endbr64 
    d8f4:	55                   	push   %rbp
    d8f5:	53                   	push   %rbx
    d8f6:	48 89 fb             	mov    %rdi,%rbx
    d8f9:	48 83 ec 08          	sub    $0x8,%rsp
  while (*evp) {
    d8fd:	48 8b 3d 8c 33 01 00 	mov    0x1338c(%rip),%rdi        # 20c90 <queue>
    d904:	48 85 ff             	test   %rdi,%rdi
    d907:	74 35                	je     d93e <remove_client_data+0x4e>
    d909:	48 8d 2d 80 33 01 00 	lea    0x13380(%rip),%rbp        # 20c90 <queue>
    d910:	eb 11                	jmp    d923 <remove_client_data+0x33>
    d912:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
      evp = &((*evp)->next);
    d918:	48 89 fd             	mov    %rdi,%rbp
    d91b:	48 89 c7             	mov    %rax,%rdi
  while (*evp) {
    d91e:	48 85 ff             	test   %rdi,%rdi
    d921:	74 1b                	je     d93e <remove_client_data+0x4e>
    if (ev->client_data == client_data) {
    d923:	48 8b 07             	mov    (%rdi),%rax
    d926:	48 39 5f 18          	cmp    %rbx,0x18(%rdi)
    d92a:	75 ec                	jne    d918 <remove_client_data+0x28>
      *evp = (*evp)->next;
    d92c:	48 89 45 00          	mov    %rax,0x0(%rbp)
      free (ev);
    d930:	e8 bb 9d ff ff       	callq  76f0 <free@plt>
    d935:	48 8b 7d 00          	mov    0x0(%rbp),%rdi
  while (*evp) {
    d939:	48 85 ff             	test   %rdi,%rdi
    d93c:	75 e5                	jne    d923 <remove_client_data+0x33>
}
    d93e:	48 83 c4 08          	add    $0x8,%rsp
    d942:	5b                   	pop    %rbx
    d943:	5d                   	pop    %rbp
    d944:	c3                   	retq   
    d945:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    d94c:	00 00 00 00 

000000000000d950 <quit_main_loop>:
{
    d950:	f3 0f 1e fa          	endbr64 
  exit_flag = 1;
    d954:	c7 05 22 33 01 00 01 	movl   $0x1,0x13322(%rip)        # 20c80 <exit_flag>
    d95b:	00 00 00 
}
    d95e:	c3                   	retq   
    d95f:	90                   	nop

000000000000d960 <main_loop>:
{
    d960:	f3 0f 1e fa          	endbr64 
    d964:	55                   	push   %rbp
    d965:	53                   	push   %rbx
    d966:	48 83 ec 48          	sub    $0x48,%rsp
    d96a:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    d971:	00 00 
    d973:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
    d978:	31 c0                	xor    %eax,%eax
  time_base = vclock ();
    d97a:	e8 31 02 00 00       	callq  dbb0 <vclock>
  exit_flag = 0;
    d97f:	c7 05 f7 32 01 00 00 	movl   $0x0,0x132f7(%rip)        # 20c80 <exit_flag>
    d986:	00 00 00 
  time_base = vclock ();
    d989:	f2 0f 11 05 f7 32 01 	movsd  %xmm0,0x132f7(%rip)        # 20c88 <time_base>
    d990:	00 
  while (! exit_flag) {
    d991:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    mode_update ();
    d998:	e8 13 ae ff ff       	callq  87b0 <mode_update>
    if (queue) {
    d99d:	48 8b 05 ec 32 01 00 	mov    0x132ec(%rip),%rax        # 20c90 <queue>
    d9a4:	48 85 c0             	test   %rax,%rax
    d9a7:	0f 84 73 01 00 00    	je     db20 <main_loop+0x1c0>
      retval = wait_until (queue->t, &t);
    d9ad:	f2 0f 10 60 08       	movsd  0x8(%rax),%xmm4
    d9b2:	48 8d 6c 24 20       	lea    0x20(%rsp),%rbp
    usec = 1e6 * modf (dt, &sec) + 0.5;
    d9b7:	48 8d 5c 24 18       	lea    0x18(%rsp),%rbx
      retval = wait_until (queue->t, &t);
    d9bc:	f2 0f 11 64 24 08    	movsd  %xmm4,0x8(%rsp)
wait_until (game_time t, real_time *t_return)
    d9c2:	eb 56                	jmp    da1a <main_loop+0xba>
    d9c4:	0f 1f 40 00          	nopl   0x0(%rax)
    usec = 1e6 * modf (dt, &sec) + 0.5;
    d9c8:	48 89 df             	mov    %rbx,%rdi
    d9cb:	e8 d0 9e ff ff       	callq  78a0 <modf@plt>
    tv.tv_sec = sec + 0.5;
    d9d0:	f2 0f 10 0d 58 2d 00 	movsd  0x2d58(%rip),%xmm1        # 10730 <_IO_stdin_used+0x730>
    d9d7:	00 
    d9d8:	f2 0f 58 4c 24 18    	addsd  0x18(%rsp),%xmm1
    res = my_select (&tv);
    d9de:	48 89 ef             	mov    %rbp,%rdi
    usec = 1e6 * modf (dt, &sec) + 0.5;
    d9e1:	f2 0f 59 05 9f c4 00 	mulsd  0xc49f(%rip),%xmm0        # 19e88 <__PRETTY_FUNCTION__.7358+0x18>
    d9e8:	00 
    d9e9:	f2 0f 58 05 3f 2d 00 	addsd  0x2d3f(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    d9f0:	00 
    tv.tv_usec = usec + 0.5;
    d9f1:	f2 0f 58 05 37 2d 00 	addsd  0x2d37(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    d9f8:	00 
    tv.tv_sec = sec + 0.5;
    d9f9:	f2 48 0f 2c c1       	cvttsd2si %xmm1,%rax
    d9fe:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    tv.tv_usec = usec + 0.5;
    da03:	f2 48 0f 2c c0       	cvttsd2si %xmm0,%rax
    da08:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
    res = my_select (&tv);
    da0d:	e8 1e fb ff ff       	callq  d530 <my_select>
  } while (res < 0);
    da12:	85 c0                	test   %eax,%eax
    da14:	0f 89 26 01 00 00    	jns    db40 <main_loop+0x1e0>
    start = vclock ();
    da1a:	e8 91 01 00 00       	callq  dbb0 <vclock>
    if (dt <= 0) {
    da1f:	66 0f ef db          	pxor   %xmm3,%xmm3
    start = vclock ();
    da23:	66 0f 28 c8          	movapd %xmm0,%xmm1
  return  t + time_base;
    da27:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    da2d:	f2 0f 58 05 53 32 01 	addsd  0x13253(%rip),%xmm0        # 20c88 <time_base>
    da34:	00 
    dt = to_real(t) - start;
    da35:	f2 0f 5c c1          	subsd  %xmm1,%xmm0
    if (dt <= 0) {
    da39:	66 0f 2f d8          	comisd %xmm0,%xmm3
    da3d:	72 89                	jb     d9c8 <main_loop+0x68>
    da3f:	90                   	nop
    res = my_select (&ancient_time);
    da40:	48 89 ef             	mov    %rbp,%rdi
    da43:	f2 0f 11 4c 24 08    	movsd  %xmm1,0x8(%rsp)
    ancient_time.tv_sec = 0;
    da49:	48 c7 44 24 20 00 00 	movq   $0x0,0x20(%rsp)
    da50:	00 00 
    ancient_time.tv_usec = 0;
    da52:	48 c7 44 24 28 00 00 	movq   $0x0,0x28(%rsp)
    da59:	00 00 
    res = my_select (&ancient_time);
    da5b:	e8 d0 fa ff ff       	callq  d530 <my_select>
  } while (res < 0);
    da60:	f2 0f 10 4c 24 08    	movsd  0x8(%rsp),%xmm1
    da66:	85 c0                	test   %eax,%eax
    da68:	78 d6                	js     da40 <main_loop+0xe0>
    if (retval>0) {
    da6a:	85 c0                	test   %eax,%eax
    da6c:	74 78                	je     dae6 <main_loop+0x186>
    da6e:	f2 0f 11 4c 24 08    	movsd  %xmm1,0x8(%rsp)
      int  meaning = read_key ();
    da74:	e8 67 0e 00 00       	callq  e8e0 <read_key>
    da79:	89 c7                	mov    %eax,%edi
      if (meaning != -1) {
    da7b:	83 f8 ff             	cmp    $0xffffffff,%eax
    da7e:	74 66                	je     dae6 <main_loop+0x186>
  return  t - time_base;
    da80:	f2 0f 10 4c 24 08    	movsd  0x8(%rsp),%xmm1
    da86:	f2 0f 5c 0d fa 31 01 	subsd  0x131fa(%rip),%xmm1        # 20c88 <time_base>
    da8d:	00 
    da8e:	66 0f 28 c1          	movapd %xmm1,%xmm0
        if (! mode_keypress (to_game (t), meaning))  beep ();
    da92:	e8 c9 ad ff ff       	callq  8860 <mode_keypress>
    da97:	85 c0                	test   %eax,%eax
    da99:	75 4b                	jne    dae6 <main_loop+0x186>
    da9b:	e9 c0 00 00 00       	jmpq   db60 <main_loop+0x200>
    while (queue && queue->t <= current_time ()) {
    daa0:	f2 0f 10 50 08       	movsd  0x8(%rax),%xmm2
    daa5:	f2 0f 11 54 24 08    	movsd  %xmm2,0x8(%rsp)
  return  to_game (vclock ());
    daab:	e8 00 01 00 00       	callq  dbb0 <vclock>
  return  t - time_base;
    dab0:	f2 0f 5c 05 d0 31 01 	subsd  0x131d0(%rip),%xmm0        # 20c88 <time_base>
    dab7:	00 
    while (queue && queue->t <= current_time ()) {
    dab8:	66 0f 2f 44 24 08    	comisd 0x8(%rsp),%xmm0
    dabe:	72 32                	jb     daf2 <main_loop+0x192>
      struct event *ev = queue;
    dac0:	48 8b 2d c9 31 01 00 	mov    0x131c9(%rip),%rbp        # 20c90 <queue>
      queue = queue->next;
    dac7:	48 8b 45 00          	mov    0x0(%rbp),%rax
      ev->callback (ev->t, ev->client_data);
    dacb:	48 8b 7d 18          	mov    0x18(%rbp),%rdi
    dacf:	f2 0f 10 45 08       	movsd  0x8(%rbp),%xmm0
      queue = queue->next;
    dad4:	48 89 05 b5 31 01 00 	mov    %rax,0x131b5(%rip)        # 20c90 <queue>
      ev->callback (ev->t, ev->client_data);
    dadb:	ff 55 10             	callq  *0x10(%rbp)
      free (ev);
    dade:	48 89 ef             	mov    %rbp,%rdi
    dae1:	e8 0a 9c ff ff       	callq  76f0 <free@plt>
    while (queue && queue->t <= current_time ()) {
    dae6:	48 8b 05 a3 31 01 00 	mov    0x131a3(%rip),%rax        # 20c90 <queue>
    daed:	48 85 c0             	test   %rax,%rax
    daf0:	75 ae                	jne    daa0 <main_loop+0x140>
  while (! exit_flag) {
    daf2:	8b 05 88 31 01 00    	mov    0x13188(%rip),%eax        # 20c80 <exit_flag>
    daf8:	85 c0                	test   %eax,%eax
    dafa:	0f 84 98 fe ff ff    	je     d998 <main_loop+0x38>
}
    db00:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    db05:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    db0c:	00 00 
    db0e:	75 5a                	jne    db6a <main_loop+0x20a>
    db10:	48 83 c4 48          	add    $0x48,%rsp
    db14:	5b                   	pop    %rbx
    db15:	5d                   	pop    %rbp
    db16:	c3                   	retq   
    db17:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    db1e:	00 00 
    res = my_select (NULL);
    db20:	31 ff                	xor    %edi,%edi
    db22:	e8 09 fa ff ff       	callq  d530 <my_select>
  } while (res < 0);
    db27:	85 c0                	test   %eax,%eax
    db29:	78 f5                	js     db20 <main_loop+0x1c0>
      t = vclock ();
    db2b:	e8 80 00 00 00       	callq  dbb0 <vclock>
    db30:	66 0f 28 c8          	movapd %xmm0,%xmm1
    if (retval>0) {
    db34:	e9 35 ff ff ff       	jmpq   da6e <main_loop+0x10e>
    db39:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    db40:	89 44 24 08          	mov    %eax,0x8(%rsp)
  *t_return = vclock ();
    db44:	e8 67 00 00 00       	callq  dbb0 <vclock>
    db49:	8b 44 24 08          	mov    0x8(%rsp),%eax
    db4d:	66 0f 28 c8          	movapd %xmm0,%xmm1
  return  res;
    db51:	e9 14 ff ff ff       	jmpq   da6a <main_loop+0x10a>
    db56:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    db5d:	00 00 00 
        if (! mode_keypress (to_game (t), meaning))  beep ();
    db60:	e8 ab 9c ff ff       	callq  7810 <beep@plt>
    while (queue && queue->t <= current_time ()) {
    db65:	e9 7c ff ff ff       	jmpq   dae6 <main_loop+0x186>
}
    db6a:	e8 f1 9c ff ff       	callq  7860 <__stack_chk_fail@plt>
    db6f:	90                   	nop

000000000000db70 <print_hint_h>:
{
    db70:	f3 0f 1e fa          	endbr64 
    db74:	48 83 ec 18          	sub    $0x18,%rsp
    db78:	f2 0f 11 44 24 08    	movsd  %xmm0,0x8(%rsp)
  print_hint (client_data);
    db7e:	e8 5d a8 ff ff       	callq  83e0 <print_hint>
  remove_event (clear_hint_h);
    db83:	48 8d 3d 66 fa ff ff 	lea    -0x59a(%rip),%rdi        # d5f0 <clear_hint_h>
    db8a:	e8 91 fc ff ff       	callq  d820 <remove_event>
  add_event (t+4, clear_hint_h, NULL);
    db8f:	f2 0f 10 44 24 08    	movsd  0x8(%rsp),%xmm0
    db95:	31 f6                	xor    %esi,%esi
    db97:	f2 0f 58 05 c1 bd 00 	addsd  0xbdc1(%rip),%xmm0        # 19960 <__PRETTY_FUNCTION__.4560+0xf0>
    db9e:	00 
    db9f:	48 8d 3d 4a fa ff ff 	lea    -0x5b6(%rip),%rdi        # d5f0 <clear_hint_h>
}
    dba6:	48 83 c4 18          	add    $0x18,%rsp
  add_event (t+4, clear_hint_h, NULL);
    dbaa:	e9 f1 fb ff ff       	jmpq   d7a0 <add_event>
    dbaf:	90                   	nop

000000000000dbb0 <vclock>:

double
vclock (void)
/* Return the elapsed (wall clock) time (measured in seconds) since
 * some base time with greater precision than `time()' does.  */
{
    dbb0:	f3 0f 1e fa          	endbr64 
    dbb4:	48 83 ec 28          	sub    $0x28,%rsp
  struct timeval  x;

  gettimeofday (&x, NULL);
    dbb8:	31 f6                	xor    %esi,%esi
{
    dbba:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    dbc1:	00 00 
    dbc3:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    dbc8:	31 c0                	xor    %eax,%eax
  gettimeofday (&x, NULL);
    dbca:	48 89 e7             	mov    %rsp,%rdi
    dbcd:	e8 fe 9c ff ff       	callq  78d0 <gettimeofday@plt>
  return  (x.tv_sec + x.tv_usec*1.0e-6);
    dbd2:	66 0f ef c0          	pxor   %xmm0,%xmm0
    dbd6:	66 0f ef c9          	pxor   %xmm1,%xmm1
}
    dbda:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
    dbdf:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    dbe6:	00 00 
  return  (x.tv_sec + x.tv_usec*1.0e-6);
    dbe8:	f2 48 0f 2a 44 24 08 	cvtsi2sdq 0x8(%rsp),%xmm0
    dbef:	f2 0f 59 05 99 c2 00 	mulsd  0xc299(%rip),%xmm0        # 19e90 <__PRETTY_FUNCTION__.7358+0x20>
    dbf6:	00 
    dbf7:	f2 48 0f 2a 0c 24    	cvtsi2sdq (%rsp),%xmm1
    dbfd:	f2 0f 58 c1          	addsd  %xmm1,%xmm0
}
    dc01:	75 05                	jne    dc08 <vclock+0x58>
    dc03:	48 83 c4 28          	add    $0x28,%rsp
    dc07:	c3                   	retq   
    dc08:	e8 53 9c ff ff       	callq  7860 <__stack_chk_fail@plt>
    dc0d:	0f 1f 00             	nopl   (%rax)

000000000000dc10 <parse_date>:

time_t
parse_date (const char *str)
/* Read the date from STR and convert it to a `time_t'.
 * This is used to decode highscore entries.  */
{
    dc10:	f3 0f 1e fa          	endbr64 
    dc14:	55                   	push   %rbp
  struct tm  broken;

  sscanf (str, "%d-%d-%d %d:%d:%d",
    dc15:	48 8d 35 7c c2 00 00 	lea    0xc27c(%rip),%rsi        # 19e98 <__PRETTY_FUNCTION__.7358+0x28>
{
    dc1c:	48 83 ec 40          	sub    $0x40,%rsp
    dc20:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    dc27:	00 00 
    dc29:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
    dc2e:	31 c0                	xor    %eax,%eax
  sscanf (str, "%d-%d-%d %d:%d:%d",
    dc30:	48 89 e5             	mov    %rsp,%rbp
    dc33:	48 8d 4c 24 10       	lea    0x10(%rsp),%rcx
    dc38:	48 8d 54 24 14       	lea    0x14(%rsp),%rdx
    dc3d:	55                   	push   %rbp
    dc3e:	48 8d 44 24 0c       	lea    0xc(%rsp),%rax
    dc43:	50                   	push   %rax
    dc44:	31 c0                	xor    %eax,%eax
    dc46:	4c 8d 4c 24 18       	lea    0x18(%rsp),%r9
    dc4b:	4c 8d 44 24 1c       	lea    0x1c(%rsp),%r8
    dc50:	e8 1b 9e ff ff       	callq  7a70 <__isoc99_sscanf@plt>
          &broken.tm_hour, &broken.tm_min, &broken.tm_sec);
  broken.tm_year -= 1900;
  broken.tm_mon -= 1;
  broken.tm_isdst = -1;

  return  mktime (&broken);
    dc55:	48 89 ef             	mov    %rbp,%rdi
  broken.tm_year -= 1900;
    dc58:	81 6c 24 24 6c 07 00 	subl   $0x76c,0x24(%rsp)
    dc5f:	00 
  broken.tm_mon -= 1;
    dc60:	83 6c 24 20 01       	subl   $0x1,0x20(%rsp)
  broken.tm_isdst = -1;
    dc65:	c7 44 24 30 ff ff ff 	movl   $0xffffffff,0x30(%rsp)
    dc6c:	ff 
  return  mktime (&broken);
    dc6d:	e8 2e 9e ff ff       	callq  7aa0 <mktime@plt>
    dc72:	5a                   	pop    %rdx
    dc73:	59                   	pop    %rcx
}
    dc74:	48 8b 74 24 38       	mov    0x38(%rsp),%rsi
    dc79:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
    dc80:	00 00 
    dc82:	75 06                	jne    dc8a <parse_date+0x7a>
    dc84:	48 83 c4 40          	add    $0x40,%rsp
    dc88:	5d                   	pop    %rbp
    dc89:	c3                   	retq   
    dc8a:	e8 d1 9b ff ff       	callq  7860 <__stack_chk_fail@plt>
    dc8f:	90                   	nop

000000000000dc90 <convert_old_date>:

time_t
convert_old_date (int day, int month, int year)
{
    dc90:	f3 0f 1e fa          	endbr64 
    dc94:	48 83 ec 48          	sub    $0x48,%rsp
  struct tm  broken;

  broken.tm_year = year-1900;
    dc98:	81 ea 6c 07 00 00    	sub    $0x76c,%edx
  broken.tm_mon = month-1;
    dc9e:	83 ee 01             	sub    $0x1,%esi
{
    dca1:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    dca8:	00 00 
    dcaa:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
    dcaf:	31 c0                	xor    %eax,%eax
  broken.tm_mday = day;
    dcb1:	89 7c 24 0c          	mov    %edi,0xc(%rsp)
  broken.tm_hour = 12;
  broken.tm_min = 0;
  broken.tm_sec = 0;

  return  mktime (&broken);
    dcb5:	48 89 e7             	mov    %rsp,%rdi
  broken.tm_year = year-1900;
    dcb8:	89 54 24 14          	mov    %edx,0x14(%rsp)
  broken.tm_mon = month-1;
    dcbc:	89 74 24 10          	mov    %esi,0x10(%rsp)
  broken.tm_sec = 0;
    dcc0:	48 c7 04 24 00 00 00 	movq   $0x0,(%rsp)
    dcc7:	00 
  broken.tm_hour = 12;
    dcc8:	c7 44 24 08 0c 00 00 	movl   $0xc,0x8(%rsp)
    dccf:	00 
  return  mktime (&broken);
    dcd0:	e8 cb 9d ff ff       	callq  7aa0 <mktime@plt>
}
    dcd5:	48 8b 4c 24 38       	mov    0x38(%rsp),%rcx
    dcda:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    dce1:	00 00 
    dce3:	75 05                	jne    dcea <convert_old_date+0x5a>
    dce5:	48 83 c4 48          	add    $0x48,%rsp
    dce9:	c3                   	retq   
    dcea:	e8 71 9b ff ff       	callq  7860 <__stack_chk_fail@plt>
    dcef:	90                   	nop

000000000000dcf0 <format_date>:
void
format_date (char *buffer, time_t date)
/* Into the BUFFER format a textual representation of DATE.
 * Buffer must contain at least MAX_DATE_CHARS characters.
 * The filled-in string is feasible for parsing with `parse_date'.  */
{
    dcf0:	f3 0f 1e fa          	endbr64 
    dcf4:	55                   	push   %rbp
    dcf5:	48 89 fd             	mov    %rdi,%rbp
    dcf8:	48 83 ec 10          	sub    $0x10,%rsp
  struct tm *loctime;

  loctime = localtime (&date);
    dcfc:	48 8d 7c 24 08       	lea    0x8(%rsp),%rdi
{
    dd01:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
  loctime = localtime (&date);
    dd06:	e8 f5 99 ff ff       	callq  7700 <localtime@plt>
  if (loctime) {
    dd0b:	48 85 c0             	test   %rax,%rax
    dd0e:	74 50                	je     dd60 <format_date+0x70>
    dd10:	8b 30                	mov    (%rax),%esi
    sprintf (buffer, "%d-%d-%d %d:%d:%d",
    dd12:	8b 48 10             	mov    0x10(%rax),%ecx
    dd15:	48 89 ef             	mov    %rbp,%rdi
    dd18:	8b 50 14             	mov    0x14(%rax),%edx
    dd1b:	56                   	push   %rsi
    dd1c:	8b 70 04             	mov    0x4(%rax),%esi
    dd1f:	44 8d 49 01          	lea    0x1(%rcx),%r9d
    dd23:	48 8d 0d 6e c1 00 00 	lea    0xc16e(%rip),%rcx        # 19e98 <__PRETTY_FUNCTION__.7358+0x28>
    dd2a:	44 8d 82 6c 07 00 00 	lea    0x76c(%rdx),%r8d
    dd31:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    dd38:	56                   	push   %rsi
    dd39:	8b 70 08             	mov    0x8(%rax),%esi
    dd3c:	56                   	push   %rsi
    dd3d:	8b 40 0c             	mov    0xc(%rax),%eax
    dd40:	be 01 00 00 00       	mov    $0x1,%esi
    dd45:	50                   	push   %rax
    dd46:	31 c0                	xor    %eax,%eax
    dd48:	e8 c3 9f ff ff       	callq  7d10 <__sprintf_chk@plt>
    dd4d:	48 83 c4 20          	add    $0x20,%rsp
             loctime->tm_year+1900, loctime->tm_mon+1, loctime->tm_mday,
             loctime->tm_hour, loctime->tm_min, loctime->tm_sec);
  } else {
    sprintf (buffer, "sometimes");
  }
}
    dd51:	48 83 c4 10          	add    $0x10,%rsp
    dd55:	5d                   	pop    %rbp
    dd56:	c3                   	retq   
    dd57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    dd5e:	00 00 
    dd60:	48 b8 73 6f 6d 65 74 	movabs $0x656d6974656d6f73,%rax
    dd67:	69 6d 65 
    dd6a:	48 89 45 00          	mov    %rax,0x0(%rbp)
    dd6e:	b8 73 00 00 00       	mov    $0x73,%eax
    dd73:	66 89 45 08          	mov    %ax,0x8(%rbp)
    dd77:	48 83 c4 10          	add    $0x10,%rsp
    dd7b:	5d                   	pop    %rbp
    dd7c:	c3                   	retq   
    dd7d:	0f 1f 00             	nopl   (%rax)

000000000000dd80 <format_display_date>:
void
format_display_date (char *buffer, time_t date)
/* Into the BUFFER format a textual representation of DATE.
 * Buffer must contain at least 11 characters.  The filled-in string
 * is meant to be part of the displayed highscore list.  */
{
    dd80:	f3 0f 1e fa          	endbr64 
    dd84:	55                   	push   %rbp
    dd85:	48 89 fd             	mov    %rdi,%rbp
    dd88:	48 83 ec 10          	sub    $0x10,%rsp
  struct tm *loctime;

  loctime = localtime (&date);
    dd8c:	48 8d 7c 24 08       	lea    0x8(%rsp),%rdi
{
    dd91:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
  loctime = localtime (&date);
    dd96:	e8 65 99 ff ff       	callq  7700 <localtime@plt>
  if (loctime) {
    dd9b:	48 85 c0             	test   %rax,%rax
    dd9e:	74 40                	je     dde0 <format_display_date+0x60>
    sprintf (buffer, "%4d-%02d-%02d",
    dda0:	8b 48 10             	mov    0x10(%rax),%ecx
    dda3:	8b 50 14             	mov    0x14(%rax),%edx
    dda6:	48 83 ec 08          	sub    $0x8,%rsp
    ddaa:	48 89 ef             	mov    %rbp,%rdi
    ddad:	8b 40 0c             	mov    0xc(%rax),%eax
    ddb0:	be 01 00 00 00       	mov    $0x1,%esi
    ddb5:	44 8d 49 01          	lea    0x1(%rcx),%r9d
    ddb9:	44 8d 82 6c 07 00 00 	lea    0x76c(%rdx),%r8d
    ddc0:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    ddc7:	50                   	push   %rax
    ddc8:	48 8d 0d db c0 00 00 	lea    0xc0db(%rip),%rcx        # 19eaa <__PRETTY_FUNCTION__.7358+0x3a>
    ddcf:	31 c0                	xor    %eax,%eax
    ddd1:	e8 3a 9f ff ff       	callq  7d10 <__sprintf_chk@plt>
    ddd6:	5a                   	pop    %rdx
    ddd7:	59                   	pop    %rcx
             loctime->tm_year+1900, loctime->tm_mon+1, loctime->tm_mday);
  } else {
    sprintf (buffer, "sometimes");
  }
}
    ddd8:	48 83 c4 10          	add    $0x10,%rsp
    dddc:	5d                   	pop    %rbp
    dddd:	c3                   	retq   
    ddde:	66 90                	xchg   %ax,%ax
    dde0:	48 b8 73 6f 6d 65 74 	movabs $0x656d6974656d6f73,%rax
    dde7:	69 6d 65 
    ddea:	48 89 45 00          	mov    %rax,0x0(%rbp)
    ddee:	b8 73 00 00 00       	mov    $0x73,%eax
    ddf3:	66 89 45 08          	mov    %ax,0x8(%rbp)
    ddf7:	48 83 c4 10          	add    $0x10,%rsp
    ddfb:	5d                   	pop    %rbp
    ddfc:	c3                   	retq   
    ddfd:	0f 1f 00             	nopl   (%rax)

000000000000de00 <format_relative_time>:
void
format_relative_time (char *buffer, double dt)
/* Into the BUFFER format a textual representation of time period DT.
 * Buffer must contain at least 5 characters.  The filled-in string
 * is meant to be part of the displayed highscore list.  */
{
    de00:	f3 0f 1e fa          	endbr64 
  double  hour = 60*60;
  double  day = 24*hour;

  if (dt <= 0) {
    de04:	66 0f ef c9          	pxor   %xmm1,%xmm1
    de08:	66 0f 2f c8          	comisd %xmm0,%xmm1
    de0c:	73 6a                	jae    de78 <format_relative_time+0x78>
    sprintf (buffer, "soon");
  } else if (dt > 999*day) {
    de0e:	66 0f 2f 05 b2 c0 00 	comisd 0xc0b2(%rip),%xmm0        # 19ec8 <__PRETTY_FUNCTION__.7358+0x58>
    de15:	00 
    de16:	77 50                	ja     de68 <format_relative_time+0x68>
    sprintf (buffer, " -- ");
  } else if (dt >= day) {
    de18:	f2 0f 10 0d b0 c0 00 	movsd  0xc0b0(%rip),%xmm1        # 19ed0 <__PRETTY_FUNCTION__.7358+0x60>
    de1f:	00 
    de20:	66 0f 2f c1          	comisd %xmm1,%xmm0
    de24:	0f 83 96 00 00 00    	jae    dec0 <format_relative_time+0xc0>
    sprintf (buffer, "%3dd", (int)(dt/day+0.5));
  } else if (dt >= hour) {
    de2a:	f2 0f 10 0d a6 c0 00 	movsd  0xc0a6(%rip),%xmm1        # 19ed8 <__PRETTY_FUNCTION__.7358+0x68>
    de31:	00 
    de32:	66 0f 2f c1          	comisd %xmm1,%xmm0
    de36:	72 50                	jb     de88 <format_relative_time+0x88>
    sprintf (buffer, "%3dh", (int)(dt/hour+0.5));
    de38:	f2 0f 5e c1          	divsd  %xmm1,%xmm0
    de3c:	48 8d 0d 7a c0 00 00 	lea    0xc07a(%rip),%rcx        # 19ebd <__PRETTY_FUNCTION__.7358+0x4d>
    de43:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    de4a:	31 c0                	xor    %eax,%eax
    de4c:	be 01 00 00 00       	mov    $0x1,%esi
    de51:	f2 0f 58 05 d7 28 00 	addsd  0x28d7(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    de58:	00 
    de59:	f2 44 0f 2c c0       	cvttsd2si %xmm0,%r8d
    de5e:	e9 ad 9e ff ff       	jmpq   7d10 <__sprintf_chk@plt>
    de63:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    de68:	c7 07 20 2d 2d 20    	movl   $0x202d2d20,(%rdi)
    de6e:	c6 47 04 00          	movb   $0x0,0x4(%rdi)
  } else {
    sprintf (buffer, "%3dm", (int)(dt/60+0.5));
  }
}
    de72:	c3                   	retq   
    de73:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    de78:	c7 07 73 6f 6f 6e    	movl   $0x6e6f6f73,(%rdi)
    de7e:	c6 47 04 00          	movb   $0x0,0x4(%rdi)
    de82:	c3                   	retq   
    de83:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    sprintf (buffer, "%3dm", (int)(dt/60+0.5));
    de88:	f2 0f 5e 05 50 c0 00 	divsd  0xc050(%rip),%xmm0        # 19ee0 <__PRETTY_FUNCTION__.7358+0x70>
    de8f:	00 
    de90:	f2 0f 58 05 98 28 00 	addsd  0x2898(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    de97:	00 
    de98:	be 01 00 00 00       	mov    $0x1,%esi
    de9d:	31 c0                	xor    %eax,%eax
    de9f:	48 8d 0d 1c c0 00 00 	lea    0xc01c(%rip),%rcx        # 19ec2 <__PRETTY_FUNCTION__.7358+0x52>
    dea6:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    dead:	f2 44 0f 2c c0       	cvttsd2si %xmm0,%r8d
    deb2:	e9 59 9e ff ff       	jmpq   7d10 <__sprintf_chk@plt>
    deb7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    debe:	00 00 
    sprintf (buffer, "%3dd", (int)(dt/day+0.5));
    dec0:	f2 0f 5e c1          	divsd  %xmm1,%xmm0
    dec4:	48 8d 0d ed bf 00 00 	lea    0xbfed(%rip),%rcx        # 19eb8 <__PRETTY_FUNCTION__.7358+0x48>
    decb:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    ded2:	31 c0                	xor    %eax,%eax
    ded4:	be 01 00 00 00       	mov    $0x1,%esi
    ded9:	f2 0f 58 05 4f 28 00 	addsd  0x284f(%rip),%xmm0        # 10730 <_IO_stdin_used+0x730>
    dee0:	00 
    dee1:	f2 44 0f 2c c0       	cvttsd2si %xmm0,%r8d
    dee6:	e9 25 9e ff ff       	jmpq   7d10 <__sprintf_chk@plt>
    deeb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000def0 <initialise_persona>:
{
    def0:	f3 0f 1e fa          	endbr64 
    def4:	41 54                	push   %r12
    def6:	55                   	push   %rbp
    def7:	53                   	push   %rbx
  current = pers_GAME;
    def8:	c7 05 a6 2d 01 00 00 	movl   $0x0,0x12da6(%rip)        # 20ca8 <current>
    deff:	00 00 00 
  method = m_NONE;
    df02:	c7 05 a0 2d 01 00 00 	movl   $0x0,0x12da0(%rip)        # 20cac <method>
    df09:	00 00 00 
  user_uid = getuid ();
    df0c:	e8 5f 99 ff ff       	callq  7870 <getuid@plt>
    df11:	89 05 8d 2d 01 00    	mov    %eax,0x12d8d(%rip)        # 20ca4 <user_uid>
    df17:	41 89 c4             	mov    %eax,%r12d
  game_uid = geteuid ();
    df1a:	e8 01 9a ff ff       	callq  7920 <geteuid@plt>
    df1f:	89 05 7b 2d 01 00    	mov    %eax,0x12d7b(%rip)        # 20ca0 <game_uid>
    df25:	89 c5                	mov    %eax,%ebp
  user_gid = getgid ();
    df27:	e8 d4 9a ff ff       	callq  7a00 <getgid@plt>
    df2c:	89 05 6a 2d 01 00    	mov    %eax,0x12d6a(%rip)        # 20c9c <user_gid>
    df32:	89 c3                	mov    %eax,%ebx
  game_gid = getegid ();
    df34:	e8 57 9b ff ff       	callq  7a90 <getegid@plt>
    df39:	89 05 59 2d 01 00    	mov    %eax,0x12d59(%rip)        # 20c98 <game_gid>
  if (user_uid == game_uid && user_gid == game_gid)  return;
    df3f:	39 c3                	cmp    %eax,%ebx
    df41:	75 05                	jne    df48 <initialise_persona+0x58>
    df43:	41 39 ec             	cmp    %ebp,%r12d
    df46:	74 0a                	je     df52 <initialise_persona+0x62>
    method = m_SAVED;
    df48:	c7 05 5a 2d 01 00 01 	movl   $0x1,0x12d5a(%rip)        # 20cac <method>
    df4f:	00 00 00 
}
    df52:	5b                   	pop    %rbx
    df53:	5d                   	pop    %rbp
    df54:	41 5c                	pop    %r12
    df56:	c3                   	retq   
    df57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    df5e:	00 00 

000000000000df60 <is_setgid>:
{
    df60:	f3 0f 1e fa          	endbr64 
  return  (user_gid != game_gid && current == pers_GAME);
    df64:	8b 15 2e 2d 01 00    	mov    0x12d2e(%rip),%edx        # 20c98 <game_gid>
    df6a:	31 c0                	xor    %eax,%eax
    df6c:	39 15 2a 2d 01 00    	cmp    %edx,0x12d2a(%rip)        # 20c9c <user_gid>
    df72:	74 0d                	je     df81 <is_setgid+0x21>
    df74:	8b 15 2e 2d 01 00    	mov    0x12d2e(%rip),%edx        # 20ca8 <current>
    df7a:	31 c0                	xor    %eax,%eax
    df7c:	85 d2                	test   %edx,%edx
    df7e:	0f 94 c0             	sete   %al
}
    df81:	c3                   	retq   
    df82:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    df89:	00 00 00 00 
    df8d:	0f 1f 00             	nopl   (%rax)

000000000000df90 <set_persona>:
{
    df90:	f3 0f 1e fa          	endbr64 
    df94:	41 54                	push   %r12
    df96:	55                   	push   %rbp
    df97:	53                   	push   %rbx
    df98:	89 fb                	mov    %edi,%ebx
  if (current == pers)  return;
    df9a:	39 1d 08 2d 01 00    	cmp    %ebx,0x12d08(%rip)        # 20ca8 <current>
    dfa0:	74 33                	je     dfd5 <set_persona+0x45>
  switch (pers) {
    dfa2:	85 db                	test   %ebx,%ebx
    dfa4:	75 3a                	jne    dfe0 <set_persona+0x50>
  }

  switch (method) {
    dfa6:	8b 05 00 2d 01 00    	mov    0x12d00(%rip),%eax        # 20cac <method>
    old_uid = user_uid;
    dfac:	8b 3d f2 2c 01 00    	mov    0x12cf2(%rip),%edi        # 20ca4 <user_uid>
    new_uid = game_uid;
    dfb2:	8b 35 e8 2c 01 00    	mov    0x12ce8(%rip),%esi        # 20ca0 <game_uid>
    old_gid = user_gid;
    dfb8:	44 8b 25 dd 2c 01 00 	mov    0x12cdd(%rip),%r12d        # 20c9c <user_gid>
    new_gid = game_gid;
    dfbf:	8b 2d d3 2c 01 00    	mov    0x12cd3(%rip),%ebp        # 20c98 <game_gid>
  switch (method) {
    dfc5:	83 f8 01             	cmp    $0x1,%eax
    dfc8:	74 43                	je     e00d <set_persona+0x7d>
    dfca:	83 f8 02             	cmp    $0x2,%eax
    dfcd:	74 71                	je     e040 <set_persona+0xb0>
#else
    abort ();			/* should not happen */
#endif
    break;
  }
  current = pers;
    dfcf:	89 1d d3 2c 01 00    	mov    %ebx,0x12cd3(%rip)        # 20ca8 <current>
}
    dfd5:	5b                   	pop    %rbx
    dfd6:	5d                   	pop    %rbp
    dfd7:	41 5c                	pop    %r12
    dfd9:	c3                   	retq   
    dfda:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  switch (pers) {
    dfe0:	83 fb 01             	cmp    $0x1,%ebx
    dfe3:	0f 85 bd 00 00 00    	jne    e0a6 <set_persona+0x116>
  switch (method) {
    dfe9:	8b 05 bd 2c 01 00    	mov    0x12cbd(%rip),%eax        # 20cac <method>
    old_uid = game_uid;
    dfef:	8b 3d ab 2c 01 00    	mov    0x12cab(%rip),%edi        # 20ca0 <game_uid>
    new_uid = user_uid;
    dff5:	8b 35 a9 2c 01 00    	mov    0x12ca9(%rip),%esi        # 20ca4 <user_uid>
    old_gid = game_gid;
    dffb:	44 8b 25 96 2c 01 00 	mov    0x12c96(%rip),%r12d        # 20c98 <game_gid>
    new_gid = user_gid;
    e002:	8b 2d 94 2c 01 00    	mov    0x12c94(%rip),%ebp        # 20c9c <user_gid>
  switch (method) {
    e008:	83 f8 01             	cmp    $0x1,%eax
    e00b:	75 bd                	jne    dfca <set_persona+0x3a>
    res = setuid (new_uid);
    e00d:	89 f7                	mov    %esi,%edi
    e00f:	e8 5c 9c ff ff       	callq  7c70 <setuid@plt>
    if (res < 0)  fatal ("Cannot set uid to %s", name[pers]);
    e014:	85 c0                	test   %eax,%eax
    e016:	78 5c                	js     e074 <set_persona+0xe4>
    res = setgid (new_gid);
    e018:	89 ef                	mov    %ebp,%edi
    e01a:	e8 61 9b ff ff       	callq  7b80 <setgid@plt>
    if (res < 0)  fatal ("Cannot set gid to %s", name[pers]);
    e01f:	85 c0                	test   %eax,%eax
    e021:	79 ac                	jns    dfcf <set_persona+0x3f>
    e023:	48 8d 05 26 0a 01 00 	lea    0x10a26(%rip),%rax        # 1ea50 <name>
    e02a:	48 8d 3d cc be 00 00 	lea    0xbecc(%rip),%rdi        # 19efd <__PRETTY_FUNCTION__.7358+0x8d>
    e031:	48 8b 34 d8          	mov    (%rax,%rbx,8),%rsi
    e035:	31 c0                	xor    %eax,%eax
    e037:	e8 24 15 00 00       	callq  f560 <fatal>
    e03c:	0f 1f 40 00          	nopl   0x0(%rax)
    res = setreuid (old_uid, new_uid);
    e040:	e8 9b 9a ff ff       	callq  7ae0 <setreuid@plt>
    if (res < 0)  fatal ("Cannot switch real/effective uid to %s", name[pers]);
    e045:	85 c0                	test   %eax,%eax
    e047:	78 44                	js     e08d <set_persona+0xfd>
    res = setregid (old_gid, new_gid);
    e049:	89 ee                	mov    %ebp,%esi
    e04b:	44 89 e7             	mov    %r12d,%edi
    e04e:	e8 9d 9a ff ff       	callq  7af0 <setregid@plt>
    if (res < 0)  fatal ("Cannot switch real/effective gid to %s", name[pers]);
    e053:	85 c0                	test   %eax,%eax
    e055:	0f 89 74 ff ff ff    	jns    dfcf <set_persona+0x3f>
    e05b:	48 8d 05 ee 09 01 00 	lea    0x109ee(%rip),%rax        # 1ea50 <name>
    e062:	48 8d 3d d7 be 00 00 	lea    0xbed7(%rip),%rdi        # 19f40 <__PRETTY_FUNCTION__.7358+0xd0>
    e069:	48 8b 34 d8          	mov    (%rax,%rbx,8),%rsi
    e06d:	31 c0                	xor    %eax,%eax
    e06f:	e8 ec 14 00 00       	callq  f560 <fatal>
    if (res < 0)  fatal ("Cannot set uid to %s", name[pers]);
    e074:	48 8d 05 d5 09 01 00 	lea    0x109d5(%rip),%rax        # 1ea50 <name>
    e07b:	48 8d 3d 66 be 00 00 	lea    0xbe66(%rip),%rdi        # 19ee8 <__PRETTY_FUNCTION__.7358+0x78>
    e082:	48 8b 34 d8          	mov    (%rax,%rbx,8),%rsi
    e086:	31 c0                	xor    %eax,%eax
    e088:	e8 d3 14 00 00       	callq  f560 <fatal>
    if (res < 0)  fatal ("Cannot switch real/effective uid to %s", name[pers]);
    e08d:	48 8d 05 bc 09 01 00 	lea    0x109bc(%rip),%rax        # 1ea50 <name>
    e094:	48 8d 3d 7d be 00 00 	lea    0xbe7d(%rip),%rdi        # 19f18 <__PRETTY_FUNCTION__.7358+0xa8>
    e09b:	48 8b 34 d8          	mov    (%rax,%rbx,8),%rsi
    e09f:	31 c0                	xor    %eax,%eax
    e0a1:	e8 ba 14 00 00       	callq  f560 <fatal>
    e0a6:	e9 75 9c ff ff       	jmpq   7d20 <set_persona.cold>
    e0ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000e0b0 <winch_handler>:
  clock_thaw ();
}

static void
winch_handler (int signum)
{
    e0b0:	f3 0f 1e fa          	endbr64 
    e0b4:	48 83 ec 08          	sub    $0x8,%rsp
  clock_freeze ();
    e0b8:	e8 c3 f7 ff ff       	callq  d880 <clock_freeze>
  delwin (moon);
    e0bd:	48 8b 3d 54 2d 01 00 	mov    0x12d54(%rip),%rdi        # 20e18 <moon>
    e0c4:	e8 57 99 ff ff       	callq  7a20 <delwin@plt>
  delwin (status);
    e0c9:	48 8b 3d 40 2d 01 00 	mov    0x12d40(%rip),%rdi        # 20e10 <status>
    e0d0:	e8 4b 99 ff ff       	callq  7a20 <delwin@plt>
  delwin (message);
    e0d5:	48 8b 3d 24 2d 01 00 	mov    0x12d24(%rip),%rdi        # 20e00 <message>
    e0dc:	e8 3f 99 ff ff       	callq  7a20 <delwin@plt>
  sleep (1);
    e0e1:	bf 01 00 00 00       	mov    $0x1,%edi
    e0e6:	e8 c5 9b ff ff       	callq  7cb0 <sleep@plt>
  endwin ();
    e0eb:	e8 90 9b ff ff       	callq  7c80 <endwin@plt>

  refresh ();
    e0f0:	48 8b 3d 79 11 01 00 	mov    0x11179(%rip),%rdi        # 1f270 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    e0f7:	e8 04 98 ff ff       	callq  7900 <wrefresh@plt>
  allocate_windows ();
    e0fc:	e8 ff a3 ff ff       	callq  8500 <allocate_windows>
  hide_cursor ();
    e101:	e8 4a 13 00 00       	callq  f450 <hide_cursor>
  mode_redraw ();
    e106:	e8 35 a7 ff ff       	callq  8840 <mode_redraw>
  clock_thaw ();
}
    e10b:	48 83 c4 08          	add    $0x8,%rsp
  clock_thaw ();
    e10f:	e9 5c f5 ff ff       	jmpq   d670 <clock_thaw>
    e114:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    e11b:	00 00 00 00 
    e11f:	90                   	nop

000000000000e120 <termination_handler>:
{
    e120:	f3 0f 1e fa          	endbr64 
    e124:	55                   	push   %rbp
    e125:	89 fd                	mov    %edi,%ebp
  prepare_for_exit ();
    e127:	e8 b4 a3 ff ff       	callq  84e0 <prepare_for_exit>
  return __fprintf_chk (__stream, __USE_FORTIFY_LEVEL - 1, __fmt,
    e12c:	48 8b 3d 6d 11 01 00 	mov    0x1116d(%rip),%rdi        # 1f2a0 <stderr@@GLIBC_2.2.5>
    e133:	89 e9                	mov    %ebp,%ecx
    e135:	31 c0                	xor    %eax,%eax
    e137:	48 8d 15 29 be 00 00 	lea    0xbe29(%rip),%rdx        # 19f67 <__PRETTY_FUNCTION__.7358+0xf7>
    e13e:	be 01 00 00 00       	mov    $0x1,%esi
    e143:	e8 f8 9a ff ff       	callq  7c40 <__fprintf_chk@plt>
  raise (signum);
    e148:	89 ef                	mov    %ebp,%edi
}
    e14a:	5d                   	pop    %rbp
  raise (signum);
    e14b:	e9 90 95 ff ff       	jmpq   76e0 <raise@plt>

000000000000e150 <install_signal>:
{
    e150:	41 54                	push   %r12
    e152:	55                   	push   %rbp
    e153:	89 fd                	mov    %edi,%ebp
    e155:	48 81 ec a8 00 00 00 	sub    $0xa8,%rsp
    e15c:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    e163:	00 00 
    e165:	48 89 84 24 98 00 00 	mov    %rax,0x98(%rsp)
    e16c:	00 
    e16d:	31 c0                	xor    %eax,%eax
  sigemptyset (&action.sa_mask);
    e16f:	48 8d 7c 24 08       	lea    0x8(%rsp),%rdi
    e174:	49 89 e4             	mov    %rsp,%r12
  action.sa_handler = handler;
    e177:	48 89 34 24          	mov    %rsi,(%rsp)
  sigemptyset (&action.sa_mask);
    e17b:	e8 20 98 ff ff       	callq  79a0 <sigemptyset@plt>
  ret = sigaction (signum, &action, NULL);
    e180:	31 d2                	xor    %edx,%edx
    e182:	4c 89 e6             	mov    %r12,%rsi
    e185:	89 ef                	mov    %ebp,%edi
  action.sa_flags = 0;
    e187:	c7 84 24 88 00 00 00 	movl   $0x0,0x88(%rsp)
    e18e:	00 00 00 00 
  ret = sigaction (signum, &action, NULL);
    e192:	e8 39 96 ff ff       	callq  77d0 <sigaction@plt>
  assert (ret == 0);
    e197:	85 c0                	test   %eax,%eax
    e199:	75 1e                	jne    e1b9 <install_signal+0x69>
}
    e19b:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    e1a2:	00 
    e1a3:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    e1aa:	00 00 
    e1ac:	75 2a                	jne    e1d8 <install_signal+0x88>
    e1ae:	48 81 c4 a8 00 00 00 	add    $0xa8,%rsp
    e1b5:	5d                   	pop    %rbp
    e1b6:	41 5c                	pop    %r12
    e1b8:	c3                   	retq   
  assert (ret == 0);
    e1b9:	48 8d 0d 00 be 00 00 	lea    0xbe00(%rip),%rcx        # 19fc0 <__PRETTY_FUNCTION__.5191>
    e1c0:	ba 3a 00 00 00       	mov    $0x3a,%edx
    e1c5:	48 8d 35 b5 bd 00 00 	lea    0xbdb5(%rip),%rsi        # 19f81 <__PRETTY_FUNCTION__.7358+0x111>
    e1cc:	48 8d 3d b7 bd 00 00 	lea    0xbdb7(%rip),%rdi        # 19f8a <__PRETTY_FUNCTION__.7358+0x11a>
    e1d3:	e8 08 97 ff ff       	callq  78e0 <__assert_fail@plt>
}
    e1d8:	e8 83 96 ff ff       	callq  7860 <__stack_chk_fail@plt>
    e1dd:	0f 1f 00             	nopl   (%rax)

000000000000e1e0 <tstp_handler>:
{
    e1e0:	f3 0f 1e fa          	endbr64 
    e1e4:	55                   	push   %rbp
    e1e5:	89 fd                	mov    %edi,%ebp
  clock_freeze ();
    e1e7:	e8 94 f6 ff ff       	callq  d880 <clock_freeze>
  mode_signal (signum);
    e1ec:	89 ef                	mov    %ebp,%edi
    e1ee:	e8 ed a6 ff ff       	callq  88e0 <mode_signal>
  prepare_for_exit ();
    e1f3:	e8 e8 a2 ff ff       	callq  84e0 <prepare_for_exit>
  install_signal (SIGTSTP, SIG_DFL);
    e1f8:	bf 14 00 00 00       	mov    $0x14,%edi
    e1fd:	31 f6                	xor    %esi,%esi
    e1ff:	e8 4c ff ff ff       	callq  e150 <install_signal>
  raise (SIGTSTP);
    e204:	bf 14 00 00 00       	mov    $0x14,%edi
}
    e209:	5d                   	pop    %rbp
  raise (SIGTSTP);
    e20a:	e9 d1 94 ff ff       	jmpq   76e0 <raise@plt>
    e20f:	90                   	nop

000000000000e210 <cont_handler>:
{
    e210:	f3 0f 1e fa          	endbr64 
    e214:	55                   	push   %rbp
  install_signal (SIGTSTP, tstp_handler);
    e215:	48 8d 35 c4 ff ff ff 	lea    -0x3c(%rip),%rsi        # e1e0 <tstp_handler>
{
    e21c:	89 fd                	mov    %edi,%ebp
  install_signal (SIGTSTP, tstp_handler);
    e21e:	bf 14 00 00 00       	mov    $0x14,%edi
    e223:	e8 28 ff ff ff       	callq  e150 <install_signal>
  refresh ();
    e228:	48 8b 3d 41 10 01 00 	mov    0x11041(%rip),%rdi        # 1f270 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    e22f:	e8 cc 96 ff ff       	callq  7900 <wrefresh@plt>
  prepare_screen ();
    e234:	e8 77 a2 ff ff       	callq  84b0 <prepare_screen>
  mode_redraw ();
    e239:	e8 02 a6 ff ff       	callq  8840 <mode_redraw>
  mode_signal (signum);
    e23e:	89 ef                	mov    %ebp,%edi
    e240:	e8 9b a6 ff ff       	callq  88e0 <mode_signal>
}
    e245:	5d                   	pop    %rbp
  clock_thaw ();
    e246:	e9 25 f4 ff ff       	jmpq   d670 <clock_thaw>
    e24b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000e250 <my_signal>:
{
    e250:	55                   	push   %rbp
    e251:	89 fd                	mov    %edi,%ebp
    e253:	53                   	push   %rbx
    e254:	48 89 f3             	mov    %rsi,%rbx
    e257:	48 81 ec a8 00 00 00 	sub    $0xa8,%rsp
    e25e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    e265:	00 00 
    e267:	48 89 84 24 98 00 00 	mov    %rax,0x98(%rsp)
    e26e:	00 
    e26f:	31 c0                	xor    %eax,%eax
  if (ignore_test) {
    e271:	85 d2                	test   %edx,%edx
    e273:	75 6b                	jne    e2e0 <my_signal+0x90>
  DA_ADD_EMPTY (sig_info_table, struct sig_info, info);
    e275:	8b 15 61 2b 01 00    	mov    0x12b61(%rip),%edx        # 20ddc <sig_info_table+0xc>
    e27b:	8b 35 57 2b 01 00    	mov    0x12b57(%rip),%esi        # 20dd8 <sig_info_table+0x8>
    e281:	48 8b 3d 48 2b 01 00 	mov    0x12b48(%rip),%rdi        # 20dd0 <sig_info_table>
    e288:	39 f2                	cmp    %esi,%edx
    e28a:	7d 6c                	jge    e2f8 <my_signal+0xa8>
    e28c:	48 63 c2             	movslq %edx,%rax
  install_signal (signum, generic_handler);
    e28f:	48 8d 35 9a 00 00 00 	lea    0x9a(%rip),%rsi        # e330 <generic_handler>
  DA_ADD_EMPTY (sig_info_table, struct sig_info, info);
    e296:	83 c2 01             	add    $0x1,%edx
    e299:	48 c1 e0 04          	shl    $0x4,%rax
    e29d:	89 15 39 2b 01 00    	mov    %edx,0x12b39(%rip)        # 20ddc <sig_info_table+0xc>
    e2a3:	48 01 c7             	add    %rax,%rdi
  info->signum = signum;
    e2a6:	89 2f                	mov    %ebp,(%rdi)
  info->pending = 0;
    e2a8:	c7 47 04 00 00 00 00 	movl   $0x0,0x4(%rdi)
  info->handler = handler;
    e2af:	48 89 5f 08          	mov    %rbx,0x8(%rdi)
  install_signal (signum, generic_handler);
    e2b3:	89 ef                	mov    %ebp,%edi
    e2b5:	e8 96 fe ff ff       	callq  e150 <install_signal>
}
    e2ba:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    e2c1:	00 
    e2c2:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    e2c9:	00 00 
    e2cb:	75 55                	jne    e322 <my_signal+0xd2>
    e2cd:	48 81 c4 a8 00 00 00 	add    $0xa8,%rsp
    e2d4:	5b                   	pop    %rbx
    e2d5:	5d                   	pop    %rbp
    e2d6:	c3                   	retq   
    e2d7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    e2de:	00 00 
    sigaction (signum, NULL, &action);
    e2e0:	31 f6                	xor    %esi,%esi
    e2e2:	48 89 e2             	mov    %rsp,%rdx
    e2e5:	e8 e6 94 ff ff       	callq  77d0 <sigaction@plt>
    if (action.sa_handler == SIG_IGN)  return;
    e2ea:	48 83 3c 24 01       	cmpq   $0x1,(%rsp)
    e2ef:	75 84                	jne    e275 <my_signal+0x25>
    e2f1:	eb c7                	jmp    e2ba <my_signal+0x6a>
    e2f3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  DA_ADD_EMPTY (sig_info_table, struct sig_info, info);
    e2f8:	83 c6 04             	add    $0x4,%esi
    e2fb:	89 35 d7 2a 01 00    	mov    %esi,0x12ad7(%rip)        # 20dd8 <sig_info_table+0x8>
    e301:	48 63 f6             	movslq %esi,%rsi
    e304:	48 c1 e6 04          	shl    $0x4,%rsi
    e308:	e8 83 13 00 00       	callq  f690 <xrealloc>
    e30d:	8b 15 c9 2a 01 00    	mov    0x12ac9(%rip),%edx        # 20ddc <sig_info_table+0xc>
    e313:	48 89 05 b6 2a 01 00 	mov    %rax,0x12ab6(%rip)        # 20dd0 <sig_info_table>
    e31a:	48 89 c7             	mov    %rax,%rdi
    e31d:	e9 6a ff ff ff       	jmpq   e28c <my_signal+0x3c>
}
    e322:	e8 39 95 ff ff       	callq  7860 <__stack_chk_fail@plt>
    e327:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    e32e:	00 00 

000000000000e330 <generic_handler>:
{
    e330:	f3 0f 1e fa          	endbr64 
  signal_arrived = 1;
    e334:	c7 05 82 2a 01 00 01 	movl   $0x1,0x12a82(%rip)        # 20dc0 <signal_arrived>
    e33b:	00 00 00 
  for (i=0; i<sig_info_table.used; ++i) {
    e33e:	8b 15 98 2a 01 00    	mov    0x12a98(%rip),%edx        # 20ddc <sig_info_table+0xc>
    e344:	85 d2                	test   %edx,%edx
    e346:	7e 4f                	jle    e397 <generic_handler+0x67>
    e348:	48 8b 05 81 2a 01 00 	mov    0x12a81(%rip),%rax        # 20dd0 <sig_info_table>
    e34f:	83 ea 01             	sub    $0x1,%edx
    e352:	48 c1 e2 04          	shl    $0x4,%rdx
    e356:	48 8d 54 10 10       	lea    0x10(%rax,%rdx,1),%rdx
    e35b:	eb 0c                	jmp    e369 <generic_handler+0x39>
    e35d:	0f 1f 00             	nopl   (%rax)
    e360:	48 83 c0 10          	add    $0x10,%rax
    e364:	48 39 d0             	cmp    %rdx,%rax
    e367:	74 2e                	je     e397 <generic_handler+0x67>
    if (sig_info_table.data[i].signum == signum)  break;
    e369:	39 38                	cmp    %edi,(%rax)
    e36b:	75 f3                	jne    e360 <generic_handler+0x30>
  sig_info_table.data[i].pending = 1;
    e36d:	c7 40 04 01 00 00 00 	movl   $0x1,0x4(%rax)
  if (signum == SIGINT || signum == SIGHUP || signum == SIGTERM) {
    e374:	8d 47 ff             	lea    -0x1(%rdi),%eax
    e377:	83 f8 01             	cmp    $0x1,%eax
    e37a:	76 14                	jbe    e390 <generic_handler+0x60>
    e37c:	83 ff 0f             	cmp    $0xf,%edi
    e37f:	74 0f                	je     e390 <generic_handler+0x60>
    install_signal (signum, generic_handler);
    e381:	48 8d 35 a8 ff ff ff 	lea    -0x58(%rip),%rsi        # e330 <generic_handler>
    e388:	e9 c3 fd ff ff       	jmpq   e150 <install_signal>
    e38d:	0f 1f 00             	nopl   (%rax)
    install_signal (signum, SIG_DFL);
    e390:	31 f6                	xor    %esi,%esi
    e392:	e9 b9 fd ff ff       	jmpq   e150 <install_signal>
{
    e397:	50                   	push   %rax
  assert (i<sig_info_table.used);
    e398:	48 8d 0d 11 bc 00 00 	lea    0xbc11(%rip),%rcx        # 19fb0 <__PRETTY_FUNCTION__.5199>
    e39f:	ba 48 00 00 00       	mov    $0x48,%edx
    e3a4:	48 8d 35 d6 bb 00 00 	lea    0xbbd6(%rip),%rsi        # 19f81 <__PRETTY_FUNCTION__.7358+0x111>
    e3ab:	48 8d 3d e1 bb 00 00 	lea    0xbbe1(%rip),%rdi        # 19f93 <__PRETTY_FUNCTION__.7358+0x123>
    e3b2:	e8 29 95 ff ff       	callq  78e0 <__assert_fail@plt>
    e3b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    e3be:	00 00 

000000000000e3c0 <block_all>:
{
    e3c0:	f3 0f 1e fa          	endbr64 
  sigprocmask (SIG_BLOCK, &full_set, &old_sigset);
    e3c4:	48 8d 15 f5 28 01 00 	lea    0x128f5(%rip),%rdx        # 20cc0 <old_sigset>
    e3cb:	48 8d 35 6e 29 01 00 	lea    0x1296e(%rip),%rsi        # 20d40 <full_set>
    e3d2:	31 ff                	xor    %edi,%edi
    e3d4:	e9 f7 92 ff ff       	jmpq   76d0 <sigprocmask@plt>
    e3d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

000000000000e3e0 <unblock>:
{
    e3e0:	f3 0f 1e fa          	endbr64 
  sigprocmask (SIG_SETMASK, &old_sigset, NULL);
    e3e4:	31 d2                	xor    %edx,%edx
    e3e6:	48 8d 35 d3 28 01 00 	lea    0x128d3(%rip),%rsi        # 20cc0 <old_sigset>
    e3ed:	bf 02 00 00 00       	mov    $0x2,%edi
    e3f2:	e9 d9 92 ff ff       	jmpq   76d0 <sigprocmask@plt>
    e3f7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    e3fe:	00 00 

000000000000e400 <initialise_signals>:
 * The outside-visible entry point
 */

void
initialise_signals (void)
{
    e400:	f3 0f 1e fa          	endbr64 
    e404:	48 83 ec 08          	sub    $0x8,%rsp
  DA_INIT (sig_info_table, struct sig_info);
    e408:	bf 40 00 00 00       	mov    $0x40,%edi
    e40d:	c7 05 c1 29 01 00 04 	movl   $0x4,0x129c1(%rip)        # 20dd8 <sig_info_table+0x8>
    e414:	00 00 00 
    e417:	e8 44 12 00 00       	callq  f660 <xmalloc>
  my_signal (SIGINT, termination_handler, 1);
    e41c:	ba 01 00 00 00       	mov    $0x1,%edx
    e421:	bf 02 00 00 00       	mov    $0x2,%edi
    e426:	48 8d 35 f3 fc ff ff 	lea    -0x30d(%rip),%rsi        # e120 <termination_handler>
  DA_INIT (sig_info_table, struct sig_info);
    e42d:	48 89 05 9c 29 01 00 	mov    %rax,0x1299c(%rip)        # 20dd0 <sig_info_table>
    e434:	c7 05 9e 29 01 00 00 	movl   $0x0,0x1299e(%rip)        # 20ddc <sig_info_table+0xc>
    e43b:	00 00 00 
  my_signal (SIGINT, termination_handler, 1);
    e43e:	e8 0d fe ff ff       	callq  e250 <my_signal>
  my_signal (SIGHUP, termination_handler, 1);
    e443:	ba 01 00 00 00       	mov    $0x1,%edx
    e448:	bf 01 00 00 00       	mov    $0x1,%edi
    e44d:	48 8d 35 cc fc ff ff 	lea    -0x334(%rip),%rsi        # e120 <termination_handler>
    e454:	e8 f7 fd ff ff       	callq  e250 <my_signal>
  my_signal (SIGTERM, termination_handler, 1);
    e459:	ba 01 00 00 00       	mov    $0x1,%edx
    e45e:	bf 0f 00 00 00       	mov    $0xf,%edi
    e463:	48 8d 35 b6 fc ff ff 	lea    -0x34a(%rip),%rsi        # e120 <termination_handler>
    e46a:	e8 e1 fd ff ff       	callq  e250 <my_signal>
  my_signal (SIGCONT, cont_handler, 0);
    e46f:	31 d2                	xor    %edx,%edx
    e471:	bf 12 00 00 00       	mov    $0x12,%edi
    e476:	48 8d 35 93 fd ff ff 	lea    -0x26d(%rip),%rsi        # e210 <cont_handler>
    e47d:	e8 ce fd ff ff       	callq  e250 <my_signal>
  my_signal (SIGTSTP, tstp_handler, 0);
    e482:	31 d2                	xor    %edx,%edx
    e484:	bf 14 00 00 00       	mov    $0x14,%edi
    e489:	48 8d 35 50 fd ff ff 	lea    -0x2b0(%rip),%rsi        # e1e0 <tstp_handler>
    e490:	e8 bb fd ff ff       	callq  e250 <my_signal>
#ifdef SIGWINCH
  my_signal (SIGWINCH, winch_handler, 0);
    e495:	bf 1c 00 00 00       	mov    $0x1c,%edi
    e49a:	31 d2                	xor    %edx,%edx
    e49c:	48 8d 35 0d fc ff ff 	lea    -0x3f3(%rip),%rsi        # e0b0 <winch_handler>
    e4a3:	e8 a8 fd ff ff       	callq  e250 <my_signal>
#endif

  sigfillset (&full_set);
    e4a8:	48 8d 3d 91 28 01 00 	lea    0x12891(%rip),%rdi        # 20d40 <full_set>
}
    e4af:	48 83 c4 08          	add    $0x8,%rsp
  sigfillset (&full_set);
    e4b3:	e9 18 95 ff ff       	jmpq   79d0 <sigfillset@plt>
    e4b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    e4bf:	00 

000000000000e4c0 <handle_signals>:

int
handle_signals (void)
/* Execute signal actions, for all signals, which occured before.
 * Return 1, if any action was taken.  */
{
    e4c0:	f3 0f 1e fa          	endbr64 
  int  res = 0;

  while (signal_arrived) {
    e4c4:	8b 05 f6 28 01 00    	mov    0x128f6(%rip),%eax        # 20dc0 <signal_arrived>
    e4ca:	85 c0                	test   %eax,%eax
    e4cc:	74 6a                	je     e538 <handle_signals+0x78>
{
    e4ce:	55                   	push   %rbp
    e4cf:	53                   	push   %rbx
    e4d0:	48 83 ec 08          	sub    $0x8,%rsp
    e4d4:	0f 1f 40 00          	nopl   0x0(%rax)
    int  i;

    signal_arrived = 0;
    e4d8:	c7 05 de 28 01 00 00 	movl   $0x0,0x128de(%rip)        # 20dc0 <signal_arrived>
    e4df:	00 00 00 
    res = 1;
    for (i=0; i<sig_info_table.used; ++i) {
    e4e2:	8b 05 f4 28 01 00    	mov    0x128f4(%rip),%eax        # 20ddc <sig_info_table+0xc>
    e4e8:	85 c0                	test   %eax,%eax
    e4ea:	7e 36                	jle    e522 <handle_signals+0x62>
    e4ec:	31 db                	xor    %ebx,%ebx
    e4ee:	48 8d 2d db 28 01 00 	lea    0x128db(%rip),%rbp        # 20dd0 <sig_info_table>
    e4f5:	0f 1f 00             	nopl   (%rax)
      if (sig_info_table.data[i].pending) {
    e4f8:	48 89 d8             	mov    %rbx,%rax
    e4fb:	48 c1 e0 04          	shl    $0x4,%rax
    e4ff:	48 03 45 00          	add    0x0(%rbp),%rax
    e503:	8b 50 04             	mov    0x4(%rax),%edx
    e506:	85 d2                	test   %edx,%edx
    e508:	74 0c                	je     e516 <handle_signals+0x56>
        sig_info_table.data[i].pending = 0;
    e50a:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%rax)
        sig_info_table.data[i].handler (sig_info_table.data[i].signum);
    e511:	8b 38                	mov    (%rax),%edi
    e513:	ff 50 08             	callq  *0x8(%rax)
    for (i=0; i<sig_info_table.used; ++i) {
    e516:	48 83 c3 01          	add    $0x1,%rbx
    e51a:	39 1d bc 28 01 00    	cmp    %ebx,0x128bc(%rip)        # 20ddc <sig_info_table+0xc>
    e520:	7f d6                	jg     e4f8 <handle_signals+0x38>
  while (signal_arrived) {
    e522:	8b 05 98 28 01 00    	mov    0x12898(%rip),%eax        # 20dc0 <signal_arrived>
    e528:	85 c0                	test   %eax,%eax
    e52a:	75 ac                	jne    e4d8 <handle_signals+0x18>
      }
    }
  }
  return  res;
}
    e52c:	48 83 c4 08          	add    $0x8,%rsp
    res = 1;
    e530:	b8 01 00 00 00       	mov    $0x1,%eax
}
    e535:	5b                   	pop    %rbx
    e536:	5d                   	pop    %rbp
    e537:	c3                   	retq   
    e538:	c3                   	retq   
    e539:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

000000000000e540 <add_key>:
  return  res;
}

static void
add_key (int key_code, enum mb_key meaning, int priority)
{
    e540:	41 55                	push   %r13
    e542:	41 89 d5             	mov    %edx,%r13d
    e545:	41 54                	push   %r12
    e547:	41 89 f4             	mov    %esi,%r12d
    e54a:	55                   	push   %rbp
    e54b:	53                   	push   %rbx
    e54c:	89 fb                	mov    %edi,%ebx
    e54e:	48 83 ec 08          	sub    $0x8,%rsp
  struct hash_entry **entry_p;

#if NCURSES_VERSION_MAJOR >= 4
  if ((key_code < 0 || key_code > 255) && ! has_key (key_code))  return;
    e552:	81 ff ff 00 00 00    	cmp    $0xff,%edi
    e558:	7f 76                	jg     e5d0 <add_key+0x90>
  int  r = x%y;
    e55a:	48 63 c3             	movslq %ebx,%rax
    e55d:	89 da                	mov    %ebx,%edx
    e55f:	89 d9                	mov    %ebx,%ecx
    e561:	48 69 c0 a7 c8 67 dd 	imul   $0xffffffffdd67c8a7,%rax,%rax
    e568:	c1 fa 1f             	sar    $0x1f,%edx
    e56b:	48 c1 e8 20          	shr    $0x20,%rax
    e56f:	01 d8                	add    %ebx,%eax
    e571:	c1 f8 05             	sar    $0x5,%eax
    e574:	29 d0                	sub    %edx,%eax
    e576:	8d 14 c0             	lea    (%rax,%rax,8),%edx
    e579:	8d 04 90             	lea    (%rax,%rdx,4),%eax
  struct hash_entry **res = &hash_table[slot];
    e57c:	48 8d 15 fd 28 01 00 	lea    0x128fd(%rip),%rdx        # 20e80 <hash_table>
  int  r = x%y;
    e583:	29 c1                	sub    %eax,%ecx
    e585:	48 63 c1             	movslq %ecx,%rax
  struct hash_entry **res = &hash_table[slot];
    e588:	48 8d 2c c2          	lea    (%rdx,%rax,8),%rbp
    e58c:	48 8b 04 c2          	mov    (%rdx,%rax,8),%rax
  while (*res && (*res)->key_code != key_code)  res = &((*res)->next);
    e590:	48 85 c0             	test   %rax,%rax
    e593:	75 16                	jne    e5ab <add_key+0x6b>
    e595:	eb 51                	jmp    e5e8 <add_key+0xa8>
    e597:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    e59e:	00 00 
    e5a0:	48 89 c5             	mov    %rax,%rbp
    e5a3:	48 8b 00             	mov    (%rax),%rax
    e5a6:	48 85 c0             	test   %rax,%rax
    e5a9:	74 3d                	je     e5e8 <add_key+0xa8>
    e5ab:	3b 58 08             	cmp    0x8(%rax),%ebx
    e5ae:	75 f0                	jne    e5a0 <add_key+0x60>
    e5b0:	48 8b 45 00          	mov    0x0(%rbp),%rax
    e5b4:	44 0b 60 0c          	or     0xc(%rax),%r12d
    (*entry_p)->next = NULL;
    (*entry_p)->key_code = key_code;
    (*entry_p)->meaning = 0;
    (*entry_p)->priority = priority;
  }
  (*entry_p)->meaning |= meaning;
    e5b8:	44 89 60 0c          	mov    %r12d,0xc(%rax)
}
    e5bc:	48 83 c4 08          	add    $0x8,%rsp
    e5c0:	5b                   	pop    %rbx
    e5c1:	5d                   	pop    %rbp
    e5c2:	41 5c                	pop    %r12
    e5c4:	41 5d                	pop    %r13
    e5c6:	c3                   	retq   
    e5c7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    e5ce:	00 00 
  if ((key_code < 0 || key_code > 255) && ! has_key (key_code))  return;
    e5d0:	e8 3b 96 ff ff       	callq  7c10 <has_key@plt>
    e5d5:	85 c0                	test   %eax,%eax
    e5d7:	75 81                	jne    e55a <add_key+0x1a>
}
    e5d9:	48 83 c4 08          	add    $0x8,%rsp
    e5dd:	5b                   	pop    %rbx
    e5de:	5d                   	pop    %rbp
    e5df:	41 5c                	pop    %r12
    e5e1:	41 5d                	pop    %r13
    e5e3:	c3                   	retq   
    e5e4:	0f 1f 40 00          	nopl   0x0(%rax)
    *entry_p = xmalloc (sizeof (struct hash_entry));
    e5e8:	bf 18 00 00 00       	mov    $0x18,%edi
    e5ed:	e8 6e 10 00 00       	callq  f660 <xmalloc>
    e5f2:	48 89 45 00          	mov    %rax,0x0(%rbp)
    (*entry_p)->next = NULL;
    e5f6:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    (*entry_p)->key_code = key_code;
    e5fd:	48 8b 45 00          	mov    0x0(%rbp),%rax
    e601:	89 58 08             	mov    %ebx,0x8(%rax)
    (*entry_p)->meaning = 0;
    e604:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%rax)
    (*entry_p)->priority = priority;
    e60b:	44 89 68 10          	mov    %r13d,0x10(%rax)
    e60f:	eb a7                	jmp    e5b8 <add_key+0x78>
    e611:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    e618:	00 00 00 00 
    e61c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000e620 <compare_keys>:
  for (i=0; i<k; ++i)  data[i].priority = data[i].base_priority;
}

static int
compare_keys (const void *a, const void *b)
{
    e620:	f3 0f 1e fa          	endbr64 
  const struct key_name *aa = a;
  const struct key_name *bb = b;

  if (aa->priority < bb->priority)  return +1;
    e624:	8b 46 08             	mov    0x8(%rsi),%eax
    e627:	39 47 08             	cmp    %eax,0x8(%rdi)
    e62a:	7c 44                	jl     e670 <compare_keys+0x50>
  if (aa->priority > bb->priority)  return -1;
    e62c:	7f 48                	jg     e676 <compare_keys+0x56>
{
    e62e:	41 54                	push   %r12
    e630:	49 89 f4             	mov    %rsi,%r12
    e633:	55                   	push   %rbp
    e634:	48 89 fd             	mov    %rdi,%rbp
    e637:	53                   	push   %rbx
  if (strlen (aa->name) < strlen (bb->name))  return -1;
    e638:	e8 03 92 ff ff       	callq  7840 <strlen@plt>
    e63d:	4c 89 e7             	mov    %r12,%rdi
    e640:	48 89 c3             	mov    %rax,%rbx
    e643:	e8 f8 91 ff ff       	callq  7840 <strlen@plt>
    e648:	48 39 c3             	cmp    %rax,%rbx
    e64b:	72 2f                	jb     e67c <compare_keys+0x5c>
  if (strlen (aa->name) > strlen (bb->name))  return +1;
    e64d:	77 11                	ja     e660 <compare_keys+0x40>
  return  strcmp (aa->name, bb->name);
}
    e64f:	5b                   	pop    %rbx
  return  strcmp (aa->name, bb->name);
    e650:	4c 89 e6             	mov    %r12,%rsi
    e653:	48 89 ef             	mov    %rbp,%rdi
}
    e656:	5d                   	pop    %rbp
    e657:	41 5c                	pop    %r12
  return  strcmp (aa->name, bb->name);
    e659:	e9 32 93 ff ff       	jmpq   7990 <strcmp@plt>
    e65e:	66 90                	xchg   %ax,%ax
  if (aa->priority < bb->priority)  return +1;
    e660:	b8 01 00 00 00       	mov    $0x1,%eax
}
    e665:	5b                   	pop    %rbx
    e666:	5d                   	pop    %rbp
    e667:	41 5c                	pop    %r12
    e669:	c3                   	retq   
    e66a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  if (aa->priority < bb->priority)  return +1;
    e670:	b8 01 00 00 00       	mov    $0x1,%eax
    e675:	c3                   	retq   
  if (aa->priority > bb->priority)  return -1;
    e676:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
    e67b:	c3                   	retq   
  if (aa->priority > bb->priority)  return -1;
    e67c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    e681:	eb e2                	jmp    e665 <compare_keys+0x45>
    e683:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    e68a:	00 00 00 00 
    e68e:	66 90                	xchg   %ax,%ax

000000000000e690 <install_keys>:
{
    e690:	f3 0f 1e fa          	endbr64 
  for (i=0; i<HASH_SIZE; ++i)  hash_table [i] = NULL;
    e694:	48 8d 05 e5 27 01 00 	lea    0x127e5(%rip),%rax        # 20e80 <hash_table>
{
    e69b:	48 83 ec 08          	sub    $0x8,%rsp
    e69f:	48 8d 90 28 01 00 00 	lea    0x128(%rax),%rdx
    e6a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    e6ad:	00 00 00 
  for (i=0; i<HASH_SIZE; ++i)  hash_table [i] = NULL;
    e6b0:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    e6b7:	48 83 c0 08          	add    $0x8,%rax
    e6bb:	48 39 d0             	cmp    %rdx,%rax
    e6be:	75 f0                	jne    e6b0 <install_keys+0x20>
  add_key ('c', mbk_copyright, 100);
    e6c0:	ba 64 00 00 00       	mov    $0x64,%edx
    e6c5:	be 01 00 00 00       	mov    $0x1,%esi
    e6ca:	bf 63 00 00 00       	mov    $0x63,%edi
    e6cf:	e8 6c fe ff ff       	callq  e540 <add_key>
  add_key (14, mbk_down, 80);	/* \C-n */
    e6d4:	ba 50 00 00 00       	mov    $0x50,%edx
    e6d9:	be 02 00 00 00       	mov    $0x2,%esi
    e6de:	bf 0e 00 00 00       	mov    $0xe,%edi
    e6e3:	e8 58 fe ff ff       	callq  e540 <add_key>
  add_key (KEY_DOWN, mbk_down, 100);
    e6e8:	ba 64 00 00 00       	mov    $0x64,%edx
    e6ed:	be 02 00 00 00       	mov    $0x2,%esi
    e6f2:	bf 02 01 00 00       	mov    $0x102,%edi
    e6f7:	e8 44 fe ff ff       	callq  e540 <add_key>
  add_key ('q', mbk_end, 100);
    e6fc:	ba 64 00 00 00       	mov    $0x64,%edx
    e701:	be 04 00 00 00       	mov    $0x4,%esi
    e706:	bf 71 00 00 00       	mov    $0x71,%edi
    e70b:	e8 30 fe ff ff       	callq  e540 <add_key>
  add_key ('n', mbk_end, 90);
    e710:	ba 5a 00 00 00       	mov    $0x5a,%edx
    e715:	be 04 00 00 00       	mov    $0x4,%esi
    e71a:	bf 6e 00 00 00       	mov    $0x6e,%edi
    e71f:	e8 1c fe ff ff       	callq  e540 <add_key>
  add_key (27, mbk_end, 80);
    e724:	ba 50 00 00 00       	mov    $0x50,%edx
    e729:	be 04 00 00 00       	mov    $0x4,%esi
    e72e:	bf 1b 00 00 00       	mov    $0x1b,%edi
    e733:	e8 08 fe ff ff       	callq  e540 <add_key>
  add_key ('a', mbk_fire, 100);
    e738:	ba 64 00 00 00       	mov    $0x64,%edx
    e73d:	be 08 00 00 00       	mov    $0x8,%esi
    e742:	bf 61 00 00 00       	mov    $0x61,%edi
    e747:	e8 f4 fd ff ff       	callq  e540 <add_key>
  add_key ('l', mbk_fire, 60);
    e74c:	ba 3c 00 00 00       	mov    $0x3c,%edx
    e751:	be 08 00 00 00       	mov    $0x8,%esi
    e756:	bf 6c 00 00 00       	mov    $0x6c,%edi
    e75b:	e8 e0 fd ff ff       	callq  e540 <add_key>
  add_key ('<', mbk_first, 90);
    e760:	ba 5a 00 00 00       	mov    $0x5a,%edx
    e765:	be 10 00 00 00       	mov    $0x10,%esi
    e76a:	bf 3c 00 00 00       	mov    $0x3c,%edi
    e76f:	e8 cc fd ff ff       	callq  e540 <add_key>
  add_key (KEY_HOME, mbk_first, 100);
    e774:	ba 64 00 00 00       	mov    $0x64,%edx
    e779:	be 10 00 00 00       	mov    $0x10,%esi
    e77e:	bf 06 01 00 00       	mov    $0x106,%edi
    e783:	e8 b8 fd ff ff       	callq  e540 <add_key>
  add_key (' ', mbk_jump, 100);
    e788:	ba 64 00 00 00       	mov    $0x64,%edx
    e78d:	be 20 00 00 00       	mov    $0x20,%esi
    e792:	bf 20 00 00 00       	mov    $0x20,%edi
    e797:	e8 a4 fd ff ff       	callq  e540 <add_key>
  add_key ('j', mbk_jump, 50);
    e79c:	ba 32 00 00 00       	mov    $0x32,%edx
    e7a1:	be 20 00 00 00       	mov    $0x20,%esi
    e7a6:	bf 6a 00 00 00       	mov    $0x6a,%edi
    e7ab:	e8 90 fd ff ff       	callq  e540 <add_key>
  add_key ('>', mbk_last, 90);
    e7b0:	ba 5a 00 00 00       	mov    $0x5a,%edx
    e7b5:	be 40 00 00 00       	mov    $0x40,%esi
    e7ba:	bf 3e 00 00 00       	mov    $0x3e,%edi
    e7bf:	e8 7c fd ff ff       	callq  e540 <add_key>
  add_key (KEY_END, mbk_last, 100);
    e7c4:	ba 64 00 00 00       	mov    $0x64,%edx
    e7c9:	be 40 00 00 00       	mov    $0x40,%esi
    e7ce:	bf 68 01 00 00       	mov    $0x168,%edi
    e7d3:	e8 68 fd ff ff       	callq  e540 <add_key>
  add_key (' ', mbk_pagedown, 90);
    e7d8:	ba 5a 00 00 00       	mov    $0x5a,%edx
    e7dd:	be 80 00 00 00       	mov    $0x80,%esi
    e7e2:	bf 20 00 00 00       	mov    $0x20,%edi
    e7e7:	e8 54 fd ff ff       	callq  e540 <add_key>
  add_key (KEY_NPAGE, mbk_pagedown, 100);
    e7ec:	ba 64 00 00 00       	mov    $0x64,%edx
    e7f1:	be 80 00 00 00       	mov    $0x80,%esi
    e7f6:	bf 52 01 00 00       	mov    $0x152,%edi
    e7fb:	e8 40 fd ff ff       	callq  e540 <add_key>
  add_key ('b', mbk_pageup, 90);
    e800:	ba 5a 00 00 00       	mov    $0x5a,%edx
    e805:	be 00 01 00 00       	mov    $0x100,%esi
    e80a:	bf 62 00 00 00       	mov    $0x62,%edi
    e80f:	e8 2c fd ff ff       	callq  e540 <add_key>
  add_key (KEY_PPAGE, mbk_pageup, 100);
    e814:	ba 64 00 00 00       	mov    $0x64,%edx
    e819:	be 00 01 00 00       	mov    $0x100,%esi
    e81e:	bf 53 01 00 00       	mov    $0x153,%edi
    e823:	e8 18 fd ff ff       	callq  e540 <add_key>
  add_key ('y', mbk_start, 100);
    e828:	ba 64 00 00 00       	mov    $0x64,%edx
    e82d:	be 00 02 00 00       	mov    $0x200,%esi
    e832:	bf 79 00 00 00       	mov    $0x79,%edi
    e837:	e8 04 fd ff ff       	callq  e540 <add_key>
  add_key (' ', mbk_start, 90);
    e83c:	ba 5a 00 00 00       	mov    $0x5a,%edx
    e841:	be 00 02 00 00       	mov    $0x200,%esi
    e846:	bf 20 00 00 00       	mov    $0x20,%edi
    e84b:	e8 f0 fc ff ff       	callq  e540 <add_key>
  add_key (10, mbk_start, 80);	/* RET */
    e850:	ba 50 00 00 00       	mov    $0x50,%edx
    e855:	be 00 02 00 00       	mov    $0x200,%esi
    e85a:	bf 0a 00 00 00       	mov    $0xa,%edi
    e85f:	e8 dc fc ff ff       	callq  e540 <add_key>
  add_key (16, mbk_up, 80);	/* \C-p */
    e864:	ba 50 00 00 00       	mov    $0x50,%edx
    e869:	be 00 04 00 00       	mov    $0x400,%esi
    e86e:	bf 10 00 00 00       	mov    $0x10,%edi
    e873:	e8 c8 fc ff ff       	callq  e540 <add_key>
  add_key (KEY_UP, mbk_up, 100);
    e878:	ba 64 00 00 00       	mov    $0x64,%edx
    e87d:	be 00 04 00 00       	mov    $0x400,%esi
    e882:	bf 03 01 00 00       	mov    $0x103,%edi
    e887:	e8 b4 fc ff ff       	callq  e540 <add_key>
  add_key ('w', mbk_warranty, 100);
    e88c:	ba 64 00 00 00       	mov    $0x64,%edx
    e891:	be 00 08 00 00       	mov    $0x800,%esi
    e896:	bf 77 00 00 00       	mov    $0x77,%edi
    e89b:	e8 a0 fc ff ff       	callq  e540 <add_key>
  add_key ('s', mbk_scores, 100);
    e8a0:	ba 64 00 00 00       	mov    $0x64,%edx
    e8a5:	be 00 10 00 00       	mov    $0x1000,%esi
    e8aa:	bf 73 00 00 00       	mov    $0x73,%edi
    e8af:	e8 8c fc ff ff       	callq  e540 <add_key>
  add_key ('r', mbk_redraw, 20);
    e8b4:	ba 14 00 00 00       	mov    $0x14,%edx
    e8b9:	be 00 20 00 00       	mov    $0x2000,%esi
    e8be:	bf 72 00 00 00       	mov    $0x72,%edi
    e8c3:	e8 78 fc ff ff       	callq  e540 <add_key>
  add_key (12, mbk_redraw, 10);	/* \C-l */
    e8c8:	ba 0a 00 00 00       	mov    $0xa,%edx
    e8cd:	be 00 20 00 00       	mov    $0x2000,%esi
    e8d2:	bf 0c 00 00 00       	mov    $0xc,%edi
}
    e8d7:	48 83 c4 08          	add    $0x8,%rsp
  add_key (12, mbk_redraw, 10);	/* \C-l */
    e8db:	e9 60 fc ff ff       	jmpq   e540 <add_key>

000000000000e8e0 <read_key>:
{
    e8e0:	f3 0f 1e fa          	endbr64 
    e8e4:	55                   	push   %rbp
    e8e5:	53                   	push   %rbx
    e8e6:	48 83 ec 08          	sub    $0x8,%rsp
    e8ea:	eb 12                	jmp    e8fe <read_key+0x1e>
    e8ec:	0f 1f 40 00          	nopl   0x0(%rax)
  } while (key_code == ERR && errno == EINTR);
    e8f0:	e8 3b 8e ff ff       	callq  7730 <__errno_location@plt>
    e8f5:	83 38 04             	cmpl   $0x4,(%rax)
    e8f8:	0f 85 c2 00 00 00    	jne    e9c0 <read_key+0xe0>
    key_code = wgetch (moon);
    e8fe:	48 8b 3d 13 25 01 00 	mov    0x12513(%rip),%rdi        # 20e18 <moon>
    e905:	e8 e6 8e ff ff       	callq  77f0 <wgetch@plt>
  } while (key_code == ERR && errno == EINTR);
    e90a:	83 f8 ff             	cmp    $0xffffffff,%eax
    e90d:	74 e1                	je     e8f0 <read_key+0x10>
    e90f:	89 c3                	mov    %eax,%ebx
  if (key_code == KEY_RESIZE)  return -1;
    e911:	3d 9a 01 00 00       	cmp    $0x19a,%eax
    e916:	0f 84 9d 00 00 00    	je     e9b9 <read_key+0xd9>
  if (key_code < 256 && isalpha (key_code))  key_code = tolower (key_code);
    e91c:	48 63 eb             	movslq %ebx,%rbp
    e91f:	81 fb ff 00 00 00    	cmp    $0xff,%ebx
    e925:	7e 59                	jle    e980 <read_key+0xa0>
  int  r = x%y;
    e927:	48 69 c5 a7 c8 67 dd 	imul   $0xffffffffdd67c8a7,%rbp,%rax
    e92e:	89 da                	mov    %ebx,%edx
    e930:	89 d9                	mov    %ebx,%ecx
    e932:	c1 fa 1f             	sar    $0x1f,%edx
    e935:	48 c1 e8 20          	shr    $0x20,%rax
    e939:	01 d8                	add    %ebx,%eax
    e93b:	c1 f8 05             	sar    $0x5,%eax
    e93e:	29 d0                	sub    %edx,%eax
    e940:	8d 14 c0             	lea    (%rax,%rax,8),%edx
    e943:	8d 04 90             	lea    (%rax,%rdx,4),%eax
    e946:	29 c1                	sub    %eax,%ecx
  return  r<0 ? (y<0 ? r-y : r+y) : r;
    e948:	8d 51 25             	lea    0x25(%rcx),%edx
  int  r = x%y;
    e94b:	89 c8                	mov    %ecx,%eax
  return  r<0 ? (y<0 ? r-y : r+y) : r;
    e94d:	0f 48 c2             	cmovs  %edx,%eax
  struct hash_entry **res = &hash_table[slot];
    e950:	48 8d 15 29 25 01 00 	lea    0x12529(%rip),%rdx        # 20e80 <hash_table>
    e957:	48 98                	cltq   
    e959:	48 8b 04 c2          	mov    (%rdx,%rax,8),%rax
  while (*res && (*res)->key_code != key_code)  res = &((*res)->next);
    e95d:	48 85 c0             	test   %rax,%rax
    e960:	75 0e                	jne    e970 <read_key+0x90>
    e962:	eb 14                	jmp    e978 <read_key+0x98>
    e964:	0f 1f 40 00          	nopl   0x0(%rax)
    e968:	48 8b 00             	mov    (%rax),%rax
    e96b:	48 85 c0             	test   %rax,%rax
    e96e:	74 40                	je     e9b0 <read_key+0xd0>
    e970:	3b 58 08             	cmp    0x8(%rax),%ebx
    e973:	75 f3                	jne    e968 <read_key+0x88>
  return  *entry_p ? (*entry_p)->meaning : 0;
    e975:	8b 40 0c             	mov    0xc(%rax),%eax
}
    e978:	48 83 c4 08          	add    $0x8,%rsp
    e97c:	5b                   	pop    %rbx
    e97d:	5d                   	pop    %rbp
    e97e:	c3                   	retq   
    e97f:	90                   	nop
  if (key_code < 256 && isalpha (key_code))  key_code = tolower (key_code);
    e980:	e8 7b 93 ff ff       	callq  7d00 <__ctype_b_loc@plt>
    e985:	48 8b 00             	mov    (%rax),%rax
    e988:	f6 44 68 01 04       	testb  $0x4,0x1(%rax,%rbp,2)
    e98d:	74 98                	je     e927 <read_key+0x47>

# ifdef __USE_EXTERN_INLINES
__extern_inline int
__NTH (tolower (int __c))
{
  return __c >= -128 && __c < 256 ? (*__ctype_tolower_loc ())[__c] : __c;
    e98f:	8d 83 80 00 00 00    	lea    0x80(%rbx),%eax
    e995:	3d 7f 01 00 00       	cmp    $0x17f,%eax
    e99a:	77 8b                	ja     e927 <read_key+0x47>
    e99c:	e8 4f 93 ff ff       	callq  7cf0 <__ctype_tolower_loc@plt>
    e9a1:	48 8b 00             	mov    (%rax),%rax
    e9a4:	48 63 2c a8          	movslq (%rax,%rbp,4),%rbp
    e9a8:	48 89 eb             	mov    %rbp,%rbx
    e9ab:	e9 77 ff ff ff       	jmpq   e927 <read_key+0x47>
}
    e9b0:	48 83 c4 08          	add    $0x8,%rsp
  return  *entry_p ? (*entry_p)->meaning : 0;
    e9b4:	31 c0                	xor    %eax,%eax
}
    e9b6:	5b                   	pop    %rbx
    e9b7:	5d                   	pop    %rbp
    e9b8:	c3                   	retq   
  if (key_code == KEY_RESIZE)  return -1;
    e9b9:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    e9be:	eb b8                	jmp    e978 <read_key+0x98>
  if (key_code == ERR)  fatal ("Cannot read keyboard input");
    e9c0:	48 8d 3d 08 b6 00 00 	lea    0xb608(%rip),%rdi        # 19fcf <__PRETTY_FUNCTION__.5191+0xf>
    e9c7:	31 c0                	xor    %eax,%eax
    e9c9:	e8 92 0b 00 00       	callq  f560 <fatal>
    e9ce:	66 90                	xchg   %ax,%ax

000000000000e9d0 <key_name>:
{
    e9d0:	f3 0f 1e fa          	endbr64 
  if (key == KEY_BACKSPACE)  return "BS";
    e9d4:	48 8d 05 17 b6 00 00 	lea    0xb617(%rip),%rax        # 19ff2 <__PRETTY_FUNCTION__.5191+0x32>
    e9db:	81 ff 07 01 00 00    	cmp    $0x107,%edi
    e9e1:	0f 84 89 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_BEG)  return "BEG";
    e9e7:	48 8d 05 07 b6 00 00 	lea    0xb607(%rip),%rax        # 19ff5 <__PRETTY_FUNCTION__.5191+0x35>
    e9ee:	81 ff 62 01 00 00    	cmp    $0x162,%edi
    e9f4:	0f 84 76 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_BREAK)  return "BREAK";
    e9fa:	48 8d 05 f8 b5 00 00 	lea    0xb5f8(%rip),%rax        # 19ff9 <__PRETTY_FUNCTION__.5191+0x39>
    ea01:	81 ff 01 01 00 00    	cmp    $0x101,%edi
    ea07:	0f 84 63 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_CANCEL)  return "CANCEL";
    ea0d:	48 8d 05 eb b5 00 00 	lea    0xb5eb(%rip),%rax        # 19fff <__PRETTY_FUNCTION__.5191+0x3f>
    ea14:	81 ff 63 01 00 00    	cmp    $0x163,%edi
    ea1a:	0f 84 50 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_CLOSE)  return "CLOSE";
    ea20:	48 8d 05 df b5 00 00 	lea    0xb5df(%rip),%rax        # 1a006 <__PRETTY_FUNCTION__.5191+0x46>
    ea27:	81 ff 64 01 00 00    	cmp    $0x164,%edi
    ea2d:	0f 84 3d 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_DC)  return "DEL";
    ea33:	48 8d 05 d2 b5 00 00 	lea    0xb5d2(%rip),%rax        # 1a00c <__PRETTY_FUNCTION__.5191+0x4c>
    ea3a:	81 ff 4a 01 00 00    	cmp    $0x14a,%edi
    ea40:	0f 84 2a 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_DOWN)  return "DOWN";
    ea46:	48 8d 05 c3 b5 00 00 	lea    0xb5c3(%rip),%rax        # 1a010 <__PRETTY_FUNCTION__.5191+0x50>
    ea4d:	81 ff 02 01 00 00    	cmp    $0x102,%edi
    ea53:	0f 84 17 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_END)  return "END";
    ea59:	48 8d 05 b5 b5 00 00 	lea    0xb5b5(%rip),%rax        # 1a015 <__PRETTY_FUNCTION__.5191+0x55>
    ea60:	81 ff 68 01 00 00    	cmp    $0x168,%edi
    ea66:	0f 84 04 01 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_ENTER)  return "ENTER";
    ea6c:	48 8d 05 a6 b5 00 00 	lea    0xb5a6(%rip),%rax        # 1a019 <__PRETTY_FUNCTION__.5191+0x59>
    ea73:	81 ff 57 01 00 00    	cmp    $0x157,%edi
    ea79:	0f 84 f1 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_EXIT)  return "EXIT";
    ea7f:	48 8d 05 99 b5 00 00 	lea    0xb599(%rip),%rax        # 1a01f <__PRETTY_FUNCTION__.5191+0x5f>
    ea86:	81 ff 69 01 00 00    	cmp    $0x169,%edi
    ea8c:	0f 84 de 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_HOME)  return "HOME";
    ea92:	48 8d 05 8b b5 00 00 	lea    0xb58b(%rip),%rax        # 1a024 <__PRETTY_FUNCTION__.5191+0x64>
    ea99:	81 ff 06 01 00 00    	cmp    $0x106,%edi
    ea9f:	0f 84 cb 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_IC)  return "INS";
    eaa5:	48 8d 05 7d b5 00 00 	lea    0xb57d(%rip),%rax        # 1a029 <__PRETTY_FUNCTION__.5191+0x69>
    eaac:	81 ff 4b 01 00 00    	cmp    $0x14b,%edi
    eab2:	0f 84 b8 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_LEFT)  return "LEFT";
    eab8:	48 8d 05 6e b5 00 00 	lea    0xb56e(%rip),%rax        # 1a02d <__PRETTY_FUNCTION__.5191+0x6d>
    eabf:	81 ff 04 01 00 00    	cmp    $0x104,%edi
    eac5:	0f 84 a5 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_NPAGE)  return "NEXT";
    eacb:	48 8d 05 60 b5 00 00 	lea    0xb560(%rip),%rax        # 1a032 <__PRETTY_FUNCTION__.5191+0x72>
    ead2:	81 ff 52 01 00 00    	cmp    $0x152,%edi
    ead8:	0f 84 92 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_PPAGE)  return "PREV";
    eade:	48 8d 05 52 b5 00 00 	lea    0xb552(%rip),%rax        # 1a037 <__PRETTY_FUNCTION__.5191+0x77>
    eae5:	81 ff 53 01 00 00    	cmp    $0x153,%edi
    eaeb:	0f 84 7f 00 00 00    	je     eb70 <key_name+0x1a0>
  if (key == KEY_RIGHT)  return "RIGHT";
    eaf1:	48 8d 05 44 b5 00 00 	lea    0xb544(%rip),%rax        # 1a03c <__PRETTY_FUNCTION__.5191+0x7c>
    eaf8:	81 ff 05 01 00 00    	cmp    $0x105,%edi
    eafe:	74 70                	je     eb70 <key_name+0x1a0>
  if (key == KEY_UNDO)  return "UNDO";
    eb00:	48 8d 05 e3 b4 00 00 	lea    0xb4e3(%rip),%rax        # 19fea <__PRETTY_FUNCTION__.5191+0x2a>
    eb07:	81 ff 98 01 00 00    	cmp    $0x198,%edi
    eb0d:	74 61                	je     eb70 <key_name+0x1a0>
  if (key == KEY_UP)  return "UP";
    eb0f:	48 8d 05 d9 b4 00 00 	lea    0xb4d9(%rip),%rax        # 19fef <__PRETTY_FUNCTION__.5191+0x2f>
    eb16:	81 ff 03 01 00 00    	cmp    $0x103,%edi
    eb1c:	74 52                	je     eb70 <key_name+0x1a0>
{
    eb1e:	48 83 ec 18          	sub    $0x18,%rsp
    eb22:	44 8d 87 f8 fe ff ff 	lea    -0x108(%rdi),%r8d
  for (i=0; i<64; ++i) {
    eb29:	31 c0                	xor    %eax,%eax
    eb2b:	eb 0b                	jmp    eb38 <key_name+0x168>
    eb2d:	0f 1f 00             	nopl   (%rax)
    eb30:	83 c0 01             	add    $0x1,%eax
    eb33:	83 f8 40             	cmp    $0x40,%eax
    eb36:	74 39                	je     eb71 <key_name+0x1a1>
    if (key == KEY_F(i)) {
    eb38:	41 39 c0             	cmp    %eax,%r8d
    eb3b:	75 f3                	jne    eb30 <key_name+0x160>
  return __builtin___sprintf_chk (__s, __USE_FORTIFY_LEVEL - 1,
    eb3d:	48 8d 0d 06 b5 00 00 	lea    0xb506(%rip),%rcx        # 1a04a <__PRETTY_FUNCTION__.5191+0x8a>
    eb44:	ba 08 00 00 00       	mov    $0x8,%edx
    eb49:	be 01 00 00 00       	mov    $0x1,%esi
    eb4e:	48 8d 3d 8b 22 01 00 	lea    0x1228b(%rip),%rdi        # 20de0 <buffer.4660>
    eb55:	31 c0                	xor    %eax,%eax
    eb57:	e8 b4 91 ff ff       	callq  7d10 <__sprintf_chk@plt>
    return  buffer;
    eb5c:	48 8d 05 7d 22 01 00 	lea    0x1227d(%rip),%rax        # 20de0 <buffer.4660>
}
    eb63:	48 83 c4 18          	add    $0x18,%rsp
    eb67:	c3                   	retq   
    eb68:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    eb6f:	00 
    eb70:	c3                   	retq   
  if (key > 255)  return NULL;
    eb71:	81 ff ff 00 00 00    	cmp    $0xff,%edi
    eb77:	7f 6a                	jg     ebe3 <key_name+0x213>
  if (key == ' ')  return "SPC";
    eb79:	48 8d 05 c2 b4 00 00 	lea    0xb4c2(%rip),%rax        # 1a042 <__PRETTY_FUNCTION__.5191+0x82>
    eb80:	83 ff 20             	cmp    $0x20,%edi
    eb83:	74 de                	je     eb63 <key_name+0x193>
  if (key == 10)  return "RET";
    eb85:	83 ff 0a             	cmp    $0xa,%edi
    eb88:	89 7c 24 0c          	mov    %edi,0xc(%rsp)
    eb8c:	48 8d 05 b3 b4 00 00 	lea    0xb4b3(%rip),%rax        # 1a046 <__PRETTY_FUNCTION__.5191+0x86>
    eb93:	74 ce                	je     eb63 <key_name+0x193>
  if (isgraph (key)) {
    eb95:	e8 66 91 ff ff       	callq  7d00 <__ctype_b_loc@plt>
    eb9a:	49 89 c0             	mov    %rax,%r8
    eb9d:	48 63 44 24 0c       	movslq 0xc(%rsp),%rax
    eba2:	49 8b 10             	mov    (%r8),%rdx
    eba5:	48 89 c7             	mov    %rax,%rdi
    eba8:	66 83 3c 42 00       	cmpw   $0x0,(%rdx,%rax,2)
    ebad:	78 3b                	js     ebea <key_name+0x21a>
  return  key >= 1 && key <= 26;
    ebaf:	8d 50 ff             	lea    -0x1(%rax),%edx
  if (key > 255)  return NULL;
    ebb2:	31 c0                	xor    %eax,%eax
  if (control_key (key)) {
    ebb4:	83 fa 19             	cmp    $0x19,%edx
    ebb7:	77 aa                	ja     eb63 <key_name+0x193>
    ebb9:	44 8d 47 60          	lea    0x60(%rdi),%r8d
    ebbd:	ba 08 00 00 00       	mov    $0x8,%edx
    ebc2:	48 8d 0d 85 b4 00 00 	lea    0xb485(%rip),%rcx        # 1a04e <__PRETTY_FUNCTION__.5191+0x8e>
    ebc9:	be 01 00 00 00       	mov    $0x1,%esi
    ebce:	48 8d 3d 0b 22 01 00 	lea    0x1220b(%rip),%rdi        # 20de0 <buffer.4660>
    ebd5:	e8 36 91 ff ff       	callq  7d10 <__sprintf_chk@plt>
    return  buffer;
    ebda:	48 8d 05 ff 21 01 00 	lea    0x121ff(%rip),%rax        # 20de0 <buffer.4660>
    ebe1:	eb 80                	jmp    eb63 <key_name+0x193>
  if (key > 255)  return NULL;
    ebe3:	31 c0                	xor    %eax,%eax
    ebe5:	e9 79 ff ff ff       	jmpq   eb63 <key_name+0x193>
    ebea:	41 89 c0             	mov    %eax,%r8d
    ebed:	48 8d 0d 5c b4 00 00 	lea    0xb45c(%rip),%rcx        # 1a050 <__PRETTY_FUNCTION__.5191+0x90>
    ebf4:	e9 4b ff ff ff       	jmpq   eb44 <key_name+0x174>
    ebf9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

000000000000ec00 <describe_keys>:
  return  len;
}

void
describe_keys (int n, const struct binding *b)
{
    ec00:	f3 0f 1e fa          	endbr64 
    ec04:	48 63 c7             	movslq %edi,%rax
    ec07:	41 57                	push   %r15
  struct key_info *keys;
  char* buffer;
  int  len, max_len;
  int  i, j, k;

  keys = xmalloc (n*sizeof(struct key_info));
    ec09:	48 89 c7             	mov    %rax,%rdi
{
    ec0c:	41 56                	push   %r14
    ec0e:	49 89 c7             	mov    %rax,%r15
    ec11:	41 55                	push   %r13
  keys = xmalloc (n*sizeof(struct key_info));
    ec13:	48 c1 e7 04          	shl    $0x4,%rdi
{
    ec17:	41 54                	push   %r12
  keys = xmalloc (n*sizeof(struct key_info));
    ec19:	48 01 c7             	add    %rax,%rdi
{
    ec1c:	55                   	push   %rbp
  keys = xmalloc (n*sizeof(struct key_info));
    ec1d:	48 c1 e7 04          	shl    $0x4,%rdi
{
    ec21:	53                   	push   %rbx
    ec22:	48 89 f3             	mov    %rsi,%rbx
    ec25:	48 83 ec 38          	sub    $0x38,%rsp
  keys = xmalloc (n*sizeof(struct key_info));
    ec29:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    ec2e:	e8 2d 0a 00 00       	callq  f660 <xmalloc>
    ec33:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
  for (i=0; i<n; ++i) {
    ec38:	45 85 ff             	test   %r15d,%r15d
    ec3b:	7e 50                	jle    ec8d <describe_keys+0x8d>
    ec3d:	41 8d 57 ff          	lea    -0x1(%r15),%edx
    ec41:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
    ec46:	48 8d 4a 01          	lea    0x1(%rdx),%rcx
    ec4a:	48 89 ca             	mov    %rcx,%rdx
    ec4d:	48 89 f0             	mov    %rsi,%rax
    ec50:	48 c1 e2 04          	shl    $0x4,%rdx
    ec54:	48 01 ca             	add    %rcx,%rdx
    ec57:	48 c1 e2 04          	shl    $0x4,%rdx
    ec5b:	48 01 f2             	add    %rsi,%rdx
    keys[i].fn = 0;
    ec5e:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
    keys[i].ctrl = 0;
    ec64:	48 05 10 01 00 00    	add    $0x110,%rax
    ec6a:	c7 80 f4 fe ff ff 00 	movl   $0x0,-0x10c(%rax)
    ec71:	00 00 00 
    keys[i].norm = 0;
    ec74:	c7 80 f8 fe ff ff 00 	movl   $0x0,-0x108(%rax)
    ec7b:	00 00 00 
    keys[i].k = 0;
    ec7e:	c7 80 fc fe ff ff 00 	movl   $0x0,-0x104(%rax)
    ec85:	00 00 00 
  for (i=0; i<n; ++i) {
    ec88:	48 39 c2             	cmp    %rax,%rdx
    ec8b:	75 d1                	jne    ec5e <describe_keys+0x5e>
    ec8d:	4c 8d 2d ec 21 01 00 	lea    0x121ec(%rip),%r13        # 20e80 <hash_table>
    ec94:	45 8d 67 ff          	lea    -0x1(%r15),%r12d
    ec98:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    ec9f:	00 
  }
  for (j=0; j<HASH_SIZE; ++j) {
    struct hash_entry *ent = hash_table[j];
    eca0:	4d 8b 75 00          	mov    0x0(%r13),%r14

    while (ent) {
    eca4:	4d 85 f6             	test   %r14,%r14
    eca7:	0f 84 ff 00 00 00    	je     edac <describe_keys+0x1ac>
    ecad:	0f 1f 00             	nopl   (%rax)
      for (i=0; i<n; ++i) {
    ecb0:	45 85 ff             	test   %r15d,%r15d
    ecb3:	0f 8e e7 00 00 00    	jle    eda0 <describe_keys+0x1a0>
        if (ent->meaning & b[i].meanings) {
    ecb9:	41 8b 76 0c          	mov    0xc(%r14),%esi
    ecbd:	48 89 d8             	mov    %rbx,%rax
    ecc0:	44 89 e7             	mov    %r12d,%edi
    ecc3:	31 ed                	xor    %ebp,%ebp
    ecc5:	eb 1d                	jmp    ece4 <describe_keys+0xe4>
    ecc7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    ecce:	00 00 
      for (i=0; i<n; ++i) {
    ecd0:	48 8d 4d 01          	lea    0x1(%rbp),%rcx
    ecd4:	48 83 c0 18          	add    $0x18,%rax
    ecd8:	48 39 fd             	cmp    %rdi,%rbp
    ecdb:	0f 84 bf 00 00 00    	je     eda0 <describe_keys+0x1a0>
    ece1:	48 89 cd             	mov    %rcx,%rbp
        if (ent->meaning & b[i].meanings) {
    ece4:	85 30                	test   %esi,(%rax)
    ece6:	74 e8                	je     ecd0 <describe_keys+0xd0>
          char *name = key_name (ent->key_code);
    ece8:	41 8b 7e 08          	mov    0x8(%r14),%edi
    ecec:	e8 df fc ff ff       	callq  e9d0 <key_name>
    ecf1:	48 89 c6             	mov    %rax,%rsi

          if (name) {
    ecf4:	48 85 c0             	test   %rax,%rax
    ecf7:	0f 84 a3 00 00 00    	je     eda0 <describe_keys+0x1a0>
            k = keys[i].k++;
    ecfd:	48 89 e9             	mov    %rbp,%rcx
    ed00:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
    ed05:	48 c1 e1 04          	shl    $0x4,%rcx
    ed09:	48 8d 14 29          	lea    (%rcx,%rbp,1),%rdx
    ed0d:	48 c1 e2 04          	shl    $0x4,%rdx
    ed11:	48 8d 2c 10          	lea    (%rax,%rdx,1),%rbp
    ed15:	ba 07 00 00 00       	mov    $0x7,%edx
    ed1a:	4c 63 4d 0c          	movslq 0xc(%rbp),%r9
    ed1e:	41 8d 41 01          	lea    0x1(%r9),%eax
            strncpy (keys[i].data[k].name, name, 7);
    ed22:	49 8d 79 01          	lea    0x1(%r9),%rdi
    ed26:	4c 89 4c 24 08       	mov    %r9,0x8(%rsp)
            k = keys[i].k++;
    ed2b:	89 45 0c             	mov    %eax,0xc(%rbp)
            strncpy (keys[i].data[k].name, name, 7);
    ed2e:	48 c1 e7 04          	shl    $0x4,%rdi
    ed32:	48 01 ef             	add    %rbp,%rdi
    ed35:	e8 06 8a ff ff       	callq  7740 <strncpy@plt>
            keys[i].data[k].name[7] = 0;
    ed3a:	4c 8b 4c 24 08       	mov    0x8(%rsp),%r9
    ed3f:	49 c1 e1 04          	shl    $0x4,%r9
    ed43:	4a 8d 44 0d 00       	lea    0x0(%rbp,%r9,1),%rax
    ed48:	c6 40 17 00          	movb   $0x0,0x17(%rax)
            keys[i].data[k].base_priority = ent->priority;
            keys[i].data[k].priority = ent->priority;
            if (function_key (ent->key_code)) {
    ed4c:	41 8b 76 08          	mov    0x8(%r14),%esi
            keys[i].data[k].base_priority = ent->priority;
    ed50:	41 8b 56 10          	mov    0x10(%r14),%edx
  return  key>255 || key == ' ' || key == 10;
    ed54:	81 fe ff 00 00 00    	cmp    $0xff,%esi
    ed5a:	41 0f 9f c1          	setg   %r9b
    ed5e:	83 fe 20             	cmp    $0x20,%esi
            keys[i].data[k].base_priority = ent->priority;
    ed61:	89 50 1c             	mov    %edx,0x1c(%rax)
  return  key>255 || key == ' ' || key == 10;
    ed64:	40 0f 94 c7          	sete   %dil
            keys[i].data[k].priority = ent->priority;
    ed68:	89 50 18             	mov    %edx,0x18(%rax)
  return  key>255 || key == ' ' || key == 10;
    ed6b:	41 08 f9             	or     %dil,%r9b
    ed6e:	0f 85 0c 02 00 00    	jne    ef80 <describe_keys+0x380>
    ed74:	83 fe 0a             	cmp    $0xa,%esi
    ed77:	0f 84 03 02 00 00    	je     ef80 <describe_keys+0x380>
  return  key >= 1 && key <= 26;
    ed7d:	83 ee 01             	sub    $0x1,%esi
              if (keys[i].fn == 0)  keys[i].data[k].priority += 1050;
              ++keys[i].fn;
            } else if (control_key (ent->key_code)) {
    ed80:	83 fe 19             	cmp    $0x19,%esi
    ed83:	0f 87 12 02 00 00    	ja     ef9b <describe_keys+0x39b>
              if (keys[i].ctrl == 0)  keys[i].data[k].priority += 1000;
    ed89:	8b 75 04             	mov    0x4(%rbp),%esi
    ed8c:	85 f6                	test   %esi,%esi
    ed8e:	75 09                	jne    ed99 <describe_keys+0x199>
    ed90:	81 c2 e8 03 00 00    	add    $0x3e8,%edx
    ed96:	89 50 18             	mov    %edx,0x18(%rax)
              ++keys[i].ctrl;
    ed99:	83 c6 01             	add    $0x1,%esi
    ed9c:	89 75 04             	mov    %esi,0x4(%rbp)
    ed9f:	90                   	nop
            }
          }
          break;
        }
      }
      ent = ent->next;
    eda0:	4d 8b 36             	mov    (%r14),%r14
    while (ent) {
    eda3:	4d 85 f6             	test   %r14,%r14
    eda6:	0f 85 04 ff ff ff    	jne    ecb0 <describe_keys+0xb0>
  for (j=0; j<HASH_SIZE; ++j) {
    edac:	49 83 c5 08          	add    $0x8,%r13
    edb0:	48 8d 05 f1 21 01 00 	lea    0x121f1(%rip),%rax        # 20fa8 <hash_table+0x128>
    edb7:	4c 39 e8             	cmp    %r13,%rax
    edba:	0f 85 e0 fe ff ff    	jne    eca0 <describe_keys+0xa0>
    }
  }
  for (i=0; i<n; ++i) {
    edc0:	45 85 ff             	test   %r15d,%r15d
    edc3:	0f 8e 0b 04 00 00    	jle    f1d4 <describe_keys+0x5d4>
    edc9:	41 8d 6f ff          	lea    -0x1(%r15),%ebp
    edcd:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
    qsort (keys[i].data, keys[i].k, sizeof (struct key_name), compare_keys);
    edd2:	4c 8d 25 47 f8 ff ff 	lea    -0x7b9(%rip),%r12        # e620 <compare_keys>
    edd9:	48 89 e8             	mov    %rbp,%rax
    eddc:	48 c1 e0 04          	shl    $0x4,%rax
    ede0:	4c 8d 72 10          	lea    0x10(%rdx),%r14
    ede4:	48 01 e8             	add    %rbp,%rax
    ede7:	48 c1 e0 04          	shl    $0x4,%rax
    edeb:	4c 8d ac 02 20 01 00 	lea    0x120(%rdx,%rax,1),%r13
    edf2:	00 
    edf3:	49 63 76 fc          	movslq -0x4(%r14),%rsi
    edf7:	4c 89 f7             	mov    %r14,%rdi
    edfa:	4c 89 e1             	mov    %r12,%rcx
    edfd:	ba 10 00 00 00       	mov    $0x10,%edx
    ee02:	49 81 c6 10 01 00 00 	add    $0x110,%r14
    ee09:	e8 a2 89 ff ff       	callq  77b0 <qsort@plt>
  for (i=0; i<n; ++i) {
    ee0e:	4d 39 f5             	cmp    %r14,%r13
    ee11:	75 e0                	jne    edf3 <describe_keys+0x1f3>
  }

  max_len = COLS;
    ee13:	44 8b 25 66 04 01 00 	mov    0x10466(%rip),%r12d        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
    ee1a:	48 8d 43 08          	lea    0x8(%rbx),%rax
    ee1e:	45 31 f6             	xor    %r14d,%r14d
    ee21:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    ee26:	48 89 c1             	mov    %rax,%rcx
    ee29:	44 89 64 24 2c       	mov    %r12d,0x2c(%rsp)
  for (i=0; i<*n; ++i) {
    ee2e:	eb 1c                	jmp    ee4c <describe_keys+0x24c>
      len -= x;
    ee30:	48 8b 4c 24 08       	mov    0x8(%rsp),%rcx
    ee35:	41 29 c4             	sub    %eax,%r12d
  for (i=0; i<*n; ++i) {
    ee38:	49 8d 46 01          	lea    0x1(%r14),%rax
    ee3c:	48 83 c1 18          	add    $0x18,%rcx
    ee40:	4c 39 f5             	cmp    %r14,%rbp
    ee43:	0f 84 68 03 00 00    	je     f1b1 <describe_keys+0x5b1>
    ee49:	49 89 c6             	mov    %rax,%r14
    x += 2 + strlen(b[i].desc);	/* "x:desc" */
    ee4c:	48 8b 39             	mov    (%rcx),%rdi
    ee4f:	48 89 4c 24 08       	mov    %rcx,0x8(%rsp)
    ee54:	45 89 f5             	mov    %r14d,%r13d
    ee57:	e8 e4 89 ff ff       	callq  7840 <strlen@plt>
    x = (i>0) ? 1 : 0;		/* " " */
    ee5c:	31 f6                	xor    %esi,%esi
    ee5e:	45 85 f6             	test   %r14d,%r14d
    ee61:	40 0f 9f c6          	setg   %sil
    x += 2 + strlen(b[i].desc);	/* "x:desc" */
    ee65:	8d 44 06 02          	lea    0x2(%rsi,%rax,1),%eax
    if (len >= x) {
    ee69:	44 39 e0             	cmp    %r12d,%eax
    ee6c:	7e c2                	jle    ee30 <describe_keys+0x230>
  first = xmalloc (*n * sizeof(int));
    ee6e:	4a 8d 3c b5 00 00 00 	lea    0x0(,%r14,4),%rdi
    ee75:	00 
    ee76:	e8 e5 07 00 00       	callq  f660 <xmalloc>
    ee7b:	49 89 c6             	mov    %rax,%r14
  for (i=0; i<*n; ++i) {
    ee7e:	45 85 ed             	test   %r13d,%r13d
    ee81:	0f 84 43 03 00 00    	je     f1ca <describe_keys+0x5ca>
  first = xmalloc (*n * sizeof(int));
    ee87:	44 8b 64 24 2c       	mov    0x2c(%rsp),%r12d
    ee8c:	45 31 ff             	xor    %r15d,%r15d
    len -= 1 + strlen(b[i].desc); /* ":desc" */
    ee8f:	48 8b 6c 24 18       	mov    0x18(%rsp),%rbp
    first[i] = 1;
    ee94:	43 c7 04 be 01 00 00 	movl   $0x1,(%r14,%r15,4)
    ee9b:	00 
    if (i>0)  --len;		/* " " */
    ee9c:	49 83 ff 01          	cmp    $0x1,%r15
    eea0:	41 83 d4 ff          	adc    $0xffffffff,%r12d
    len -= 1 + strlen(b[i].desc); /* ":desc" */
    eea4:	49 83 c7 01          	add    $0x1,%r15
    eea8:	48 8b 7d 00          	mov    0x0(%rbp),%rdi
    eeac:	41 83 ec 01          	sub    $0x1,%r12d
    eeb0:	48 83 c5 18          	add    $0x18,%rbp
    eeb4:	e8 87 89 ff ff       	callq  7840 <strlen@plt>
    eeb9:	48 89 6c 24 18       	mov    %rbp,0x18(%rsp)
    eebe:	41 29 c4             	sub    %eax,%r12d
  for (i=0; i<*n; ++i) {
    eec1:	45 39 fd             	cmp    %r15d,%r13d
    eec4:	7f c9                	jg     ee8f <describe_keys+0x28f>
    finished = 1;
    eec6:	c7 44 24 20 01 00 00 	movl   $0x1,0x20(%rsp)
    eecd:	00 
  for (k=0; ! finished; ++k) {
    eece:	45 31 ff             	xor    %r15d,%r15d
    for (i=0; i<*n; ++i) {
    eed1:	31 c0                	xor    %eax,%eax
    eed3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    eed8:	41 8d 6f 01          	lea    0x1(%r15),%ebp
    eedc:	44 39 e8             	cmp    %r13d,%eax
    eedf:	0f 8d f2 00 00 00    	jge    efd7 <describe_keys+0x3d7>
    eee5:	48 89 c7             	mov    %rax,%rdi
    eee8:	49 63 d7             	movslq %r15d,%rdx
    eeeb:	8d 48 01             	lea    0x1(%rax),%ecx
    eeee:	48 c1 e7 04          	shl    $0x4,%rdi
    eef2:	48 63 c9             	movslq %ecx,%rcx
    eef5:	48 01 c7             	add    %rax,%rdi
    eef8:	48 89 d0             	mov    %rdx,%rax
    eefb:	48 f7 d8             	neg    %rax
    eefe:	48 8d 7c 3a 01       	lea    0x1(%rdx,%rdi,1),%rdi
    ef03:	48 c1 e0 04          	shl    $0x4,%rax
    ef07:	48 c1 e7 04          	shl    $0x4,%rdi
    ef0b:	48 03 7c 24 10       	add    0x10(%rsp),%rdi
    ef10:	48 89 c2             	mov    %rax,%rdx
      if (k < keys[i].k) {
    ef13:	44 39 7c 17 fc       	cmp    %r15d,-0x4(%rdi,%rdx,1)
    ef18:	48 89 4c 24 18       	mov    %rcx,0x18(%rsp)
    ef1d:	48 63 c1             	movslq %ecx,%rax
    ef20:	48 89 54 24 08       	mov    %rdx,0x8(%rsp)
    ef25:	7e b1                	jle    eed8 <describe_keys+0x2d8>
        x += strlen (keys[i].data[k].name);
    ef27:	48 89 7c 24 20       	mov    %rdi,0x20(%rsp)
    ef2c:	e8 0f 89 ff ff       	callq  7840 <strlen@plt>
        x = first[i] ? 0 : 1;	/* "," */
    ef31:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
        if (x <= len) {
    ef36:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
        x += strlen (keys[i].data[k].name);
    ef3b:	49 89 c0             	mov    %rax,%r8
        x = first[i] ? 0 : 1;	/* "," */
    ef3e:	31 c0                	xor    %eax,%eax
    ef40:	41 8b 54 8e fc       	mov    -0x4(%r14,%rcx,4),%edx
    ef45:	85 d2                	test   %edx,%edx
        if (x <= len) {
    ef47:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
        x = first[i] ? 0 : 1;	/* "," */
    ef4c:	0f 94 c0             	sete   %al
        x += strlen (keys[i].data[k].name);
    ef4f:	44 01 c0             	add    %r8d,%eax
        if (x <= len) {
    ef52:	41 39 c4             	cmp    %eax,%r12d
    ef55:	7c 56                	jl     efad <describe_keys+0x3ad>
          first[i] = 0;
    ef57:	41 c7 44 8e fc 00 00 	movl   $0x0,-0x4(%r14,%rcx,4)
    ef5e:	00 00 
          len -= x;
    ef60:	41 29 c4             	sub    %eax,%r12d
    for (i=0; i<*n; ++i) {
    ef63:	41 39 cd             	cmp    %ecx,%r13d
    ef66:	7e 51                	jle    efb9 <describe_keys+0x3b9>
  max_len = COLS;
    ef68:	c7 44 24 20 00 00 00 	movl   $0x0,0x20(%rsp)
    ef6f:	00 
    ef70:	48 83 c1 01          	add    $0x1,%rcx
    ef74:	48 81 c7 10 01 00 00 	add    $0x110,%rdi
    ef7b:	eb 96                	jmp    ef13 <describe_keys+0x313>
    ef7d:	0f 1f 00             	nopl   (%rax)
              if (keys[i].fn == 0)  keys[i].data[k].priority += 1050;
    ef80:	8b 75 00             	mov    0x0(%rbp),%esi
    ef83:	85 f6                	test   %esi,%esi
    ef85:	75 09                	jne    ef90 <describe_keys+0x390>
    ef87:	81 c2 1a 04 00 00    	add    $0x41a,%edx
    ef8d:	89 50 18             	mov    %edx,0x18(%rax)
              ++keys[i].fn;
    ef90:	83 c6 01             	add    $0x1,%esi
    ef93:	89 75 00             	mov    %esi,0x0(%rbp)
    ef96:	e9 05 fe ff ff       	jmpq   eda0 <describe_keys+0x1a0>
              keys[i].data[k].priority += 1100;
    ef9b:	81 c2 4c 04 00 00    	add    $0x44c,%edx
    efa1:	89 50 18             	mov    %edx,0x18(%rax)
              ++keys[i].norm;
    efa4:	83 45 08 01          	addl   $0x1,0x8(%rbp)
    efa8:	e9 f3 fd ff ff       	jmpq   eda0 <describe_keys+0x1a0>
          keys[i].data[k].base_priority = 0;
    efad:	c7 47 0c 00 00 00 00 	movl   $0x0,0xc(%rdi)
    for (i=0; i<*n; ++i) {
    efb4:	41 39 cd             	cmp    %ecx,%r13d
    efb7:	7f af                	jg     ef68 <describe_keys+0x368>
    efb9:	45 85 ed             	test   %r13d,%r13d
    efbc:	0f 8e aa 01 00 00    	jle    f16c <describe_keys+0x56c>
    efc2:	41 89 ef             	mov    %ebp,%r15d
    efc5:	c7 44 24 20 01 00 00 	movl   $0x1,0x20(%rsp)
    efcc:	00 
    efcd:	83 c5 01             	add    $0x1,%ebp
    efd0:	31 c0                	xor    %eax,%eax
    efd2:	e9 0e ff ff ff       	jmpq   eee5 <describe_keys+0x2e5>
  for (k=0; ! finished; ++k) {
    efd7:	44 8b 5c 24 20       	mov    0x20(%rsp),%r11d
    efdc:	45 85 db             	test   %r11d,%r11d
    efdf:	74 d8                	je     efb9 <describe_keys+0x3b9>
  free (first);
    efe1:	4c 89 f7             	mov    %r14,%rdi
    efe4:	e8 07 87 ff ff       	callq  76f0 <free@plt>
  for (i=0; i<*n; ++i) {
    efe9:	45 85 ed             	test   %r13d,%r13d
    efec:	0f 8e 82 01 00 00    	jle    f174 <describe_keys+0x574>
    eff2:	41 8d 55 ff          	lea    -0x1(%r13),%edx
    eff6:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
    qsort (keys[i].data, keys[i].k, sizeof (struct key_name), compare_keys);
    effb:	4c 8d 3d 1e f6 ff ff 	lea    -0x9e2(%rip),%r15        # e620 <compare_keys>
    f002:	48 89 d0             	mov    %rdx,%rax
    f005:	48 89 54 24 18       	mov    %rdx,0x18(%rsp)
    f00a:	48 8d 77 10          	lea    0x10(%rdi),%rsi
    f00e:	48 c1 e0 04          	shl    $0x4,%rax
    f012:	48 01 d0             	add    %rdx,%rax
    f015:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
  for (i=0; i<*n; ++i) {
    f01a:	49 89 f5             	mov    %rsi,%r13
    f01d:	48 c1 e0 04          	shl    $0x4,%rax
    f021:	48 8d ac 07 20 01 00 	lea    0x120(%rdi,%rax,1),%rbp
    f028:	00 
    set_display_priorities (keys[i].data, keys[i].k);
    f029:	49 63 75 fc          	movslq -0x4(%r13),%rsi
  for (i=0; i<k; ++i)  data[i].priority = data[i].base_priority;
    f02d:	85 f6                	test   %esi,%esi
    f02f:	7e 26                	jle    f057 <describe_keys+0x457>
    f031:	8d 56 ff             	lea    -0x1(%rsi),%edx
    f034:	49 8d 45 08          	lea    0x8(%r13),%rax
    f038:	48 c1 e2 04          	shl    $0x4,%rdx
    f03c:	49 8d 4c 15 18       	lea    0x18(%r13,%rdx,1),%rcx
    f041:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    f048:	8b 50 04             	mov    0x4(%rax),%edx
    f04b:	48 83 c0 10          	add    $0x10,%rax
    f04f:	89 50 f0             	mov    %edx,-0x10(%rax)
    f052:	48 39 c1             	cmp    %rax,%rcx
    f055:	75 f1                	jne    f048 <describe_keys+0x448>
    qsort (keys[i].data, keys[i].k, sizeof (struct key_name), compare_keys);
    f057:	4c 89 ef             	mov    %r13,%rdi
    f05a:	4c 89 f9             	mov    %r15,%rcx
    f05d:	ba 10 00 00 00       	mov    $0x10,%edx
    f062:	49 81 c5 10 01 00 00 	add    $0x110,%r13
    f069:	e8 42 87 ff ff       	callq  77b0 <qsort@plt>
  for (i=0; i<*n; ++i) {
    f06e:	4c 39 ed             	cmp    %r13,%rbp
    f071:	75 b6                	jne    f029 <describe_keys+0x429>
  len = choose_keys (&n, b, keys, max_len);
  buffer = xmalloc (max_len+1);
    f073:	8b 7c 24 2c          	mov    0x2c(%rsp),%edi

  buffer[0] = '\0';
    f077:	31 ed                	xor    %ebp,%ebp
  buffer = xmalloc (max_len+1);
    f079:	83 c7 01             	add    $0x1,%edi
    f07c:	48 63 ff             	movslq %edi,%rdi
    f07f:	e8 dc 05 00 00       	callq  f660 <xmalloc>
  buffer[0] = '\0';
    f084:	c6 00 00             	movb   $0x0,(%rax)
  buffer = xmalloc (max_len+1);
    f087:	49 89 c7             	mov    %rax,%r15
  for (i=0; i<n; ++i) {
    int  first = 1;
    for (k=0; k<keys[i].k; ++k) {
    f08a:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
    int  first = 1;
    f08f:	8b 44 24 20          	mov    0x20(%rsp),%eax
    for (k=0; k<keys[i].k; ++k) {
    f093:	45 31 ed             	xor    %r13d,%r13d
    f096:	49 89 d6             	mov    %rdx,%r14
    f099:	8b 52 fc             	mov    -0x4(%rdx),%edx
    f09c:	85 d2                	test   %edx,%edx
    f09e:	7f 50                	jg     f0f0 <describe_keys+0x4f0>
    f0a0:	eb 70                	jmp    f112 <describe_keys+0x512>
      if (keys[i].data[k].priority) {
        if (! first) {
          strcat (buffer, ",");
        } else {
          if (i>0) {
    f0a2:	48 85 ed             	test   %rbp,%rbp
    f0a5:	74 29                	je     f0d0 <describe_keys+0x4d0>
            if (len > 0) {
    f0a7:	4c 89 ff             	mov    %r15,%rdi
    f0aa:	e8 91 87 ff ff       	callq  7840 <strlen@plt>
    f0af:	4c 01 f8             	add    %r15,%rax
    f0b2:	45 85 e4             	test   %r12d,%r12d
    f0b5:	0f 8e 7f 00 00 00    	jle    f13a <describe_keys+0x53a>
  return __builtin___strcat_chk (__dest, __src, __bos (__dest));
    f0bb:	41 b8 20 20 00 00    	mov    $0x2020,%r8d
    f0c1:	c6 40 02 00          	movb   $0x0,0x2(%rax)
              --len;
    f0c5:	41 83 ec 01          	sub    $0x1,%r12d
    f0c9:	66 44 89 00          	mov    %r8w,(%rax)
    f0cd:	0f 1f 00             	nopl   (%rax)
    f0d0:	4c 89 f6             	mov    %r14,%rsi
    f0d3:	4c 89 ff             	mov    %r15,%rdi
    f0d6:	e8 25 8b ff ff       	callq  7c00 <strcat@plt>
    f0db:	31 c0                	xor    %eax,%eax
    for (k=0; k<keys[i].k; ++k) {
    f0dd:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
    f0e2:	41 83 c5 01          	add    $0x1,%r13d
    f0e6:	49 83 c6 10          	add    $0x10,%r14
    f0ea:	44 39 6a fc          	cmp    %r13d,-0x4(%rdx)
    f0ee:	7e 22                	jle    f112 <describe_keys+0x512>
      if (keys[i].data[k].priority) {
    f0f0:	45 8b 56 08          	mov    0x8(%r14),%r10d
    f0f4:	45 85 d2             	test   %r10d,%r10d
    f0f7:	74 e4                	je     f0dd <describe_keys+0x4dd>
        if (! first) {
    f0f9:	85 c0                	test   %eax,%eax
    f0fb:	75 a5                	jne    f0a2 <describe_keys+0x4a2>
    f0fd:	4c 89 ff             	mov    %r15,%rdi
    f100:	e8 3b 87 ff ff       	callq  7840 <strlen@plt>
    f105:	41 b9 2c 00 00 00    	mov    $0x2c,%r9d
    f10b:	66 45 89 0c 07       	mov    %r9w,(%r15,%rax,1)
    f110:	eb be                	jmp    f0d0 <describe_keys+0x4d0>
          first = 0;
        }
        strcat (buffer, keys[i].data[k].name);
      }
    }
    if (keys[i].data[0].priority) {
    f112:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    f117:	8b 70 08             	mov    0x8(%rax),%esi
    f11a:	85 f6                	test   %esi,%esi
    f11c:	75 26                	jne    f144 <describe_keys+0x544>
  for (i=0; i<n; ++i) {
    f11e:	48 81 44 24 08 10 01 	addq   $0x110,0x8(%rsp)
    f125:	00 00 
    f127:	48 8d 45 01          	lea    0x1(%rbp),%rax
    f12b:	48 39 6c 24 18       	cmp    %rbp,0x18(%rsp)
    f130:	74 57                	je     f189 <describe_keys+0x589>
    f132:	48 89 c5             	mov    %rax,%rbp
    f135:	e9 50 ff ff ff       	jmpq   f08a <describe_keys+0x48a>
    f13a:	bf 20 00 00 00       	mov    $0x20,%edi
    f13f:	66 89 38             	mov    %di,(%rax)
    f142:	eb 8c                	jmp    f0d0 <describe_keys+0x4d0>
    f144:	4c 89 ff             	mov    %r15,%rdi
    f147:	e8 f4 86 ff ff       	callq  7840 <strlen@plt>
    f14c:	b9 3a 00 00 00       	mov    $0x3a,%ecx
      strcat (buffer, ":");
      strcat (buffer, b[i].desc);
    f151:	48 8d 54 6d 00       	lea    0x0(%rbp,%rbp,2),%rdx
    f156:	66 41 89 0c 07       	mov    %cx,(%r15,%rax,1)
    f15b:	48 8b 74 d3 08       	mov    0x8(%rbx,%rdx,8),%rsi
    f160:	49 8d 7c 07 01       	lea    0x1(%r15,%rax,1),%rdi
    f165:	e8 f6 85 ff ff       	callq  7760 <strcpy@plt>
    f16a:	eb b2                	jmp    f11e <describe_keys+0x51e>
  free (first);
    f16c:	4c 89 f7             	mov    %r14,%rdi
    f16f:	e8 7c 85 ff ff       	callq  76f0 <free@plt>
  buffer = xmalloc (max_len+1);
    f174:	8b 7c 24 2c          	mov    0x2c(%rsp),%edi
    f178:	83 c7 01             	add    $0x1,%edi
    f17b:	48 63 ff             	movslq %edi,%rdi
    f17e:	e8 dd 04 00 00       	callq  f660 <xmalloc>
  buffer[0] = '\0';
    f183:	c6 00 00             	movb   $0x0,(%rax)
  buffer = xmalloc (max_len+1);
    f186:	49 89 c7             	mov    %rax,%r15
    }
  }
  print_message (buffer);
    f189:	4c 89 ff             	mov    %r15,%rdi
    f18c:	e8 df 91 ff ff       	callq  8370 <print_message>

  free (buffer);
    f191:	4c 89 ff             	mov    %r15,%rdi
    f194:	e8 57 85 ff ff       	callq  76f0 <free@plt>
  free (keys);
    f199:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
}
    f19e:	48 83 c4 38          	add    $0x38,%rsp
    f1a2:	5b                   	pop    %rbx
    f1a3:	5d                   	pop    %rbp
    f1a4:	41 5c                	pop    %r12
    f1a6:	41 5d                	pop    %r13
    f1a8:	41 5e                	pop    %r14
    f1aa:	41 5f                	pop    %r15
  free (keys);
    f1ac:	e9 3f 85 ff ff       	jmpq   76f0 <free@plt>
  first = xmalloc (*n * sizeof(int));
    f1b1:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    f1b6:	45 89 fd             	mov    %r15d,%r13d
    f1b9:	48 c1 e7 02          	shl    $0x2,%rdi
    f1bd:	e8 9e 04 00 00       	callq  f660 <xmalloc>
    f1c2:	49 89 c6             	mov    %rax,%r14
  for (i=0; i<*n; ++i) {
    f1c5:	e9 bd fc ff ff       	jmpq   ee87 <describe_keys+0x287>
  max_len = COLS;
    f1ca:	44 8b 64 24 2c       	mov    0x2c(%rsp),%r12d
    f1cf:	e9 f2 fc ff ff       	jmpq   eec6 <describe_keys+0x2c6>
  first = xmalloc (*n * sizeof(int));
    f1d4:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
  max_len = COLS;
    f1d9:	44 8b 25 a0 00 01 00 	mov    0x100a0(%rip),%r12d        # 1f280 <COLS@@NCURSES6_TINFO_5.0.19991023>
  first = xmalloc (*n * sizeof(int));
    f1e0:	45 89 fd             	mov    %r15d,%r13d
    f1e3:	48 c1 e7 02          	shl    $0x2,%rdi
    f1e7:	e8 74 04 00 00       	callq  f660 <xmalloc>
  max_len = COLS;
    f1ec:	44 89 64 24 2c       	mov    %r12d,0x2c(%rsp)
  first = xmalloc (*n * sizeof(int));
    f1f1:	49 89 c6             	mov    %rax,%r14
  for (i=0; i<*n; ++i) {
    f1f4:	e9 cd fc ff ff       	jmpq   eec6 <describe_keys+0x2c6>
    f1f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

000000000000f200 <term_prepare>:
void
term_prepare (int mesg_n_flag)
/* Prepare the terminal for game play.
 * This tries to disable the C-s key and, if MESG_N_FLAG is set,
 * restricts write access to the terminal as "mesg n" would do.  */
{
    f200:	f3 0f 1e fa          	endbr64 
    f204:	41 54                	push   %r12
    f206:	53                   	push   %rbx
    f207:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    f20e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    f215:	00 00 
    f217:	48 89 84 24 d8 00 00 	mov    %rax,0xd8(%rsp)
    f21e:	00 
    f21f:	31 c0                	xor    %eax,%eax
#if HAVE_TERMIOS_H
  struct termios  settings;
#endif
  int  res;

  assert (! term_mode_valid);
    f221:	8b 05 c5 1b 01 00    	mov    0x11bc5(%rip),%eax        # 20dec <term_mode_valid>
    f227:	85 c0                	test   %eax,%eax
    f229:	0f 85 ed 00 00 00    	jne    f31c <term_prepare+0x11c>
    f22f:	89 fb                	mov    %edi,%ebx
  if ( ! isatty (0) )  return;
    f231:	31 ff                	xor    %edi,%edi
    f233:	e8 88 85 ff ff       	callq  77c0 <isatty@plt>
    f238:	85 c0                	test   %eax,%eax
    f23a:	74 5c                	je     f298 <term_prepare+0x98>

  if (mesg_n_flag) {
    f23c:	85 db                	test   %ebx,%ebx
    f23e:	74 3f                	je     f27f <term_prepare+0x7f>
# endif

__extern_inline int
__NTH (fstat (int __fd, struct stat *__statbuf))
{
  return __fxstat (_STAT_VER, __fd, __statbuf);
    f240:	31 f6                	xor    %esi,%esi
    f242:	48 8d 54 24 40       	lea    0x40(%rsp),%rdx
    f247:	bf 01 00 00 00       	mov    $0x1,%edi
    f24c:	e8 2f 88 ff ff       	callq  7a80 <__fxstat@plt>
    res = fstat (0, &st);
    if (res < 0)
    f251:	85 c0                	test   %eax,%eax
    f253:	0f 88 a6 00 00 00    	js     f2ff <term_prepare+0xff>
      fatal ("Cannot get terminal attributes: %s", strerror (errno));

    term_mode = st.st_mode;
    term_mode_valid = 1;
    f259:	c7 05 89 1b 01 00 01 	movl   $0x1,0x11b89(%rip)        # 20dec <term_mode_valid>
    f260:	00 00 00 
    term_mode = st.st_mode;
    f263:	8b 74 24 58          	mov    0x58(%rsp),%esi

    st.st_mode &= ~(S_IWGRP|S_IWOTH);
    res = fchmod (0, st.st_mode);
    f267:	31 ff                	xor    %edi,%edi
    term_mode = st.st_mode;
    f269:	89 35 81 1b 01 00    	mov    %esi,0x11b81(%rip)        # 20df0 <term_mode>
    st.st_mode &= ~(S_IWGRP|S_IWOTH);
    f26f:	83 e6 ed             	and    $0xffffffed,%esi
    f272:	89 74 24 58          	mov    %esi,0x58(%rsp)
    res = fchmod (0, st.st_mode);
    f276:	e8 d5 88 ff ff       	callq  7b50 <fchmod@plt>
    if (res < 0)
    f27b:	85 c0                	test   %eax,%eax
    f27d:	78 63                	js     f2e2 <term_prepare+0xe2>
      fatal ("Cannot set terminal permissions: %s", strerror (errno));
  }

#if HAVE_TERMIOS_H
  res = tcgetattr (0, &settings);
    f27f:	49 89 e4             	mov    %rsp,%r12
    f282:	31 ff                	xor    %edi,%edi
    f284:	4c 89 e6             	mov    %r12,%rsi
    f287:	e8 04 89 ff ff       	callq  7b90 <tcgetattr@plt>
  if (res < 0)
    f28c:	85 c0                	test   %eax,%eax
    f28e:	78 6f                	js     f2ff <term_prepare+0xff>
    fatal ("Cannot get terminal attributes: %s", strerror (errno));

  if (settings.c_iflag & IXON) {
    f290:	8b 04 24             	mov    (%rsp),%eax
    f293:	f6 c4 04             	test   $0x4,%ah
    f296:	75 28                	jne    f2c0 <term_prepare+0xc0>
    if (res < 0)
      fatal ("Cannot set terminal attributes: %s", strerror (errno));
    attributes_changed = 1;
  }
#endif
}
    f298:	48 8b 84 24 d8 00 00 	mov    0xd8(%rsp),%rax
    f29f:	00 
    f2a0:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    f2a7:	00 00 
    f2a9:	0f 85 8c 00 00 00    	jne    f33b <term_prepare+0x13b>
    f2af:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    f2b6:	5b                   	pop    %rbx
    f2b7:	41 5c                	pop    %r12
    f2b9:	c3                   	retq   
    f2ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    settings.c_iflag &= ~IXON;
    f2c0:	80 e4 fb             	and    $0xfb,%ah
    res = tcsetattr (0, TCSANOW, &settings);
    f2c3:	31 f6                	xor    %esi,%esi
    f2c5:	31 ff                	xor    %edi,%edi
    f2c7:	4c 89 e2             	mov    %r12,%rdx
    settings.c_iflag &= ~IXON;
    f2ca:	89 04 24             	mov    %eax,(%rsp)
    res = tcsetattr (0, TCSANOW, &settings);
    f2cd:	e8 de 88 ff ff       	callq  7bb0 <tcsetattr@plt>
    if (res < 0)
    f2d2:	85 c0                	test   %eax,%eax
    f2d4:	78 6a                	js     f340 <term_prepare+0x140>
    attributes_changed = 1;
    f2d6:	c7 05 08 1b 01 00 01 	movl   $0x1,0x11b08(%rip)        # 20de8 <attributes_changed>
    f2dd:	00 00 00 
    f2e0:	eb b6                	jmp    f298 <term_prepare+0x98>
      fatal ("Cannot set terminal permissions: %s", strerror (errno));
    f2e2:	e8 49 84 ff ff       	callq  7730 <__errno_location@plt>
    f2e7:	8b 38                	mov    (%rax),%edi
    f2e9:	e8 a2 89 ff ff       	callq  7c90 <strerror@plt>
    f2ee:	48 8d 3d a3 ad 00 00 	lea    0xada3(%rip),%rdi        # 1a098 <__PRETTY_FUNCTION__.5191+0xd8>
    f2f5:	48 89 c6             	mov    %rax,%rsi
    f2f8:	31 c0                	xor    %eax,%eax
    f2fa:	e8 61 02 00 00       	callq  f560 <fatal>
    fatal ("Cannot get terminal attributes: %s", strerror (errno));
    f2ff:	e8 2c 84 ff ff       	callq  7730 <__errno_location@plt>
    f304:	8b 38                	mov    (%rax),%edi
    f306:	e8 85 89 ff ff       	callq  7c90 <strerror@plt>
    f30b:	48 8d 3d 5e ad 00 00 	lea    0xad5e(%rip),%rdi        # 1a070 <__PRETTY_FUNCTION__.5191+0xb0>
    f312:	48 89 c6             	mov    %rax,%rsi
    f315:	31 c0                	xor    %eax,%eax
    f317:	e8 44 02 00 00       	callq  f560 <fatal>
  assert (! term_mode_valid);
    f31c:	48 8d 0d ed ad 00 00 	lea    0xaded(%rip),%rcx        # 1a110 <__PRETTY_FUNCTION__.6408>
    f323:	ba 2e 00 00 00       	mov    $0x2e,%edx
    f328:	48 8d 35 24 ad 00 00 	lea    0xad24(%rip),%rsi        # 1a053 <__PRETTY_FUNCTION__.5191+0x93>
    f32f:	48 8d 3d 28 ad 00 00 	lea    0xad28(%rip),%rdi        # 1a05e <__PRETTY_FUNCTION__.5191+0x9e>
    f336:	e8 a5 85 ff ff       	callq  78e0 <__assert_fail@plt>
}
    f33b:	e8 20 85 ff ff       	callq  7860 <__stack_chk_fail@plt>
      fatal ("Cannot set terminal attributes: %s", strerror (errno));
    f340:	e8 eb 83 ff ff       	callq  7730 <__errno_location@plt>
    f345:	8b 38                	mov    (%rax),%edi
    f347:	e8 44 89 ff ff       	callq  7c90 <strerror@plt>
    f34c:	48 8d 3d 6d ad 00 00 	lea    0xad6d(%rip),%rdi        # 1a0c0 <__PRETTY_FUNCTION__.5191+0x100>
    f353:	48 89 c6             	mov    %rax,%rsi
    f356:	31 c0                	xor    %eax,%eax
    f358:	e8 03 02 00 00       	callq  f560 <fatal>
    f35d:	0f 1f 00             	nopl   (%rax)

000000000000f360 <term_restore>:

void
term_restore (void)
/* Restore the terminal's original access mode.  */
{
    f360:	f3 0f 1e fa          	endbr64 
    f364:	41 54                	push   %r12
    f366:	48 83 ec 50          	sub    $0x50,%rsp
  struct termios  settings;
#endif
  int  res;

#if HAVE_TERMIOS_H
  if (attributes_changed) {
    f36a:	8b 15 78 1a 01 00    	mov    0x11a78(%rip),%edx        # 20de8 <attributes_changed>
{
    f370:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    f377:	00 00 
    f379:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
    f37e:	31 c0                	xor    %eax,%eax
  if (attributes_changed) {
    f380:	85 d2                	test   %edx,%edx
    f382:	75 24                	jne    f3a8 <term_restore+0x48>
    if (res < 0)
      fatal ("Cannot set terminal attributes: %s", strerror (errno));
  }
#endif

  if (term_mode_valid) {
    f384:	8b 05 62 1a 01 00    	mov    0x11a62(%rip),%eax        # 20dec <term_mode_valid>
    f38a:	85 c0                	test   %eax,%eax
    f38c:	75 62                	jne    f3f0 <term_restore+0x90>
    res = fchmod (0, term_mode);
    if (res < 0)
      fatal ("Cannot restore terminal permissions: %s", strerror (errno));
    term_mode_valid = 0;
  }
}
    f38e:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    f393:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    f39a:	00 00 
    f39c:	75 6f                	jne    f40d <term_restore+0xad>
    f39e:	48 83 c4 50          	add    $0x50,%rsp
    f3a2:	41 5c                	pop    %r12
    f3a4:	c3                   	retq   
    f3a5:	0f 1f 00             	nopl   (%rax)
    res = tcgetattr (0, &settings);
    f3a8:	49 89 e4             	mov    %rsp,%r12
    f3ab:	31 ff                	xor    %edi,%edi
    f3ad:	4c 89 e6             	mov    %r12,%rsi
    f3b0:	e8 db 87 ff ff       	callq  7b90 <tcgetattr@plt>
    if (res < 0)
    f3b5:	85 c0                	test   %eax,%eax
    f3b7:	78 76                	js     f42f <term_restore+0xcf>
    res = tcsetattr (0, TCSANOW, &settings);
    f3b9:	31 f6                	xor    %esi,%esi
    f3bb:	31 ff                	xor    %edi,%edi
    f3bd:	4c 89 e2             	mov    %r12,%rdx
    settings.c_iflag |= IXON;
    f3c0:	81 0c 24 00 04 00 00 	orl    $0x400,(%rsp)
    res = tcsetattr (0, TCSANOW, &settings);
    f3c7:	e8 e4 87 ff ff       	callq  7bb0 <tcsetattr@plt>
    if (res < 0)
    f3cc:	85 c0                	test   %eax,%eax
    f3ce:	79 b4                	jns    f384 <term_restore+0x24>
      fatal ("Cannot set terminal attributes: %s", strerror (errno));
    f3d0:	e8 5b 83 ff ff       	callq  7730 <__errno_location@plt>
    f3d5:	8b 38                	mov    (%rax),%edi
    f3d7:	e8 b4 88 ff ff       	callq  7c90 <strerror@plt>
    f3dc:	48 8d 3d dd ac 00 00 	lea    0xacdd(%rip),%rdi        # 1a0c0 <__PRETTY_FUNCTION__.5191+0x100>
    f3e3:	48 89 c6             	mov    %rax,%rsi
    f3e6:	31 c0                	xor    %eax,%eax
    f3e8:	e8 73 01 00 00       	callq  f560 <fatal>
    f3ed:	0f 1f 00             	nopl   (%rax)
    res = fchmod (0, term_mode);
    f3f0:	8b 35 fa 19 01 00    	mov    0x119fa(%rip),%esi        # 20df0 <term_mode>
    f3f6:	31 ff                	xor    %edi,%edi
    f3f8:	e8 53 87 ff ff       	callq  7b50 <fchmod@plt>
    if (res < 0)
    f3fd:	85 c0                	test   %eax,%eax
    f3ff:	78 11                	js     f412 <term_restore+0xb2>
    term_mode_valid = 0;
    f401:	c7 05 e1 19 01 00 00 	movl   $0x0,0x119e1(%rip)        # 20dec <term_mode_valid>
    f408:	00 00 00 
}
    f40b:	eb 81                	jmp    f38e <term_restore+0x2e>
    f40d:	e8 4e 84 ff ff       	callq  7860 <__stack_chk_fail@plt>
      fatal ("Cannot restore terminal permissions: %s", strerror (errno));
    f412:	e8 19 83 ff ff       	callq  7730 <__errno_location@plt>
    f417:	8b 38                	mov    (%rax),%edi
    f419:	e8 72 88 ff ff       	callq  7c90 <strerror@plt>
    f41e:	48 8d 3d c3 ac 00 00 	lea    0xacc3(%rip),%rdi        # 1a0e8 <__PRETTY_FUNCTION__.5191+0x128>
    f425:	48 89 c6             	mov    %rax,%rsi
    f428:	31 c0                	xor    %eax,%eax
    f42a:	e8 31 01 00 00       	callq  f560 <fatal>
      fatal ("Cannot get terminal attributes: %s", strerror (errno));
    f42f:	e8 fc 82 ff ff       	callq  7730 <__errno_location@plt>
    f434:	8b 38                	mov    (%rax),%edi
    f436:	e8 55 88 ff ff       	callq  7c90 <strerror@plt>
    f43b:	48 8d 3d 2e ac 00 00 	lea    0xac2e(%rip),%rdi        # 1a070 <__PRETTY_FUNCTION__.5191+0xb0>
    f442:	48 89 c6             	mov    %rax,%rsi
    f445:	31 c0                	xor    %eax,%eax
    f447:	e8 14 01 00 00       	callq  f560 <fatal>
    f44c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000f450 <hide_cursor>:
#include "moon-buggy.h"


void
hide_cursor (void)
{
    f450:	f3 0f 1e fa          	endbr64 
    f454:	48 83 ec 08          	sub    $0x8,%rsp
  leaveok (moon, TRUE);
    f458:	48 8b 3d b9 19 01 00 	mov    0x119b9(%rip),%rdi        # 20e18 <moon>
    f45f:	be 01 00 00 00       	mov    $0x1,%esi
    f464:	e8 17 85 ff ff       	callq  7980 <leaveok@plt>
  leaveok (status, TRUE);
    f469:	48 8b 3d a0 19 01 00 	mov    0x119a0(%rip),%rdi        # 20e10 <status>
    f470:	be 01 00 00 00       	mov    $0x1,%esi
    f475:	e8 06 85 ff ff       	callq  7980 <leaveok@plt>
  leaveok (message, TRUE);
    f47a:	48 8b 3d 7f 19 01 00 	mov    0x1197f(%rip),%rdi        # 20e00 <message>
    f481:	be 01 00 00 00       	mov    $0x1,%esi
    f486:	e8 f5 84 ff ff       	callq  7980 <leaveok@plt>
  curs_set (0);
    f48b:	31 ff                	xor    %edi,%edi
}
    f48d:	48 83 c4 08          	add    $0x8,%rsp
  curs_set (0);
    f491:	e9 ea 82 ff ff       	jmpq   7780 <curs_set@plt>
    f496:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    f49d:	00 00 00 

000000000000f4a0 <show_cursor>:

void
show_cursor (void)
{
    f4a0:	f3 0f 1e fa          	endbr64 
    f4a4:	48 83 ec 08          	sub    $0x8,%rsp
  curs_set (1);
    f4a8:	bf 01 00 00 00       	mov    $0x1,%edi
    f4ad:	e8 ce 82 ff ff       	callq  7780 <curs_set@plt>
  leaveok (moon, FALSE);
    f4b2:	48 8b 3d 5f 19 01 00 	mov    0x1195f(%rip),%rdi        # 20e18 <moon>
    f4b9:	31 f6                	xor    %esi,%esi
    f4bb:	e8 c0 84 ff ff       	callq  7980 <leaveok@plt>
  leaveok (status, FALSE);
    f4c0:	48 8b 3d 49 19 01 00 	mov    0x11949(%rip),%rdi        # 20e10 <status>
    f4c7:	31 f6                	xor    %esi,%esi
    f4c9:	e8 b2 84 ff ff       	callq  7980 <leaveok@plt>
  leaveok (message, FALSE);
    f4ce:	48 8b 3d 2b 19 01 00 	mov    0x1192b(%rip),%rdi        # 20e00 <message>
    f4d5:	31 f6                	xor    %esi,%esi
}
    f4d7:	48 83 c4 08          	add    $0x8,%rsp
  leaveok (message, FALSE);
    f4db:	e9 a0 84 ff ff       	jmpq   7980 <leaveok@plt>

000000000000f4e0 <init_rnd>:

void
init_rnd (void)
/* Initialise the random number generator with a random seed.
 * The seed is based on the current time.  */
{
    f4e0:	f3 0f 1e fa          	endbr64 
    f4e4:	48 83 ec 08          	sub    $0x8,%rsp
  srand (time (0));
    f4e8:	31 ff                	xor    %edi,%edi
    f4ea:	e8 f1 84 ff ff       	callq  79e0 <time@plt>
}
    f4ef:	48 83 c4 08          	add    $0x8,%rsp
  srand (time (0));
    f4f3:	48 89 c7             	mov    %rax,%rdi
    f4f6:	e9 75 84 ff ff       	jmpq   7970 <srand@plt>
    f4fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000f500 <uniform_rnd>:

int
uniform_rnd (unsigned limit)
/* Returns a pseudo random integer `x' with `0 <= x < limit'.
 * The numbers a uniformly distributed.  */
{
    f500:	f3 0f 1e fa          	endbr64 
    f504:	53                   	push   %rbx
    f505:	89 fb                	mov    %edi,%ebx
  assert (limit > 1);
    f507:	83 fb 01             	cmp    $0x1,%ebx
    f50a:	76 28                	jbe    f534 <uniform_rnd+0x34>
  return  (int)((double)limit*rand()/(RAND_MAX+1.0));
    f50c:	e8 cf 87 ff ff       	callq  7ce0 <rand@plt>
    f511:	66 0f ef c0          	pxor   %xmm0,%xmm0
    f515:	66 0f ef c9          	pxor   %xmm1,%xmm1
    f519:	f2 48 0f 2a c3       	cvtsi2sd %rbx,%xmm0
}
    f51e:	5b                   	pop    %rbx
  return  (int)((double)limit*rand()/(RAND_MAX+1.0));
    f51f:	f2 0f 2a c8          	cvtsi2sd %eax,%xmm1
    f523:	f2 0f 59 c1          	mulsd  %xmm1,%xmm0
    f527:	f2 0f 59 05 11 ac 00 	mulsd  0xac11(%rip),%xmm0        # 1a140 <__PRETTY_FUNCTION__.4433+0x10>
    f52e:	00 
    f52f:	f2 0f 2c c0          	cvttsd2si %xmm0,%eax
}
    f533:	c3                   	retq   
  assert (limit > 1);
    f534:	48 8d 0d f5 ab 00 00 	lea    0xabf5(%rip),%rcx        # 1a130 <__PRETTY_FUNCTION__.4433>
    f53b:	ba 1d 00 00 00       	mov    $0x1d,%edx
    f540:	48 8d 35 d6 ab 00 00 	lea    0xabd6(%rip),%rsi        # 1a11d <__PRETTY_FUNCTION__.6408+0xd>
    f547:	48 8d 3d d8 ab 00 00 	lea    0xabd8(%rip),%rdi        # 1a126 <__PRETTY_FUNCTION__.6408+0x16>
    f54e:	e8 8d 83 ff ff       	callq  78e0 <__assert_fail@plt>
    f553:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    f55a:	00 00 00 
    f55d:	0f 1f 00             	nopl   (%rax)

000000000000f560 <fatal>:
void
fatal (const char *format, ...)
/* Signal a fatal error and quit immediately.  The arguments have the
 * same meaning, as in the function `printf'.
 * The message should start with a capital letter.  */
{
    f560:	f3 0f 1e fa          	endbr64 
    f564:	41 54                	push   %r12
    f566:	49 89 fc             	mov    %rdi,%r12
    f569:	48 81 ec d0 00 00 00 	sub    $0xd0,%rsp
    f570:	48 89 74 24 28       	mov    %rsi,0x28(%rsp)
    f575:	48 89 54 24 30       	mov    %rdx,0x30(%rsp)
    f57a:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
    f57f:	4c 89 44 24 40       	mov    %r8,0x40(%rsp)
    f584:	4c 89 4c 24 48       	mov    %r9,0x48(%rsp)
    f589:	84 c0                	test   %al,%al
    f58b:	74 37                	je     f5c4 <fatal+0x64>
    f58d:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
    f592:	0f 29 4c 24 60       	movaps %xmm1,0x60(%rsp)
    f597:	0f 29 54 24 70       	movaps %xmm2,0x70(%rsp)
    f59c:	0f 29 9c 24 80 00 00 	movaps %xmm3,0x80(%rsp)
    f5a3:	00 
    f5a4:	0f 29 a4 24 90 00 00 	movaps %xmm4,0x90(%rsp)
    f5ab:	00 
    f5ac:	0f 29 ac 24 a0 00 00 	movaps %xmm5,0xa0(%rsp)
    f5b3:	00 
    f5b4:	0f 29 b4 24 b0 00 00 	movaps %xmm6,0xb0(%rsp)
    f5bb:	00 
    f5bc:	0f 29 bc 24 c0 00 00 	movaps %xmm7,0xc0(%rsp)
    f5c3:	00 
    f5c4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    f5cb:	00 00 
    f5cd:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    f5d2:	31 c0                	xor    %eax,%eax
  va_list  ap;

  prepare_for_exit ();
    f5d4:	e8 07 8f ff ff       	callq  84e0 <prepare_for_exit>

  va_start (ap, format);
    f5d9:	48 8d 84 24 e0 00 00 	lea    0xe0(%rsp),%rax
    f5e0:	00 
  fflush (NULL);
    f5e1:	31 ff                	xor    %edi,%edi
  va_start (ap, format);
    f5e3:	c7 04 24 08 00 00 00 	movl   $0x8,(%rsp)
    f5ea:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    f5ef:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
    f5f4:	c7 44 24 04 30 00 00 	movl   $0x30,0x4(%rsp)
    f5fb:	00 
    f5fc:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
  fflush (NULL);
    f601:	e8 5a 84 ff ff       	callq  7a60 <fflush@plt>
  fputs ("Fatal error: ", stderr);
    f606:	ba 0d 00 00 00       	mov    $0xd,%edx
    f60b:	48 8b 0d 8e fc 00 00 	mov    0xfc8e(%rip),%rcx        # 1f2a0 <stderr@@GLIBC_2.2.5>
    f612:	be 01 00 00 00       	mov    $0x1,%esi
    f617:	48 8d 3d 2a ab 00 00 	lea    0xab2a(%rip),%rdi        # 1a148 <__PRETTY_FUNCTION__.4433+0x18>
    f61e:	e8 0d 86 ff ff       	callq  7c30 <fwrite@plt>

__fortify_function int
vfprintf (FILE *__restrict __stream,
	  const char *__restrict __fmt, __gnuc_va_list __ap)
{
  return __vfprintf_chk (__stream, __USE_FORTIFY_LEVEL - 1, __fmt, __ap);
    f623:	48 89 e1             	mov    %rsp,%rcx
    f626:	4c 89 e2             	mov    %r12,%rdx
    f629:	be 01 00 00 00       	mov    $0x1,%esi
    f62e:	48 8b 3d 6b fc 00 00 	mov    0xfc6b(%rip),%rdi        # 1f2a0 <stderr@@GLIBC_2.2.5>
    f635:	e8 d6 80 ff ff       	callq  7710 <__vfprintf_chk@plt>
  vfprintf (stderr, format, ap);
  fputc ('\n', stderr);
    f63a:	48 8b 35 5f fc 00 00 	mov    0xfc5f(%rip),%rsi        # 1f2a0 <stderr@@GLIBC_2.2.5>
    f641:	bf 0a 00 00 00       	mov    $0xa,%edi
    f646:	e8 f5 82 ff ff       	callq  7940 <fputc@plt>
  va_end (ap);

  exit (EXIT_FAILURE);
    f64b:	bf 01 00 00 00       	mov    $0x1,%edi
    f650:	e8 cb 85 ff ff       	callq  7c20 <exit@plt>
    f655:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    f65c:	00 00 00 
    f65f:	90                   	nop

000000000000f660 <xmalloc>:

void *
xmalloc (size_t size)
/* Like `malloc', but check for shortage of memory.  `xmalloc' never
 * returns `NULL'.  */
{
    f660:	f3 0f 1e fa          	endbr64 
    f664:	48 83 ec 08          	sub    $0x8,%rsp
  void *ptr = malloc (size);
    f668:	e8 e3 83 ff ff       	callq  7a50 <malloc@plt>
  if (ptr == NULL)  fatal ("Memory exhausted");
    f66d:	48 85 c0             	test   %rax,%rax
    f670:	74 05                	je     f677 <xmalloc+0x17>
  return  ptr;
}
    f672:	48 83 c4 08          	add    $0x8,%rsp
    f676:	c3                   	retq   
  if (ptr == NULL)  fatal ("Memory exhausted");
    f677:	48 8d 3d d8 aa 00 00 	lea    0xaad8(%rip),%rdi        # 1a156 <__PRETTY_FUNCTION__.4433+0x26>
    f67e:	e8 dd fe ff ff       	callq  f560 <fatal>
    f683:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    f68a:	00 00 00 00 
    f68e:	66 90                	xchg   %ax,%ax

000000000000f690 <xrealloc>:

void *
xrealloc (void *ptr, size_t size)
/* Like `realloc', but check for shortage of memory.  `xrealloc' never
 * returns `NULL'.  */
{
    f690:	f3 0f 1e fa          	endbr64 
    f694:	48 83 ec 08          	sub    $0x8,%rsp
  void *tmp;

  if (ptr) {
    f698:	48 85 ff             	test   %rdi,%rdi
    f69b:	74 13                	je     f6b0 <xrealloc+0x20>
    tmp = realloc (ptr, size);
    f69d:	e8 5e 84 ff ff       	callq  7b00 <realloc@plt>
  } else {
    tmp = malloc (size);
  }
  if (tmp == NULL)  fatal ("Memory exhausted");
    f6a2:	48 85 c0             	test   %rax,%rax
    f6a5:	74 13                	je     f6ba <xrealloc+0x2a>
  return  tmp;
}
    f6a7:	48 83 c4 08          	add    $0x8,%rsp
    f6ab:	c3                   	retq   
    f6ac:	0f 1f 40 00          	nopl   0x0(%rax)
    tmp = malloc (size);
    f6b0:	48 89 f7             	mov    %rsi,%rdi
    f6b3:	e8 98 83 ff ff       	callq  7a50 <malloc@plt>
    f6b8:	eb e8                	jmp    f6a2 <xrealloc+0x12>
  if (tmp == NULL)  fatal ("Memory exhausted");
    f6ba:	48 8d 3d 95 aa 00 00 	lea    0xaa95(%rip),%rdi        # 1a156 <__PRETTY_FUNCTION__.4433+0x26>
    f6c1:	e8 9a fe ff ff       	callq  f560 <fatal>
    f6c6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    f6cd:	00 00 00 

000000000000f6d0 <xstrdup>:


char *
xstrdup (const char *str)
/* Duplicate STR as `strdup' does, but never return NULL.  */
{
    f6d0:	f3 0f 1e fa          	endbr64 
    f6d4:	55                   	push   %rbp
    f6d5:	48 89 fd             	mov    %rdi,%rbp
  char *tmp = xmalloc (strlen(str) + 1);
    f6d8:	e8 63 81 ff ff       	callq  7840 <strlen@plt>
    f6dd:	48 8d 78 01          	lea    0x1(%rax),%rdi
    f6e1:	e8 7a ff ff ff       	callq  f660 <xmalloc>
  return __builtin___strcpy_chk (__dest, __src, __bos (__dest));
    f6e6:	48 89 ee             	mov    %rbp,%rsi
    f6e9:	48 89 c7             	mov    %rax,%rdi
    f6ec:	e8 6f 80 ff ff       	callq  7760 <strcpy@plt>
  strcpy (tmp, str);
  return  tmp;
}
    f6f1:	5d                   	pop    %rbp
    f6f2:	c3                   	retq   
    f6f3:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    f6fa:	00 00 00 00 
    f6fe:	66 90                	xchg   %ax,%ax

000000000000f700 <xstrnlen>:

size_t
xstrnlen (const char *str, size_t size)
{
    f700:	f3 0f 1e fa          	endbr64 
  size_t  n = 0;
    f704:	31 c0                	xor    %eax,%eax
  while (n<size && str[n])  ++n;
    f706:	48 85 f6             	test   %rsi,%rsi
    f709:	75 0e                	jne    f719 <xstrnlen+0x19>
    f70b:	eb 13                	jmp    f720 <xstrnlen+0x20>
    f70d:	0f 1f 00             	nopl   (%rax)
    f710:	48 83 c0 01          	add    $0x1,%rax
    f714:	48 39 c6             	cmp    %rax,%rsi
    f717:	74 06                	je     f71f <xstrnlen+0x1f>
    f719:	80 3c 07 00          	cmpb   $0x0,(%rdi,%rax,1)
    f71d:	75 f1                	jne    f710 <xstrnlen+0x10>
  return  n;
}
    f71f:	c3                   	retq   
    f720:	c3                   	retq   
    f721:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    f728:	00 00 00 00 
    f72c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000000f730 <xstrndup>:

char *
xstrndup (const char *str, size_t size)
/* Like `strndup' from glibc, but never returns NULL.  */
{
    f730:	f3 0f 1e fa          	endbr64 
    f734:	55                   	push   %rbp
    f735:	48 89 fd             	mov    %rdi,%rbp
  while (n<size && str[n])  ++n;
    f738:	bf 01 00 00 00       	mov    $0x1,%edi
{
    f73d:	53                   	push   %rbx
  size_t  n = 0;
    f73e:	31 db                	xor    %ebx,%ebx
{
    f740:	48 83 ec 08          	sub    $0x8,%rsp
  while (n<size && str[n])  ++n;
    f744:	48 85 f6             	test   %rsi,%rsi
    f747:	74 1c                	je     f765 <xstrndup+0x35>
    f749:	31 ff                	xor    %edi,%edi
    f74b:	eb 08                	jmp    f755 <xstrndup+0x25>
    f74d:	0f 1f 00             	nopl   (%rax)
    f750:	48 39 fe             	cmp    %rdi,%rsi
    f753:	74 3b                	je     f790 <xstrndup+0x60>
    f755:	0f b6 44 3d 00       	movzbl 0x0(%rbp,%rdi,1),%eax
    f75a:	48 89 fb             	mov    %rdi,%rbx
    f75d:	48 83 c7 01          	add    $0x1,%rdi
    f761:	84 c0                	test   %al,%al
    f763:	75 eb                	jne    f750 <xstrndup+0x20>
  size_t  n = xstrnlen (str, size);
  char *tmp = xmalloc (n + 1);
    f765:	e8 f6 fe ff ff       	callq  f660 <xmalloc>

  if (tmp == NULL)  fatal ("Memory exhausted");
    f76a:	48 85 c0             	test   %rax,%rax
    f76d:	74 2d                	je     f79c <xstrndup+0x6c>
  return __builtin___strncpy_chk (__dest, __src, __len, __bos (__dest));
    f76f:	48 89 da             	mov    %rbx,%rdx
    f772:	48 89 ee             	mov    %rbp,%rsi
    f775:	48 89 c7             	mov    %rax,%rdi
    f778:	e8 c3 7f ff ff       	callq  7740 <strncpy@plt>
  strncpy (tmp, str, n);
  tmp[n] = '\0';
    f77d:	c6 04 18 00          	movb   $0x0,(%rax,%rbx,1)

  return  tmp;
}
    f781:	48 83 c4 08          	add    $0x8,%rsp
    f785:	5b                   	pop    %rbx
    f786:	5d                   	pop    %rbp
    f787:	c3                   	retq   
    f788:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    f78f:	00 
    f790:	48 8d 43 02          	lea    0x2(%rbx),%rax
  while (n<size && str[n])  ++n;
    f794:	48 89 fb             	mov    %rdi,%rbx
    f797:	48 89 c7             	mov    %rax,%rdi
    f79a:	eb c9                	jmp    f765 <xstrndup+0x35>
  if (tmp == NULL)  fatal ("Memory exhausted");
    f79c:	48 8d 3d b3 a9 00 00 	lea    0xa9b3(%rip),%rdi        # 1a156 <__PRETTY_FUNCTION__.4433+0x26>
    f7a3:	31 c0                	xor    %eax,%eax
    f7a5:	e8 b6 fd ff ff       	callq  f560 <fatal>
    f7aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000f7b0 <__libc_csu_init>:
    f7b0:	f3 0f 1e fa          	endbr64 
    f7b4:	41 57                	push   %r15
    f7b6:	4c 8d 3d 53 db 00 00 	lea    0xdb53(%rip),%r15        # 1d310 <__frame_dummy_init_array_entry>
    f7bd:	41 56                	push   %r14
    f7bf:	49 89 d6             	mov    %rdx,%r14
    f7c2:	41 55                	push   %r13
    f7c4:	49 89 f5             	mov    %rsi,%r13
    f7c7:	41 54                	push   %r12
    f7c9:	41 89 fc             	mov    %edi,%r12d
    f7cc:	55                   	push   %rbp
    f7cd:	48 8d 2d 44 db 00 00 	lea    0xdb44(%rip),%rbp        # 1d318 <__do_global_dtors_aux_fini_array_entry>
    f7d4:	53                   	push   %rbx
    f7d5:	4c 29 fd             	sub    %r15,%rbp
    f7d8:	48 83 ec 08          	sub    $0x8,%rsp
    f7dc:	e8 1f 78 ff ff       	callq  7000 <_init>
    f7e1:	48 c1 fd 03          	sar    $0x3,%rbp
    f7e5:	74 1f                	je     f806 <__libc_csu_init+0x56>
    f7e7:	31 db                	xor    %ebx,%ebx
    f7e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    f7f0:	4c 89 f2             	mov    %r14,%rdx
    f7f3:	4c 89 ee             	mov    %r13,%rsi
    f7f6:	44 89 e7             	mov    %r12d,%edi
    f7f9:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    f7fd:	48 83 c3 01          	add    $0x1,%rbx
    f801:	48 39 dd             	cmp    %rbx,%rbp
    f804:	75 ea                	jne    f7f0 <__libc_csu_init+0x40>
    f806:	48 83 c4 08          	add    $0x8,%rsp
    f80a:	5b                   	pop    %rbx
    f80b:	5d                   	pop    %rbp
    f80c:	41 5c                	pop    %r12
    f80e:	41 5d                	pop    %r13
    f810:	41 5e                	pop    %r14
    f812:	41 5f                	pop    %r15
    f814:	c3                   	retq   
    f815:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    f81c:	00 00 00 00 

000000000000f820 <__libc_csu_fini>:
    f820:	f3 0f 1e fa          	endbr64 
    f824:	c3                   	retq   

Disassembly of section .fini:

000000000000f828 <_fini>:
    f828:	f3 0f 1e fa          	endbr64 
    f82c:	48 83 ec 08          	sub    $0x8,%rsp
    f830:	48 83 c4 08          	add    $0x8,%rsp
    f834:	c3                   	retq   
