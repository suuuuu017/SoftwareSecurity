
flappybird:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 3f 00 00 	mov    0x3fd9(%rip),%rax        # 4fe8 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	callq  *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	retq   

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 92 3e 00 00    	pushq  0x3e92(%rip)        # 4eb8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 93 3e 00 00 	bnd jmpq *0x3e93(%rip)        # 4ec0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	pushq  $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmpq 1020 <.plt>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	pushq  $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmpq 1020 <.plt>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	pushq  $0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmpq 1020 <.plt>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	pushq  $0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmpq 1020 <.plt>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64 
    1074:	68 04 00 00 00       	pushq  $0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmpq 1020 <.plt>
    107f:	90                   	nop
    1080:	f3 0f 1e fa          	endbr64 
    1084:	68 05 00 00 00       	pushq  $0x5
    1089:	f2 e9 91 ff ff ff    	bnd jmpq 1020 <.plt>
    108f:	90                   	nop
    1090:	f3 0f 1e fa          	endbr64 
    1094:	68 06 00 00 00       	pushq  $0x6
    1099:	f2 e9 81 ff ff ff    	bnd jmpq 1020 <.plt>
    109f:	90                   	nop
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	68 07 00 00 00       	pushq  $0x7
    10a9:	f2 e9 71 ff ff ff    	bnd jmpq 1020 <.plt>
    10af:	90                   	nop
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	68 08 00 00 00       	pushq  $0x8
    10b9:	f2 e9 61 ff ff ff    	bnd jmpq 1020 <.plt>
    10bf:	90                   	nop
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	68 09 00 00 00       	pushq  $0x9
    10c9:	f2 e9 51 ff ff ff    	bnd jmpq 1020 <.plt>
    10cf:	90                   	nop
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	68 0a 00 00 00       	pushq  $0xa
    10d9:	f2 e9 41 ff ff ff    	bnd jmpq 1020 <.plt>
    10df:	90                   	nop
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	68 0b 00 00 00       	pushq  $0xb
    10e9:	f2 e9 31 ff ff ff    	bnd jmpq 1020 <.plt>
    10ef:	90                   	nop
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	68 0c 00 00 00       	pushq  $0xc
    10f9:	f2 e9 21 ff ff ff    	bnd jmpq 1020 <.plt>
    10ff:	90                   	nop
    1100:	f3 0f 1e fa          	endbr64 
    1104:	68 0d 00 00 00       	pushq  $0xd
    1109:	f2 e9 11 ff ff ff    	bnd jmpq 1020 <.plt>
    110f:	90                   	nop
    1110:	f3 0f 1e fa          	endbr64 
    1114:	68 0e 00 00 00       	pushq  $0xe
    1119:	f2 e9 01 ff ff ff    	bnd jmpq 1020 <.plt>
    111f:	90                   	nop
    1120:	f3 0f 1e fa          	endbr64 
    1124:	68 0f 00 00 00       	pushq  $0xf
    1129:	f2 e9 f1 fe ff ff    	bnd jmpq 1020 <.plt>
    112f:	90                   	nop
    1130:	f3 0f 1e fa          	endbr64 
    1134:	68 10 00 00 00       	pushq  $0x10
    1139:	f2 e9 e1 fe ff ff    	bnd jmpq 1020 <.plt>
    113f:	90                   	nop
    1140:	f3 0f 1e fa          	endbr64 
    1144:	68 11 00 00 00       	pushq  $0x11
    1149:	f2 e9 d1 fe ff ff    	bnd jmpq 1020 <.plt>
    114f:	90                   	nop
    1150:	f3 0f 1e fa          	endbr64 
    1154:	68 12 00 00 00       	pushq  $0x12
    1159:	f2 e9 c1 fe ff ff    	bnd jmpq 1020 <.plt>
    115f:	90                   	nop
    1160:	f3 0f 1e fa          	endbr64 
    1164:	68 13 00 00 00       	pushq  $0x13
    1169:	f2 e9 b1 fe ff ff    	bnd jmpq 1020 <.plt>
    116f:	90                   	nop
    1170:	f3 0f 1e fa          	endbr64 
    1174:	68 14 00 00 00       	pushq  $0x14
    1179:	f2 e9 a1 fe ff ff    	bnd jmpq 1020 <.plt>
    117f:	90                   	nop
    1180:	f3 0f 1e fa          	endbr64 
    1184:	68 15 00 00 00       	pushq  $0x15
    1189:	f2 e9 91 fe ff ff    	bnd jmpq 1020 <.plt>
    118f:	90                   	nop
    1190:	f3 0f 1e fa          	endbr64 
    1194:	68 16 00 00 00       	pushq  $0x16
    1199:	f2 e9 81 fe ff ff    	bnd jmpq 1020 <.plt>
    119f:	90                   	nop
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	68 17 00 00 00       	pushq  $0x17
    11a9:	f2 e9 71 fe ff ff    	bnd jmpq 1020 <.plt>
    11af:	90                   	nop
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	68 18 00 00 00       	pushq  $0x18
    11b9:	f2 e9 61 fe ff ff    	bnd jmpq 1020 <.plt>
    11bf:	90                   	nop
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	68 19 00 00 00       	pushq  $0x19
    11c9:	f2 e9 51 fe ff ff    	bnd jmpq 1020 <.plt>
    11cf:	90                   	nop
    11d0:	f3 0f 1e fa          	endbr64 
    11d4:	68 1a 00 00 00       	pushq  $0x1a
    11d9:	f2 e9 41 fe ff ff    	bnd jmpq 1020 <.plt>
    11df:	90                   	nop
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	68 1b 00 00 00       	pushq  $0x1b
    11e9:	f2 e9 31 fe ff ff    	bnd jmpq 1020 <.plt>
    11ef:	90                   	nop
    11f0:	f3 0f 1e fa          	endbr64 
    11f4:	68 1c 00 00 00       	pushq  $0x1c
    11f9:	f2 e9 21 fe ff ff    	bnd jmpq 1020 <.plt>
    11ff:	90                   	nop
    1200:	f3 0f 1e fa          	endbr64 
    1204:	68 1d 00 00 00       	pushq  $0x1d
    1209:	f2 e9 11 fe ff ff    	bnd jmpq 1020 <.plt>
    120f:	90                   	nop
    1210:	f3 0f 1e fa          	endbr64 
    1214:	68 1e 00 00 00       	pushq  $0x1e
    1219:	f2 e9 01 fe ff ff    	bnd jmpq 1020 <.plt>
    121f:	90                   	nop
    1220:	f3 0f 1e fa          	endbr64 
    1224:	68 1f 00 00 00       	pushq  $0x1f
    1229:	f2 e9 f1 fd ff ff    	bnd jmpq 1020 <.plt>
    122f:	90                   	nop
    1230:	f3 0f 1e fa          	endbr64 
    1234:	68 20 00 00 00       	pushq  $0x20
    1239:	f2 e9 e1 fd ff ff    	bnd jmpq 1020 <.plt>
    123f:	90                   	nop

Disassembly of section .plt.got:

0000000000001240 <__cxa_finalize@plt>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	f2 ff 25 85 3d 00 00 	bnd jmpq *0x3d85(%rip)        # 4fd0 <__cxa_finalize@GLIBC_2.2.5>
    124b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001250 <printf@plt>:
    1250:	f3 0f 1e fa          	endbr64 
    1254:	f2 ff 25 6d 3c 00 00 	bnd jmpq *0x3c6d(%rip)        # 4ec8 <printf@GLIBC_2.2.5>
    125b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001260 <init_pair@plt>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	f2 ff 25 65 3c 00 00 	bnd jmpq *0x3c65(%rip)        # 4ed0 <init_pair@NCURSES6_5.0.19991023>
    126b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001270 <start_color@plt>:
    1270:	f3 0f 1e fa          	endbr64 
    1274:	f2 ff 25 5d 3c 00 00 	bnd jmpq *0x3c5d(%rip)        # 4ed8 <start_color@NCURSES6_5.0.19991023>
    127b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001280 <rand@plt>:
    1280:	f3 0f 1e fa          	endbr64 
    1284:	f2 ff 25 55 3c 00 00 	bnd jmpq *0x3c55(%rip)        # 4ee0 <rand@GLIBC_2.2.5>
    128b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001290 <waddch@plt>:
    1290:	f3 0f 1e fa          	endbr64 
    1294:	f2 ff 25 4d 3c 00 00 	bnd jmpq *0x3c4d(%rip)        # 4ee8 <waddch@NCURSES6_5.0.19991023>
    129b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012a0 <wgetch@plt>:
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	f2 ff 25 45 3c 00 00 	bnd jmpq *0x3c45(%rip)        # 4ef0 <wgetch@NCURSES6_5.0.19991023>
    12ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012b0 <keypad@plt>:
    12b0:	f3 0f 1e fa          	endbr64 
    12b4:	f2 ff 25 3d 3c 00 00 	bnd jmpq *0x3c3d(%rip)        # 4ef8 <keypad@NCURSES6_TINFO_5.0.19991023>
    12bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012c0 <assume_default_colors@plt>:
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	f2 ff 25 35 3c 00 00 	bnd jmpq *0x3c35(%rip)        # 4f00 <assume_default_colors@NCURSES6_5.1.20000708>
    12cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012d0 <wattr_on@plt>:
    12d0:	f3 0f 1e fa          	endbr64 
    12d4:	f2 ff 25 2d 3c 00 00 	bnd jmpq *0x3c2d(%rip)        # 4f08 <wattr_on@NCURSES6_5.0.19991023>
    12db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012e0 <sleep@plt>:
    12e0:	f3 0f 1e fa          	endbr64 
    12e4:	f2 ff 25 25 3c 00 00 	bnd jmpq *0x3c25(%rip)        # 4f10 <sleep@GLIBC_2.2.5>
    12eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012f0 <curs_set@plt>:
    12f0:	f3 0f 1e fa          	endbr64 
    12f4:	f2 ff 25 1d 3c 00 00 	bnd jmpq *0x3c1d(%rip)        # 4f18 <curs_set@NCURSES6_TINFO_5.0.19991023>
    12fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001300 <__cxa_atexit@plt>:
    1300:	f3 0f 1e fa          	endbr64 
    1304:	f2 ff 25 15 3c 00 00 	bnd jmpq *0x3c15(%rip)        # 4f20 <__cxa_atexit@GLIBC_2.2.5>
    130b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001310 <time@plt>:
    1310:	f3 0f 1e fa          	endbr64 
    1314:	f2 ff 25 0d 3c 00 00 	bnd jmpq *0x3c0d(%rip)        # 4f28 <time@GLIBC_2.2.5>
    131b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001320 <strcpy@plt>:
    1320:	f3 0f 1e fa          	endbr64 
    1324:	f2 ff 25 05 3c 00 00 	bnd jmpq *0x3c05(%rip)        # 4f30 <strcpy@GLIBC_2.2.5>
    132b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001330 <srand@plt>:
    1330:	f3 0f 1e fa          	endbr64 
    1334:	f2 ff 25 fd 3b 00 00 	bnd jmpq *0x3bfd(%rip)        # 4f38 <srand@GLIBC_2.2.5>
    133b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001340 <fclose@plt>:
    1340:	f3 0f 1e fa          	endbr64 
    1344:	f2 ff 25 f5 3b 00 00 	bnd jmpq *0x3bf5(%rip)        # 4f40 <fclose@GLIBC_2.2.5>
    134b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001350 <wmove@plt>:
    1350:	f3 0f 1e fa          	endbr64 
    1354:	f2 ff 25 ed 3b 00 00 	bnd jmpq *0x3bed(%rip)        # 4f48 <wmove@NCURSES6_5.0.19991023>
    135b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001360 <__stack_chk_fail@plt>:
    1360:	f3 0f 1e fa          	endbr64 
    1364:	f2 ff 25 e5 3b 00 00 	bnd jmpq *0x3be5(%rip)        # 4f50 <__stack_chk_fail@GLIBC_2.4>
    136b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001370 <noecho@plt>:
    1370:	f3 0f 1e fa          	endbr64 
    1374:	f2 ff 25 dd 3b 00 00 	bnd jmpq *0x3bdd(%rip)        # 4f58 <noecho@NCURSES6_5.0.19991023>
    137b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001380 <wtimeout@plt>:
    1380:	f3 0f 1e fa          	endbr64 
    1384:	f2 ff 25 d5 3b 00 00 	bnd jmpq *0x3bd5(%rip)        # 4f60 <wtimeout@NCURSES6_TINFO_5.0.19991023>
    138b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001390 <endwin@plt>:
    1390:	f3 0f 1e fa          	endbr64 
    1394:	f2 ff 25 cd 3b 00 00 	bnd jmpq *0x3bcd(%rip)        # 4f68 <endwin@NCURSES6_5.0.19991023>
    139b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013a0 <fopen@plt>:
    13a0:	f3 0f 1e fa          	endbr64 
    13a4:	f2 ff 25 c5 3b 00 00 	bnd jmpq *0x3bc5(%rip)        # 4f70 <fopen@GLIBC_2.2.5>
    13ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013b0 <wattr_off@plt>:
    13b0:	f3 0f 1e fa          	endbr64 
    13b4:	f2 ff 25 bd 3b 00 00 	bnd jmpq *0x3bbd(%rip)        # 4f78 <wattr_off@NCURSES6_5.0.19991023>
    13bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013c0 <mvprintw@plt>:
    13c0:	f3 0f 1e fa          	endbr64 
    13c4:	f2 ff 25 b5 3b 00 00 	bnd jmpq *0x3bb5(%rip)        # 4f80 <mvprintw@NCURSES6_5.0.19991023>
    13cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013d0 <getchar@plt>:
    13d0:	f3 0f 1e fa          	endbr64 
    13d4:	f2 ff 25 ad 3b 00 00 	bnd jmpq *0x3bad(%rip)        # 4f88 <getchar@GLIBC_2.2.5>
    13db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013e0 <usleep@plt>:
    13e0:	f3 0f 1e fa          	endbr64 
    13e4:	f2 ff 25 a5 3b 00 00 	bnd jmpq *0x3ba5(%rip)        # 4f90 <usleep@GLIBC_2.2.5>
    13eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013f0 <initscr@plt>:
    13f0:	f3 0f 1e fa          	endbr64 
    13f4:	f2 ff 25 9d 3b 00 00 	bnd jmpq *0x3b9d(%rip)        # 4f98 <initscr@NCURSES6_5.0.19991023>
    13fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001400 <wgetnstr@plt>:
    1400:	f3 0f 1e fa          	endbr64 
    1404:	f2 ff 25 95 3b 00 00 	bnd jmpq *0x3b95(%rip)        # 4fa0 <wgetnstr@NCURSES6_5.0.19991023>
    140b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001410 <fread@plt>:
    1410:	f3 0f 1e fa          	endbr64 
    1414:	f2 ff 25 8d 3b 00 00 	bnd jmpq *0x3b8d(%rip)        # 4fa8 <fread@GLIBC_2.2.5>
    141b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001420 <_ZNSt8ios_base4InitC1Ev@plt>:
    1420:	f3 0f 1e fa          	endbr64 
    1424:	f2 ff 25 85 3b 00 00 	bnd jmpq *0x3b85(%rip)        # 4fb0 <_ZNSt8ios_base4InitC1Ev@GLIBCXX_3.4>
    142b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001430 <refresh@plt>:
    1430:	f3 0f 1e fa          	endbr64 
    1434:	f2 ff 25 7d 3b 00 00 	bnd jmpq *0x3b7d(%rip)        # 4fb8 <refresh@NCURSES6_5.0.19991023>
    143b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001440 <clear@plt>:
    1440:	f3 0f 1e fa          	endbr64 
    1444:	f2 ff 25 75 3b 00 00 	bnd jmpq *0x3b75(%rip)        # 4fc0 <clear@NCURSES6_5.0.19991023>
    144b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001450 <fwrite@plt>:
    1450:	f3 0f 1e fa          	endbr64 
    1454:	f2 ff 25 6d 3b 00 00 	bnd jmpq *0x3b6d(%rip)        # 4fc8 <fwrite@GLIBC_2.2.5>
    145b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001460 <_start>:
    1460:	f3 0f 1e fa          	endbr64 
    1464:	31 ed                	xor    %ebp,%ebp
    1466:	49 89 d1             	mov    %rdx,%r9
    1469:	5e                   	pop    %rsi
    146a:	48 89 e2             	mov    %rsp,%rdx
    146d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1471:	50                   	push   %rax
    1472:	54                   	push   %rsp
    1473:	4c 8d 05 c6 17 00 00 	lea    0x17c6(%rip),%r8        # 2c40 <__libc_csu_fini>
    147a:	48 8d 0d 4f 17 00 00 	lea    0x174f(%rip),%rcx        # 2bd0 <__libc_csu_init>
    1481:	48 8d 3d c1 00 00 00 	lea    0xc1(%rip),%rdi        # 1549 <main>
    1488:	ff 15 52 3b 00 00    	callq  *0x3b52(%rip)        # 4fe0 <__libc_start_main@GLIBC_2.2.5>
    148e:	f4                   	hlt    
    148f:	90                   	nop

0000000000001490 <deregister_tm_clones>:
    1490:	48 8d 3d 79 3b 00 00 	lea    0x3b79(%rip),%rdi        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1497:	48 8d 05 72 3b 00 00 	lea    0x3b72(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    149e:	48 39 f8             	cmp    %rdi,%rax
    14a1:	74 15                	je     14b8 <deregister_tm_clones+0x28>
    14a3:	48 8b 05 2e 3b 00 00 	mov    0x3b2e(%rip),%rax        # 4fd8 <_ITM_deregisterTMCloneTable>
    14aa:	48 85 c0             	test   %rax,%rax
    14ad:	74 09                	je     14b8 <deregister_tm_clones+0x28>
    14af:	ff e0                	jmpq   *%rax
    14b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    14b8:	c3                   	retq   
    14b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000014c0 <register_tm_clones>:
    14c0:	48 8d 3d 49 3b 00 00 	lea    0x3b49(%rip),%rdi        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    14c7:	48 8d 35 42 3b 00 00 	lea    0x3b42(%rip),%rsi        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    14ce:	48 29 fe             	sub    %rdi,%rsi
    14d1:	48 89 f0             	mov    %rsi,%rax
    14d4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    14d8:	48 c1 f8 03          	sar    $0x3,%rax
    14dc:	48 01 c6             	add    %rax,%rsi
    14df:	48 d1 fe             	sar    %rsi
    14e2:	74 14                	je     14f8 <register_tm_clones+0x38>
    14e4:	48 8b 05 05 3b 00 00 	mov    0x3b05(%rip),%rax        # 4ff0 <_ITM_registerTMCloneTable>
    14eb:	48 85 c0             	test   %rax,%rax
    14ee:	74 08                	je     14f8 <register_tm_clones+0x38>
    14f0:	ff e0                	jmpq   *%rax
    14f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    14f8:	c3                   	retq   
    14f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001500 <__do_global_dtors_aux>:
    1500:	f3 0f 1e fa          	endbr64 
    1504:	80 3d 0d 3b 00 00 00 	cmpb   $0x0,0x3b0d(%rip)        # 5018 <completed.8061>
    150b:	75 2b                	jne    1538 <__do_global_dtors_aux+0x38>
    150d:	55                   	push   %rbp
    150e:	48 83 3d ba 3a 00 00 	cmpq   $0x0,0x3aba(%rip)        # 4fd0 <__cxa_finalize@GLIBC_2.2.5>
    1515:	00 
    1516:	48 89 e5             	mov    %rsp,%rbp
    1519:	74 0c                	je     1527 <__do_global_dtors_aux+0x27>
    151b:	48 8b 3d e6 3a 00 00 	mov    0x3ae6(%rip),%rdi        # 5008 <__dso_handle>
    1522:	e8 19 fd ff ff       	callq  1240 <__cxa_finalize@plt>
    1527:	e8 64 ff ff ff       	callq  1490 <deregister_tm_clones>
    152c:	c6 05 e5 3a 00 00 01 	movb   $0x1,0x3ae5(%rip)        # 5018 <completed.8061>
    1533:	5d                   	pop    %rbp
    1534:	c3                   	retq   
    1535:	0f 1f 00             	nopl   (%rax)
    1538:	c3                   	retq   
    1539:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001540 <frame_dummy>:
    1540:	f3 0f 1e fa          	endbr64 
    1544:	e9 77 ff ff ff       	jmpq   14c0 <register_tm_clones>

0000000000001549 <main>:
    1549:	f3 0f 1e fa          	endbr64 
    154d:	55                   	push   %rbp
    154e:	48 89 e5             	mov    %rsp,%rbp
    1551:	48 81 ec 40 01 00 00 	sub    $0x140,%rsp
    1558:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    155f:	00 00 
    1561:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1565:	31 c0                	xor    %eax,%eax
    1567:	bf 00 00 00 00       	mov    $0x0,%edi
    156c:	e8 9f fd ff ff       	callq  1310 <time@plt>
    1571:	89 c7                	mov    %eax,%edi
    1573:	e8 b8 fd ff ff       	callq  1330 <srand@plt>
    1578:	c7 85 dc fe ff ff 00 	movl   $0x0,-0x124(%rbp)
    157f:	00 00 00 
    1582:	c7 85 e0 fe ff ff 00 	movl   $0x0,-0x120(%rbp)
    1589:	00 00 00 
    158c:	c7 85 c8 fe ff ff 00 	movl   $0x0,-0x138(%rbp)
    1593:	00 00 00 
    1596:	c7 85 e4 fe ff ff 00 	movl   $0x0,-0x11c(%rbp)
    159d:	00 00 00 
    15a0:	c7 85 e8 fe ff ff ff 	movl   $0xffffffff,-0x118(%rbp)
    15a7:	ff ff ff 
    15aa:	c7 85 fc fe ff ff b0 	movl   $0x1adb0,-0x104(%rbp)
    15b1:	ad 01 00 
    15b4:	c6 85 c7 fe ff ff 40 	movb   $0x40,-0x139(%rbp)
    15bb:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    15bf:	48 8d 85 c8 fe ff ff 	lea    -0x138(%rbp),%rax
    15c6:	48 89 d6             	mov    %rdx,%rsi
    15c9:	48 89 c7             	mov    %rax,%rdi
    15cc:	e8 5f 14 00 00       	callq  2a30 <_Z8readBestPiPc>
    15d1:	e8 1a fe ff ff       	callq  13f0 <initscr@plt>
    15d6:	bf 00 00 00 00       	mov    $0x0,%edi
    15db:	e8 10 fd ff ff       	callq  12f0 <curs_set@plt>
    15e0:	48 8b 05 29 3a 00 00 	mov    0x3a29(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    15e7:	be 01 00 00 00       	mov    $0x1,%esi
    15ec:	48 89 c7             	mov    %rax,%rdi
    15ef:	e8 bc fc ff ff       	callq  12b0 <keypad@plt>
    15f4:	e8 77 fc ff ff       	callq  1270 <start_color@plt>
    15f9:	e8 82 fc ff ff       	callq  1280 <rand@plt>
    15fe:	99                   	cltd   
    15ff:	c1 ea 1f             	shr    $0x1f,%edx
    1602:	01 d0                	add    %edx,%eax
    1604:	83 e0 01             	and    $0x1,%eax
    1607:	29 d0                	sub    %edx,%eax
    1609:	89 85 04 ff ff ff    	mov    %eax,-0xfc(%rbp)
    160f:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    1616:	75 11                	jne    1629 <main+0xe0>
    1618:	be 06 00 00 00       	mov    $0x6,%esi
    161d:	bf 00 00 00 00       	mov    $0x0,%edi
    1622:	e8 99 fc ff ff       	callq  12c0 <assume_default_colors@plt>
    1627:	eb 0f                	jmp    1638 <main+0xef>
    1629:	be 00 00 00 00       	mov    $0x0,%esi
    162e:	bf 07 00 00 00       	mov    $0x7,%edi
    1633:	e8 88 fc ff ff       	callq  12c0 <assume_default_colors@plt>
    1638:	ba 02 00 00 00       	mov    $0x2,%edx
    163d:	be 00 00 00 00       	mov    $0x0,%esi
    1642:	bf 01 00 00 00       	mov    $0x1,%edi
    1647:	e8 14 fc ff ff       	callq  1260 <init_pair@plt>
    164c:	e8 2f fc ff ff       	callq  1280 <rand@plt>
    1651:	89 c2                	mov    %eax,%edx
    1653:	48 63 c2             	movslq %edx,%rax
    1656:	48 69 c0 56 55 55 55 	imul   $0x55555556,%rax,%rax
    165d:	48 c1 e8 20          	shr    $0x20,%rax
    1661:	48 89 c1             	mov    %rax,%rcx
    1664:	89 d0                	mov    %edx,%eax
    1666:	c1 f8 1f             	sar    $0x1f,%eax
    1669:	29 c1                	sub    %eax,%ecx
    166b:	89 c8                	mov    %ecx,%eax
    166d:	89 85 08 ff ff ff    	mov    %eax,-0xf8(%rbp)
    1673:	8b 8d 08 ff ff ff    	mov    -0xf8(%rbp),%ecx
    1679:	89 c8                	mov    %ecx,%eax
    167b:	01 c0                	add    %eax,%eax
    167d:	01 c8                	add    %ecx,%eax
    167f:	29 c2                	sub    %eax,%edx
    1681:	89 d0                	mov    %edx,%eax
    1683:	89 85 08 ff ff ff    	mov    %eax,-0xf8(%rbp)
    1689:	83 bd 08 ff ff ff 00 	cmpl   $0x0,-0xf8(%rbp)
    1690:	75 4f                	jne    16e1 <main+0x198>
    1692:	ba 03 00 00 00       	mov    $0x3,%edx
    1697:	be 00 00 00 00       	mov    $0x0,%esi
    169c:	bf 02 00 00 00       	mov    $0x2,%edi
    16a1:	e8 ba fb ff ff       	callq  1260 <init_pair@plt>
    16a6:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    16ad:	75 19                	jne    16c8 <main+0x17f>
    16af:	ba 06 00 00 00       	mov    $0x6,%edx
    16b4:	be 03 00 00 00       	mov    $0x3,%esi
    16b9:	bf 07 00 00 00       	mov    $0x7,%edi
    16be:	e8 9d fb ff ff       	callq  1260 <init_pair@plt>
    16c3:	e9 bb 00 00 00       	jmpq   1783 <main+0x23a>
    16c8:	ba 00 00 00 00       	mov    $0x0,%edx
    16cd:	be 03 00 00 00       	mov    $0x3,%esi
    16d2:	bf 07 00 00 00       	mov    $0x7,%edi
    16d7:	e8 84 fb ff ff       	callq  1260 <init_pair@plt>
    16dc:	e9 a2 00 00 00       	jmpq   1783 <main+0x23a>
    16e1:	83 bd 08 ff ff ff 01 	cmpl   $0x1,-0xf8(%rbp)
    16e8:	75 49                	jne    1733 <main+0x1ea>
    16ea:	ba 01 00 00 00       	mov    $0x1,%edx
    16ef:	be 00 00 00 00       	mov    $0x0,%esi
    16f4:	bf 02 00 00 00       	mov    $0x2,%edi
    16f9:	e8 62 fb ff ff       	callq  1260 <init_pair@plt>
    16fe:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    1705:	75 16                	jne    171d <main+0x1d4>
    1707:	ba 06 00 00 00       	mov    $0x6,%edx
    170c:	be 01 00 00 00       	mov    $0x1,%esi
    1711:	bf 07 00 00 00       	mov    $0x7,%edi
    1716:	e8 45 fb ff ff       	callq  1260 <init_pair@plt>
    171b:	eb 66                	jmp    1783 <main+0x23a>
    171d:	ba 00 00 00 00       	mov    $0x0,%edx
    1722:	be 01 00 00 00       	mov    $0x1,%esi
    1727:	bf 07 00 00 00       	mov    $0x7,%edi
    172c:	e8 2f fb ff ff       	callq  1260 <init_pair@plt>
    1731:	eb 50                	jmp    1783 <main+0x23a>
    1733:	83 bd 08 ff ff ff 02 	cmpl   $0x2,-0xf8(%rbp)
    173a:	75 47                	jne    1783 <main+0x23a>
    173c:	ba 04 00 00 00       	mov    $0x4,%edx
    1741:	be 00 00 00 00       	mov    $0x0,%esi
    1746:	bf 02 00 00 00       	mov    $0x2,%edi
    174b:	e8 10 fb ff ff       	callq  1260 <init_pair@plt>
    1750:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    1757:	75 16                	jne    176f <main+0x226>
    1759:	ba 06 00 00 00       	mov    $0x6,%edx
    175e:	be 04 00 00 00       	mov    $0x4,%esi
    1763:	bf 07 00 00 00       	mov    $0x7,%edi
    1768:	e8 f3 fa ff ff       	callq  1260 <init_pair@plt>
    176d:	eb 14                	jmp    1783 <main+0x23a>
    176f:	ba 00 00 00 00       	mov    $0x0,%edx
    1774:	be 04 00 00 00       	mov    $0x4,%esi
    1779:	bf 07 00 00 00       	mov    $0x7,%edi
    177e:	e8 dd fa ff ff       	callq  1260 <init_pair@plt>
    1783:	ba 03 00 00 00       	mov    $0x3,%edx
    1788:	be 03 00 00 00       	mov    $0x3,%esi
    178d:	bf 03 00 00 00       	mov    $0x3,%edi
    1792:	e8 c9 fa ff ff       	callq  1260 <init_pair@plt>
    1797:	ba 07 00 00 00       	mov    $0x7,%edx
    179c:	be 00 00 00 00       	mov    $0x0,%esi
    17a1:	bf 04 00 00 00       	mov    $0x4,%edi
    17a6:	e8 b5 fa ff ff       	callq  1260 <init_pair@plt>
    17ab:	ba 01 00 00 00       	mov    $0x1,%edx
    17b0:	be 07 00 00 00       	mov    $0x7,%esi
    17b5:	bf 05 00 00 00       	mov    $0x5,%edi
    17ba:	e8 a1 fa ff ff       	callq  1260 <init_pair@plt>
    17bf:	ba 02 00 00 00       	mov    $0x2,%edx
    17c4:	be 07 00 00 00       	mov    $0x7,%esi
    17c9:	bf 06 00 00 00       	mov    $0x6,%edi
    17ce:	e8 8d fa ff ff       	callq  1260 <init_pair@plt>
    17d3:	48 8b 05 36 38 00 00 	mov    0x3836(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    17da:	48 85 c0             	test   %rax,%rax
    17dd:	74 11                	je     17f0 <main+0x2a7>
    17df:	48 8b 05 2a 38 00 00 	mov    0x382a(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    17e6:	0f b7 40 04          	movzwl 0x4(%rax),%eax
    17ea:	98                   	cwtl   
    17eb:	83 c0 01             	add    $0x1,%eax
    17ee:	eb 05                	jmp    17f5 <main+0x2ac>
    17f0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    17f5:	89 85 0c ff ff ff    	mov    %eax,-0xf4(%rbp)
    17fb:	48 8b 05 0e 38 00 00 	mov    0x380e(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1802:	48 85 c0             	test   %rax,%rax
    1805:	74 11                	je     1818 <main+0x2cf>
    1807:	48 8b 05 02 38 00 00 	mov    0x3802(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    180e:	0f b7 40 06          	movzwl 0x6(%rax),%eax
    1812:	98                   	cwtl   
    1813:	83 c0 01             	add    $0x1,%eax
    1816:	eb 05                	jmp    181d <main+0x2d4>
    1818:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    181d:	89 85 10 ff ff ff    	mov    %eax,-0xf0(%rbp)
    1823:	83 bd 0c ff ff ff 17 	cmpl   $0x17,-0xf4(%rbp)
    182a:	7e 09                	jle    1835 <main+0x2ec>
    182c:	83 bd 10 ff ff ff 4a 	cmpl   $0x4a,-0xf0(%rbp)
    1833:	7f 0a                	jg     183f <main+0x2f6>
    1835:	c7 85 fc fe ff ff e0 	movl   $0x222e0,-0x104(%rbp)
    183c:	22 02 00 
    183f:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    1845:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    184b:	89 d6                	mov    %edx,%esi
    184d:	89 c7                	mov    %eax,%edi
    184f:	e8 08 09 00 00       	callq  215c <_Z9writeInfoii>
    1854:	48 8b 05 b5 37 00 00 	mov    0x37b5(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    185b:	48 8d 8d 20 ff ff ff 	lea    -0xe0(%rbp),%rcx
    1862:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    1867:	48 89 ce             	mov    %rcx,%rsi
    186a:	48 89 c7             	mov    %rax,%rdi
    186d:	e8 8e fb ff ff       	callq  1400 <wgetnstr@plt>
    1872:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    1878:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    187e:	89 d6                	mov    %edx,%esi
    1880:	89 c7                	mov    %eax,%edi
    1882:	e8 0b 0f 00 00       	callq  2792 <_Z12drawStartingii>
    1887:	e8 a4 fb ff ff       	callq  1430 <refresh@plt>
    188c:	e8 df fa ff ff       	callq  1370 <noecho@plt>
    1891:	48 8b 05 78 37 00 00 	mov    0x3778(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1898:	be 01 00 00 00       	mov    $0x1,%esi
    189d:	48 89 c7             	mov    %rax,%rdi
    18a0:	e8 db fa ff ff       	callq  1380 <wtimeout@plt>
    18a5:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    18ab:	89 c2                	mov    %eax,%edx
    18ad:	c1 ea 1f             	shr    $0x1f,%edx
    18b0:	01 d0                	add    %edx,%eax
    18b2:	d1 f8                	sar    %eax
    18b4:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
    18ba:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18c0:	8d 50 03             	lea    0x3(%rax),%edx
    18c3:	85 c0                	test   %eax,%eax
    18c5:	0f 48 c2             	cmovs  %edx,%eax
    18c8:	c1 f8 02             	sar    $0x2,%eax
    18cb:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    18d1:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18d7:	89 85 f0 fe ff ff    	mov    %eax,-0x110(%rbp)
    18dd:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18e3:	89 85 f4 fe ff ff    	mov    %eax,-0x10c(%rbp)
    18e9:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18ef:	89 85 f8 fe ff ff    	mov    %eax,-0x108(%rbp)
    18f5:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    18fb:	48 8d 8d d0 fe ff ff 	lea    -0x130(%rbp),%rcx
    1902:	48 8d 85 cc fe ff ff 	lea    -0x134(%rbp),%rax
    1909:	48 89 ce             	mov    %rcx,%rsi
    190c:	48 89 c7             	mov    %rax,%rdi
    190f:	e8 0a 12 00 00       	callq  2b1e <_Z15getNewPipeValuePiS_i>
    1914:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    191a:	48 8d 8d d8 fe ff ff 	lea    -0x128(%rbp),%rcx
    1921:	48 8d 85 d4 fe ff ff 	lea    -0x12c(%rbp),%rax
    1928:	48 89 ce             	mov    %rcx,%rsi
    192b:	48 89 c7             	mov    %rax,%rdi
    192e:	e8 eb 11 00 00       	callq  2b1e <_Z15getNewPipeValuePiS_i>
    1933:	83 bd e4 fe ff ff 00 	cmpl   $0x0,-0x11c(%rbp)
    193a:	0f 85 3c 05 00 00    	jne    1e7c <main+0x933>
    1940:	e8 fb fa ff ff       	callq  1440 <clear@plt>
    1945:	48 8b 05 c4 36 00 00 	mov    0x36c4(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    194c:	8b 95 14 ff ff ff    	mov    -0xec(%rbp),%edx
    1952:	8b 8d ec fe ff ff    	mov    -0x114(%rbp),%ecx
    1958:	89 ce                	mov    %ecx,%esi
    195a:	48 89 c7             	mov    %rax,%rdi
    195d:	e8 ee f9 ff ff       	callq  1350 <wmove@plt>
    1962:	83 f8 ff             	cmp    $0xffffffff,%eax
    1965:	74 1d                	je     1984 <main+0x43b>
    1967:	0f be 85 c7 fe ff ff 	movsbl -0x139(%rbp),%eax
    196e:	80 cc 02             	or     $0x2,%ah
    1971:	89 c2                	mov    %eax,%edx
    1973:	48 8b 05 96 36 00 00 	mov    0x3696(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    197a:	89 d6                	mov    %edx,%esi
    197c:	48 89 c7             	mov    %rax,%rdi
    197f:	e8 0c f9 ff ff       	callq  1290 <waddch@plt>
    1984:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    198a:	83 e0 07             	and    $0x7,%eax
    198d:	85 c0                	test   %eax,%eax
    198f:	75 3d                	jne    19ce <main+0x485>
    1991:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1997:	8d 50 07             	lea    0x7(%rax),%edx
    199a:	85 c0                	test   %eax,%eax
    199c:	0f 48 c2             	cmovs  %edx,%eax
    199f:	c1 f8 03             	sar    $0x3,%eax
    19a2:	89 c1                	mov    %eax,%ecx
    19a4:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    19aa:	89 c2                	mov    %eax,%edx
    19ac:	c1 ea 1f             	shr    $0x1f,%edx
    19af:	01 d0                	add    %edx,%eax
    19b1:	d1 f8                	sar    %eax
    19b3:	83 e8 14             	sub    $0x14,%eax
    19b6:	48 8d 15 4c 16 00 00 	lea    0x164c(%rip),%rdx        # 3009 <_ZStL19piecewise_construct+0x1>
    19bd:	89 c6                	mov    %eax,%esi
    19bf:	bf 01 00 00 00       	mov    $0x1,%edi
    19c4:	b8 00 00 00 00       	mov    $0x0,%eax
    19c9:	e8 f2 f9 ff ff       	callq  13c0 <mvprintw@plt>
    19ce:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    19d4:	89 c2                	mov    %eax,%edx
    19d6:	c1 ea 1f             	shr    $0x1f,%edx
    19d9:	01 d0                	add    %edx,%eax
    19db:	d1 f8                	sar    %eax
    19dd:	8d 70 ec             	lea    -0x14(%rax),%esi
    19e0:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    19e7:	48 89 c1             	mov    %rax,%rcx
    19ea:	48 8d 15 23 16 00 00 	lea    0x1623(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    19f1:	bf 00 00 00 00       	mov    $0x0,%edi
    19f6:	b8 00 00 00 00       	mov    $0x0,%eax
    19fb:	e8 c0 f9 ff ff       	callq  13c0 <mvprintw@plt>
    1a00:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1a06:	89 c2                	mov    %eax,%edx
    1a08:	c1 ea 1f             	shr    $0x1f,%edx
    1a0b:	01 d0                	add    %edx,%eax
    1a0d:	d1 f8                	sar    %eax
    1a0f:	8d 70 0d             	lea    0xd(%rax),%esi
    1a12:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    1a16:	48 89 c1             	mov    %rax,%rcx
    1a19:	48 8d 15 f4 15 00 00 	lea    0x15f4(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    1a20:	bf 00 00 00 00       	mov    $0x0,%edi
    1a25:	b8 00 00 00 00       	mov    $0x0,%eax
    1a2a:	e8 91 f9 ff ff       	callq  13c0 <mvprintw@plt>
    1a2f:	8b 95 c8 fe ff ff    	mov    -0x138(%rbp),%edx
    1a35:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1a3b:	89 c1                	mov    %eax,%ecx
    1a3d:	c1 e9 1f             	shr    $0x1f,%ecx
    1a40:	01 c8                	add    %ecx,%eax
    1a42:	d1 f8                	sar    %eax
    1a44:	83 c0 0d             	add    $0xd,%eax
    1a47:	89 d1                	mov    %edx,%ecx
    1a49:	48 8d 15 c7 15 00 00 	lea    0x15c7(%rip),%rdx        # 3017 <_ZStL19piecewise_construct+0xf>
    1a50:	89 c6                	mov    %eax,%esi
    1a52:	bf 01 00 00 00       	mov    $0x1,%edi
    1a57:	b8 00 00 00 00       	mov    $0x0,%eax
    1a5c:	e8 5f f9 ff ff       	callq  13c0 <mvprintw@plt>
    1a61:	48 8b 05 a8 35 00 00 	mov    0x35a8(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1a68:	ba 00 00 00 00       	mov    $0x0,%edx
    1a6d:	be 00 01 00 00       	mov    $0x100,%esi
    1a72:	48 89 c7             	mov    %rax,%rdi
    1a75:	e8 56 f8 ff ff       	callq  12d0 <wattr_on@plt>
    1a7a:	8b b5 d0 fe ff ff    	mov    -0x130(%rbp),%esi
    1a80:	8b 85 cc fe ff ff    	mov    -0x134(%rbp),%eax
    1a86:	8b 8d 0c ff ff ff    	mov    -0xf4(%rbp),%ecx
    1a8c:	8b 95 f0 fe ff ff    	mov    -0x110(%rbp),%edx
    1a92:	89 c7                	mov    %eax,%edi
    1a94:	e8 bc 0b 00 00       	callq  2655 <_Z8drawPipeiiii>
    1a99:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1a9f:	89 c2                	mov    %eax,%edx
    1aa1:	c1 ea 1f             	shr    $0x1f,%edx
    1aa4:	01 d0                	add    %edx,%eax
    1aa6:	d1 f8                	sar    %eax
    1aa8:	39 85 f8 fe ff ff    	cmp    %eax,-0x108(%rbp)
    1aae:	7d 26                	jge    1ad6 <main+0x58d>
    1ab0:	8b b5 d8 fe ff ff    	mov    -0x128(%rbp),%esi
    1ab6:	8b 85 d4 fe ff ff    	mov    -0x12c(%rbp),%eax
    1abc:	8b 8d 0c ff ff ff    	mov    -0xf4(%rbp),%ecx
    1ac2:	8b 95 f4 fe ff ff    	mov    -0x10c(%rbp),%edx
    1ac8:	89 c7                	mov    %eax,%edi
    1aca:	e8 86 0b 00 00       	callq  2655 <_Z8drawPipeiiii>
    1acf:	83 ad f4 fe ff ff 01 	subl   $0x1,-0x10c(%rbp)
    1ad6:	83 ad f0 fe ff ff 01 	subl   $0x1,-0x110(%rbp)
    1add:	48 8b 05 2c 35 00 00 	mov    0x352c(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1ae4:	ba 00 00 00 00       	mov    $0x0,%edx
    1ae9:	be 00 01 00 00       	mov    $0x100,%esi
    1aee:	48 89 c7             	mov    %rax,%rdi
    1af1:	e8 ba f8 ff ff       	callq  13b0 <wattr_off@plt>
    1af6:	c7 85 00 ff ff ff 00 	movl   $0x0,-0x100(%rbp)
    1afd:	00 00 00 
    1b00:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b06:	3b 85 10 ff ff ff    	cmp    -0xf0(%rbp),%eax
    1b0c:	0f 8d dc 00 00 00    	jge    1bee <main+0x6a5>
    1b12:	48 8b 05 f7 34 00 00 	mov    0x34f7(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1b19:	ba 00 00 00 00       	mov    $0x0,%edx
    1b1e:	be 00 03 00 00       	mov    $0x300,%esi
    1b23:	48 89 c7             	mov    %rax,%rdi
    1b26:	e8 a5 f7 ff ff       	callq  12d0 <wattr_on@plt>
    1b2b:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1b31:	8d 48 ff             	lea    -0x1(%rax),%ecx
    1b34:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b3a:	48 8d 15 e0 14 00 00 	lea    0x14e0(%rip),%rdx        # 3021 <_ZStL19piecewise_construct+0x19>
    1b41:	89 c6                	mov    %eax,%esi
    1b43:	89 cf                	mov    %ecx,%edi
    1b45:	b8 00 00 00 00       	mov    $0x0,%eax
    1b4a:	e8 71 f8 ff ff       	callq  13c0 <mvprintw@plt>
    1b4f:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1b55:	8d 48 fe             	lea    -0x2(%rax),%ecx
    1b58:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b5e:	48 8d 15 bc 14 00 00 	lea    0x14bc(%rip),%rdx        # 3021 <_ZStL19piecewise_construct+0x19>
    1b65:	89 c6                	mov    %eax,%esi
    1b67:	89 cf                	mov    %ecx,%edi
    1b69:	b8 00 00 00 00       	mov    $0x0,%eax
    1b6e:	e8 4d f8 ff ff       	callq  13c0 <mvprintw@plt>
    1b73:	48 8b 05 96 34 00 00 	mov    0x3496(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1b7a:	ba 00 00 00 00       	mov    $0x0,%edx
    1b7f:	be 00 03 00 00       	mov    $0x300,%esi
    1b84:	48 89 c7             	mov    %rax,%rdi
    1b87:	e8 24 f8 ff ff       	callq  13b0 <wattr_off@plt>
    1b8c:	48 8b 05 7d 34 00 00 	mov    0x347d(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1b93:	ba 00 00 00 00       	mov    $0x0,%edx
    1b98:	be 00 06 00 00       	mov    $0x600,%esi
    1b9d:	48 89 c7             	mov    %rax,%rdi
    1ba0:	e8 2b f7 ff ff       	callq  12d0 <wattr_on@plt>
    1ba5:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1bab:	8d 48 fd             	lea    -0x3(%rax),%ecx
    1bae:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1bb4:	48 8d 15 68 14 00 00 	lea    0x1468(%rip),%rdx        # 3023 <_ZStL19piecewise_construct+0x1b>
    1bbb:	89 c6                	mov    %eax,%esi
    1bbd:	89 cf                	mov    %ecx,%edi
    1bbf:	b8 00 00 00 00       	mov    $0x0,%eax
    1bc4:	e8 f7 f7 ff ff       	callq  13c0 <mvprintw@plt>
    1bc9:	48 8b 05 40 34 00 00 	mov    0x3440(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1bd0:	ba 00 00 00 00       	mov    $0x0,%edx
    1bd5:	be 00 06 00 00       	mov    $0x600,%esi
    1bda:	48 89 c7             	mov    %rax,%rdi
    1bdd:	e8 ce f7 ff ff       	callq  13b0 <wattr_off@plt>
    1be2:	83 85 00 ff ff ff 01 	addl   $0x1,-0x100(%rbp)
    1be9:	e9 12 ff ff ff       	jmpq   1b00 <main+0x5b7>
    1bee:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1bf4:	83 e8 01             	sub    $0x1,%eax
    1bf7:	39 85 ec fe ff ff    	cmp    %eax,-0x114(%rbp)
    1bfd:	7d 07                	jge    1c06 <main+0x6bd>
    1bff:	83 85 ec fe ff ff 01 	addl   $0x1,-0x114(%rbp)
    1c06:	48 8b 05 03 34 00 00 	mov    0x3403(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1c0d:	48 89 c7             	mov    %rax,%rdi
    1c10:	e8 8b f6 ff ff       	callq  12a0 <wgetch@plt>
    1c15:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    1c1b:	83 bd 18 ff ff ff 20 	cmpl   $0x20,-0xe8(%rbp)
    1c22:	75 10                	jne    1c34 <main+0x6eb>
    1c24:	83 85 e8 fe ff ff 01 	addl   $0x1,-0x118(%rbp)
    1c2b:	83 ad ec fe ff ff 04 	subl   $0x4,-0x114(%rbp)
    1c32:	eb 16                	jmp    1c4a <main+0x701>
    1c34:	81 bd 18 ff ff ff 0d 	cmpl   $0x10d,-0xe8(%rbp)
    1c3b:	01 00 00 
    1c3e:	75 0a                	jne    1c4a <main+0x701>
    1c40:	81 ad fc fe ff ff 10 	subl   $0x2710,-0x104(%rbp)
    1c47:	27 00 00 
    1c4a:	83 bd ec fe ff ff 01 	cmpl   $0x1,-0x114(%rbp)
    1c51:	7f 0a                	jg     1c5d <main+0x714>
    1c53:	c7 85 ec fe ff ff 02 	movl   $0x2,-0x114(%rbp)
    1c5a:	00 00 00 
    1c5d:	8b bd d0 fe ff ff    	mov    -0x130(%rbp),%edi
    1c63:	8b 8d cc fe ff ff    	mov    -0x134(%rbp),%ecx
    1c69:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
    1c6f:	8b b5 14 ff ff ff    	mov    -0xec(%rbp),%esi
    1c75:	8b 85 f0 fe ff ff    	mov    -0x110(%rbp),%eax
    1c7b:	41 89 f8             	mov    %edi,%r8d
    1c7e:	89 c7                	mov    %eax,%edi
    1c80:	e8 3c 09 00 00       	callq  25c1 <_Z16controlCollisioniiiii>
    1c85:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    1c8b:	be 12 12 12 12       	mov    $0x12121212,%esi
    1c90:	48 8d 3d 8e 13 00 00 	lea    0x138e(%rip),%rdi        # 3025 <_ZStL19piecewise_construct+0x1d>
    1c97:	b8 00 00 00 00       	mov    $0x0,%eax
    1c9c:	e8 af f5 ff ff       	callq  1250 <printf@plt>
    1ca1:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    1ca8:	74 6f                	je     1d19 <main+0x7d0>
    1caa:	83 bd 1c ff ff ff 02 	cmpl   $0x2,-0xe4(%rbp)
    1cb1:	75 0c                	jne    1cbf <main+0x776>
    1cb3:	c7 85 e4 fe ff ff 01 	movl   $0x1,-0x11c(%rbp)
    1cba:	00 00 00 
    1cbd:	eb 5a                	jmp    1d19 <main+0x7d0>
    1cbf:	83 bd e0 fe ff ff 00 	cmpl   $0x0,-0x120(%rbp)
    1cc6:	74 51                	je     1d19 <main+0x7d0>
    1cc8:	83 85 dc fe ff ff 01 	addl   $0x1,-0x124(%rbp)
    1ccf:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1cd5:	8d 50 07             	lea    0x7(%rax),%edx
    1cd8:	85 c0                	test   %eax,%eax
    1cda:	0f 48 c2             	cmovs  %edx,%eax
    1cdd:	c1 f8 03             	sar    $0x3,%eax
    1ce0:	89 c2                	mov    %eax,%edx
    1ce2:	8b 85 c8 fe ff ff    	mov    -0x138(%rbp),%eax
    1ce8:	39 c2                	cmp    %eax,%edx
    1cea:	7e 2d                	jle    1d19 <main+0x7d0>
    1cec:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1cf2:	8d 50 07             	lea    0x7(%rax),%edx
    1cf5:	85 c0                	test   %eax,%eax
    1cf7:	0f 48 c2             	cmovs  %edx,%eax
    1cfa:	c1 f8 03             	sar    $0x3,%eax
    1cfd:	89 85 c8 fe ff ff    	mov    %eax,-0x138(%rbp)
    1d03:	48 8d 95 20 ff ff ff 	lea    -0xe0(%rbp),%rdx
    1d0a:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    1d0e:	48 89 d6             	mov    %rdx,%rsi
    1d11:	48 89 c7             	mov    %rax,%rdi
    1d14:	e8 07 f6 ff ff       	callq  1320 <strcpy@plt>
    1d19:	8b bd d8 fe ff ff    	mov    -0x128(%rbp),%edi
    1d1f:	8b 8d d4 fe ff ff    	mov    -0x12c(%rbp),%ecx
    1d25:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
    1d2b:	8b b5 14 ff ff ff    	mov    -0xec(%rbp),%esi
    1d31:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    1d37:	41 89 f8             	mov    %edi,%r8d
    1d3a:	89 c7                	mov    %eax,%edi
    1d3c:	e8 80 08 00 00       	callq  25c1 <_Z16controlCollisioniiiii>
    1d41:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    1d47:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    1d4e:	74 6f                	je     1dbf <main+0x876>
    1d50:	83 bd 1c ff ff ff 02 	cmpl   $0x2,-0xe4(%rbp)
    1d57:	75 0c                	jne    1d65 <main+0x81c>
    1d59:	c7 85 e4 fe ff ff 01 	movl   $0x1,-0x11c(%rbp)
    1d60:	00 00 00 
    1d63:	eb 5a                	jmp    1dbf <main+0x876>
    1d65:	83 bd e0 fe ff ff 00 	cmpl   $0x0,-0x120(%rbp)
    1d6c:	74 51                	je     1dbf <main+0x876>
    1d6e:	83 85 dc fe ff ff 01 	addl   $0x1,-0x124(%rbp)
    1d75:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1d7b:	8d 50 07             	lea    0x7(%rax),%edx
    1d7e:	85 c0                	test   %eax,%eax
    1d80:	0f 48 c2             	cmovs  %edx,%eax
    1d83:	c1 f8 03             	sar    $0x3,%eax
    1d86:	89 c2                	mov    %eax,%edx
    1d88:	8b 85 c8 fe ff ff    	mov    -0x138(%rbp),%eax
    1d8e:	39 c2                	cmp    %eax,%edx
    1d90:	7e 2d                	jle    1dbf <main+0x876>
    1d92:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1d98:	8d 50 07             	lea    0x7(%rax),%edx
    1d9b:	85 c0                	test   %eax,%eax
    1d9d:	0f 48 c2             	cmovs  %edx,%eax
    1da0:	c1 f8 03             	sar    $0x3,%eax
    1da3:	89 85 c8 fe ff ff    	mov    %eax,-0x138(%rbp)
    1da9:	48 8d 95 20 ff ff ff 	lea    -0xe0(%rbp),%rdx
    1db0:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    1db4:	48 89 d6             	mov    %rdx,%rsi
    1db7:	48 89 c7             	mov    %rax,%rdi
    1dba:	e8 61 f5 ff ff       	callq  1320 <strcpy@plt>
    1dbf:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1dc5:	83 e8 03             	sub    $0x3,%eax
    1dc8:	39 85 ec fe ff ff    	cmp    %eax,-0x114(%rbp)
    1dce:	7c 0a                	jl     1dda <main+0x891>
    1dd0:	c7 85 e4 fe ff ff 01 	movl   $0x1,-0x11c(%rbp)
    1dd7:	00 00 00 
    1dda:	83 bd f0 fe ff ff 00 	cmpl   $0x0,-0x110(%rbp)
    1de1:	75 2b                	jne    1e0e <main+0x8c5>
    1de3:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    1de9:	48 8d 8d d0 fe ff ff 	lea    -0x130(%rbp),%rcx
    1df0:	48 8d 85 cc fe ff ff 	lea    -0x134(%rbp),%rax
    1df7:	48 89 ce             	mov    %rcx,%rsi
    1dfa:	48 89 c7             	mov    %rax,%rdi
    1dfd:	e8 1c 0d 00 00       	callq  2b1e <_Z15getNewPipeValuePiS_i>
    1e02:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1e08:	89 85 f0 fe ff ff    	mov    %eax,-0x110(%rbp)
    1e0e:	83 bd f4 fe ff ff 00 	cmpl   $0x0,-0x10c(%rbp)
    1e15:	75 40                	jne    1e57 <main+0x90e>
    1e17:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    1e1d:	48 8d 8d d8 fe ff ff 	lea    -0x128(%rbp),%rcx
    1e24:	48 8d 85 d4 fe ff ff 	lea    -0x12c(%rbp),%rax
    1e2b:	48 89 ce             	mov    %rcx,%rsi
    1e2e:	48 89 c7             	mov    %rax,%rdi
    1e31:	e8 e8 0c 00 00       	callq  2b1e <_Z15getNewPipeValuePiS_i>
    1e36:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1e3c:	89 85 f4 fe ff ff    	mov    %eax,-0x10c(%rbp)
    1e42:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1e48:	89 c2                	mov    %eax,%edx
    1e4a:	c1 ea 1f             	shr    $0x1f,%edx
    1e4d:	01 d0                	add    %edx,%eax
    1e4f:	d1 f8                	sar    %eax
    1e51:	89 85 f8 fe ff ff    	mov    %eax,-0x108(%rbp)
    1e57:	83 85 e0 fe ff ff 01 	addl   $0x1,-0x120(%rbp)
    1e5e:	83 ad f8 fe ff ff 01 	subl   $0x1,-0x108(%rbp)
    1e65:	e8 c6 f5 ff ff       	callq  1430 <refresh@plt>
    1e6a:	8b 85 fc fe ff ff    	mov    -0x104(%rbp),%eax
    1e70:	89 c7                	mov    %eax,%edi
    1e72:	e8 69 f5 ff ff       	callq  13e0 <usleep@plt>
    1e77:	e9 b7 fa ff ff       	jmpq   1933 <main+0x3ea>
    1e7c:	8b 85 c8 fe ff ff    	mov    -0x138(%rbp),%eax
    1e82:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    1e86:	48 89 d6             	mov    %rdx,%rsi
    1e89:	89 c7                	mov    %eax,%edi
    1e8b:	e8 1b 0c 00 00       	callq  2aab <_Z9writeBestiPKc>
    1e90:	e8 ab f5 ff ff       	callq  1440 <clear@plt>
    1e95:	48 8b 05 74 31 00 00 	mov    0x3174(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1e9c:	ba 00 00 00 00       	mov    $0x0,%edx
    1ea1:	be 00 05 20 00       	mov    $0x200500,%esi
    1ea6:	48 89 c7             	mov    %rax,%rdi
    1ea9:	e8 22 f4 ff ff       	callq  12d0 <wattr_on@plt>
    1eae:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1eb4:	83 e8 33             	sub    $0x33,%eax
    1eb7:	89 c2                	mov    %eax,%edx
    1eb9:	c1 ea 1f             	shr    $0x1f,%edx
    1ebc:	01 d0                	add    %edx,%eax
    1ebe:	d1 f8                	sar    %eax
    1ec0:	89 c1                	mov    %eax,%ecx
    1ec2:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1ec8:	89 c2                	mov    %eax,%edx
    1eca:	c1 ea 1f             	shr    $0x1f,%edx
    1ecd:	01 d0                	add    %edx,%eax
    1ecf:	d1 f8                	sar    %eax
    1ed1:	83 e8 0a             	sub    $0xa,%eax
    1ed4:	48 8d 15 55 11 00 00 	lea    0x1155(%rip),%rdx        # 3030 <_ZStL19piecewise_construct+0x28>
    1edb:	89 ce                	mov    %ecx,%esi
    1edd:	89 c7                	mov    %eax,%edi
    1edf:	b8 00 00 00 00       	mov    $0x0,%eax
    1ee4:	e8 d7 f4 ff ff       	callq  13c0 <mvprintw@plt>
    1ee9:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1eef:	83 e8 33             	sub    $0x33,%eax
    1ef2:	89 c2                	mov    %eax,%edx
    1ef4:	c1 ea 1f             	shr    $0x1f,%edx
    1ef7:	01 d0                	add    %edx,%eax
    1ef9:	d1 f8                	sar    %eax
    1efb:	89 c1                	mov    %eax,%ecx
    1efd:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1f03:	89 c2                	mov    %eax,%edx
    1f05:	c1 ea 1f             	shr    $0x1f,%edx
    1f08:	01 d0                	add    %edx,%eax
    1f0a:	d1 f8                	sar    %eax
    1f0c:	83 e8 09             	sub    $0x9,%eax
    1f0f:	48 8d 15 52 11 00 00 	lea    0x1152(%rip),%rdx        # 3068 <_ZStL19piecewise_construct+0x60>
    1f16:	89 ce                	mov    %ecx,%esi
    1f18:	89 c7                	mov    %eax,%edi
    1f1a:	b8 00 00 00 00       	mov    $0x0,%eax
    1f1f:	e8 9c f4 ff ff       	callq  13c0 <mvprintw@plt>
    1f24:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1f2a:	83 e8 33             	sub    $0x33,%eax
    1f2d:	89 c2                	mov    %eax,%edx
    1f2f:	c1 ea 1f             	shr    $0x1f,%edx
    1f32:	01 d0                	add    %edx,%eax
    1f34:	d1 f8                	sar    %eax
    1f36:	89 c1                	mov    %eax,%ecx
    1f38:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1f3e:	89 c2                	mov    %eax,%edx
    1f40:	c1 ea 1f             	shr    $0x1f,%edx
    1f43:	01 d0                	add    %edx,%eax
    1f45:	d1 f8                	sar    %eax
    1f47:	83 e8 08             	sub    $0x8,%eax
    1f4a:	48 8d 15 4f 11 00 00 	lea    0x114f(%rip),%rdx        # 30a0 <_ZStL19piecewise_construct+0x98>
    1f51:	89 ce                	mov    %ecx,%esi
    1f53:	89 c7                	mov    %eax,%edi
    1f55:	b8 00 00 00 00       	mov    $0x0,%eax
    1f5a:	e8 61 f4 ff ff       	callq  13c0 <mvprintw@plt>
    1f5f:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1f65:	83 e8 33             	sub    $0x33,%eax
    1f68:	89 c2                	mov    %eax,%edx
    1f6a:	c1 ea 1f             	shr    $0x1f,%edx
    1f6d:	01 d0                	add    %edx,%eax
    1f6f:	d1 f8                	sar    %eax
    1f71:	89 c1                	mov    %eax,%ecx
    1f73:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1f79:	89 c2                	mov    %eax,%edx
    1f7b:	c1 ea 1f             	shr    $0x1f,%edx
    1f7e:	01 d0                	add    %edx,%eax
    1f80:	d1 f8                	sar    %eax
    1f82:	83 e8 07             	sub    $0x7,%eax
    1f85:	48 8d 15 4c 11 00 00 	lea    0x114c(%rip),%rdx        # 30d8 <_ZStL19piecewise_construct+0xd0>
    1f8c:	89 ce                	mov    %ecx,%esi
    1f8e:	89 c7                	mov    %eax,%edi
    1f90:	b8 00 00 00 00       	mov    $0x0,%eax
    1f95:	e8 26 f4 ff ff       	callq  13c0 <mvprintw@plt>
    1f9a:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1fa0:	83 e8 33             	sub    $0x33,%eax
    1fa3:	89 c2                	mov    %eax,%edx
    1fa5:	c1 ea 1f             	shr    $0x1f,%edx
    1fa8:	01 d0                	add    %edx,%eax
    1faa:	d1 f8                	sar    %eax
    1fac:	89 c1                	mov    %eax,%ecx
    1fae:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1fb4:	89 c2                	mov    %eax,%edx
    1fb6:	c1 ea 1f             	shr    $0x1f,%edx
    1fb9:	01 d0                	add    %edx,%eax
    1fbb:	d1 f8                	sar    %eax
    1fbd:	83 e8 06             	sub    $0x6,%eax
    1fc0:	48 8d 15 49 11 00 00 	lea    0x1149(%rip),%rdx        # 3110 <_ZStL19piecewise_construct+0x108>
    1fc7:	89 ce                	mov    %ecx,%esi
    1fc9:	89 c7                	mov    %eax,%edi
    1fcb:	b8 00 00 00 00       	mov    $0x0,%eax
    1fd0:	e8 eb f3 ff ff       	callq  13c0 <mvprintw@plt>
    1fd5:	48 8b 05 34 30 00 00 	mov    0x3034(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1fdc:	ba 00 00 00 00       	mov    $0x0,%edx
    1fe1:	be 00 05 20 00       	mov    $0x200500,%esi
    1fe6:	48 89 c7             	mov    %rax,%rdi
    1fe9:	e8 c2 f3 ff ff       	callq  13b0 <wattr_off@plt>
    1fee:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1ff4:	8d 50 07             	lea    0x7(%rax),%edx
    1ff7:	85 c0                	test   %eax,%eax
    1ff9:	0f 48 c2             	cmovs  %edx,%eax
    1ffc:	c1 f8 03             	sar    $0x3,%eax
    1fff:	89 c1                	mov    %eax,%ecx
    2001:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    2007:	89 c2                	mov    %eax,%edx
    2009:	c1 ea 1f             	shr    $0x1f,%edx
    200c:	01 d0                	add    %edx,%eax
    200e:	d1 f8                	sar    %eax
    2010:	8d 70 ec             	lea    -0x14(%rax),%esi
    2013:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    2019:	89 c2                	mov    %eax,%edx
    201b:	c1 ea 1f             	shr    $0x1f,%edx
    201e:	01 d0                	add    %edx,%eax
    2020:	d1 f8                	sar    %eax
    2022:	83 e8 01             	sub    $0x1,%eax
    2025:	48 8d 15 dd 0f 00 00 	lea    0xfdd(%rip),%rdx        # 3009 <_ZStL19piecewise_construct+0x1>
    202c:	89 c7                	mov    %eax,%edi
    202e:	b8 00 00 00 00       	mov    $0x0,%eax
    2033:	e8 88 f3 ff ff       	callq  13c0 <mvprintw@plt>
    2038:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    203e:	89 c2                	mov    %eax,%edx
    2040:	c1 ea 1f             	shr    $0x1f,%edx
    2043:	01 d0                	add    %edx,%eax
    2045:	d1 f8                	sar    %eax
    2047:	8d 70 ec             	lea    -0x14(%rax),%esi
    204a:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    2050:	89 c2                	mov    %eax,%edx
    2052:	c1 ea 1f             	shr    $0x1f,%edx
    2055:	01 d0                	add    %edx,%eax
    2057:	d1 f8                	sar    %eax
    2059:	8d 78 fe             	lea    -0x2(%rax),%edi
    205c:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    2063:	48 89 c1             	mov    %rax,%rcx
    2066:	48 8d 15 a7 0f 00 00 	lea    0xfa7(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    206d:	b8 00 00 00 00       	mov    $0x0,%eax
    2072:	e8 49 f3 ff ff       	callq  13c0 <mvprintw@plt>
    2077:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    207d:	89 c2                	mov    %eax,%edx
    207f:	c1 ea 1f             	shr    $0x1f,%edx
    2082:	01 d0                	add    %edx,%eax
    2084:	d1 f8                	sar    %eax
    2086:	8d 70 0a             	lea    0xa(%rax),%esi
    2089:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    208f:	89 c2                	mov    %eax,%edx
    2091:	c1 ea 1f             	shr    $0x1f,%edx
    2094:	01 d0                	add    %edx,%eax
    2096:	d1 f8                	sar    %eax
    2098:	8d 78 fe             	lea    -0x2(%rax),%edi
    209b:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    209f:	48 89 c1             	mov    %rax,%rcx
    20a2:	48 8d 15 6b 0f 00 00 	lea    0xf6b(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    20a9:	b8 00 00 00 00       	mov    $0x0,%eax
    20ae:	e8 0d f3 ff ff       	callq  13c0 <mvprintw@plt>
    20b3:	8b 95 c8 fe ff ff    	mov    -0x138(%rbp),%edx
    20b9:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    20bf:	89 c1                	mov    %eax,%ecx
    20c1:	c1 e9 1f             	shr    $0x1f,%ecx
    20c4:	01 c8                	add    %ecx,%eax
    20c6:	d1 f8                	sar    %eax
    20c8:	8d 70 0a             	lea    0xa(%rax),%esi
    20cb:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    20d1:	89 c1                	mov    %eax,%ecx
    20d3:	c1 e9 1f             	shr    $0x1f,%ecx
    20d6:	01 c8                	add    %ecx,%eax
    20d8:	d1 f8                	sar    %eax
    20da:	83 e8 01             	sub    $0x1,%eax
    20dd:	89 d1                	mov    %edx,%ecx
    20df:	48 8d 15 31 0f 00 00 	lea    0xf31(%rip),%rdx        # 3017 <_ZStL19piecewise_construct+0xf>
    20e6:	89 c7                	mov    %eax,%edi
    20e8:	b8 00 00 00 00       	mov    $0x0,%eax
    20ed:	e8 ce f2 ff ff       	callq  13c0 <mvprintw@plt>
    20f2:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    20f8:	83 e8 27             	sub    $0x27,%eax
    20fb:	89 c2                	mov    %eax,%edx
    20fd:	c1 ea 1f             	shr    $0x1f,%edx
    2100:	01 d0                	add    %edx,%eax
    2102:	d1 f8                	sar    %eax
    2104:	89 c6                	mov    %eax,%esi
    2106:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    210c:	89 c2                	mov    %eax,%edx
    210e:	c1 ea 1f             	shr    $0x1f,%edx
    2111:	01 d0                	add    %edx,%eax
    2113:	d1 f8                	sar    %eax
    2115:	83 c0 01             	add    $0x1,%eax
    2118:	48 8d 0d 25 10 00 00 	lea    0x1025(%rip),%rcx        # 3144 <_ZStL19piecewise_construct+0x13c>
    211f:	48 8d 15 2c 10 00 00 	lea    0x102c(%rip),%rdx        # 3152 <_ZStL19piecewise_construct+0x14a>
    2126:	89 c7                	mov    %eax,%edi
    2128:	b8 00 00 00 00       	mov    $0x0,%eax
    212d:	e8 8e f2 ff ff       	callq  13c0 <mvprintw@plt>
    2132:	e8 f9 f2 ff ff       	callq  1430 <refresh@plt>
    2137:	e8 94 f2 ff ff       	callq  13d0 <getchar@plt>
    213c:	e8 4f f2 ff ff       	callq  1390 <endwin@plt>
    2141:	b8 00 00 00 00       	mov    $0x0,%eax
    2146:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
    214a:	64 48 33 3c 25 28 00 	xor    %fs:0x28,%rdi
    2151:	00 00 
    2153:	74 05                	je     215a <main+0xc11>
    2155:	e8 06 f2 ff ff       	callq  1360 <__stack_chk_fail@plt>
    215a:	c9                   	leaveq 
    215b:	c3                   	retq   

000000000000215c <_Z9writeInfoii>:
    215c:	f3 0f 1e fa          	endbr64 
    2160:	55                   	push   %rbp
    2161:	48 89 e5             	mov    %rsp,%rbp
    2164:	48 83 ec 10          	sub    $0x10,%rsp
    2168:	89 7d fc             	mov    %edi,-0x4(%rbp)
    216b:	89 75 f8             	mov    %esi,-0x8(%rbp)
    216e:	48 8b 05 9b 2e 00 00 	mov    0x2e9b(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    2175:	ba 00 00 00 00       	mov    $0x0,%edx
    217a:	be 00 04 20 00       	mov    $0x200400,%esi
    217f:	48 89 c7             	mov    %rax,%rdi
    2182:	e8 49 f1 ff ff       	callq  12d0 <wattr_on@plt>
    2187:	8b 45 f8             	mov    -0x8(%rbp),%eax
    218a:	83 e8 32             	sub    $0x32,%eax
    218d:	89 c2                	mov    %eax,%edx
    218f:	c1 ea 1f             	shr    $0x1f,%edx
    2192:	01 d0                	add    %edx,%eax
    2194:	d1 f8                	sar    %eax
    2196:	89 c1                	mov    %eax,%ecx
    2198:	8b 45 fc             	mov    -0x4(%rbp),%eax
    219b:	89 c2                	mov    %eax,%edx
    219d:	c1 ea 1f             	shr    $0x1f,%edx
    21a0:	01 d0                	add    %edx,%eax
    21a2:	d1 f8                	sar    %eax
    21a4:	83 e8 0a             	sub    $0xa,%eax
    21a7:	48 8d 15 c2 0f 00 00 	lea    0xfc2(%rip),%rdx        # 3170 <_ZStL19piecewise_construct+0x168>
    21ae:	89 ce                	mov    %ecx,%esi
    21b0:	89 c7                	mov    %eax,%edi
    21b2:	b8 00 00 00 00       	mov    $0x0,%eax
    21b7:	e8 04 f2 ff ff       	callq  13c0 <mvprintw@plt>
    21bc:	8b 45 f8             	mov    -0x8(%rbp),%eax
    21bf:	83 e8 32             	sub    $0x32,%eax
    21c2:	89 c2                	mov    %eax,%edx
    21c4:	c1 ea 1f             	shr    $0x1f,%edx
    21c7:	01 d0                	add    %edx,%eax
    21c9:	d1 f8                	sar    %eax
    21cb:	89 c1                	mov    %eax,%ecx
    21cd:	8b 45 fc             	mov    -0x4(%rbp),%eax
    21d0:	89 c2                	mov    %eax,%edx
    21d2:	c1 ea 1f             	shr    $0x1f,%edx
    21d5:	01 d0                	add    %edx,%eax
    21d7:	d1 f8                	sar    %eax
    21d9:	83 e8 09             	sub    $0x9,%eax
    21dc:	48 8d 15 c5 0f 00 00 	lea    0xfc5(%rip),%rdx        # 31a8 <_ZStL19piecewise_construct+0x1a0>
    21e3:	89 ce                	mov    %ecx,%esi
    21e5:	89 c7                	mov    %eax,%edi
    21e7:	b8 00 00 00 00       	mov    $0x0,%eax
    21ec:	e8 cf f1 ff ff       	callq  13c0 <mvprintw@plt>
    21f1:	8b 45 f8             	mov    -0x8(%rbp),%eax
    21f4:	83 e8 32             	sub    $0x32,%eax
    21f7:	89 c2                	mov    %eax,%edx
    21f9:	c1 ea 1f             	shr    $0x1f,%edx
    21fc:	01 d0                	add    %edx,%eax
    21fe:	d1 f8                	sar    %eax
    2200:	89 c1                	mov    %eax,%ecx
    2202:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2205:	89 c2                	mov    %eax,%edx
    2207:	c1 ea 1f             	shr    $0x1f,%edx
    220a:	01 d0                	add    %edx,%eax
    220c:	d1 f8                	sar    %eax
    220e:	83 e8 08             	sub    $0x8,%eax
    2211:	48 8d 15 c8 0f 00 00 	lea    0xfc8(%rip),%rdx        # 31e0 <_ZStL19piecewise_construct+0x1d8>
    2218:	89 ce                	mov    %ecx,%esi
    221a:	89 c7                	mov    %eax,%edi
    221c:	b8 00 00 00 00       	mov    $0x0,%eax
    2221:	e8 9a f1 ff ff       	callq  13c0 <mvprintw@plt>
    2226:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2229:	83 e8 32             	sub    $0x32,%eax
    222c:	89 c2                	mov    %eax,%edx
    222e:	c1 ea 1f             	shr    $0x1f,%edx
    2231:	01 d0                	add    %edx,%eax
    2233:	d1 f8                	sar    %eax
    2235:	89 c1                	mov    %eax,%ecx
    2237:	8b 45 fc             	mov    -0x4(%rbp),%eax
    223a:	89 c2                	mov    %eax,%edx
    223c:	c1 ea 1f             	shr    $0x1f,%edx
    223f:	01 d0                	add    %edx,%eax
    2241:	d1 f8                	sar    %eax
    2243:	83 e8 07             	sub    $0x7,%eax
    2246:	48 8d 15 cb 0f 00 00 	lea    0xfcb(%rip),%rdx        # 3218 <_ZStL19piecewise_construct+0x210>
    224d:	89 ce                	mov    %ecx,%esi
    224f:	89 c7                	mov    %eax,%edi
    2251:	b8 00 00 00 00       	mov    $0x0,%eax
    2256:	e8 65 f1 ff ff       	callq  13c0 <mvprintw@plt>
    225b:	8b 45 f8             	mov    -0x8(%rbp),%eax
    225e:	83 e8 32             	sub    $0x32,%eax
    2261:	89 c2                	mov    %eax,%edx
    2263:	c1 ea 1f             	shr    $0x1f,%edx
    2266:	01 d0                	add    %edx,%eax
    2268:	d1 f8                	sar    %eax
    226a:	89 c1                	mov    %eax,%ecx
    226c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    226f:	89 c2                	mov    %eax,%edx
    2271:	c1 ea 1f             	shr    $0x1f,%edx
    2274:	01 d0                	add    %edx,%eax
    2276:	d1 f8                	sar    %eax
    2278:	83 e8 06             	sub    $0x6,%eax
    227b:	48 8d 15 ce 0f 00 00 	lea    0xfce(%rip),%rdx        # 3250 <_ZStL19piecewise_construct+0x248>
    2282:	89 ce                	mov    %ecx,%esi
    2284:	89 c7                	mov    %eax,%edi
    2286:	b8 00 00 00 00       	mov    $0x0,%eax
    228b:	e8 30 f1 ff ff       	callq  13c0 <mvprintw@plt>
    2290:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2293:	83 e8 32             	sub    $0x32,%eax
    2296:	89 c2                	mov    %eax,%edx
    2298:	c1 ea 1f             	shr    $0x1f,%edx
    229b:	01 d0                	add    %edx,%eax
    229d:	d1 f8                	sar    %eax
    229f:	89 c1                	mov    %eax,%ecx
    22a1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    22a4:	89 c2                	mov    %eax,%edx
    22a6:	c1 ea 1f             	shr    $0x1f,%edx
    22a9:	01 d0                	add    %edx,%eax
    22ab:	d1 f8                	sar    %eax
    22ad:	83 e8 05             	sub    $0x5,%eax
    22b0:	48 8d 15 d1 0f 00 00 	lea    0xfd1(%rip),%rdx        # 3288 <_ZStL19piecewise_construct+0x280>
    22b7:	89 ce                	mov    %ecx,%esi
    22b9:	89 c7                	mov    %eax,%edi
    22bb:	b8 00 00 00 00       	mov    $0x0,%eax
    22c0:	e8 fb f0 ff ff       	callq  13c0 <mvprintw@plt>
    22c5:	48 8b 05 44 2d 00 00 	mov    0x2d44(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    22cc:	ba 00 00 00 00       	mov    $0x0,%edx
    22d1:	be 00 04 20 00       	mov    $0x200400,%esi
    22d6:	48 89 c7             	mov    %rax,%rdi
    22d9:	e8 d2 f0 ff ff       	callq  13b0 <wattr_off@plt>
    22de:	48 8b 05 2b 2d 00 00 	mov    0x2d2b(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    22e5:	ba 00 00 00 00       	mov    $0x0,%edx
    22ea:	be 00 07 00 00       	mov    $0x700,%esi
    22ef:	48 89 c7             	mov    %rax,%rdi
    22f2:	e8 d9 ef ff ff       	callq  12d0 <wattr_on@plt>
    22f7:	8b 45 f8             	mov    -0x8(%rbp),%eax
    22fa:	83 e8 22             	sub    $0x22,%eax
    22fd:	89 c2                	mov    %eax,%edx
    22ff:	c1 ea 1f             	shr    $0x1f,%edx
    2302:	01 d0                	add    %edx,%eax
    2304:	d1 f8                	sar    %eax
    2306:	89 c1                	mov    %eax,%ecx
    2308:	8b 45 fc             	mov    -0x4(%rbp),%eax
    230b:	89 c2                	mov    %eax,%edx
    230d:	c1 ea 1f             	shr    $0x1f,%edx
    2310:	01 d0                	add    %edx,%eax
    2312:	d1 f8                	sar    %eax
    2314:	83 e8 03             	sub    $0x3,%eax
    2317:	48 8d 15 a2 0f 00 00 	lea    0xfa2(%rip),%rdx        # 32c0 <_ZStL19piecewise_construct+0x2b8>
    231e:	89 ce                	mov    %ecx,%esi
    2320:	89 c7                	mov    %eax,%edi
    2322:	b8 00 00 00 00       	mov    $0x0,%eax
    2327:	e8 94 f0 ff ff       	callq  13c0 <mvprintw@plt>
    232c:	8b 45 f8             	mov    -0x8(%rbp),%eax
    232f:	83 e8 22             	sub    $0x22,%eax
    2332:	89 c2                	mov    %eax,%edx
    2334:	c1 ea 1f             	shr    $0x1f,%edx
    2337:	01 d0                	add    %edx,%eax
    2339:	d1 f8                	sar    %eax
    233b:	89 c1                	mov    %eax,%ecx
    233d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2340:	89 c2                	mov    %eax,%edx
    2342:	c1 ea 1f             	shr    $0x1f,%edx
    2345:	01 d0                	add    %edx,%eax
    2347:	d1 f8                	sar    %eax
    2349:	83 e8 02             	sub    $0x2,%eax
    234c:	48 8d 15 95 0f 00 00 	lea    0xf95(%rip),%rdx        # 32e8 <_ZStL19piecewise_construct+0x2e0>
    2353:	89 ce                	mov    %ecx,%esi
    2355:	89 c7                	mov    %eax,%edi
    2357:	b8 00 00 00 00       	mov    $0x0,%eax
    235c:	e8 5f f0 ff ff       	callq  13c0 <mvprintw@plt>
    2361:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2364:	83 e8 22             	sub    $0x22,%eax
    2367:	89 c2                	mov    %eax,%edx
    2369:	c1 ea 1f             	shr    $0x1f,%edx
    236c:	01 d0                	add    %edx,%eax
    236e:	d1 f8                	sar    %eax
    2370:	89 c1                	mov    %eax,%ecx
    2372:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2375:	89 c2                	mov    %eax,%edx
    2377:	c1 ea 1f             	shr    $0x1f,%edx
    237a:	01 d0                	add    %edx,%eax
    237c:	d1 f8                	sar    %eax
    237e:	83 e8 01             	sub    $0x1,%eax
    2381:	48 8d 15 88 0f 00 00 	lea    0xf88(%rip),%rdx        # 3310 <_ZStL19piecewise_construct+0x308>
    2388:	89 ce                	mov    %ecx,%esi
    238a:	89 c7                	mov    %eax,%edi
    238c:	b8 00 00 00 00       	mov    $0x0,%eax
    2391:	e8 2a f0 ff ff       	callq  13c0 <mvprintw@plt>
    2396:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2399:	83 e8 22             	sub    $0x22,%eax
    239c:	89 c2                	mov    %eax,%edx
    239e:	c1 ea 1f             	shr    $0x1f,%edx
    23a1:	01 d0                	add    %edx,%eax
    23a3:	d1 f8                	sar    %eax
    23a5:	89 c1                	mov    %eax,%ecx
    23a7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23aa:	89 c2                	mov    %eax,%edx
    23ac:	c1 ea 1f             	shr    $0x1f,%edx
    23af:	01 d0                	add    %edx,%eax
    23b1:	d1 f8                	sar    %eax
    23b3:	48 8d 15 7e 0f 00 00 	lea    0xf7e(%rip),%rdx        # 3338 <_ZStL19piecewise_construct+0x330>
    23ba:	89 ce                	mov    %ecx,%esi
    23bc:	89 c7                	mov    %eax,%edi
    23be:	b8 00 00 00 00       	mov    $0x0,%eax
    23c3:	e8 f8 ef ff ff       	callq  13c0 <mvprintw@plt>
    23c8:	8b 45 f8             	mov    -0x8(%rbp),%eax
    23cb:	83 e8 22             	sub    $0x22,%eax
    23ce:	89 c2                	mov    %eax,%edx
    23d0:	c1 ea 1f             	shr    $0x1f,%edx
    23d3:	01 d0                	add    %edx,%eax
    23d5:	d1 f8                	sar    %eax
    23d7:	89 c1                	mov    %eax,%ecx
    23d9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23dc:	89 c2                	mov    %eax,%edx
    23de:	c1 ea 1f             	shr    $0x1f,%edx
    23e1:	01 d0                	add    %edx,%eax
    23e3:	d1 f8                	sar    %eax
    23e5:	83 c0 01             	add    $0x1,%eax
    23e8:	48 8d 15 71 0f 00 00 	lea    0xf71(%rip),%rdx        # 3360 <_ZStL19piecewise_construct+0x358>
    23ef:	89 ce                	mov    %ecx,%esi
    23f1:	89 c7                	mov    %eax,%edi
    23f3:	b8 00 00 00 00       	mov    $0x0,%eax
    23f8:	e8 c3 ef ff ff       	callq  13c0 <mvprintw@plt>
    23fd:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2400:	83 e8 22             	sub    $0x22,%eax
    2403:	89 c2                	mov    %eax,%edx
    2405:	c1 ea 1f             	shr    $0x1f,%edx
    2408:	01 d0                	add    %edx,%eax
    240a:	d1 f8                	sar    %eax
    240c:	89 c1                	mov    %eax,%ecx
    240e:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2411:	89 c2                	mov    %eax,%edx
    2413:	c1 ea 1f             	shr    $0x1f,%edx
    2416:	01 d0                	add    %edx,%eax
    2418:	d1 f8                	sar    %eax
    241a:	83 c0 02             	add    $0x2,%eax
    241d:	48 8d 15 64 0f 00 00 	lea    0xf64(%rip),%rdx        # 3388 <_ZStL19piecewise_construct+0x380>
    2424:	89 ce                	mov    %ecx,%esi
    2426:	89 c7                	mov    %eax,%edi
    2428:	b8 00 00 00 00       	mov    $0x0,%eax
    242d:	e8 8e ef ff ff       	callq  13c0 <mvprintw@plt>
    2432:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2435:	83 e8 22             	sub    $0x22,%eax
    2438:	89 c2                	mov    %eax,%edx
    243a:	c1 ea 1f             	shr    $0x1f,%edx
    243d:	01 d0                	add    %edx,%eax
    243f:	d1 f8                	sar    %eax
    2441:	89 c1                	mov    %eax,%ecx
    2443:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2446:	89 c2                	mov    %eax,%edx
    2448:	c1 ea 1f             	shr    $0x1f,%edx
    244b:	01 d0                	add    %edx,%eax
    244d:	d1 f8                	sar    %eax
    244f:	83 c0 03             	add    $0x3,%eax
    2452:	48 8d 15 57 0f 00 00 	lea    0xf57(%rip),%rdx        # 33b0 <_ZStL19piecewise_construct+0x3a8>
    2459:	89 ce                	mov    %ecx,%esi
    245b:	89 c7                	mov    %eax,%edi
    245d:	b8 00 00 00 00       	mov    $0x0,%eax
    2462:	e8 59 ef ff ff       	callq  13c0 <mvprintw@plt>
    2467:	8b 45 f8             	mov    -0x8(%rbp),%eax
    246a:	83 e8 22             	sub    $0x22,%eax
    246d:	89 c2                	mov    %eax,%edx
    246f:	c1 ea 1f             	shr    $0x1f,%edx
    2472:	01 d0                	add    %edx,%eax
    2474:	d1 f8                	sar    %eax
    2476:	89 c1                	mov    %eax,%ecx
    2478:	8b 45 fc             	mov    -0x4(%rbp),%eax
    247b:	89 c2                	mov    %eax,%edx
    247d:	c1 ea 1f             	shr    $0x1f,%edx
    2480:	01 d0                	add    %edx,%eax
    2482:	d1 f8                	sar    %eax
    2484:	83 c0 04             	add    $0x4,%eax
    2487:	48 8d 15 4a 0f 00 00 	lea    0xf4a(%rip),%rdx        # 33d8 <_ZStL19piecewise_construct+0x3d0>
    248e:	89 ce                	mov    %ecx,%esi
    2490:	89 c7                	mov    %eax,%edi
    2492:	b8 00 00 00 00       	mov    $0x0,%eax
    2497:	e8 24 ef ff ff       	callq  13c0 <mvprintw@plt>
    249c:	8b 45 f8             	mov    -0x8(%rbp),%eax
    249f:	83 e8 22             	sub    $0x22,%eax
    24a2:	89 c2                	mov    %eax,%edx
    24a4:	c1 ea 1f             	shr    $0x1f,%edx
    24a7:	01 d0                	add    %edx,%eax
    24a9:	d1 f8                	sar    %eax
    24ab:	89 c1                	mov    %eax,%ecx
    24ad:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24b0:	89 c2                	mov    %eax,%edx
    24b2:	c1 ea 1f             	shr    $0x1f,%edx
    24b5:	01 d0                	add    %edx,%eax
    24b7:	d1 f8                	sar    %eax
    24b9:	83 c0 05             	add    $0x5,%eax
    24bc:	48 8d 15 3d 0f 00 00 	lea    0xf3d(%rip),%rdx        # 3400 <_ZStL19piecewise_construct+0x3f8>
    24c3:	89 ce                	mov    %ecx,%esi
    24c5:	89 c7                	mov    %eax,%edi
    24c7:	b8 00 00 00 00       	mov    $0x0,%eax
    24cc:	e8 ef ee ff ff       	callq  13c0 <mvprintw@plt>
    24d1:	8b 45 f8             	mov    -0x8(%rbp),%eax
    24d4:	83 e8 22             	sub    $0x22,%eax
    24d7:	89 c2                	mov    %eax,%edx
    24d9:	c1 ea 1f             	shr    $0x1f,%edx
    24dc:	01 d0                	add    %edx,%eax
    24de:	d1 f8                	sar    %eax
    24e0:	89 c1                	mov    %eax,%ecx
    24e2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24e5:	89 c2                	mov    %eax,%edx
    24e7:	c1 ea 1f             	shr    $0x1f,%edx
    24ea:	01 d0                	add    %edx,%eax
    24ec:	d1 f8                	sar    %eax
    24ee:	83 c0 06             	add    $0x6,%eax
    24f1:	48 8d 15 30 0f 00 00 	lea    0xf30(%rip),%rdx        # 3428 <_ZStL19piecewise_construct+0x420>
    24f8:	89 ce                	mov    %ecx,%esi
    24fa:	89 c7                	mov    %eax,%edi
    24fc:	b8 00 00 00 00       	mov    $0x0,%eax
    2501:	e8 ba ee ff ff       	callq  13c0 <mvprintw@plt>
    2506:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2509:	83 e8 22             	sub    $0x22,%eax
    250c:	89 c2                	mov    %eax,%edx
    250e:	c1 ea 1f             	shr    $0x1f,%edx
    2511:	01 d0                	add    %edx,%eax
    2513:	d1 f8                	sar    %eax
    2515:	89 c1                	mov    %eax,%ecx
    2517:	8b 45 fc             	mov    -0x4(%rbp),%eax
    251a:	89 c2                	mov    %eax,%edx
    251c:	c1 ea 1f             	shr    $0x1f,%edx
    251f:	01 d0                	add    %edx,%eax
    2521:	d1 f8                	sar    %eax
    2523:	83 c0 07             	add    $0x7,%eax
    2526:	48 8d 15 23 0f 00 00 	lea    0xf23(%rip),%rdx        # 3450 <_ZStL19piecewise_construct+0x448>
    252d:	89 ce                	mov    %ecx,%esi
    252f:	89 c7                	mov    %eax,%edi
    2531:	b8 00 00 00 00       	mov    $0x0,%eax
    2536:	e8 85 ee ff ff       	callq  13c0 <mvprintw@plt>
    253b:	8b 45 f8             	mov    -0x8(%rbp),%eax
    253e:	83 e8 22             	sub    $0x22,%eax
    2541:	89 c2                	mov    %eax,%edx
    2543:	c1 ea 1f             	shr    $0x1f,%edx
    2546:	01 d0                	add    %edx,%eax
    2548:	d1 f8                	sar    %eax
    254a:	89 c1                	mov    %eax,%ecx
    254c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    254f:	89 c2                	mov    %eax,%edx
    2551:	c1 ea 1f             	shr    $0x1f,%edx
    2554:	01 d0                	add    %edx,%eax
    2556:	d1 f8                	sar    %eax
    2558:	83 c0 08             	add    $0x8,%eax
    255b:	48 8d 15 16 0f 00 00 	lea    0xf16(%rip),%rdx        # 3478 <_ZStL19piecewise_construct+0x470>
    2562:	89 ce                	mov    %ecx,%esi
    2564:	89 c7                	mov    %eax,%edi
    2566:	b8 00 00 00 00       	mov    $0x0,%eax
    256b:	e8 50 ee ff ff       	callq  13c0 <mvprintw@plt>
    2570:	48 8b 05 99 2a 00 00 	mov    0x2a99(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    2577:	ba 00 00 00 00       	mov    $0x0,%edx
    257c:	be 00 07 00 00       	mov    $0x700,%esi
    2581:	48 89 c7             	mov    %rax,%rdi
    2584:	e8 27 ee ff ff       	callq  13b0 <wattr_off@plt>
    2589:	8b 45 f8             	mov    -0x8(%rbp),%eax
    258c:	83 e8 18             	sub    $0x18,%eax
    258f:	89 c2                	mov    %eax,%edx
    2591:	c1 ea 1f             	shr    $0x1f,%edx
    2594:	01 d0                	add    %edx,%eax
    2596:	d1 f8                	sar    %eax
    2598:	89 c1                	mov    %eax,%ecx
    259a:	8b 45 fc             	mov    -0x4(%rbp),%eax
    259d:	89 c2                	mov    %eax,%edx
    259f:	c1 ea 1f             	shr    $0x1f,%edx
    25a2:	01 d0                	add    %edx,%eax
    25a4:	d1 f8                	sar    %eax
    25a6:	83 c0 0a             	add    $0xa,%eax
    25a9:	48 8d 15 eb 0e 00 00 	lea    0xeeb(%rip),%rdx        # 349b <_ZStL19piecewise_construct+0x493>
    25b0:	89 ce                	mov    %ecx,%esi
    25b2:	89 c7                	mov    %eax,%edi
    25b4:	b8 00 00 00 00       	mov    $0x0,%eax
    25b9:	e8 02 ee ff ff       	callq  13c0 <mvprintw@plt>
    25be:	90                   	nop
    25bf:	c9                   	leaveq 
    25c0:	c3                   	retq   

00000000000025c1 <_Z16controlCollisioniiiii>:
    25c1:	f3 0f 1e fa          	endbr64 
    25c5:	55                   	push   %rbp
    25c6:	48 89 e5             	mov    %rsp,%rbp
    25c9:	89 7d ec             	mov    %edi,-0x14(%rbp)
    25cc:	89 75 e8             	mov    %esi,-0x18(%rbp)
    25cf:	89 55 e4             	mov    %edx,-0x1c(%rbp)
    25d2:	89 4d e0             	mov    %ecx,-0x20(%rbp)
    25d5:	44 89 45 dc          	mov    %r8d,-0x24(%rbp)
    25d9:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    25e0:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25e3:	83 e8 08             	sub    $0x8,%eax
    25e6:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25e9:	74 4d                	je     2638 <_Z16controlCollisioniiiii+0x77>
    25eb:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25ee:	83 e8 07             	sub    $0x7,%eax
    25f1:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25f4:	74 42                	je     2638 <_Z16controlCollisioniiiii+0x77>
    25f6:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25f9:	83 e8 06             	sub    $0x6,%eax
    25fc:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25ff:	74 37                	je     2638 <_Z16controlCollisioniiiii+0x77>
    2601:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2604:	83 e8 05             	sub    $0x5,%eax
    2607:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    260a:	74 2c                	je     2638 <_Z16controlCollisioniiiii+0x77>
    260c:	8b 45 ec             	mov    -0x14(%rbp),%eax
    260f:	83 e8 04             	sub    $0x4,%eax
    2612:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    2615:	74 21                	je     2638 <_Z16controlCollisioniiiii+0x77>
    2617:	8b 45 ec             	mov    -0x14(%rbp),%eax
    261a:	83 e8 03             	sub    $0x3,%eax
    261d:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    2620:	74 16                	je     2638 <_Z16controlCollisioniiiii+0x77>
    2622:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2625:	83 e8 02             	sub    $0x2,%eax
    2628:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    262b:	74 0b                	je     2638 <_Z16controlCollisioniiiii+0x77>
    262d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2630:	83 e8 01             	sub    $0x1,%eax
    2633:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    2636:	75 18                	jne    2650 <_Z16controlCollisioniiiii+0x8f>
    2638:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    263c:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    263f:	3b 45 e0             	cmp    -0x20(%rbp),%eax
    2642:	7c 08                	jl     264c <_Z16controlCollisioniiiii+0x8b>
    2644:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2647:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    264a:	7e 04                	jle    2650 <_Z16controlCollisioniiiii+0x8f>
    264c:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2650:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2653:	5d                   	pop    %rbp
    2654:	c3                   	retq   

0000000000002655 <_Z8drawPipeiiii>:
    2655:	f3 0f 1e fa          	endbr64 
    2659:	55                   	push   %rbp
    265a:	48 89 e5             	mov    %rsp,%rbp
    265d:	48 83 ec 20          	sub    $0x20,%rsp
    2661:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2664:	89 75 e8             	mov    %esi,-0x18(%rbp)
    2667:	89 55 e4             	mov    %edx,-0x1c(%rbp)
    266a:	89 4d e0             	mov    %ecx,-0x20(%rbp)
    266d:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2674:	8b 45 e0             	mov    -0x20(%rbp),%eax
    2677:	83 e8 03             	sub    $0x3,%eax
    267a:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    267d:	0f 8d 0c 01 00 00    	jge    278f <_Z8drawPipeiiii+0x13a>
    2683:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2686:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    2689:	7d 7f                	jge    270a <_Z8drawPipeiiii+0xb5>
    268b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    268e:	83 e8 01             	sub    $0x1,%eax
    2691:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    2694:	74 0b                	je     26a1 <_Z8drawPipeiiii+0x4c>
    2696:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2699:	83 e8 02             	sub    $0x2,%eax
    269c:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    269f:	75 20                	jne    26c1 <_Z8drawPipeiiii+0x6c>
    26a1:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    26a4:	8d 48 f7             	lea    -0x9(%rax),%ecx
    26a7:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26aa:	48 8d 15 fc 0d 00 00 	lea    0xdfc(%rip),%rdx        # 34ad <_ZStL19piecewise_construct+0x4a5>
    26b1:	89 ce                	mov    %ecx,%esi
    26b3:	89 c7                	mov    %eax,%edi
    26b5:	b8 00 00 00 00       	mov    $0x0,%eax
    26ba:	e8 01 ed ff ff       	callq  13c0 <mvprintw@plt>
    26bf:	eb 49                	jmp    270a <_Z8drawPipeiiii+0xb5>
    26c1:	8b 45 ec             	mov    -0x14(%rbp),%eax
    26c4:	83 e8 03             	sub    $0x3,%eax
    26c7:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    26ca:	75 20                	jne    26ec <_Z8drawPipeiiii+0x97>
    26cc:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    26cf:	8d 48 f8             	lea    -0x8(%rax),%ecx
    26d2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26d5:	48 8d 15 dc 0d 00 00 	lea    0xddc(%rip),%rdx        # 34b8 <_ZStL19piecewise_construct+0x4b0>
    26dc:	89 ce                	mov    %ecx,%esi
    26de:	89 c7                	mov    %eax,%edi
    26e0:	b8 00 00 00 00       	mov    $0x0,%eax
    26e5:	e8 d6 ec ff ff       	callq  13c0 <mvprintw@plt>
    26ea:	eb 1e                	jmp    270a <_Z8drawPipeiiii+0xb5>
    26ec:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    26ef:	8d 48 f8             	lea    -0x8(%rax),%ecx
    26f2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26f5:	48 8d 15 c5 0d 00 00 	lea    0xdc5(%rip),%rdx        # 34c1 <_ZStL19piecewise_construct+0x4b9>
    26fc:	89 ce                	mov    %ecx,%esi
    26fe:	89 c7                	mov    %eax,%edi
    2700:	b8 00 00 00 00       	mov    $0x0,%eax
    2705:	e8 b6 ec ff ff       	callq  13c0 <mvprintw@plt>
    270a:	8b 45 fc             	mov    -0x4(%rbp),%eax
    270d:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    2710:	7e 74                	jle    2786 <_Z8drawPipeiiii+0x131>
    2712:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2715:	83 c0 01             	add    $0x1,%eax
    2718:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    271b:	75 20                	jne    273d <_Z8drawPipeiiii+0xe8>
    271d:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2720:	8d 48 f7             	lea    -0x9(%rax),%ecx
    2723:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2726:	48 8d 15 80 0d 00 00 	lea    0xd80(%rip),%rdx        # 34ad <_ZStL19piecewise_construct+0x4a5>
    272d:	89 ce                	mov    %ecx,%esi
    272f:	89 c7                	mov    %eax,%edi
    2731:	b8 00 00 00 00       	mov    $0x0,%eax
    2736:	e8 85 ec ff ff       	callq  13c0 <mvprintw@plt>
    273b:	eb 49                	jmp    2786 <_Z8drawPipeiiii+0x131>
    273d:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2740:	83 c0 02             	add    $0x2,%eax
    2743:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    2746:	75 20                	jne    2768 <_Z8drawPipeiiii+0x113>
    2748:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    274b:	8d 48 f7             	lea    -0x9(%rax),%ecx
    274e:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2751:	48 8d 15 72 0d 00 00 	lea    0xd72(%rip),%rdx        # 34ca <_ZStL19piecewise_construct+0x4c2>
    2758:	89 ce                	mov    %ecx,%esi
    275a:	89 c7                	mov    %eax,%edi
    275c:	b8 00 00 00 00       	mov    $0x0,%eax
    2761:	e8 5a ec ff ff       	callq  13c0 <mvprintw@plt>
    2766:	eb 1e                	jmp    2786 <_Z8drawPipeiiii+0x131>
    2768:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    276b:	8d 48 f8             	lea    -0x8(%rax),%ecx
    276e:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2771:	48 8d 15 49 0d 00 00 	lea    0xd49(%rip),%rdx        # 34c1 <_ZStL19piecewise_construct+0x4b9>
    2778:	89 ce                	mov    %ecx,%esi
    277a:	89 c7                	mov    %eax,%edi
    277c:	b8 00 00 00 00       	mov    $0x0,%eax
    2781:	e8 3a ec ff ff       	callq  13c0 <mvprintw@plt>
    2786:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    278a:	e9 e5 fe ff ff       	jmpq   2674 <_Z8drawPipeiiii+0x1f>
    278f:	90                   	nop
    2790:	c9                   	leaveq 
    2791:	c3                   	retq   

0000000000002792 <_Z12drawStartingii>:
    2792:	f3 0f 1e fa          	endbr64 
    2796:	55                   	push   %rbp
    2797:	48 89 e5             	mov    %rsp,%rbp
    279a:	48 83 ec 20          	sub    $0x20,%rsp
    279e:	89 7d ec             	mov    %edi,-0x14(%rbp)
    27a1:	89 75 e8             	mov    %esi,-0x18(%rbp)
    27a4:	e8 97 ec ff ff       	callq  1440 <clear@plt>
    27a9:	48 8b 05 60 28 00 00 	mov    0x2860(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    27b0:	ba 00 00 00 00       	mov    $0x0,%edx
    27b5:	be 00 06 20 00       	mov    $0x200600,%esi
    27ba:	48 89 c7             	mov    %rax,%rdi
    27bd:	e8 0e eb ff ff       	callq  12d0 <wattr_on@plt>
    27c2:	8b 45 e8             	mov    -0x18(%rbp),%eax
    27c5:	83 e8 30             	sub    $0x30,%eax
    27c8:	89 c2                	mov    %eax,%edx
    27ca:	c1 ea 1f             	shr    $0x1f,%edx
    27cd:	01 d0                	add    %edx,%eax
    27cf:	d1 f8                	sar    %eax
    27d1:	89 c1                	mov    %eax,%ecx
    27d3:	8b 45 ec             	mov    -0x14(%rbp),%eax
    27d6:	89 c2                	mov    %eax,%edx
    27d8:	c1 ea 1f             	shr    $0x1f,%edx
    27db:	01 d0                	add    %edx,%eax
    27dd:	d1 f8                	sar    %eax
    27df:	83 e8 0a             	sub    $0xa,%eax
    27e2:	48 8d 15 ef 0c 00 00 	lea    0xcef(%rip),%rdx        # 34d8 <_ZStL19piecewise_construct+0x4d0>
    27e9:	89 ce                	mov    %ecx,%esi
    27eb:	89 c7                	mov    %eax,%edi
    27ed:	b8 00 00 00 00       	mov    $0x0,%eax
    27f2:	e8 c9 eb ff ff       	callq  13c0 <mvprintw@plt>
    27f7:	8b 45 e8             	mov    -0x18(%rbp),%eax
    27fa:	83 e8 30             	sub    $0x30,%eax
    27fd:	89 c2                	mov    %eax,%edx
    27ff:	c1 ea 1f             	shr    $0x1f,%edx
    2802:	01 d0                	add    %edx,%eax
    2804:	d1 f8                	sar    %eax
    2806:	89 c1                	mov    %eax,%ecx
    2808:	8b 45 ec             	mov    -0x14(%rbp),%eax
    280b:	89 c2                	mov    %eax,%edx
    280d:	c1 ea 1f             	shr    $0x1f,%edx
    2810:	01 d0                	add    %edx,%eax
    2812:	d1 f8                	sar    %eax
    2814:	83 e8 09             	sub    $0x9,%eax
    2817:	48 8d 15 f2 0c 00 00 	lea    0xcf2(%rip),%rdx        # 3510 <_ZStL19piecewise_construct+0x508>
    281e:	89 ce                	mov    %ecx,%esi
    2820:	89 c7                	mov    %eax,%edi
    2822:	b8 00 00 00 00       	mov    $0x0,%eax
    2827:	e8 94 eb ff ff       	callq  13c0 <mvprintw@plt>
    282c:	8b 45 e8             	mov    -0x18(%rbp),%eax
    282f:	83 e8 30             	sub    $0x30,%eax
    2832:	89 c2                	mov    %eax,%edx
    2834:	c1 ea 1f             	shr    $0x1f,%edx
    2837:	01 d0                	add    %edx,%eax
    2839:	d1 f8                	sar    %eax
    283b:	89 c1                	mov    %eax,%ecx
    283d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2840:	89 c2                	mov    %eax,%edx
    2842:	c1 ea 1f             	shr    $0x1f,%edx
    2845:	01 d0                	add    %edx,%eax
    2847:	d1 f8                	sar    %eax
    2849:	83 e8 08             	sub    $0x8,%eax
    284c:	48 8d 15 f5 0c 00 00 	lea    0xcf5(%rip),%rdx        # 3548 <_ZStL19piecewise_construct+0x540>
    2853:	89 ce                	mov    %ecx,%esi
    2855:	89 c7                	mov    %eax,%edi
    2857:	b8 00 00 00 00       	mov    $0x0,%eax
    285c:	e8 5f eb ff ff       	callq  13c0 <mvprintw@plt>
    2861:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2864:	83 e8 30             	sub    $0x30,%eax
    2867:	89 c2                	mov    %eax,%edx
    2869:	c1 ea 1f             	shr    $0x1f,%edx
    286c:	01 d0                	add    %edx,%eax
    286e:	d1 f8                	sar    %eax
    2870:	89 c1                	mov    %eax,%ecx
    2872:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2875:	89 c2                	mov    %eax,%edx
    2877:	c1 ea 1f             	shr    $0x1f,%edx
    287a:	01 d0                	add    %edx,%eax
    287c:	d1 f8                	sar    %eax
    287e:	83 e8 07             	sub    $0x7,%eax
    2881:	48 8d 15 f8 0c 00 00 	lea    0xcf8(%rip),%rdx        # 3580 <_ZStL19piecewise_construct+0x578>
    2888:	89 ce                	mov    %ecx,%esi
    288a:	89 c7                	mov    %eax,%edi
    288c:	b8 00 00 00 00       	mov    $0x0,%eax
    2891:	e8 2a eb ff ff       	callq  13c0 <mvprintw@plt>
    2896:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2899:	83 e8 30             	sub    $0x30,%eax
    289c:	89 c2                	mov    %eax,%edx
    289e:	c1 ea 1f             	shr    $0x1f,%edx
    28a1:	01 d0                	add    %edx,%eax
    28a3:	d1 f8                	sar    %eax
    28a5:	89 c1                	mov    %eax,%ecx
    28a7:	8b 45 ec             	mov    -0x14(%rbp),%eax
    28aa:	89 c2                	mov    %eax,%edx
    28ac:	c1 ea 1f             	shr    $0x1f,%edx
    28af:	01 d0                	add    %edx,%eax
    28b1:	d1 f8                	sar    %eax
    28b3:	83 e8 06             	sub    $0x6,%eax
    28b6:	48 8d 15 fb 0c 00 00 	lea    0xcfb(%rip),%rdx        # 35b8 <_ZStL19piecewise_construct+0x5b0>
    28bd:	89 ce                	mov    %ecx,%esi
    28bf:	89 c7                	mov    %eax,%edi
    28c1:	b8 00 00 00 00       	mov    $0x0,%eax
    28c6:	e8 f5 ea ff ff       	callq  13c0 <mvprintw@plt>
    28cb:	8b 45 e8             	mov    -0x18(%rbp),%eax
    28ce:	83 e8 30             	sub    $0x30,%eax
    28d1:	89 c2                	mov    %eax,%edx
    28d3:	c1 ea 1f             	shr    $0x1f,%edx
    28d6:	01 d0                	add    %edx,%eax
    28d8:	d1 f8                	sar    %eax
    28da:	89 c1                	mov    %eax,%ecx
    28dc:	8b 45 ec             	mov    -0x14(%rbp),%eax
    28df:	89 c2                	mov    %eax,%edx
    28e1:	c1 ea 1f             	shr    $0x1f,%edx
    28e4:	01 d0                	add    %edx,%eax
    28e6:	d1 f8                	sar    %eax
    28e8:	83 e8 05             	sub    $0x5,%eax
    28eb:	48 8d 15 fe 0c 00 00 	lea    0xcfe(%rip),%rdx        # 35f0 <_ZStL19piecewise_construct+0x5e8>
    28f2:	89 ce                	mov    %ecx,%esi
    28f4:	89 c7                	mov    %eax,%edi
    28f6:	b8 00 00 00 00       	mov    $0x0,%eax
    28fb:	e8 c0 ea ff ff       	callq  13c0 <mvprintw@plt>
    2900:	48 8b 05 09 27 00 00 	mov    0x2709(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    2907:	ba 00 00 00 00       	mov    $0x0,%edx
    290c:	be 00 06 20 00       	mov    $0x200600,%esi
    2911:	48 89 c7             	mov    %rax,%rdi
    2914:	e8 97 ea ff ff       	callq  13b0 <wattr_off@plt>
    2919:	8b 45 e8             	mov    -0x18(%rbp),%eax
    291c:	83 e8 05             	sub    $0x5,%eax
    291f:	89 c2                	mov    %eax,%edx
    2921:	c1 ea 1f             	shr    $0x1f,%edx
    2924:	01 d0                	add    %edx,%eax
    2926:	d1 f8                	sar    %eax
    2928:	8d 48 03             	lea    0x3(%rax),%ecx
    292b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    292e:	89 c2                	mov    %eax,%edx
    2930:	c1 ea 1f             	shr    $0x1f,%edx
    2933:	01 d0                	add    %edx,%eax
    2935:	d1 f8                	sar    %eax
    2937:	83 c0 01             	add    $0x1,%eax
    293a:	48 8d 15 e0 0c 00 00 	lea    0xce0(%rip),%rdx        # 3621 <_ZStL19piecewise_construct+0x619>
    2941:	89 ce                	mov    %ecx,%esi
    2943:	89 c7                	mov    %eax,%edi
    2945:	b8 00 00 00 00       	mov    $0x0,%eax
    294a:	e8 71 ea ff ff       	callq  13c0 <mvprintw@plt>
    294f:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2952:	83 e8 05             	sub    $0x5,%eax
    2955:	89 c2                	mov    %eax,%edx
    2957:	c1 ea 1f             	shr    $0x1f,%edx
    295a:	01 d0                	add    %edx,%eax
    295c:	d1 f8                	sar    %eax
    295e:	8d 48 ff             	lea    -0x1(%rax),%ecx
    2961:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2964:	89 c2                	mov    %eax,%edx
    2966:	c1 ea 1f             	shr    $0x1f,%edx
    2969:	01 d0                	add    %edx,%eax
    296b:	d1 f8                	sar    %eax
    296d:	83 c0 01             	add    $0x1,%eax
    2970:	48 8d 15 ac 0c 00 00 	lea    0xcac(%rip),%rdx        # 3623 <_ZStL19piecewise_construct+0x61b>
    2977:	89 ce                	mov    %ecx,%esi
    2979:	89 c7                	mov    %eax,%edi
    297b:	b8 00 00 00 00       	mov    $0x0,%eax
    2980:	e8 3b ea ff ff       	callq  13c0 <mvprintw@plt>
    2985:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2988:	83 e8 22             	sub    $0x22,%eax
    298b:	89 c2                	mov    %eax,%edx
    298d:	c1 ea 1f             	shr    $0x1f,%edx
    2990:	01 d0                	add    %edx,%eax
    2992:	d1 f8                	sar    %eax
    2994:	89 c1                	mov    %eax,%ecx
    2996:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2999:	89 c2                	mov    %eax,%edx
    299b:	c1 ea 1f             	shr    $0x1f,%edx
    299e:	01 d0                	add    %edx,%eax
    29a0:	d1 f8                	sar    %eax
    29a2:	83 c0 03             	add    $0x3,%eax
    29a5:	48 8d 15 7c 0c 00 00 	lea    0xc7c(%rip),%rdx        # 3628 <_ZStL19piecewise_construct+0x620>
    29ac:	89 ce                	mov    %ecx,%esi
    29ae:	89 c7                	mov    %eax,%edi
    29b0:	b8 00 00 00 00       	mov    $0x0,%eax
    29b5:	e8 06 ea ff ff       	callq  13c0 <mvprintw@plt>
    29ba:	c7 45 f8 01 00 00 00 	movl   $0x1,-0x8(%rbp)
    29c1:	83 7d f8 03          	cmpl   $0x3,-0x8(%rbp)
    29c5:	7f 66                	jg     2a2d <_Z12drawStartingii+0x29b>
    29c7:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    29ce:	8b 45 fc             	mov    -0x4(%rbp),%eax
    29d1:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    29d4:	7d 47                	jge    2a1d <_Z12drawStartingii+0x28b>
    29d6:	8b 45 e8             	mov    -0x18(%rbp),%eax
    29d9:	83 e8 05             	sub    $0x5,%eax
    29dc:	89 c2                	mov    %eax,%edx
    29de:	c1 ea 1f             	shr    $0x1f,%edx
    29e1:	01 d0                	add    %edx,%eax
    29e3:	d1 f8                	sar    %eax
    29e5:	8d 50 ff             	lea    -0x1(%rax),%edx
    29e8:	8b 45 f8             	mov    -0x8(%rbp),%eax
    29eb:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
    29ee:	8b 45 ec             	mov    -0x14(%rbp),%eax
    29f1:	89 c2                	mov    %eax,%edx
    29f3:	c1 ea 1f             	shr    $0x1f,%edx
    29f6:	01 d0                	add    %edx,%eax
    29f8:	d1 f8                	sar    %eax
    29fa:	83 c0 01             	add    $0x1,%eax
    29fd:	48 8d 15 1d 06 00 00 	lea    0x61d(%rip),%rdx        # 3021 <_ZStL19piecewise_construct+0x19>
    2a04:	89 ce                	mov    %ecx,%esi
    2a06:	89 c7                	mov    %eax,%edi
    2a08:	b8 00 00 00 00       	mov    $0x0,%eax
    2a0d:	e8 ae e9 ff ff       	callq  13c0 <mvprintw@plt>
    2a12:	e8 19 ea ff ff       	callq  1430 <refresh@plt>
    2a17:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2a1b:	eb b1                	jmp    29ce <_Z12drawStartingii+0x23c>
    2a1d:	bf 01 00 00 00       	mov    $0x1,%edi
    2a22:	e8 b9 e8 ff ff       	callq  12e0 <sleep@plt>
    2a27:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    2a2b:	eb 94                	jmp    29c1 <_Z12drawStartingii+0x22f>
    2a2d:	90                   	nop
    2a2e:	c9                   	leaveq 
    2a2f:	c3                   	retq   

0000000000002a30 <_Z8readBestPiPc>:
    2a30:	f3 0f 1e fa          	endbr64 
    2a34:	55                   	push   %rbp
    2a35:	48 89 e5             	mov    %rsp,%rbp
    2a38:	48 83 ec 20          	sub    $0x20,%rsp
    2a3c:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    2a40:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    2a44:	48 8d 35 00 0c 00 00 	lea    0xc00(%rip),%rsi        # 364b <_ZStL19piecewise_construct+0x643>
    2a4b:	48 8d 3d f2 06 00 00 	lea    0x6f2(%rip),%rdi        # 3144 <_ZStL19piecewise_construct+0x13c>
    2a52:	e8 49 e9 ff ff       	callq  13a0 <fopen@plt>
    2a57:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2a5b:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    2a60:	74 46                	je     2aa8 <_Z8readBestPiPc+0x78>
    2a62:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2a66:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a6a:	48 89 d1             	mov    %rdx,%rcx
    2a6d:	ba 01 00 00 00       	mov    $0x1,%edx
    2a72:	be 04 00 00 00       	mov    $0x4,%esi
    2a77:	48 89 c7             	mov    %rax,%rdi
    2a7a:	e8 91 e9 ff ff       	callq  1410 <fread@plt>
    2a7f:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2a83:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2a87:	48 89 d1             	mov    %rdx,%rcx
    2a8a:	ba 01 00 00 00       	mov    $0x1,%edx
    2a8f:	be 64 00 00 00       	mov    $0x64,%esi
    2a94:	48 89 c7             	mov    %rax,%rdi
    2a97:	e8 74 e9 ff ff       	callq  1410 <fread@plt>
    2a9c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2aa0:	48 89 c7             	mov    %rax,%rdi
    2aa3:	e8 98 e8 ff ff       	callq  1340 <fclose@plt>
    2aa8:	90                   	nop
    2aa9:	c9                   	leaveq 
    2aaa:	c3                   	retq   

0000000000002aab <_Z9writeBestiPKc>:
    2aab:	f3 0f 1e fa          	endbr64 
    2aaf:	55                   	push   %rbp
    2ab0:	48 89 e5             	mov    %rsp,%rbp
    2ab3:	48 83 ec 20          	sub    $0x20,%rsp
    2ab7:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2aba:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    2abe:	48 8d 35 89 0b 00 00 	lea    0xb89(%rip),%rsi        # 364e <_ZStL19piecewise_construct+0x646>
    2ac5:	48 8d 3d 78 06 00 00 	lea    0x678(%rip),%rdi        # 3144 <_ZStL19piecewise_construct+0x13c>
    2acc:	e8 cf e8 ff ff       	callq  13a0 <fopen@plt>
    2ad1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2ad5:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2ad9:	48 8d 45 ec          	lea    -0x14(%rbp),%rax
    2add:	48 89 d1             	mov    %rdx,%rcx
    2ae0:	ba 01 00 00 00       	mov    $0x1,%edx
    2ae5:	be 04 00 00 00       	mov    $0x4,%esi
    2aea:	48 89 c7             	mov    %rax,%rdi
    2aed:	e8 5e e9 ff ff       	callq  1450 <fwrite@plt>
    2af2:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2af6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2afa:	48 89 d1             	mov    %rdx,%rcx
    2afd:	ba 01 00 00 00       	mov    $0x1,%edx
    2b02:	be 64 00 00 00       	mov    $0x64,%esi
    2b07:	48 89 c7             	mov    %rax,%rdi
    2b0a:	e8 41 e9 ff ff       	callq  1450 <fwrite@plt>
    2b0f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b13:	48 89 c7             	mov    %rax,%rdi
    2b16:	e8 25 e8 ff ff       	callq  1340 <fclose@plt>
    2b1b:	90                   	nop
    2b1c:	c9                   	leaveq 
    2b1d:	c3                   	retq   

0000000000002b1e <_Z15getNewPipeValuePiS_i>:
    2b1e:	f3 0f 1e fa          	endbr64 
    2b22:	55                   	push   %rbp
    2b23:	48 89 e5             	mov    %rsp,%rbp
    2b26:	48 83 ec 20          	sub    $0x20,%rsp
    2b2a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2b2e:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    2b32:	89 55 ec             	mov    %edx,-0x14(%rbp)
    2b35:	e8 46 e7 ff ff       	callq  1280 <rand@plt>
    2b3a:	99                   	cltd   
    2b3b:	f7 7d ec             	idivl  -0x14(%rbp)
    2b3e:	89 d0                	mov    %edx,%eax
    2b40:	89 c2                	mov    %eax,%edx
    2b42:	c1 ea 1f             	shr    $0x1f,%edx
    2b45:	01 d0                	add    %edx,%eax
    2b47:	d1 f8                	sar    %eax
    2b49:	8d 50 03             	lea    0x3(%rax),%edx
    2b4c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b50:	89 10                	mov    %edx,(%rax)
    2b52:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b56:	8b 00                	mov    (%rax),%eax
    2b58:	8d 50 04             	lea    0x4(%rax),%edx
    2b5b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2b5f:	89 10                	mov    %edx,(%rax)
    2b61:	90                   	nop
    2b62:	c9                   	leaveq 
    2b63:	c3                   	retq   

0000000000002b64 <_Z41__static_initialization_and_destruction_0ii>:
    2b64:	f3 0f 1e fa          	endbr64 
    2b68:	55                   	push   %rbp
    2b69:	48 89 e5             	mov    %rsp,%rbp
    2b6c:	48 83 ec 10          	sub    $0x10,%rsp
    2b70:	89 7d fc             	mov    %edi,-0x4(%rbp)
    2b73:	89 75 f8             	mov    %esi,-0x8(%rbp)
    2b76:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    2b7a:	75 32                	jne    2bae <_Z41__static_initialization_and_destruction_0ii+0x4a>
    2b7c:	81 7d f8 ff ff 00 00 	cmpl   $0xffff,-0x8(%rbp)
    2b83:	75 29                	jne    2bae <_Z41__static_initialization_and_destruction_0ii+0x4a>
    2b85:	48 8d 3d 8d 24 00 00 	lea    0x248d(%rip),%rdi        # 5019 <_ZStL8__ioinit>
    2b8c:	e8 8f e8 ff ff       	callq  1420 <_ZNSt8ios_base4InitC1Ev@plt>
    2b91:	48 8d 15 70 24 00 00 	lea    0x2470(%rip),%rdx        # 5008 <__dso_handle>
    2b98:	48 8d 35 7a 24 00 00 	lea    0x247a(%rip),%rsi        # 5019 <_ZStL8__ioinit>
    2b9f:	48 8b 05 52 24 00 00 	mov    0x2452(%rip),%rax        # 4ff8 <_ZNSt8ios_base4InitD1Ev@GLIBCXX_3.4>
    2ba6:	48 89 c7             	mov    %rax,%rdi
    2ba9:	e8 52 e7 ff ff       	callq  1300 <__cxa_atexit@plt>
    2bae:	90                   	nop
    2baf:	c9                   	leaveq 
    2bb0:	c3                   	retq   

0000000000002bb1 <_GLOBAL__sub_I_main>:
    2bb1:	f3 0f 1e fa          	endbr64 
    2bb5:	55                   	push   %rbp
    2bb6:	48 89 e5             	mov    %rsp,%rbp
    2bb9:	be ff ff 00 00       	mov    $0xffff,%esi
    2bbe:	bf 01 00 00 00       	mov    $0x1,%edi
    2bc3:	e8 9c ff ff ff       	callq  2b64 <_Z41__static_initialization_and_destruction_0ii>
    2bc8:	5d                   	pop    %rbp
    2bc9:	c3                   	retq   
    2bca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000002bd0 <__libc_csu_init>:
    2bd0:	f3 0f 1e fa          	endbr64 
    2bd4:	41 57                	push   %r15
    2bd6:	4c 8d 3d 9b 20 00 00 	lea    0x209b(%rip),%r15        # 4c78 <__frame_dummy_init_array_entry>
    2bdd:	41 56                	push   %r14
    2bdf:	49 89 d6             	mov    %rdx,%r14
    2be2:	41 55                	push   %r13
    2be4:	49 89 f5             	mov    %rsi,%r13
    2be7:	41 54                	push   %r12
    2be9:	41 89 fc             	mov    %edi,%r12d
    2bec:	55                   	push   %rbp
    2bed:	48 8d 2d 94 20 00 00 	lea    0x2094(%rip),%rbp        # 4c88 <__do_global_dtors_aux_fini_array_entry>
    2bf4:	53                   	push   %rbx
    2bf5:	4c 29 fd             	sub    %r15,%rbp
    2bf8:	48 83 ec 08          	sub    $0x8,%rsp
    2bfc:	e8 ff e3 ff ff       	callq  1000 <_init>
    2c01:	48 c1 fd 03          	sar    $0x3,%rbp
    2c05:	74 1f                	je     2c26 <__libc_csu_init+0x56>
    2c07:	31 db                	xor    %ebx,%ebx
    2c09:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    2c10:	4c 89 f2             	mov    %r14,%rdx
    2c13:	4c 89 ee             	mov    %r13,%rsi
    2c16:	44 89 e7             	mov    %r12d,%edi
    2c19:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    2c1d:	48 83 c3 01          	add    $0x1,%rbx
    2c21:	48 39 dd             	cmp    %rbx,%rbp
    2c24:	75 ea                	jne    2c10 <__libc_csu_init+0x40>
    2c26:	48 83 c4 08          	add    $0x8,%rsp
    2c2a:	5b                   	pop    %rbx
    2c2b:	5d                   	pop    %rbp
    2c2c:	41 5c                	pop    %r12
    2c2e:	41 5d                	pop    %r13
    2c30:	41 5e                	pop    %r14
    2c32:	41 5f                	pop    %r15
    2c34:	c3                   	retq   
    2c35:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    2c3c:	00 00 00 00 

0000000000002c40 <__libc_csu_fini>:
    2c40:	f3 0f 1e fa          	endbr64 
    2c44:	c3                   	retq   

Disassembly of section .fini:

0000000000002c48 <_fini>:
    2c48:	f3 0f 1e fa          	endbr64 
    2c4c:	48 83 ec 08          	sub    $0x8,%rsp
    2c50:	48 83 c4 08          	add    $0x8,%rsp
    2c54:	c3                   	retq   
