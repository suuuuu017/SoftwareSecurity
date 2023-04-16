
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
    1020:	ff 35 9a 3e 00 00    	pushq  0x3e9a(%rip)        # 4ec0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 9b 3e 00 00 	bnd jmpq *0x3e9b(%rip)        # 4ec8 <_GLOBAL_OFFSET_TABLE_+0x10>
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

Disassembly of section .plt.got:

0000000000001230 <__cxa_finalize@plt>:
    1230:	f3 0f 1e fa          	endbr64 
    1234:	f2 ff 25 95 3d 00 00 	bnd jmpq *0x3d95(%rip)        # 4fd0 <__cxa_finalize@GLIBC_2.2.5>
    123b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001240 <init_pair@plt>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	f2 ff 25 85 3c 00 00 	bnd jmpq *0x3c85(%rip)        # 4ed0 <init_pair@NCURSES6_5.0.19991023>
    124b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001250 <start_color@plt>:
    1250:	f3 0f 1e fa          	endbr64 
    1254:	f2 ff 25 7d 3c 00 00 	bnd jmpq *0x3c7d(%rip)        # 4ed8 <start_color@NCURSES6_5.0.19991023>
    125b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001260 <rand@plt>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	f2 ff 25 75 3c 00 00 	bnd jmpq *0x3c75(%rip)        # 4ee0 <rand@GLIBC_2.2.5>
    126b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001270 <waddch@plt>:
    1270:	f3 0f 1e fa          	endbr64 
    1274:	f2 ff 25 6d 3c 00 00 	bnd jmpq *0x3c6d(%rip)        # 4ee8 <waddch@NCURSES6_5.0.19991023>
    127b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001280 <wgetch@plt>:
    1280:	f3 0f 1e fa          	endbr64 
    1284:	f2 ff 25 65 3c 00 00 	bnd jmpq *0x3c65(%rip)        # 4ef0 <wgetch@NCURSES6_5.0.19991023>
    128b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001290 <keypad@plt>:
    1290:	f3 0f 1e fa          	endbr64 
    1294:	f2 ff 25 5d 3c 00 00 	bnd jmpq *0x3c5d(%rip)        # 4ef8 <keypad@NCURSES6_TINFO_5.0.19991023>
    129b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012a0 <assume_default_colors@plt>:
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	f2 ff 25 55 3c 00 00 	bnd jmpq *0x3c55(%rip)        # 4f00 <assume_default_colors@NCURSES6_5.1.20000708>
    12ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012b0 <wattr_on@plt>:
    12b0:	f3 0f 1e fa          	endbr64 
    12b4:	f2 ff 25 4d 3c 00 00 	bnd jmpq *0x3c4d(%rip)        # 4f08 <wattr_on@NCURSES6_5.0.19991023>
    12bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012c0 <sleep@plt>:
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	f2 ff 25 45 3c 00 00 	bnd jmpq *0x3c45(%rip)        # 4f10 <sleep@GLIBC_2.2.5>
    12cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012d0 <curs_set@plt>:
    12d0:	f3 0f 1e fa          	endbr64 
    12d4:	f2 ff 25 3d 3c 00 00 	bnd jmpq *0x3c3d(%rip)        # 4f18 <curs_set@NCURSES6_TINFO_5.0.19991023>
    12db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012e0 <__cxa_atexit@plt>:
    12e0:	f3 0f 1e fa          	endbr64 
    12e4:	f2 ff 25 35 3c 00 00 	bnd jmpq *0x3c35(%rip)        # 4f20 <__cxa_atexit@GLIBC_2.2.5>
    12eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012f0 <time@plt>:
    12f0:	f3 0f 1e fa          	endbr64 
    12f4:	f2 ff 25 2d 3c 00 00 	bnd jmpq *0x3c2d(%rip)        # 4f28 <time@GLIBC_2.2.5>
    12fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001300 <strcpy@plt>:
    1300:	f3 0f 1e fa          	endbr64 
    1304:	f2 ff 25 25 3c 00 00 	bnd jmpq *0x3c25(%rip)        # 4f30 <strcpy@GLIBC_2.2.5>
    130b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001310 <srand@plt>:
    1310:	f3 0f 1e fa          	endbr64 
    1314:	f2 ff 25 1d 3c 00 00 	bnd jmpq *0x3c1d(%rip)        # 4f38 <srand@GLIBC_2.2.5>
    131b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001320 <fclose@plt>:
    1320:	f3 0f 1e fa          	endbr64 
    1324:	f2 ff 25 15 3c 00 00 	bnd jmpq *0x3c15(%rip)        # 4f40 <fclose@GLIBC_2.2.5>
    132b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001330 <wmove@plt>:
    1330:	f3 0f 1e fa          	endbr64 
    1334:	f2 ff 25 0d 3c 00 00 	bnd jmpq *0x3c0d(%rip)        # 4f48 <wmove@NCURSES6_5.0.19991023>
    133b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001340 <__stack_chk_fail@plt>:
    1340:	f3 0f 1e fa          	endbr64 
    1344:	f2 ff 25 05 3c 00 00 	bnd jmpq *0x3c05(%rip)        # 4f50 <__stack_chk_fail@GLIBC_2.4>
    134b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001350 <noecho@plt>:
    1350:	f3 0f 1e fa          	endbr64 
    1354:	f2 ff 25 fd 3b 00 00 	bnd jmpq *0x3bfd(%rip)        # 4f58 <noecho@NCURSES6_5.0.19991023>
    135b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001360 <wtimeout@plt>:
    1360:	f3 0f 1e fa          	endbr64 
    1364:	f2 ff 25 f5 3b 00 00 	bnd jmpq *0x3bf5(%rip)        # 4f60 <wtimeout@NCURSES6_TINFO_5.0.19991023>
    136b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001370 <endwin@plt>:
    1370:	f3 0f 1e fa          	endbr64 
    1374:	f2 ff 25 ed 3b 00 00 	bnd jmpq *0x3bed(%rip)        # 4f68 <endwin@NCURSES6_5.0.19991023>
    137b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001380 <fopen@plt>:
    1380:	f3 0f 1e fa          	endbr64 
    1384:	f2 ff 25 e5 3b 00 00 	bnd jmpq *0x3be5(%rip)        # 4f70 <fopen@GLIBC_2.2.5>
    138b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001390 <wattr_off@plt>:
    1390:	f3 0f 1e fa          	endbr64 
    1394:	f2 ff 25 dd 3b 00 00 	bnd jmpq *0x3bdd(%rip)        # 4f78 <wattr_off@NCURSES6_5.0.19991023>
    139b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013a0 <mvprintw@plt>:
    13a0:	f3 0f 1e fa          	endbr64 
    13a4:	f2 ff 25 d5 3b 00 00 	bnd jmpq *0x3bd5(%rip)        # 4f80 <mvprintw@NCURSES6_5.0.19991023>
    13ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013b0 <getchar@plt>:
    13b0:	f3 0f 1e fa          	endbr64 
    13b4:	f2 ff 25 cd 3b 00 00 	bnd jmpq *0x3bcd(%rip)        # 4f88 <getchar@GLIBC_2.2.5>
    13bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013c0 <usleep@plt>:
    13c0:	f3 0f 1e fa          	endbr64 
    13c4:	f2 ff 25 c5 3b 00 00 	bnd jmpq *0x3bc5(%rip)        # 4f90 <usleep@GLIBC_2.2.5>
    13cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013d0 <initscr@plt>:
    13d0:	f3 0f 1e fa          	endbr64 
    13d4:	f2 ff 25 bd 3b 00 00 	bnd jmpq *0x3bbd(%rip)        # 4f98 <initscr@NCURSES6_5.0.19991023>
    13db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013e0 <wgetnstr@plt>:
    13e0:	f3 0f 1e fa          	endbr64 
    13e4:	f2 ff 25 b5 3b 00 00 	bnd jmpq *0x3bb5(%rip)        # 4fa0 <wgetnstr@NCURSES6_5.0.19991023>
    13eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000013f0 <fread@plt>:
    13f0:	f3 0f 1e fa          	endbr64 
    13f4:	f2 ff 25 ad 3b 00 00 	bnd jmpq *0x3bad(%rip)        # 4fa8 <fread@GLIBC_2.2.5>
    13fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001400 <_ZNSt8ios_base4InitC1Ev@plt>:
    1400:	f3 0f 1e fa          	endbr64 
    1404:	f2 ff 25 a5 3b 00 00 	bnd jmpq *0x3ba5(%rip)        # 4fb0 <_ZNSt8ios_base4InitC1Ev@GLIBCXX_3.4>
    140b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001410 <refresh@plt>:
    1410:	f3 0f 1e fa          	endbr64 
    1414:	f2 ff 25 9d 3b 00 00 	bnd jmpq *0x3b9d(%rip)        # 4fb8 <refresh@NCURSES6_5.0.19991023>
    141b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001420 <clear@plt>:
    1420:	f3 0f 1e fa          	endbr64 
    1424:	f2 ff 25 95 3b 00 00 	bnd jmpq *0x3b95(%rip)        # 4fc0 <clear@NCURSES6_5.0.19991023>
    142b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001430 <fwrite@plt>:
    1430:	f3 0f 1e fa          	endbr64 
    1434:	f2 ff 25 8d 3b 00 00 	bnd jmpq *0x3b8d(%rip)        # 4fc8 <fwrite@GLIBC_2.2.5>
    143b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001440 <_start>:
    1440:	f3 0f 1e fa          	endbr64 
    1444:	31 ed                	xor    %ebp,%ebp
    1446:	49 89 d1             	mov    %rdx,%r9
    1449:	5e                   	pop    %rsi
    144a:	48 89 e2             	mov    %rsp,%rdx
    144d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1451:	50                   	push   %rax
    1452:	54                   	push   %rsp
    1453:	4c 8d 05 b6 17 00 00 	lea    0x17b6(%rip),%r8        # 2c10 <__libc_csu_fini>
    145a:	48 8d 0d 3f 17 00 00 	lea    0x173f(%rip),%rcx        # 2ba0 <__libc_csu_init>
    1461:	48 8d 3d c1 00 00 00 	lea    0xc1(%rip),%rdi        # 1529 <main>
    1468:	ff 15 72 3b 00 00    	callq  *0x3b72(%rip)        # 4fe0 <__libc_start_main@GLIBC_2.2.5>
    146e:	f4                   	hlt    
    146f:	90                   	nop

0000000000001470 <deregister_tm_clones>:
    1470:	48 8d 3d 99 3b 00 00 	lea    0x3b99(%rip),%rdi        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1477:	48 8d 05 92 3b 00 00 	lea    0x3b92(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    147e:	48 39 f8             	cmp    %rdi,%rax
    1481:	74 15                	je     1498 <deregister_tm_clones+0x28>
    1483:	48 8b 05 4e 3b 00 00 	mov    0x3b4e(%rip),%rax        # 4fd8 <_ITM_deregisterTMCloneTable>
    148a:	48 85 c0             	test   %rax,%rax
    148d:	74 09                	je     1498 <deregister_tm_clones+0x28>
    148f:	ff e0                	jmpq   *%rax
    1491:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1498:	c3                   	retq   
    1499:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000014a0 <register_tm_clones>:
    14a0:	48 8d 3d 69 3b 00 00 	lea    0x3b69(%rip),%rdi        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    14a7:	48 8d 35 62 3b 00 00 	lea    0x3b62(%rip),%rsi        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    14ae:	48 29 fe             	sub    %rdi,%rsi
    14b1:	48 89 f0             	mov    %rsi,%rax
    14b4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    14b8:	48 c1 f8 03          	sar    $0x3,%rax
    14bc:	48 01 c6             	add    %rax,%rsi
    14bf:	48 d1 fe             	sar    %rsi
    14c2:	74 14                	je     14d8 <register_tm_clones+0x38>
    14c4:	48 8b 05 25 3b 00 00 	mov    0x3b25(%rip),%rax        # 4ff0 <_ITM_registerTMCloneTable>
    14cb:	48 85 c0             	test   %rax,%rax
    14ce:	74 08                	je     14d8 <register_tm_clones+0x38>
    14d0:	ff e0                	jmpq   *%rax
    14d2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    14d8:	c3                   	retq   
    14d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000014e0 <__do_global_dtors_aux>:
    14e0:	f3 0f 1e fa          	endbr64 
    14e4:	80 3d 2d 3b 00 00 00 	cmpb   $0x0,0x3b2d(%rip)        # 5018 <completed.8061>
    14eb:	75 2b                	jne    1518 <__do_global_dtors_aux+0x38>
    14ed:	55                   	push   %rbp
    14ee:	48 83 3d da 3a 00 00 	cmpq   $0x0,0x3ada(%rip)        # 4fd0 <__cxa_finalize@GLIBC_2.2.5>
    14f5:	00 
    14f6:	48 89 e5             	mov    %rsp,%rbp
    14f9:	74 0c                	je     1507 <__do_global_dtors_aux+0x27>
    14fb:	48 8b 3d 06 3b 00 00 	mov    0x3b06(%rip),%rdi        # 5008 <__dso_handle>
    1502:	e8 29 fd ff ff       	callq  1230 <__cxa_finalize@plt>
    1507:	e8 64 ff ff ff       	callq  1470 <deregister_tm_clones>
    150c:	c6 05 05 3b 00 00 01 	movb   $0x1,0x3b05(%rip)        # 5018 <completed.8061>
    1513:	5d                   	pop    %rbp
    1514:	c3                   	retq   
    1515:	0f 1f 00             	nopl   (%rax)
    1518:	c3                   	retq   
    1519:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001520 <frame_dummy>:
    1520:	f3 0f 1e fa          	endbr64 
    1524:	e9 77 ff ff ff       	jmpq   14a0 <register_tm_clones>

0000000000001529 <main>:
void getPlayerName(char playerName);
void getNewPipeValue(int * crackStart, int * crackFinish, int row);
int controlCollision(int pipeCol, int birdCol, int birdRow, int crackStart,
					 int crackFinish);

int main() {
    1529:	f3 0f 1e fa          	endbr64 
    152d:	55                   	push   %rbp
    152e:	48 89 e5             	mov    %rsp,%rbp
    1531:	48 81 ec 40 01 00 00 	sub    $0x140,%rsp
    1538:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    153f:	00 00 
    1541:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1545:	31 c0                	xor    %eax,%eax
	srand(time(NULL));
    1547:	bf 00 00 00 00       	mov    $0x0,%edi
    154c:	e8 9f fd ff ff       	callq  12f0 <time@plt>
    1551:	89 c7                	mov    %eax,%edi
    1553:	e8 b8 fd ff ff       	callq  1310 <srand@plt>
	int score = 0, isScore = 0, bestScore = 0;
    1558:	c7 85 dc fe ff ff 00 	movl   $0x0,-0x124(%rbp)
    155f:	00 00 00 
    1562:	c7 85 e0 fe ff ff 00 	movl   $0x0,-0x120(%rbp)
    1569:	00 00 00 
    156c:	c7 85 c8 fe ff ff 00 	movl   $0x0,-0x138(%rbp)
    1573:	00 00 00 
	int isOver = 0, flag = -1;
    1576:	c7 85 e4 fe ff ff 00 	movl   $0x0,-0x11c(%rbp)
    157d:	00 00 00 
    1580:	c7 85 e8 fe ff ff ff 	movl   $0xffffffff,-0x118(%rbp)
    1587:	ff ff ff 
	;
	int crackStart1, crackFinish1, crackStart2, crackFinish2;
	int row, col, birdRow, birdCol, pipeCol1, pipeCol2;
	int pipeCounter, collision;
	int wait = WAIT_LIT;
    158a:	c7 85 fc fe ff ff b0 	movl   $0x1adb0,-0x104(%rbp)
    1591:	ad 01 00 
	int command;
	char playerName[NAME_SIZE], bestPlayerName[NAME_SIZE];
	char bird = '@', ch;
    1594:	c6 85 c7 fe ff ff 40 	movb   $0x40,-0x139(%rbp)

	readBest(&bestScore, bestPlayerName);
    159b:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    159f:	48 8d 85 c8 fe ff ff 	lea    -0x138(%rbp),%rax
    15a6:	48 89 d6             	mov    %rdx,%rsi
    15a9:	48 89 c7             	mov    %rax,%rdi
    15ac:	e8 49 14 00 00       	callq  29fa <_Z8readBestPiPc>

	initscr();
    15b1:	e8 1a fe ff ff       	callq  13d0 <initscr@plt>
	curs_set(0);
    15b6:	bf 00 00 00 00       	mov    $0x0,%edi
    15bb:	e8 10 fd ff ff       	callq  12d0 <curs_set@plt>
	keypad(stdscr, true);
    15c0:	48 8b 05 49 3a 00 00 	mov    0x3a49(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    15c7:	be 01 00 00 00       	mov    $0x1,%esi
    15cc:	48 89 c7             	mov    %rax,%rdi
    15cf:	e8 bc fc ff ff       	callq  1290 <keypad@plt>
	start_color();
    15d4:	e8 77 fc ff ff       	callq  1250 <start_color@plt>
	int mode = rand() % 2;
    15d9:	e8 82 fc ff ff       	callq  1260 <rand@plt>
    15de:	99                   	cltd   
    15df:	c1 ea 1f             	shr    $0x1f,%edx
    15e2:	01 d0                	add    %edx,%eax
    15e4:	83 e0 01             	and    $0x1,%eax
    15e7:	29 d0                	sub    %edx,%eax
    15e9:	89 85 04 ff ff ff    	mov    %eax,-0xfc(%rbp)
	// RANDOM FOREGROUND AND BACKGROUND COLORS
	if (mode == 0) {
    15ef:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    15f6:	75 11                	jne    1609 <main+0xe0>
		assume_default_colors(COLOR_BLACK, COLOR_CYAN);  // DAY MODE
    15f8:	be 06 00 00 00       	mov    $0x6,%esi
    15fd:	bf 00 00 00 00       	mov    $0x0,%edi
    1602:	e8 99 fc ff ff       	callq  12a0 <assume_default_colors@plt>
    1607:	eb 0f                	jmp    1618 <main+0xef>
	} else {
		assume_default_colors(COLOR_WHITE, COLOR_BLACK);  // NIGHT MODE
    1609:	be 00 00 00 00       	mov    $0x0,%esi
    160e:	bf 07 00 00 00       	mov    $0x7,%edi
    1613:	e8 88 fc ff ff       	callq  12a0 <assume_default_colors@plt>
	}
	init_pair(1, COLOR_BLACK, COLOR_GREEN);  // PIPE COLORS
    1618:	ba 02 00 00 00       	mov    $0x2,%edx
    161d:	be 00 00 00 00       	mov    $0x0,%esi
    1622:	bf 01 00 00 00       	mov    $0x1,%edi
    1627:	e8 14 fc ff ff       	callq  1240 <init_pair@plt>
	int birdType = rand() % 3;
    162c:	e8 2f fc ff ff       	callq  1260 <rand@plt>
    1631:	89 c2                	mov    %eax,%edx
    1633:	48 63 c2             	movslq %edx,%rax
    1636:	48 69 c0 56 55 55 55 	imul   $0x55555556,%rax,%rax
    163d:	48 c1 e8 20          	shr    $0x20,%rax
    1641:	48 89 c1             	mov    %rax,%rcx
    1644:	89 d0                	mov    %edx,%eax
    1646:	c1 f8 1f             	sar    $0x1f,%eax
    1649:	29 c1                	sub    %eax,%ecx
    164b:	89 c8                	mov    %ecx,%eax
    164d:	89 85 08 ff ff ff    	mov    %eax,-0xf8(%rbp)
    1653:	8b 8d 08 ff ff ff    	mov    -0xf8(%rbp),%ecx
    1659:	89 c8                	mov    %ecx,%eax
    165b:	01 c0                	add    %eax,%eax
    165d:	01 c8                	add    %ecx,%eax
    165f:	29 c2                	sub    %eax,%edx
    1661:	89 d0                	mov    %edx,%eax
    1663:	89 85 08 ff ff ff    	mov    %eax,-0xf8(%rbp)
	// RANDOM BIRD COLORS
	if (birdType == 0) {
    1669:	83 bd 08 ff ff ff 00 	cmpl   $0x0,-0xf8(%rbp)
    1670:	75 4f                	jne    16c1 <main+0x198>
		init_pair(2, COLOR_BLACK, COLOR_YELLOW);
    1672:	ba 03 00 00 00       	mov    $0x3,%edx
    1677:	be 00 00 00 00       	mov    $0x0,%esi
    167c:	bf 02 00 00 00       	mov    $0x2,%edi
    1681:	e8 ba fb ff ff       	callq  1240 <init_pair@plt>
		if (mode == 0) {
    1686:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    168d:	75 19                	jne    16a8 <main+0x17f>
			init_pair(7, COLOR_YELLOW, COLOR_CYAN);
    168f:	ba 06 00 00 00       	mov    $0x6,%edx
    1694:	be 03 00 00 00       	mov    $0x3,%esi
    1699:	bf 07 00 00 00       	mov    $0x7,%edi
    169e:	e8 9d fb ff ff       	callq  1240 <init_pair@plt>
    16a3:	e9 bb 00 00 00       	jmpq   1763 <main+0x23a>
		} else {
			init_pair(7, COLOR_YELLOW, COLOR_BLACK);
    16a8:	ba 00 00 00 00       	mov    $0x0,%edx
    16ad:	be 03 00 00 00       	mov    $0x3,%esi
    16b2:	bf 07 00 00 00       	mov    $0x7,%edi
    16b7:	e8 84 fb ff ff       	callq  1240 <init_pair@plt>
    16bc:	e9 a2 00 00 00       	jmpq   1763 <main+0x23a>
		}
	} else if (birdType == 1) {
    16c1:	83 bd 08 ff ff ff 01 	cmpl   $0x1,-0xf8(%rbp)
    16c8:	75 49                	jne    1713 <main+0x1ea>
		init_pair(2, COLOR_BLACK, COLOR_RED);
    16ca:	ba 01 00 00 00       	mov    $0x1,%edx
    16cf:	be 00 00 00 00       	mov    $0x0,%esi
    16d4:	bf 02 00 00 00       	mov    $0x2,%edi
    16d9:	e8 62 fb ff ff       	callq  1240 <init_pair@plt>
		if (mode == 0) {
    16de:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    16e5:	75 16                	jne    16fd <main+0x1d4>
			init_pair(7, COLOR_RED, COLOR_CYAN);
    16e7:	ba 06 00 00 00       	mov    $0x6,%edx
    16ec:	be 01 00 00 00       	mov    $0x1,%esi
    16f1:	bf 07 00 00 00       	mov    $0x7,%edi
    16f6:	e8 45 fb ff ff       	callq  1240 <init_pair@plt>
    16fb:	eb 66                	jmp    1763 <main+0x23a>
		} else {
			init_pair(7, COLOR_RED, COLOR_BLACK);
    16fd:	ba 00 00 00 00       	mov    $0x0,%edx
    1702:	be 01 00 00 00       	mov    $0x1,%esi
    1707:	bf 07 00 00 00       	mov    $0x7,%edi
    170c:	e8 2f fb ff ff       	callq  1240 <init_pair@plt>
    1711:	eb 50                	jmp    1763 <main+0x23a>
		}
	} else if (birdType == 2) {
    1713:	83 bd 08 ff ff ff 02 	cmpl   $0x2,-0xf8(%rbp)
    171a:	75 47                	jne    1763 <main+0x23a>
		init_pair(2, COLOR_BLACK, COLOR_BLUE);
    171c:	ba 04 00 00 00       	mov    $0x4,%edx
    1721:	be 00 00 00 00       	mov    $0x0,%esi
    1726:	bf 02 00 00 00       	mov    $0x2,%edi
    172b:	e8 10 fb ff ff       	callq  1240 <init_pair@plt>
		if (mode == 0) {
    1730:	83 bd 04 ff ff ff 00 	cmpl   $0x0,-0xfc(%rbp)
    1737:	75 16                	jne    174f <main+0x226>
			init_pair(7, COLOR_BLUE, COLOR_CYAN);
    1739:	ba 06 00 00 00       	mov    $0x6,%edx
    173e:	be 04 00 00 00       	mov    $0x4,%esi
    1743:	bf 07 00 00 00       	mov    $0x7,%edi
    1748:	e8 f3 fa ff ff       	callq  1240 <init_pair@plt>
    174d:	eb 14                	jmp    1763 <main+0x23a>
		} else {
			init_pair(7, COLOR_BLUE, COLOR_BLACK);
    174f:	ba 00 00 00 00       	mov    $0x0,%edx
    1754:	be 04 00 00 00       	mov    $0x4,%esi
    1759:	bf 07 00 00 00       	mov    $0x7,%edi
    175e:	e8 dd fa ff ff       	callq  1240 <init_pair@plt>
		}
	}
	init_pair(3, COLOR_YELLOW, COLOR_YELLOW);  // UNDERGROUND COLORS
    1763:	ba 03 00 00 00       	mov    $0x3,%edx
    1768:	be 03 00 00 00       	mov    $0x3,%esi
    176d:	bf 03 00 00 00       	mov    $0x3,%edi
    1772:	e8 c9 fa ff ff       	callq  1240 <init_pair@plt>
	init_pair(4, COLOR_BLACK, COLOR_WHITE);	// LOGO COLORS
    1777:	ba 07 00 00 00       	mov    $0x7,%edx
    177c:	be 00 00 00 00       	mov    $0x0,%esi
    1781:	bf 04 00 00 00       	mov    $0x4,%edi
    1786:	e8 b5 fa ff ff       	callq  1240 <init_pair@plt>
	init_pair(5, COLOR_WHITE, COLOR_RED);	  // GAME OVER COLORS
    178b:	ba 01 00 00 00       	mov    $0x1,%edx
    1790:	be 07 00 00 00       	mov    $0x7,%esi
    1795:	bf 05 00 00 00       	mov    $0x5,%edi
    179a:	e8 a1 fa ff ff       	callq  1240 <init_pair@plt>
	init_pair(6, COLOR_WHITE,
    179f:	ba 02 00 00 00       	mov    $0x2,%edx
    17a4:	be 07 00 00 00       	mov    $0x7,%esi
    17a9:	bf 06 00 00 00       	mov    $0x6,%edi
    17ae:	e8 8d fa ff ff       	callq  1240 <init_pair@plt>
			  COLOR_GREEN);  // GET READY AND GROUND BORDER COLORS

	getmaxyx(stdscr, row, col);
    17b3:	48 8b 05 56 38 00 00 	mov    0x3856(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    17ba:	48 85 c0             	test   %rax,%rax
    17bd:	74 11                	je     17d0 <main+0x2a7>
    17bf:	48 8b 05 4a 38 00 00 	mov    0x384a(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    17c6:	0f b7 40 04          	movzwl 0x4(%rax),%eax
    17ca:	98                   	cwtl   
    17cb:	83 c0 01             	add    $0x1,%eax
    17ce:	eb 05                	jmp    17d5 <main+0x2ac>
    17d0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    17d5:	89 85 0c ff ff ff    	mov    %eax,-0xf4(%rbp)
    17db:	48 8b 05 2e 38 00 00 	mov    0x382e(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    17e2:	48 85 c0             	test   %rax,%rax
    17e5:	74 11                	je     17f8 <main+0x2cf>
    17e7:	48 8b 05 22 38 00 00 	mov    0x3822(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    17ee:	0f b7 40 06          	movzwl 0x6(%rax),%eax
    17f2:	98                   	cwtl   
    17f3:	83 c0 01             	add    $0x1,%eax
    17f6:	eb 05                	jmp    17fd <main+0x2d4>
    17f8:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    17fd:	89 85 10 ff ff ff    	mov    %eax,-0xf0(%rbp)

	if (row < 24 || col < 75) {
    1803:	83 bd 0c ff ff ff 17 	cmpl   $0x17,-0xf4(%rbp)
    180a:	7e 09                	jle    1815 <main+0x2ec>
    180c:	83 bd 10 ff ff ff 4a 	cmpl   $0x4a,-0xf0(%rbp)
    1813:	7f 0a                	jg     181f <main+0x2f6>
		wait = WAIT_BIG;
    1815:	c7 85 fc fe ff ff e0 	movl   $0x222e0,-0x104(%rbp)
    181c:	22 02 00 
	}

	writeInfo(row, col);
    181f:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    1825:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    182b:	89 d6                	mov    %edx,%esi
    182d:	89 c7                	mov    %eax,%edi
    182f:	e8 f2 08 00 00       	callq  2126 <_Z9writeInfoii>
	GET_NAME(playerName);
    1834:	48 8b 05 d5 37 00 00 	mov    0x37d5(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    183b:	48 8d 8d 20 ff ff ff 	lea    -0xe0(%rbp),%rcx
    1842:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    1847:	48 89 ce             	mov    %rcx,%rsi
    184a:	48 89 c7             	mov    %rax,%rdi
    184d:	e8 8e fb ff ff       	callq  13e0 <wgetnstr@plt>

	drawStarting(row, col);
    1852:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    1858:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    185e:	89 d6                	mov    %edx,%esi
    1860:	89 c7                	mov    %eax,%edi
    1862:	e8 f5 0e 00 00       	callq  275c <_Z12drawStartingii>

	refresh();
    1867:	e8 a4 fb ff ff       	callq  1410 <refresh@plt>
	noecho();
    186c:	e8 df fa ff ff       	callq  1350 <noecho@plt>
	timeout(true);
    1871:	48 8b 05 98 37 00 00 	mov    0x3798(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1878:	be 01 00 00 00       	mov    $0x1,%esi
    187d:	48 89 c7             	mov    %rax,%rdi
    1880:	e8 db fa ff ff       	callq  1360 <wtimeout@plt>

	birdRow = row / 2;
    1885:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    188b:	89 c2                	mov    %eax,%edx
    188d:	c1 ea 1f             	shr    $0x1f,%edx
    1890:	01 d0                	add    %edx,%eax
    1892:	d1 f8                	sar    %eax
    1894:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
	birdCol = col / 4;
    189a:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18a0:	8d 50 03             	lea    0x3(%rax),%edx
    18a3:	85 c0                	test   %eax,%eax
    18a5:	0f 48 c2             	cmovs  %edx,%eax
    18a8:	c1 f8 02             	sar    $0x2,%eax
    18ab:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
	pipeCol1 = col;
    18b1:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18b7:	89 85 f0 fe ff ff    	mov    %eax,-0x110(%rbp)
	pipeCol2 = col;
    18bd:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18c3:	89 85 f4 fe ff ff    	mov    %eax,-0x10c(%rbp)
	pipeCounter = col;
    18c9:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    18cf:	89 85 f8 fe ff ff    	mov    %eax,-0x108(%rbp)

	getNewPipeValue(&crackStart1, &crackFinish1, row);
    18d5:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    18db:	48 8d 8d d0 fe ff ff 	lea    -0x130(%rbp),%rcx
    18e2:	48 8d 85 cc fe ff ff 	lea    -0x134(%rbp),%rax
    18e9:	48 89 ce             	mov    %rcx,%rsi
    18ec:	48 89 c7             	mov    %rax,%rdi
    18ef:	e8 f4 11 00 00       	callq  2ae8 <_Z15getNewPipeValuePiS_i>
	getNewPipeValue(&crackStart2, &crackFinish2, row);
    18f4:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    18fa:	48 8d 8d d8 fe ff ff 	lea    -0x128(%rbp),%rcx
    1901:	48 8d 85 d4 fe ff ff 	lea    -0x12c(%rbp),%rax
    1908:	48 89 ce             	mov    %rcx,%rsi
    190b:	48 89 c7             	mov    %rax,%rdi
    190e:	e8 d5 11 00 00       	callq  2ae8 <_Z15getNewPipeValuePiS_i>

	while (!isOver) {
    1913:	83 bd e4 fe ff ff 00 	cmpl   $0x0,-0x11c(%rbp)
    191a:	0f 85 26 05 00 00    	jne    1e46 <main+0x91d>
		clear();
    1920:	e8 fb fa ff ff       	callq  1420 <clear@plt>

		mvaddch(birdRow, birdCol, bird | COLOR_PAIR(2));
    1925:	48 8b 05 e4 36 00 00 	mov    0x36e4(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    192c:	8b 95 14 ff ff ff    	mov    -0xec(%rbp),%edx
    1932:	8b 8d ec fe ff ff    	mov    -0x114(%rbp),%ecx
    1938:	89 ce                	mov    %ecx,%esi
    193a:	48 89 c7             	mov    %rax,%rdi
    193d:	e8 ee f9 ff ff       	callq  1330 <wmove@plt>
    1942:	83 f8 ff             	cmp    $0xffffffff,%eax
    1945:	74 1d                	je     1964 <main+0x43b>
    1947:	0f be 85 c7 fe ff ff 	movsbl -0x139(%rbp),%eax
    194e:	80 cc 02             	or     $0x2,%ah
    1951:	89 c2                	mov    %eax,%edx
    1953:	48 8b 05 b6 36 00 00 	mov    0x36b6(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    195a:	89 d6                	mov    %edx,%esi
    195c:	48 89 c7             	mov    %rax,%rdi
    195f:	e8 0c f9 ff ff       	callq  1270 <waddch@plt>

		if (score % 8 == 0) {
    1964:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    196a:	83 e0 07             	and    $0x7,%eax
    196d:	85 c0                	test   %eax,%eax
    196f:	75 3d                	jne    19ae <main+0x485>
			mvprintw(1, col / 2 - 20, "SCORE : %d", score / 8);
    1971:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1977:	8d 50 07             	lea    0x7(%rax),%edx
    197a:	85 c0                	test   %eax,%eax
    197c:	0f 48 c2             	cmovs  %edx,%eax
    197f:	c1 f8 03             	sar    $0x3,%eax
    1982:	89 c1                	mov    %eax,%ecx
    1984:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    198a:	89 c2                	mov    %eax,%edx
    198c:	c1 ea 1f             	shr    $0x1f,%edx
    198f:	01 d0                	add    %edx,%eax
    1991:	d1 f8                	sar    %eax
    1993:	83 e8 14             	sub    $0x14,%eax
    1996:	48 8d 15 6c 16 00 00 	lea    0x166c(%rip),%rdx        # 3009 <_ZStL19piecewise_construct+0x1>
    199d:	89 c6                	mov    %eax,%esi
    199f:	bf 01 00 00 00       	mov    $0x1,%edi
    19a4:	b8 00 00 00 00       	mov    $0x0,%eax
    19a9:	e8 f2 f9 ff ff       	callq  13a0 <mvprintw@plt>
		}

		mvprintw(0, col / 2 - 20, "%s", playerName);
    19ae:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    19b4:	89 c2                	mov    %eax,%edx
    19b6:	c1 ea 1f             	shr    $0x1f,%edx
    19b9:	01 d0                	add    %edx,%eax
    19bb:	d1 f8                	sar    %eax
    19bd:	8d 70 ec             	lea    -0x14(%rax),%esi
    19c0:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    19c7:	48 89 c1             	mov    %rax,%rcx
    19ca:	48 8d 15 43 16 00 00 	lea    0x1643(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    19d1:	bf 00 00 00 00       	mov    $0x0,%edi
    19d6:	b8 00 00 00 00       	mov    $0x0,%eax
    19db:	e8 c0 f9 ff ff       	callq  13a0 <mvprintw@plt>
		mvprintw(0, col / 2 + 13, "%s", bestPlayerName);
    19e0:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    19e6:	89 c2                	mov    %eax,%edx
    19e8:	c1 ea 1f             	shr    $0x1f,%edx
    19eb:	01 d0                	add    %edx,%eax
    19ed:	d1 f8                	sar    %eax
    19ef:	8d 70 0d             	lea    0xd(%rax),%esi
    19f2:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    19f6:	48 89 c1             	mov    %rax,%rcx
    19f9:	48 8d 15 14 16 00 00 	lea    0x1614(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    1a00:	bf 00 00 00 00       	mov    $0x0,%edi
    1a05:	b8 00 00 00 00       	mov    $0x0,%eax
    1a0a:	e8 91 f9 ff ff       	callq  13a0 <mvprintw@plt>
		mvprintw(1, col / 2 + 13, "BEST : %d", bestScore);
    1a0f:	8b 95 c8 fe ff ff    	mov    -0x138(%rbp),%edx
    1a15:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1a1b:	89 c1                	mov    %eax,%ecx
    1a1d:	c1 e9 1f             	shr    $0x1f,%ecx
    1a20:	01 c8                	add    %ecx,%eax
    1a22:	d1 f8                	sar    %eax
    1a24:	83 c0 0d             	add    $0xd,%eax
    1a27:	89 d1                	mov    %edx,%ecx
    1a29:	48 8d 15 e7 15 00 00 	lea    0x15e7(%rip),%rdx        # 3017 <_ZStL19piecewise_construct+0xf>
    1a30:	89 c6                	mov    %eax,%esi
    1a32:	bf 01 00 00 00       	mov    $0x1,%edi
    1a37:	b8 00 00 00 00       	mov    $0x0,%eax
    1a3c:	e8 5f f9 ff ff       	callq  13a0 <mvprintw@plt>

		attron(COLOR_PAIR(1));
    1a41:	48 8b 05 c8 35 00 00 	mov    0x35c8(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1a48:	ba 00 00 00 00       	mov    $0x0,%edx
    1a4d:	be 00 01 00 00       	mov    $0x100,%esi
    1a52:	48 89 c7             	mov    %rax,%rdi
    1a55:	e8 56 f8 ff ff       	callq  12b0 <wattr_on@plt>
		drawPipe(crackStart1, crackFinish1, pipeCol1, row);
    1a5a:	8b b5 d0 fe ff ff    	mov    -0x130(%rbp),%esi
    1a60:	8b 85 cc fe ff ff    	mov    -0x134(%rbp),%eax
    1a66:	8b 8d 0c ff ff ff    	mov    -0xf4(%rbp),%ecx
    1a6c:	8b 95 f0 fe ff ff    	mov    -0x110(%rbp),%edx
    1a72:	89 c7                	mov    %eax,%edi
    1a74:	e8 a6 0b 00 00       	callq  261f <_Z8drawPipeiiii>

		if (pipeCounter < col / 2) {
    1a79:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1a7f:	89 c2                	mov    %eax,%edx
    1a81:	c1 ea 1f             	shr    $0x1f,%edx
    1a84:	01 d0                	add    %edx,%eax
    1a86:	d1 f8                	sar    %eax
    1a88:	39 85 f8 fe ff ff    	cmp    %eax,-0x108(%rbp)
    1a8e:	7d 26                	jge    1ab6 <main+0x58d>
			drawPipe(crackStart2, crackFinish2, pipeCol2, row);
    1a90:	8b b5 d8 fe ff ff    	mov    -0x128(%rbp),%esi
    1a96:	8b 85 d4 fe ff ff    	mov    -0x12c(%rbp),%eax
    1a9c:	8b 8d 0c ff ff ff    	mov    -0xf4(%rbp),%ecx
    1aa2:	8b 95 f4 fe ff ff    	mov    -0x10c(%rbp),%edx
    1aa8:	89 c7                	mov    %eax,%edi
    1aaa:	e8 70 0b 00 00       	callq  261f <_Z8drawPipeiiii>
			pipeCol2--;
    1aaf:	83 ad f4 fe ff ff 01 	subl   $0x1,-0x10c(%rbp)
		}
		pipeCol1--;
    1ab6:	83 ad f0 fe ff ff 01 	subl   $0x1,-0x110(%rbp)
		attroff(COLOR_PAIR(1));
    1abd:	48 8b 05 4c 35 00 00 	mov    0x354c(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1ac4:	ba 00 00 00 00       	mov    $0x0,%edx
    1ac9:	be 00 01 00 00       	mov    $0x100,%esi
    1ace:	48 89 c7             	mov    %rax,%rdi
    1ad1:	e8 ba f8 ff ff       	callq  1390 <wattr_off@plt>
		for (int i = 0; i < col; i++) {
    1ad6:	c7 85 00 ff ff ff 00 	movl   $0x0,-0x100(%rbp)
    1add:	00 00 00 
    1ae0:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1ae6:	3b 85 10 ff ff ff    	cmp    -0xf0(%rbp),%eax
    1aec:	0f 8d dc 00 00 00    	jge    1bce <main+0x6a5>
			attron(COLOR_PAIR(3));
    1af2:	48 8b 05 17 35 00 00 	mov    0x3517(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1af9:	ba 00 00 00 00       	mov    $0x0,%edx
    1afe:	be 00 03 00 00       	mov    $0x300,%esi
    1b03:	48 89 c7             	mov    %rax,%rdi
    1b06:	e8 a5 f7 ff ff       	callq  12b0 <wattr_on@plt>
			mvprintw(row - 1, i, "#");
    1b0b:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1b11:	8d 48 ff             	lea    -0x1(%rax),%ecx
    1b14:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b1a:	48 8d 15 00 15 00 00 	lea    0x1500(%rip),%rdx        # 3021 <_ZStL19piecewise_construct+0x19>
    1b21:	89 c6                	mov    %eax,%esi
    1b23:	89 cf                	mov    %ecx,%edi
    1b25:	b8 00 00 00 00       	mov    $0x0,%eax
    1b2a:	e8 71 f8 ff ff       	callq  13a0 <mvprintw@plt>
			mvprintw(row - 2, i, "#");
    1b2f:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1b35:	8d 48 fe             	lea    -0x2(%rax),%ecx
    1b38:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b3e:	48 8d 15 dc 14 00 00 	lea    0x14dc(%rip),%rdx        # 3021 <_ZStL19piecewise_construct+0x19>
    1b45:	89 c6                	mov    %eax,%esi
    1b47:	89 cf                	mov    %ecx,%edi
    1b49:	b8 00 00 00 00       	mov    $0x0,%eax
    1b4e:	e8 4d f8 ff ff       	callq  13a0 <mvprintw@plt>
			attroff(COLOR_PAIR(3));
    1b53:	48 8b 05 b6 34 00 00 	mov    0x34b6(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1b5a:	ba 00 00 00 00       	mov    $0x0,%edx
    1b5f:	be 00 03 00 00       	mov    $0x300,%esi
    1b64:	48 89 c7             	mov    %rax,%rdi
    1b67:	e8 24 f8 ff ff       	callq  1390 <wattr_off@plt>
			attron(COLOR_PAIR(6));
    1b6c:	48 8b 05 9d 34 00 00 	mov    0x349d(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1b73:	ba 00 00 00 00       	mov    $0x0,%edx
    1b78:	be 00 06 00 00       	mov    $0x600,%esi
    1b7d:	48 89 c7             	mov    %rax,%rdi
    1b80:	e8 2b f7 ff ff       	callq  12b0 <wattr_on@plt>
			mvprintw(row - 3, i, "/");
    1b85:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1b8b:	8d 48 fd             	lea    -0x3(%rax),%ecx
    1b8e:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b94:	48 8d 15 88 14 00 00 	lea    0x1488(%rip),%rdx        # 3023 <_ZStL19piecewise_construct+0x1b>
    1b9b:	89 c6                	mov    %eax,%esi
    1b9d:	89 cf                	mov    %ecx,%edi
    1b9f:	b8 00 00 00 00       	mov    $0x0,%eax
    1ba4:	e8 f7 f7 ff ff       	callq  13a0 <mvprintw@plt>
			attroff(COLOR_PAIR(6));
    1ba9:	48 8b 05 60 34 00 00 	mov    0x3460(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1bb0:	ba 00 00 00 00       	mov    $0x0,%edx
    1bb5:	be 00 06 00 00       	mov    $0x600,%esi
    1bba:	48 89 c7             	mov    %rax,%rdi
    1bbd:	e8 ce f7 ff ff       	callq  1390 <wattr_off@plt>
		for (int i = 0; i < col; i++) {
    1bc2:	83 85 00 ff ff ff 01 	addl   $0x1,-0x100(%rbp)
    1bc9:	e9 12 ff ff ff       	jmpq   1ae0 <main+0x5b7>
			// mvprintw(2, i, "#");
		}

		if (birdRow < row - 1) {
    1bce:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1bd4:	83 e8 01             	sub    $0x1,%eax
    1bd7:	39 85 ec fe ff ff    	cmp    %eax,-0x114(%rbp)
    1bdd:	7d 07                	jge    1be6 <main+0x6bd>
			birdRow++;
    1bdf:	83 85 ec fe ff ff 01 	addl   $0x1,-0x114(%rbp)
		}

		command = getch();
    1be6:	48 8b 05 23 34 00 00 	mov    0x3423(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1bed:	48 89 c7             	mov    %rax,%rdi
    1bf0:	e8 8b f6 ff ff       	callq  1280 <wgetch@plt>
    1bf5:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
		if (command == ' ') {
    1bfb:	83 bd 18 ff ff ff 20 	cmpl   $0x20,-0xe8(%rbp)
    1c02:	75 10                	jne    1c14 <main+0x6eb>
			flag++;
    1c04:	83 85 e8 fe ff ff 01 	addl   $0x1,-0x118(%rbp)
			birdRow -= JUMP;
    1c0b:	83 ad ec fe ff ff 04 	subl   $0x4,-0x114(%rbp)
    1c12:	eb 16                	jmp    1c2a <main+0x701>
		} else if (command == KEY_F(5)) {
    1c14:	81 bd 18 ff ff ff 0d 	cmpl   $0x10d,-0xe8(%rbp)
    1c1b:	01 00 00 
    1c1e:	75 0a                	jne    1c2a <main+0x701>
			wait -= 10000;
    1c20:	81 ad fc fe ff ff 10 	subl   $0x2710,-0x104(%rbp)
    1c27:	27 00 00 
		}

		if (birdRow < 2) {
    1c2a:	83 bd ec fe ff ff 01 	cmpl   $0x1,-0x114(%rbp)
    1c31:	7f 0a                	jg     1c3d <main+0x714>
			birdRow = 2;
    1c33:	c7 85 ec fe ff ff 02 	movl   $0x2,-0x114(%rbp)
    1c3a:	00 00 00 

		//1c80:       e8 3c 09 00 00          callq  25c1 <_Z16controlCollisioniiiii>
		//1c80 is before 12121212
		//1d3c:       e8 80 08 00 00          callq  25c1 <_Z16controlCollisioniiiii>

		collision = controlCollision(pipeCol1, birdCol, birdRow, crackStart1,
    1c3d:	8b bd d0 fe ff ff    	mov    -0x130(%rbp),%edi
    1c43:	8b 8d cc fe ff ff    	mov    -0x134(%rbp),%ecx
    1c49:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
    1c4f:	8b b5 14 ff ff ff    	mov    -0xec(%rbp),%esi
    1c55:	8b 85 f0 fe ff ff    	mov    -0x110(%rbp),%eax
    1c5b:	41 89 f8             	mov    %edi,%r8d
    1c5e:	89 c7                	mov    %eax,%edi
    1c60:	e8 26 09 00 00       	callq  258b <_Z16controlCollisioniiiii>
    1c65:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
									 crackFinish1); 
//        {
//            printf("%d\n", 0x12121212);
//        }
        // collision = collision == 2 ? 1 : collision; // <========================
		if (collision) {
    1c6b:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    1c72:	74 6f                	je     1ce3 <main+0x7ba>
			if (collision == DOUBLE) {
    1c74:	83 bd 1c ff ff ff 02 	cmpl   $0x2,-0xe4(%rbp)
    1c7b:	75 0c                	jne    1c89 <main+0x760>
				isOver = true;
    1c7d:	c7 85 e4 fe ff ff 01 	movl   $0x1,-0x11c(%rbp)
    1c84:	00 00 00 
    1c87:	eb 5a                	jmp    1ce3 <main+0x7ba>
			} else if (isScore) {
    1c89:	83 bd e0 fe ff ff 00 	cmpl   $0x0,-0x120(%rbp)
    1c90:	74 51                	je     1ce3 <main+0x7ba>
				score++;
    1c92:	83 85 dc fe ff ff 01 	addl   $0x1,-0x124(%rbp)
				if (score / 8 > bestScore) {
    1c99:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1c9f:	8d 50 07             	lea    0x7(%rax),%edx
    1ca2:	85 c0                	test   %eax,%eax
    1ca4:	0f 48 c2             	cmovs  %edx,%eax
    1ca7:	c1 f8 03             	sar    $0x3,%eax
    1caa:	89 c2                	mov    %eax,%edx
    1cac:	8b 85 c8 fe ff ff    	mov    -0x138(%rbp),%eax
    1cb2:	39 c2                	cmp    %eax,%edx
    1cb4:	7e 2d                	jle    1ce3 <main+0x7ba>
					bestScore = score / 8;
    1cb6:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1cbc:	8d 50 07             	lea    0x7(%rax),%edx
    1cbf:	85 c0                	test   %eax,%eax
    1cc1:	0f 48 c2             	cmovs  %edx,%eax
    1cc4:	c1 f8 03             	sar    $0x3,%eax
    1cc7:	89 85 c8 fe ff ff    	mov    %eax,-0x138(%rbp)
					strcpy(bestPlayerName, playerName);
    1ccd:	48 8d 95 20 ff ff ff 	lea    -0xe0(%rbp),%rdx
    1cd4:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    1cd8:	48 89 d6             	mov    %rdx,%rsi
    1cdb:	48 89 c7             	mov    %rax,%rdi
    1cde:	e8 1d f6 ff ff       	callq  1300 <strcpy@plt>
				}
			}
		}

		collision = controlCollision(pipeCol2, birdCol, birdRow, crackStart2,
    1ce3:	8b bd d8 fe ff ff    	mov    -0x128(%rbp),%edi
    1ce9:	8b 8d d4 fe ff ff    	mov    -0x12c(%rbp),%ecx
    1cef:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
    1cf5:	8b b5 14 ff ff ff    	mov    -0xec(%rbp),%esi
    1cfb:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    1d01:	41 89 f8             	mov    %edi,%r8d
    1d04:	89 c7                	mov    %eax,%edi
    1d06:	e8 80 08 00 00       	callq  258b <_Z16controlCollisioniiiii>
    1d0b:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
									 crackFinish2);
		//collision = collision == 2 ? 1 : collision; // // <========================
		if (collision) {
    1d11:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    1d18:	74 6f                	je     1d89 <main+0x860>
			if (collision == DOUBLE) {
    1d1a:	83 bd 1c ff ff ff 02 	cmpl   $0x2,-0xe4(%rbp)
    1d21:	75 0c                	jne    1d2f <main+0x806>
				isOver = true;
    1d23:	c7 85 e4 fe ff ff 01 	movl   $0x1,-0x11c(%rbp)
    1d2a:	00 00 00 
    1d2d:	eb 5a                	jmp    1d89 <main+0x860>
			} else if (isScore) {
    1d2f:	83 bd e0 fe ff ff 00 	cmpl   $0x0,-0x120(%rbp)
    1d36:	74 51                	je     1d89 <main+0x860>
				score++;
    1d38:	83 85 dc fe ff ff 01 	addl   $0x1,-0x124(%rbp)
				if (score / 8 > bestScore) {
    1d3f:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1d45:	8d 50 07             	lea    0x7(%rax),%edx
    1d48:	85 c0                	test   %eax,%eax
    1d4a:	0f 48 c2             	cmovs  %edx,%eax
    1d4d:	c1 f8 03             	sar    $0x3,%eax
    1d50:	89 c2                	mov    %eax,%edx
    1d52:	8b 85 c8 fe ff ff    	mov    -0x138(%rbp),%eax
    1d58:	39 c2                	cmp    %eax,%edx
    1d5a:	7e 2d                	jle    1d89 <main+0x860>
					bestScore = score / 8;
    1d5c:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1d62:	8d 50 07             	lea    0x7(%rax),%edx
    1d65:	85 c0                	test   %eax,%eax
    1d67:	0f 48 c2             	cmovs  %edx,%eax
    1d6a:	c1 f8 03             	sar    $0x3,%eax
    1d6d:	89 85 c8 fe ff ff    	mov    %eax,-0x138(%rbp)
					strcpy(bestPlayerName, playerName);
    1d73:	48 8d 95 20 ff ff ff 	lea    -0xe0(%rbp),%rdx
    1d7a:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    1d7e:	48 89 d6             	mov    %rdx,%rsi
    1d81:	48 89 c7             	mov    %rax,%rdi
    1d84:	e8 77 f5 ff ff       	callq  1300 <strcpy@plt>
				}
			}
		}

		if (birdRow > row - 4 /*|| birdRow == 2*/) {
    1d89:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1d8f:	83 e8 03             	sub    $0x3,%eax
    1d92:	39 85 ec fe ff ff    	cmp    %eax,-0x114(%rbp)
    1d98:	7c 0a                	jl     1da4 <main+0x87b>
			// TOUCH THE GROUND
			isOver = true;
    1d9a:	c7 85 e4 fe ff ff 01 	movl   $0x1,-0x11c(%rbp)
    1da1:	00 00 00 
            //isOver = false; // <========================
		}

		if (pipeCol1 == 0) {
    1da4:	83 bd f0 fe ff ff 00 	cmpl   $0x0,-0x110(%rbp)
    1dab:	75 2b                	jne    1dd8 <main+0x8af>
			getNewPipeValue(&crackStart1, &crackFinish1, row);
    1dad:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    1db3:	48 8d 8d d0 fe ff ff 	lea    -0x130(%rbp),%rcx
    1dba:	48 8d 85 cc fe ff ff 	lea    -0x134(%rbp),%rax
    1dc1:	48 89 ce             	mov    %rcx,%rsi
    1dc4:	48 89 c7             	mov    %rax,%rdi
    1dc7:	e8 1c 0d 00 00       	callq  2ae8 <_Z15getNewPipeValuePiS_i>
			pipeCol1 = col;
    1dcc:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1dd2:	89 85 f0 fe ff ff    	mov    %eax,-0x110(%rbp)
		}

		if (pipeCol2 == 0) {
    1dd8:	83 bd f4 fe ff ff 00 	cmpl   $0x0,-0x10c(%rbp)
    1ddf:	75 40                	jne    1e21 <main+0x8f8>
			getNewPipeValue(&crackStart2, &crackFinish2, row);
    1de1:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    1de7:	48 8d 8d d8 fe ff ff 	lea    -0x128(%rbp),%rcx
    1dee:	48 8d 85 d4 fe ff ff 	lea    -0x12c(%rbp),%rax
    1df5:	48 89 ce             	mov    %rcx,%rsi
    1df8:	48 89 c7             	mov    %rax,%rdi
    1dfb:	e8 e8 0c 00 00       	callq  2ae8 <_Z15getNewPipeValuePiS_i>
			pipeCol2 = col;
    1e00:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1e06:	89 85 f4 fe ff ff    	mov    %eax,-0x10c(%rbp)
			pipeCounter = col / 2;
    1e0c:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1e12:	89 c2                	mov    %eax,%edx
    1e14:	c1 ea 1f             	shr    $0x1f,%edx
    1e17:	01 d0                	add    %edx,%eax
    1e19:	d1 f8                	sar    %eax
    1e1b:	89 85 f8 fe ff ff    	mov    %eax,-0x108(%rbp)
		}

		isScore++;
    1e21:	83 85 e0 fe ff ff 01 	addl   $0x1,-0x120(%rbp)
		pipeCounter--;
    1e28:	83 ad f8 fe ff ff 01 	subl   $0x1,-0x108(%rbp)

		refresh();
    1e2f:	e8 dc f5 ff ff       	callq  1410 <refresh@plt>

		usleep(wait);
    1e34:	8b 85 fc fe ff ff    	mov    -0x104(%rbp),%eax
    1e3a:	89 c7                	mov    %eax,%edi
    1e3c:	e8 7f f5 ff ff       	callq  13c0 <usleep@plt>
	while (!isOver) {
    1e41:	e9 cd fa ff ff       	jmpq   1913 <main+0x3ea>
	}

	writeBest(bestScore, bestPlayerName);
    1e46:	8b 85 c8 fe ff ff    	mov    -0x138(%rbp),%eax
    1e4c:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    1e50:	48 89 d6             	mov    %rdx,%rsi
    1e53:	89 c7                	mov    %eax,%edi
    1e55:	e8 1b 0c 00 00       	callq  2a75 <_Z9writeBestiPKc>

	clear();
    1e5a:	e8 c1 f5 ff ff       	callq  1420 <clear@plt>
	 / ___| __ _ _ __ ___   ___   / _ \__   _____ _ __
	| |  _ / _` | '_ ` _ \ / _ \ | | | \ \ / / _ \ '__|
	| |_| | (_| | | | | | |  __/ | |_| |\ V /  __/ |
	 \____|\__,_|_| |_| |_|\___|  \___/  \_/ \___|_|
	*/
	attron(A_BOLD | COLOR_PAIR(5));
    1e5f:	48 8b 05 aa 31 00 00 	mov    0x31aa(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1e66:	ba 00 00 00 00       	mov    $0x0,%edx
    1e6b:	be 00 05 20 00       	mov    $0x200500,%esi
    1e70:	48 89 c7             	mov    %rax,%rdi
    1e73:	e8 38 f4 ff ff       	callq  12b0 <wattr_on@plt>
	mvprintw(row / 2 - 10, (col - 51) / 2,
    1e78:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1e7e:	83 e8 33             	sub    $0x33,%eax
    1e81:	89 c2                	mov    %eax,%edx
    1e83:	c1 ea 1f             	shr    $0x1f,%edx
    1e86:	01 d0                	add    %edx,%eax
    1e88:	d1 f8                	sar    %eax
    1e8a:	89 c1                	mov    %eax,%ecx
    1e8c:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1e92:	89 c2                	mov    %eax,%edx
    1e94:	c1 ea 1f             	shr    $0x1f,%edx
    1e97:	01 d0                	add    %edx,%eax
    1e99:	d1 f8                	sar    %eax
    1e9b:	83 e8 0a             	sub    $0xa,%eax
    1e9e:	48 8d 15 83 11 00 00 	lea    0x1183(%rip),%rdx        # 3028 <_ZStL19piecewise_construct+0x20>
    1ea5:	89 ce                	mov    %ecx,%esi
    1ea7:	89 c7                	mov    %eax,%edi
    1ea9:	b8 00 00 00 00       	mov    $0x0,%eax
    1eae:	e8 ed f4 ff ff       	callq  13a0 <mvprintw@plt>
			 "  ____                         ___                 ");
	mvprintw(row / 2 - 9, (col - 51) / 2,
    1eb3:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1eb9:	83 e8 33             	sub    $0x33,%eax
    1ebc:	89 c2                	mov    %eax,%edx
    1ebe:	c1 ea 1f             	shr    $0x1f,%edx
    1ec1:	01 d0                	add    %edx,%eax
    1ec3:	d1 f8                	sar    %eax
    1ec5:	89 c1                	mov    %eax,%ecx
    1ec7:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1ecd:	89 c2                	mov    %eax,%edx
    1ecf:	c1 ea 1f             	shr    $0x1f,%edx
    1ed2:	01 d0                	add    %edx,%eax
    1ed4:	d1 f8                	sar    %eax
    1ed6:	83 e8 09             	sub    $0x9,%eax
    1ed9:	48 8d 15 80 11 00 00 	lea    0x1180(%rip),%rdx        # 3060 <_ZStL19piecewise_construct+0x58>
    1ee0:	89 ce                	mov    %ecx,%esi
    1ee2:	89 c7                	mov    %eax,%edi
    1ee4:	b8 00 00 00 00       	mov    $0x0,%eax
    1ee9:	e8 b2 f4 ff ff       	callq  13a0 <mvprintw@plt>
			 " / ___| __ _ _ __ ___   ___   / _ \\__   _____ _ __ ");
	mvprintw(row / 2 - 8, (col - 51) / 2,
    1eee:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1ef4:	83 e8 33             	sub    $0x33,%eax
    1ef7:	89 c2                	mov    %eax,%edx
    1ef9:	c1 ea 1f             	shr    $0x1f,%edx
    1efc:	01 d0                	add    %edx,%eax
    1efe:	d1 f8                	sar    %eax
    1f00:	89 c1                	mov    %eax,%ecx
    1f02:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1f08:	89 c2                	mov    %eax,%edx
    1f0a:	c1 ea 1f             	shr    $0x1f,%edx
    1f0d:	01 d0                	add    %edx,%eax
    1f0f:	d1 f8                	sar    %eax
    1f11:	83 e8 08             	sub    $0x8,%eax
    1f14:	48 8d 15 7d 11 00 00 	lea    0x117d(%rip),%rdx        # 3098 <_ZStL19piecewise_construct+0x90>
    1f1b:	89 ce                	mov    %ecx,%esi
    1f1d:	89 c7                	mov    %eax,%edi
    1f1f:	b8 00 00 00 00       	mov    $0x0,%eax
    1f24:	e8 77 f4 ff ff       	callq  13a0 <mvprintw@plt>
			 "| |  _ / _` | '_ ` _ \\ / _ \\ | | | \\ \\ / / _ \\ '__|");
	mvprintw(row / 2 - 7, (col - 51) / 2,
    1f29:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1f2f:	83 e8 33             	sub    $0x33,%eax
    1f32:	89 c2                	mov    %eax,%edx
    1f34:	c1 ea 1f             	shr    $0x1f,%edx
    1f37:	01 d0                	add    %edx,%eax
    1f39:	d1 f8                	sar    %eax
    1f3b:	89 c1                	mov    %eax,%ecx
    1f3d:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1f43:	89 c2                	mov    %eax,%edx
    1f45:	c1 ea 1f             	shr    $0x1f,%edx
    1f48:	01 d0                	add    %edx,%eax
    1f4a:	d1 f8                	sar    %eax
    1f4c:	83 e8 07             	sub    $0x7,%eax
    1f4f:	48 8d 15 7a 11 00 00 	lea    0x117a(%rip),%rdx        # 30d0 <_ZStL19piecewise_construct+0xc8>
    1f56:	89 ce                	mov    %ecx,%esi
    1f58:	89 c7                	mov    %eax,%edi
    1f5a:	b8 00 00 00 00       	mov    $0x0,%eax
    1f5f:	e8 3c f4 ff ff       	callq  13a0 <mvprintw@plt>
			 "| |_| | (_| | | | | | |  __/ | |_| |\\ V /  __/ |   ");
	mvprintw(row / 2 - 6, (col - 51) / 2,
    1f64:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1f6a:	83 e8 33             	sub    $0x33,%eax
    1f6d:	89 c2                	mov    %eax,%edx
    1f6f:	c1 ea 1f             	shr    $0x1f,%edx
    1f72:	01 d0                	add    %edx,%eax
    1f74:	d1 f8                	sar    %eax
    1f76:	89 c1                	mov    %eax,%ecx
    1f78:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1f7e:	89 c2                	mov    %eax,%edx
    1f80:	c1 ea 1f             	shr    $0x1f,%edx
    1f83:	01 d0                	add    %edx,%eax
    1f85:	d1 f8                	sar    %eax
    1f87:	83 e8 06             	sub    $0x6,%eax
    1f8a:	48 8d 15 77 11 00 00 	lea    0x1177(%rip),%rdx        # 3108 <_ZStL19piecewise_construct+0x100>
    1f91:	89 ce                	mov    %ecx,%esi
    1f93:	89 c7                	mov    %eax,%edi
    1f95:	b8 00 00 00 00       	mov    $0x0,%eax
    1f9a:	e8 01 f4 ff ff       	callq  13a0 <mvprintw@plt>
			 " \\____|\\__,_|_| |_| |_|\\___|  \\___/  \\_/ \\___|_|   ");
	attroff(A_BOLD | COLOR_PAIR(5));
    1f9f:	48 8b 05 6a 30 00 00 	mov    0x306a(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    1fa6:	ba 00 00 00 00       	mov    $0x0,%edx
    1fab:	be 00 05 20 00       	mov    $0x200500,%esi
    1fb0:	48 89 c7             	mov    %rax,%rdi
    1fb3:	e8 d8 f3 ff ff       	callq  1390 <wattr_off@plt>
	mvprintw(row / 2 - 1, col / 2 - 20, "SCORE : %d", score / 8);
    1fb8:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    1fbe:	8d 50 07             	lea    0x7(%rax),%edx
    1fc1:	85 c0                	test   %eax,%eax
    1fc3:	0f 48 c2             	cmovs  %edx,%eax
    1fc6:	c1 f8 03             	sar    $0x3,%eax
    1fc9:	89 c1                	mov    %eax,%ecx
    1fcb:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1fd1:	89 c2                	mov    %eax,%edx
    1fd3:	c1 ea 1f             	shr    $0x1f,%edx
    1fd6:	01 d0                	add    %edx,%eax
    1fd8:	d1 f8                	sar    %eax
    1fda:	8d 70 ec             	lea    -0x14(%rax),%esi
    1fdd:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1fe3:	89 c2                	mov    %eax,%edx
    1fe5:	c1 ea 1f             	shr    $0x1f,%edx
    1fe8:	01 d0                	add    %edx,%eax
    1fea:	d1 f8                	sar    %eax
    1fec:	83 e8 01             	sub    $0x1,%eax
    1fef:	48 8d 15 13 10 00 00 	lea    0x1013(%rip),%rdx        # 3009 <_ZStL19piecewise_construct+0x1>
    1ff6:	89 c7                	mov    %eax,%edi
    1ff8:	b8 00 00 00 00       	mov    $0x0,%eax
    1ffd:	e8 9e f3 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 - 2, col / 2 - 20, "%s", playerName);
    2002:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    2008:	89 c2                	mov    %eax,%edx
    200a:	c1 ea 1f             	shr    $0x1f,%edx
    200d:	01 d0                	add    %edx,%eax
    200f:	d1 f8                	sar    %eax
    2011:	8d 70 ec             	lea    -0x14(%rax),%esi
    2014:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    201a:	89 c2                	mov    %eax,%edx
    201c:	c1 ea 1f             	shr    $0x1f,%edx
    201f:	01 d0                	add    %edx,%eax
    2021:	d1 f8                	sar    %eax
    2023:	8d 78 fe             	lea    -0x2(%rax),%edi
    2026:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    202d:	48 89 c1             	mov    %rax,%rcx
    2030:	48 8d 15 dd 0f 00 00 	lea    0xfdd(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    2037:	b8 00 00 00 00       	mov    $0x0,%eax
    203c:	e8 5f f3 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 - 2, col / 2 + 10, "%s", bestPlayerName);
    2041:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    2047:	89 c2                	mov    %eax,%edx
    2049:	c1 ea 1f             	shr    $0x1f,%edx
    204c:	01 d0                	add    %edx,%eax
    204e:	d1 f8                	sar    %eax
    2050:	8d 70 0a             	lea    0xa(%rax),%esi
    2053:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    2059:	89 c2                	mov    %eax,%edx
    205b:	c1 ea 1f             	shr    $0x1f,%edx
    205e:	01 d0                	add    %edx,%eax
    2060:	d1 f8                	sar    %eax
    2062:	8d 78 fe             	lea    -0x2(%rax),%edi
    2065:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    2069:	48 89 c1             	mov    %rax,%rcx
    206c:	48 8d 15 a1 0f 00 00 	lea    0xfa1(%rip),%rdx        # 3014 <_ZStL19piecewise_construct+0xc>
    2073:	b8 00 00 00 00       	mov    $0x0,%eax
    2078:	e8 23 f3 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 - 1, col / 2 + 10, "BEST : %d", bestScore);
    207d:	8b 95 c8 fe ff ff    	mov    -0x138(%rbp),%edx
    2083:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    2089:	89 c1                	mov    %eax,%ecx
    208b:	c1 e9 1f             	shr    $0x1f,%ecx
    208e:	01 c8                	add    %ecx,%eax
    2090:	d1 f8                	sar    %eax
    2092:	8d 70 0a             	lea    0xa(%rax),%esi
    2095:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    209b:	89 c1                	mov    %eax,%ecx
    209d:	c1 e9 1f             	shr    $0x1f,%ecx
    20a0:	01 c8                	add    %ecx,%eax
    20a2:	d1 f8                	sar    %eax
    20a4:	83 e8 01             	sub    $0x1,%eax
    20a7:	89 d1                	mov    %edx,%ecx
    20a9:	48 8d 15 67 0f 00 00 	lea    0xf67(%rip),%rdx        # 3017 <_ZStL19piecewise_construct+0xf>
    20b0:	89 c7                	mov    %eax,%edi
    20b2:	b8 00 00 00 00       	mov    $0x0,%eax
    20b7:	e8 e4 f2 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 1, (col - 39) / 2, "Best score was saved to \"%s\"",
    20bc:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    20c2:	83 e8 27             	sub    $0x27,%eax
    20c5:	89 c2                	mov    %eax,%edx
    20c7:	c1 ea 1f             	shr    $0x1f,%edx
    20ca:	01 d0                	add    %edx,%eax
    20cc:	d1 f8                	sar    %eax
    20ce:	89 c6                	mov    %eax,%esi
    20d0:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    20d6:	89 c2                	mov    %eax,%edx
    20d8:	c1 ea 1f             	shr    $0x1f,%edx
    20db:	01 d0                	add    %edx,%eax
    20dd:	d1 f8                	sar    %eax
    20df:	83 c0 01             	add    $0x1,%eax
    20e2:	48 8d 0d 53 10 00 00 	lea    0x1053(%rip),%rcx        # 313c <_ZStL19piecewise_construct+0x134>
    20e9:	48 8d 15 5a 10 00 00 	lea    0x105a(%rip),%rdx        # 314a <_ZStL19piecewise_construct+0x142>
    20f0:	89 c7                	mov    %eax,%edi
    20f2:	b8 00 00 00 00       	mov    $0x0,%eax
    20f7:	e8 a4 f2 ff ff       	callq  13a0 <mvprintw@plt>
			 FILE_NAME);
	refresh();
    20fc:	e8 0f f3 ff ff       	callq  1410 <refresh@plt>

	getchar();
    2101:	e8 aa f2 ff ff       	callq  13b0 <getchar@plt>

	endwin();
    2106:	e8 65 f2 ff ff       	callq  1370 <endwin@plt>
	return 0;
    210b:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2110:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
    2114:	64 48 33 3c 25 28 00 	xor    %fs:0x28,%rdi
    211b:	00 00 
    211d:	74 05                	je     2124 <main+0xbfb>
    211f:	e8 1c f2 ff ff       	callq  1340 <__stack_chk_fail@plt>
    2124:	c9                   	leaveq 
    2125:	c3                   	retq   

0000000000002126 <_Z9writeInfoii>:

void writeInfo(int row, int col) {
    2126:	f3 0f 1e fa          	endbr64 
    212a:	55                   	push   %rbp
    212b:	48 89 e5             	mov    %rsp,%rbp
    212e:	48 83 ec 10          	sub    $0x10,%rsp
    2132:	89 7d fc             	mov    %edi,-0x4(%rbp)
    2135:	89 75 f8             	mov    %esi,-0x8(%rbp)
	| |_  | |/ _` | '_ \| '_ \| | | |  _ \| | '__/ _` |
	|  _| | | (_| | |_) | |_) | |_| | |_) | | | | (_| |
	|_|   |_|\__,_| .__/| .__/ \__, |____/|_|_|  \__,_|
				  |_|   |_|    |___/
	*/
	attron(A_BOLD | COLOR_PAIR(4));
    2138:	48 8b 05 d1 2e 00 00 	mov    0x2ed1(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    213f:	ba 00 00 00 00       	mov    $0x0,%edx
    2144:	be 00 04 20 00       	mov    $0x200400,%esi
    2149:	48 89 c7             	mov    %rax,%rdi
    214c:	e8 5f f1 ff ff       	callq  12b0 <wattr_on@plt>
	mvprintw(row / 2 - 10, (col - 50) / 2,
    2151:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2154:	83 e8 32             	sub    $0x32,%eax
    2157:	89 c2                	mov    %eax,%edx
    2159:	c1 ea 1f             	shr    $0x1f,%edx
    215c:	01 d0                	add    %edx,%eax
    215e:	d1 f8                	sar    %eax
    2160:	89 c1                	mov    %eax,%ecx
    2162:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2165:	89 c2                	mov    %eax,%edx
    2167:	c1 ea 1f             	shr    $0x1f,%edx
    216a:	01 d0                	add    %edx,%eax
    216c:	d1 f8                	sar    %eax
    216e:	83 e8 0a             	sub    $0xa,%eax
    2171:	48 8d 15 f0 0f 00 00 	lea    0xff0(%rip),%rdx        # 3168 <_ZStL19piecewise_construct+0x160>
    2178:	89 ce                	mov    %ecx,%esi
    217a:	89 c7                	mov    %eax,%edi
    217c:	b8 00 00 00 00       	mov    $0x0,%eax
    2181:	e8 1a f2 ff ff       	callq  13a0 <mvprintw@plt>
			 " _____ _                         ____  _         _ ");
	mvprintw(row / 2 - 9, (col - 50) / 2,
    2186:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2189:	83 e8 32             	sub    $0x32,%eax
    218c:	89 c2                	mov    %eax,%edx
    218e:	c1 ea 1f             	shr    $0x1f,%edx
    2191:	01 d0                	add    %edx,%eax
    2193:	d1 f8                	sar    %eax
    2195:	89 c1                	mov    %eax,%ecx
    2197:	8b 45 fc             	mov    -0x4(%rbp),%eax
    219a:	89 c2                	mov    %eax,%edx
    219c:	c1 ea 1f             	shr    $0x1f,%edx
    219f:	01 d0                	add    %edx,%eax
    21a1:	d1 f8                	sar    %eax
    21a3:	83 e8 09             	sub    $0x9,%eax
    21a6:	48 8d 15 f3 0f 00 00 	lea    0xff3(%rip),%rdx        # 31a0 <_ZStL19piecewise_construct+0x198>
    21ad:	89 ce                	mov    %ecx,%esi
    21af:	89 c7                	mov    %eax,%edi
    21b1:	b8 00 00 00 00       	mov    $0x0,%eax
    21b6:	e8 e5 f1 ff ff       	callq  13a0 <mvprintw@plt>
			 "|  ___| | __ _ _ __  _ __  _   _| __ )(_)_ __ __| |");
	mvprintw(row / 2 - 8, (col - 50) / 2,
    21bb:	8b 45 f8             	mov    -0x8(%rbp),%eax
    21be:	83 e8 32             	sub    $0x32,%eax
    21c1:	89 c2                	mov    %eax,%edx
    21c3:	c1 ea 1f             	shr    $0x1f,%edx
    21c6:	01 d0                	add    %edx,%eax
    21c8:	d1 f8                	sar    %eax
    21ca:	89 c1                	mov    %eax,%ecx
    21cc:	8b 45 fc             	mov    -0x4(%rbp),%eax
    21cf:	89 c2                	mov    %eax,%edx
    21d1:	c1 ea 1f             	shr    $0x1f,%edx
    21d4:	01 d0                	add    %edx,%eax
    21d6:	d1 f8                	sar    %eax
    21d8:	83 e8 08             	sub    $0x8,%eax
    21db:	48 8d 15 f6 0f 00 00 	lea    0xff6(%rip),%rdx        # 31d8 <_ZStL19piecewise_construct+0x1d0>
    21e2:	89 ce                	mov    %ecx,%esi
    21e4:	89 c7                	mov    %eax,%edi
    21e6:	b8 00 00 00 00       	mov    $0x0,%eax
    21eb:	e8 b0 f1 ff ff       	callq  13a0 <mvprintw@plt>
			 "| |_  | |/ _` | '_ \\| '_ \\| | | |  _ \\| | '__/ _` |");
	mvprintw(row / 2 - 7, (col - 50) / 2,
    21f0:	8b 45 f8             	mov    -0x8(%rbp),%eax
    21f3:	83 e8 32             	sub    $0x32,%eax
    21f6:	89 c2                	mov    %eax,%edx
    21f8:	c1 ea 1f             	shr    $0x1f,%edx
    21fb:	01 d0                	add    %edx,%eax
    21fd:	d1 f8                	sar    %eax
    21ff:	89 c1                	mov    %eax,%ecx
    2201:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2204:	89 c2                	mov    %eax,%edx
    2206:	c1 ea 1f             	shr    $0x1f,%edx
    2209:	01 d0                	add    %edx,%eax
    220b:	d1 f8                	sar    %eax
    220d:	83 e8 07             	sub    $0x7,%eax
    2210:	48 8d 15 f9 0f 00 00 	lea    0xff9(%rip),%rdx        # 3210 <_ZStL19piecewise_construct+0x208>
    2217:	89 ce                	mov    %ecx,%esi
    2219:	89 c7                	mov    %eax,%edi
    221b:	b8 00 00 00 00       	mov    $0x0,%eax
    2220:	e8 7b f1 ff ff       	callq  13a0 <mvprintw@plt>
			 "|  _| | | (_| | |_) | |_) | |_| | |_) | | | | (_| |");
	mvprintw(row / 2 - 6, (col - 50) / 2,
    2225:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2228:	83 e8 32             	sub    $0x32,%eax
    222b:	89 c2                	mov    %eax,%edx
    222d:	c1 ea 1f             	shr    $0x1f,%edx
    2230:	01 d0                	add    %edx,%eax
    2232:	d1 f8                	sar    %eax
    2234:	89 c1                	mov    %eax,%ecx
    2236:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2239:	89 c2                	mov    %eax,%edx
    223b:	c1 ea 1f             	shr    $0x1f,%edx
    223e:	01 d0                	add    %edx,%eax
    2240:	d1 f8                	sar    %eax
    2242:	83 e8 06             	sub    $0x6,%eax
    2245:	48 8d 15 fc 0f 00 00 	lea    0xffc(%rip),%rdx        # 3248 <_ZStL19piecewise_construct+0x240>
    224c:	89 ce                	mov    %ecx,%esi
    224e:	89 c7                	mov    %eax,%edi
    2250:	b8 00 00 00 00       	mov    $0x0,%eax
    2255:	e8 46 f1 ff ff       	callq  13a0 <mvprintw@plt>
			 "|_|   |_|\\__,_| .__/| .__/ \\__, |____/|_|_|  \\__,_|");
	mvprintw(row / 2 - 5, (col - 50) / 2,
    225a:	8b 45 f8             	mov    -0x8(%rbp),%eax
    225d:	83 e8 32             	sub    $0x32,%eax
    2260:	89 c2                	mov    %eax,%edx
    2262:	c1 ea 1f             	shr    $0x1f,%edx
    2265:	01 d0                	add    %edx,%eax
    2267:	d1 f8                	sar    %eax
    2269:	89 c1                	mov    %eax,%ecx
    226b:	8b 45 fc             	mov    -0x4(%rbp),%eax
    226e:	89 c2                	mov    %eax,%edx
    2270:	c1 ea 1f             	shr    $0x1f,%edx
    2273:	01 d0                	add    %edx,%eax
    2275:	d1 f8                	sar    %eax
    2277:	83 e8 05             	sub    $0x5,%eax
    227a:	48 8d 15 ff 0f 00 00 	lea    0xfff(%rip),%rdx        # 3280 <_ZStL19piecewise_construct+0x278>
    2281:	89 ce                	mov    %ecx,%esi
    2283:	89 c7                	mov    %eax,%edi
    2285:	b8 00 00 00 00       	mov    $0x0,%eax
    228a:	e8 11 f1 ff ff       	callq  13a0 <mvprintw@plt>
			 "              |_|   |_|    |___/                   ");
	attroff(A_BOLD | COLOR_PAIR(4));
    228f:	48 8b 05 7a 2d 00 00 	mov    0x2d7a(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    2296:	ba 00 00 00 00       	mov    $0x0,%edx
    229b:	be 00 04 20 00       	mov    $0x200400,%esi
    22a0:	48 89 c7             	mov    %rax,%rdi
    22a3:	e8 e8 f0 ff ff       	callq  1390 <wattr_off@plt>
		[][][]      []  [][][][][][]
		[]            []          []
		  [][]          [][][][][]
			  [][][][][]
	*/
	attron(COLOR_PAIR(7));
    22a8:	48 8b 05 61 2d 00 00 	mov    0x2d61(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    22af:	ba 00 00 00 00       	mov    $0x0,%edx
    22b4:	be 00 07 00 00       	mov    $0x700,%esi
    22b9:	48 89 c7             	mov    %rax,%rdi
    22bc:	e8 ef ef ff ff       	callq  12b0 <wattr_on@plt>
	mvprintw(row / 2 - 3, (col - 34) / 2, "            [][][][][][]          ");
    22c1:	8b 45 f8             	mov    -0x8(%rbp),%eax
    22c4:	83 e8 22             	sub    $0x22,%eax
    22c7:	89 c2                	mov    %eax,%edx
    22c9:	c1 ea 1f             	shr    $0x1f,%edx
    22cc:	01 d0                	add    %edx,%eax
    22ce:	d1 f8                	sar    %eax
    22d0:	89 c1                	mov    %eax,%ecx
    22d2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    22d5:	89 c2                	mov    %eax,%edx
    22d7:	c1 ea 1f             	shr    $0x1f,%edx
    22da:	01 d0                	add    %edx,%eax
    22dc:	d1 f8                	sar    %eax
    22de:	83 e8 03             	sub    $0x3,%eax
    22e1:	48 8d 15 d0 0f 00 00 	lea    0xfd0(%rip),%rdx        # 32b8 <_ZStL19piecewise_construct+0x2b0>
    22e8:	89 ce                	mov    %ecx,%esi
    22ea:	89 c7                	mov    %eax,%edi
    22ec:	b8 00 00 00 00       	mov    $0x0,%eax
    22f1:	e8 aa f0 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 - 2, (col - 34) / 2, "        [][]      []    []        ");
    22f6:	8b 45 f8             	mov    -0x8(%rbp),%eax
    22f9:	83 e8 22             	sub    $0x22,%eax
    22fc:	89 c2                	mov    %eax,%edx
    22fe:	c1 ea 1f             	shr    $0x1f,%edx
    2301:	01 d0                	add    %edx,%eax
    2303:	d1 f8                	sar    %eax
    2305:	89 c1                	mov    %eax,%ecx
    2307:	8b 45 fc             	mov    -0x4(%rbp),%eax
    230a:	89 c2                	mov    %eax,%edx
    230c:	c1 ea 1f             	shr    $0x1f,%edx
    230f:	01 d0                	add    %edx,%eax
    2311:	d1 f8                	sar    %eax
    2313:	83 e8 02             	sub    $0x2,%eax
    2316:	48 8d 15 c3 0f 00 00 	lea    0xfc3(%rip),%rdx        # 32e0 <_ZStL19piecewise_construct+0x2d8>
    231d:	89 ce                	mov    %ecx,%esi
    231f:	89 c7                	mov    %eax,%edi
    2321:	b8 00 00 00 00       	mov    $0x0,%eax
    2326:	e8 75 f0 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 - 1, (col - 34) / 2, "      []        []        []      ");
    232b:	8b 45 f8             	mov    -0x8(%rbp),%eax
    232e:	83 e8 22             	sub    $0x22,%eax
    2331:	89 c2                	mov    %eax,%edx
    2333:	c1 ea 1f             	shr    $0x1f,%edx
    2336:	01 d0                	add    %edx,%eax
    2338:	d1 f8                	sar    %eax
    233a:	89 c1                	mov    %eax,%ecx
    233c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    233f:	89 c2                	mov    %eax,%edx
    2341:	c1 ea 1f             	shr    $0x1f,%edx
    2344:	01 d0                	add    %edx,%eax
    2346:	d1 f8                	sar    %eax
    2348:	83 e8 01             	sub    $0x1,%eax
    234b:	48 8d 15 b6 0f 00 00 	lea    0xfb6(%rip),%rdx        # 3308 <_ZStL19piecewise_construct+0x300>
    2352:	89 ce                	mov    %ecx,%esi
    2354:	89 c7                	mov    %eax,%edi
    2356:	b8 00 00 00 00       	mov    $0x0,%eax
    235b:	e8 40 f0 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 0, (col - 34) / 2, "  [][][][]      []      []  []    ");
    2360:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2363:	83 e8 22             	sub    $0x22,%eax
    2366:	89 c2                	mov    %eax,%edx
    2368:	c1 ea 1f             	shr    $0x1f,%edx
    236b:	01 d0                	add    %edx,%eax
    236d:	d1 f8                	sar    %eax
    236f:	89 c1                	mov    %eax,%ecx
    2371:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2374:	89 c2                	mov    %eax,%edx
    2376:	c1 ea 1f             	shr    $0x1f,%edx
    2379:	01 d0                	add    %edx,%eax
    237b:	d1 f8                	sar    %eax
    237d:	48 8d 15 ac 0f 00 00 	lea    0xfac(%rip),%rdx        # 3330 <_ZStL19piecewise_construct+0x328>
    2384:	89 ce                	mov    %ecx,%esi
    2386:	89 c7                	mov    %eax,%edi
    2388:	b8 00 00 00 00       	mov    $0x0,%eax
    238d:	e8 0e f0 ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 1, (col - 34) / 2, "[]        []    []      []  []    ");
    2392:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2395:	83 e8 22             	sub    $0x22,%eax
    2398:	89 c2                	mov    %eax,%edx
    239a:	c1 ea 1f             	shr    $0x1f,%edx
    239d:	01 d0                	add    %edx,%eax
    239f:	d1 f8                	sar    %eax
    23a1:	89 c1                	mov    %eax,%ecx
    23a3:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23a6:	89 c2                	mov    %eax,%edx
    23a8:	c1 ea 1f             	shr    $0x1f,%edx
    23ab:	01 d0                	add    %edx,%eax
    23ad:	d1 f8                	sar    %eax
    23af:	83 c0 01             	add    $0x1,%eax
    23b2:	48 8d 15 9f 0f 00 00 	lea    0xf9f(%rip),%rdx        # 3358 <_ZStL19piecewise_construct+0x350>
    23b9:	89 ce                	mov    %ecx,%esi
    23bb:	89 c7                	mov    %eax,%edi
    23bd:	b8 00 00 00 00       	mov    $0x0,%eax
    23c2:	e8 d9 ef ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 2, (col - 34) / 2, "[]          []    []        []    ");
    23c7:	8b 45 f8             	mov    -0x8(%rbp),%eax
    23ca:	83 e8 22             	sub    $0x22,%eax
    23cd:	89 c2                	mov    %eax,%edx
    23cf:	c1 ea 1f             	shr    $0x1f,%edx
    23d2:	01 d0                	add    %edx,%eax
    23d4:	d1 f8                	sar    %eax
    23d6:	89 c1                	mov    %eax,%ecx
    23d8:	8b 45 fc             	mov    -0x4(%rbp),%eax
    23db:	89 c2                	mov    %eax,%edx
    23dd:	c1 ea 1f             	shr    $0x1f,%edx
    23e0:	01 d0                	add    %edx,%eax
    23e2:	d1 f8                	sar    %eax
    23e4:	83 c0 02             	add    $0x2,%eax
    23e7:	48 8d 15 92 0f 00 00 	lea    0xf92(%rip),%rdx        # 3380 <_ZStL19piecewise_construct+0x378>
    23ee:	89 ce                	mov    %ecx,%esi
    23f0:	89 c7                	mov    %eax,%edi
    23f2:	b8 00 00 00 00       	mov    $0x0,%eax
    23f7:	e8 a4 ef ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 3, (col - 34) / 2, "[]          []      [][][][][][]  ");
    23fc:	8b 45 f8             	mov    -0x8(%rbp),%eax
    23ff:	83 e8 22             	sub    $0x22,%eax
    2402:	89 c2                	mov    %eax,%edx
    2404:	c1 ea 1f             	shr    $0x1f,%edx
    2407:	01 d0                	add    %edx,%eax
    2409:	d1 f8                	sar    %eax
    240b:	89 c1                	mov    %eax,%ecx
    240d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2410:	89 c2                	mov    %eax,%edx
    2412:	c1 ea 1f             	shr    $0x1f,%edx
    2415:	01 d0                	add    %edx,%eax
    2417:	d1 f8                	sar    %eax
    2419:	83 c0 03             	add    $0x3,%eax
    241c:	48 8d 15 85 0f 00 00 	lea    0xf85(%rip),%rdx        # 33a8 <_ZStL19piecewise_construct+0x3a0>
    2423:	89 ce                	mov    %ecx,%esi
    2425:	89 c7                	mov    %eax,%edi
    2427:	b8 00 00 00 00       	mov    $0x0,%eax
    242c:	e8 6f ef ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 4, (col - 34) / 2, "  []      []      []            []");
    2431:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2434:	83 e8 22             	sub    $0x22,%eax
    2437:	89 c2                	mov    %eax,%edx
    2439:	c1 ea 1f             	shr    $0x1f,%edx
    243c:	01 d0                	add    %edx,%eax
    243e:	d1 f8                	sar    %eax
    2440:	89 c1                	mov    %eax,%ecx
    2442:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2445:	89 c2                	mov    %eax,%edx
    2447:	c1 ea 1f             	shr    $0x1f,%edx
    244a:	01 d0                	add    %edx,%eax
    244c:	d1 f8                	sar    %eax
    244e:	83 c0 04             	add    $0x4,%eax
    2451:	48 8d 15 78 0f 00 00 	lea    0xf78(%rip),%rdx        # 33d0 <_ZStL19piecewise_construct+0x3c8>
    2458:	89 ce                	mov    %ecx,%esi
    245a:	89 c7                	mov    %eax,%edi
    245c:	b8 00 00 00 00       	mov    $0x0,%eax
    2461:	e8 3a ef ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 5, (col - 34) / 2, "    [][][]      []  [][][][][][]  ");
    2466:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2469:	83 e8 22             	sub    $0x22,%eax
    246c:	89 c2                	mov    %eax,%edx
    246e:	c1 ea 1f             	shr    $0x1f,%edx
    2471:	01 d0                	add    %edx,%eax
    2473:	d1 f8                	sar    %eax
    2475:	89 c1                	mov    %eax,%ecx
    2477:	8b 45 fc             	mov    -0x4(%rbp),%eax
    247a:	89 c2                	mov    %eax,%edx
    247c:	c1 ea 1f             	shr    $0x1f,%edx
    247f:	01 d0                	add    %edx,%eax
    2481:	d1 f8                	sar    %eax
    2483:	83 c0 05             	add    $0x5,%eax
    2486:	48 8d 15 6b 0f 00 00 	lea    0xf6b(%rip),%rdx        # 33f8 <_ZStL19piecewise_construct+0x3f0>
    248d:	89 ce                	mov    %ecx,%esi
    248f:	89 c7                	mov    %eax,%edi
    2491:	b8 00 00 00 00       	mov    $0x0,%eax
    2496:	e8 05 ef ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 6, (col - 34) / 2, "    []            []          []  ");
    249b:	8b 45 f8             	mov    -0x8(%rbp),%eax
    249e:	83 e8 22             	sub    $0x22,%eax
    24a1:	89 c2                	mov    %eax,%edx
    24a3:	c1 ea 1f             	shr    $0x1f,%edx
    24a6:	01 d0                	add    %edx,%eax
    24a8:	d1 f8                	sar    %eax
    24aa:	89 c1                	mov    %eax,%ecx
    24ac:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24af:	89 c2                	mov    %eax,%edx
    24b1:	c1 ea 1f             	shr    $0x1f,%edx
    24b4:	01 d0                	add    %edx,%eax
    24b6:	d1 f8                	sar    %eax
    24b8:	83 c0 06             	add    $0x6,%eax
    24bb:	48 8d 15 5e 0f 00 00 	lea    0xf5e(%rip),%rdx        # 3420 <_ZStL19piecewise_construct+0x418>
    24c2:	89 ce                	mov    %ecx,%esi
    24c4:	89 c7                	mov    %eax,%edi
    24c6:	b8 00 00 00 00       	mov    $0x0,%eax
    24cb:	e8 d0 ee ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 7, (col - 34) / 2, "      [][]          [][][][][]    ");
    24d0:	8b 45 f8             	mov    -0x8(%rbp),%eax
    24d3:	83 e8 22             	sub    $0x22,%eax
    24d6:	89 c2                	mov    %eax,%edx
    24d8:	c1 ea 1f             	shr    $0x1f,%edx
    24db:	01 d0                	add    %edx,%eax
    24dd:	d1 f8                	sar    %eax
    24df:	89 c1                	mov    %eax,%ecx
    24e1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24e4:	89 c2                	mov    %eax,%edx
    24e6:	c1 ea 1f             	shr    $0x1f,%edx
    24e9:	01 d0                	add    %edx,%eax
    24eb:	d1 f8                	sar    %eax
    24ed:	83 c0 07             	add    $0x7,%eax
    24f0:	48 8d 15 51 0f 00 00 	lea    0xf51(%rip),%rdx        # 3448 <_ZStL19piecewise_construct+0x440>
    24f7:	89 ce                	mov    %ecx,%esi
    24f9:	89 c7                	mov    %eax,%edi
    24fb:	b8 00 00 00 00       	mov    $0x0,%eax
    2500:	e8 9b ee ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 8, (col - 34) / 2, "          [][][][][]              ");
    2505:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2508:	83 e8 22             	sub    $0x22,%eax
    250b:	89 c2                	mov    %eax,%edx
    250d:	c1 ea 1f             	shr    $0x1f,%edx
    2510:	01 d0                	add    %edx,%eax
    2512:	d1 f8                	sar    %eax
    2514:	89 c1                	mov    %eax,%ecx
    2516:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2519:	89 c2                	mov    %eax,%edx
    251b:	c1 ea 1f             	shr    $0x1f,%edx
    251e:	01 d0                	add    %edx,%eax
    2520:	d1 f8                	sar    %eax
    2522:	83 c0 08             	add    $0x8,%eax
    2525:	48 8d 15 44 0f 00 00 	lea    0xf44(%rip),%rdx        # 3470 <_ZStL19piecewise_construct+0x468>
    252c:	89 ce                	mov    %ecx,%esi
    252e:	89 c7                	mov    %eax,%edi
    2530:	b8 00 00 00 00       	mov    $0x0,%eax
    2535:	e8 66 ee ff ff       	callq  13a0 <mvprintw@plt>
	attroff(COLOR_PAIR(7));
    253a:	48 8b 05 cf 2a 00 00 	mov    0x2acf(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    2541:	ba 00 00 00 00       	mov    $0x0,%edx
    2546:	be 00 07 00 00       	mov    $0x700,%esi
    254b:	48 89 c7             	mov    %rax,%rdi
    254e:	e8 3d ee ff ff       	callq  1390 <wattr_off@plt>
	mvprintw(row / 2 + 10, (col - 24) / 2, "Enter Your Name: ");
    2553:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2556:	83 e8 18             	sub    $0x18,%eax
    2559:	89 c2                	mov    %eax,%edx
    255b:	c1 ea 1f             	shr    $0x1f,%edx
    255e:	01 d0                	add    %edx,%eax
    2560:	d1 f8                	sar    %eax
    2562:	89 c1                	mov    %eax,%ecx
    2564:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2567:	89 c2                	mov    %eax,%edx
    2569:	c1 ea 1f             	shr    $0x1f,%edx
    256c:	01 d0                	add    %edx,%eax
    256e:	d1 f8                	sar    %eax
    2570:	83 c0 0a             	add    $0xa,%eax
    2573:	48 8d 15 19 0f 00 00 	lea    0xf19(%rip),%rdx        # 3493 <_ZStL19piecewise_construct+0x48b>
    257a:	89 ce                	mov    %ecx,%esi
    257c:	89 c7                	mov    %eax,%edi
    257e:	b8 00 00 00 00       	mov    $0x0,%eax
    2583:	e8 18 ee ff ff       	callq  13a0 <mvprintw@plt>
}
    2588:	90                   	nop
    2589:	c9                   	leaveq 
    258a:	c3                   	retq   

000000000000258b <_Z16controlCollisioniiiii>:

int controlCollision(int pipeCol, int birdCol, int birdRow, int crackStart,
					 int crackFinish) {
    258b:	f3 0f 1e fa          	endbr64 
    258f:	55                   	push   %rbp
    2590:	48 89 e5             	mov    %rsp,%rbp
    2593:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2596:	89 75 e8             	mov    %esi,-0x18(%rbp)
    2599:	89 55 e4             	mov    %edx,-0x1c(%rbp)
    259c:	89 4d e0             	mov    %ecx,-0x20(%rbp)
    259f:	44 89 45 dc          	mov    %r8d,-0x24(%rbp)
	int status = false;
    25a3:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)

	if (pipeCol - 8 == birdCol || pipeCol - 7 == birdCol ||
    25aa:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25ad:	83 e8 08             	sub    $0x8,%eax
    25b0:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25b3:	74 4d                	je     2602 <_Z16controlCollisioniiiii+0x77>
    25b5:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25b8:	83 e8 07             	sub    $0x7,%eax
    25bb:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25be:	74 42                	je     2602 <_Z16controlCollisioniiiii+0x77>
		pipeCol - 6 == birdCol || pipeCol - 5 == birdCol ||
    25c0:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25c3:	83 e8 06             	sub    $0x6,%eax
	if (pipeCol - 8 == birdCol || pipeCol - 7 == birdCol ||
    25c6:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25c9:	74 37                	je     2602 <_Z16controlCollisioniiiii+0x77>
		pipeCol - 6 == birdCol || pipeCol - 5 == birdCol ||
    25cb:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25ce:	83 e8 05             	sub    $0x5,%eax
    25d1:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25d4:	74 2c                	je     2602 <_Z16controlCollisioniiiii+0x77>
		pipeCol - 4 == birdCol || pipeCol - 3 == birdCol ||
    25d6:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25d9:	83 e8 04             	sub    $0x4,%eax
		pipeCol - 6 == birdCol || pipeCol - 5 == birdCol ||
    25dc:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25df:	74 21                	je     2602 <_Z16controlCollisioniiiii+0x77>
		pipeCol - 4 == birdCol || pipeCol - 3 == birdCol ||
    25e1:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25e4:	83 e8 03             	sub    $0x3,%eax
    25e7:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25ea:	74 16                	je     2602 <_Z16controlCollisioniiiii+0x77>
		pipeCol - 2 == birdCol || pipeCol - 1 == birdCol) {
    25ec:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25ef:	83 e8 02             	sub    $0x2,%eax
		pipeCol - 4 == birdCol || pipeCol - 3 == birdCol ||
    25f2:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    25f5:	74 0b                	je     2602 <_Z16controlCollisioniiiii+0x77>
		pipeCol - 2 == birdCol || pipeCol - 1 == birdCol) {
    25f7:	8b 45 ec             	mov    -0x14(%rbp),%eax
    25fa:	83 e8 01             	sub    $0x1,%eax
    25fd:	39 45 e8             	cmp    %eax,-0x18(%rbp)
    2600:	75 18                	jne    261a <_Z16controlCollisioniiiii+0x8f>
		status++;
    2602:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
		if (birdRow < crackStart || birdRow > crackFinish) {
    2606:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2609:	3b 45 e0             	cmp    -0x20(%rbp),%eax
    260c:	7c 08                	jl     2616 <_Z16controlCollisioniiiii+0x8b>
    260e:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2611:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    2614:	7e 04                	jle    261a <_Z16controlCollisioniiiii+0x8f>
			status++;
    2616:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
		}
	}

	return status;
    261a:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    261d:	5d                   	pop    %rbp
    261e:	c3                   	retq   

000000000000261f <_Z8drawPipeiiii>:

void drawPipe(int begin, int end, int pipeCol, int row) {
    261f:	f3 0f 1e fa          	endbr64 
    2623:	55                   	push   %rbp
    2624:	48 89 e5             	mov    %rsp,%rbp
    2627:	48 83 ec 20          	sub    $0x20,%rsp
    262b:	89 7d ec             	mov    %edi,-0x14(%rbp)
    262e:	89 75 e8             	mov    %esi,-0x18(%rbp)
    2631:	89 55 e4             	mov    %edx,-0x1c(%rbp)
    2634:	89 4d e0             	mov    %ecx,-0x20(%rbp)
	for (int i = 0; i < row - 3; i++) {
    2637:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    263e:	8b 45 e0             	mov    -0x20(%rbp),%eax
    2641:	83 e8 03             	sub    $0x3,%eax
    2644:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    2647:	0f 8d 0c 01 00 00    	jge    2759 <_Z8drawPipeiiii+0x13a>
		if (i < begin) {
    264d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2650:	3b 45 ec             	cmp    -0x14(%rbp),%eax
    2653:	7d 7f                	jge    26d4 <_Z8drawPipeiiii+0xb5>
			if (i == begin - 1 || i == begin - 2) {
    2655:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2658:	83 e8 01             	sub    $0x1,%eax
    265b:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    265e:	74 0b                	je     266b <_Z8drawPipeiiii+0x4c>
    2660:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2663:	83 e8 02             	sub    $0x2,%eax
    2666:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    2669:	75 20                	jne    268b <_Z8drawPipeiiii+0x6c>
				mvprintw(i, pipeCol - 9, "          ");
    266b:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    266e:	8d 48 f7             	lea    -0x9(%rax),%ecx
    2671:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2674:	48 8d 15 2a 0e 00 00 	lea    0xe2a(%rip),%rdx        # 34a5 <_ZStL19piecewise_construct+0x49d>
    267b:	89 ce                	mov    %ecx,%esi
    267d:	89 c7                	mov    %eax,%edi
    267f:	b8 00 00 00 00       	mov    $0x0,%eax
    2684:	e8 17 ed ff ff       	callq  13a0 <mvprintw@plt>
    2689:	eb 49                	jmp    26d4 <_Z8drawPipeiiii+0xb5>
			} else if (i == begin - 3) {
    268b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    268e:	83 e8 03             	sub    $0x3,%eax
    2691:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    2694:	75 20                	jne    26b6 <_Z8drawPipeiiii+0x97>
				mvprintw(i, pipeCol - 8, "________");
    2696:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2699:	8d 48 f8             	lea    -0x8(%rax),%ecx
    269c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    269f:	48 8d 15 0a 0e 00 00 	lea    0xe0a(%rip),%rdx        # 34b0 <_ZStL19piecewise_construct+0x4a8>
    26a6:	89 ce                	mov    %ecx,%esi
    26a8:	89 c7                	mov    %eax,%edi
    26aa:	b8 00 00 00 00       	mov    $0x0,%eax
    26af:	e8 ec ec ff ff       	callq  13a0 <mvprintw@plt>
    26b4:	eb 1e                	jmp    26d4 <_Z8drawPipeiiii+0xb5>
			} else {
				//                       9876543210
				mvprintw(i, pipeCol - 8, "        ");
    26b6:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    26b9:	8d 48 f8             	lea    -0x8(%rax),%ecx
    26bc:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26bf:	48 8d 15 f3 0d 00 00 	lea    0xdf3(%rip),%rdx        # 34b9 <_ZStL19piecewise_construct+0x4b1>
    26c6:	89 ce                	mov    %ecx,%esi
    26c8:	89 c7                	mov    %eax,%edi
    26ca:	b8 00 00 00 00       	mov    $0x0,%eax
    26cf:	e8 cc ec ff ff       	callq  13a0 <mvprintw@plt>
			}
		}
		if (i > end) {
    26d4:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26d7:	3b 45 e8             	cmp    -0x18(%rbp),%eax
    26da:	7e 74                	jle    2750 <_Z8drawPipeiiii+0x131>
			if (i == end + 1) {
    26dc:	8b 45 e8             	mov    -0x18(%rbp),%eax
    26df:	83 c0 01             	add    $0x1,%eax
    26e2:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    26e5:	75 20                	jne    2707 <_Z8drawPipeiiii+0xe8>
				mvprintw(i, pipeCol - 9, "          ");
    26e7:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    26ea:	8d 48 f7             	lea    -0x9(%rax),%ecx
    26ed:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26f0:	48 8d 15 ae 0d 00 00 	lea    0xdae(%rip),%rdx        # 34a5 <_ZStL19piecewise_construct+0x49d>
    26f7:	89 ce                	mov    %ecx,%esi
    26f9:	89 c7                	mov    %eax,%edi
    26fb:	b8 00 00 00 00       	mov    $0x0,%eax
    2700:	e8 9b ec ff ff       	callq  13a0 <mvprintw@plt>
    2705:	eb 49                	jmp    2750 <_Z8drawPipeiiii+0x131>
			} else if (i == end + 2) {
    2707:	8b 45 e8             	mov    -0x18(%rbp),%eax
    270a:	83 c0 02             	add    $0x2,%eax
    270d:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    2710:	75 20                	jne    2732 <_Z8drawPipeiiii+0x113>
				mvprintw(i, pipeCol - 9, " ________ ");
    2712:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2715:	8d 48 f7             	lea    -0x9(%rax),%ecx
    2718:	8b 45 fc             	mov    -0x4(%rbp),%eax
    271b:	48 8d 15 a0 0d 00 00 	lea    0xda0(%rip),%rdx        # 34c2 <_ZStL19piecewise_construct+0x4ba>
    2722:	89 ce                	mov    %ecx,%esi
    2724:	89 c7                	mov    %eax,%edi
    2726:	b8 00 00 00 00       	mov    $0x0,%eax
    272b:	e8 70 ec ff ff       	callq  13a0 <mvprintw@plt>
    2730:	eb 1e                	jmp    2750 <_Z8drawPipeiiii+0x131>
			} else {
				mvprintw(i, pipeCol - 8, "        ");
    2732:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    2735:	8d 48 f8             	lea    -0x8(%rax),%ecx
    2738:	8b 45 fc             	mov    -0x4(%rbp),%eax
    273b:	48 8d 15 77 0d 00 00 	lea    0xd77(%rip),%rdx        # 34b9 <_ZStL19piecewise_construct+0x4b1>
    2742:	89 ce                	mov    %ecx,%esi
    2744:	89 c7                	mov    %eax,%edi
    2746:	b8 00 00 00 00       	mov    $0x0,%eax
    274b:	e8 50 ec ff ff       	callq  13a0 <mvprintw@plt>
	for (int i = 0; i < row - 3; i++) {
    2750:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2754:	e9 e5 fe ff ff       	jmpq   263e <_Z8drawPipeiiii+0x1f>
			}
		}
	}
}
    2759:	90                   	nop
    275a:	c9                   	leaveq 
    275b:	c3                   	retq   

000000000000275c <_Z12drawStartingii>:

void drawStarting(int row, int col) {
    275c:	f3 0f 1e fa          	endbr64 
    2760:	55                   	push   %rbp
    2761:	48 89 e5             	mov    %rsp,%rbp
    2764:	48 83 ec 20          	sub    $0x20,%rsp
    2768:	89 7d ec             	mov    %edi,-0x14(%rbp)
    276b:	89 75 e8             	mov    %esi,-0x18(%rbp)
	clear();
    276e:	e8 ad ec ff ff       	callq  1420 <clear@plt>
	| |  _ / _ \ __| | |_) / _ \/ _` |/ _` | | | | |
	| |_| |  __/ |_  |  _ <  __/ (_| | (_| | |_| |_|
	 \____|\___|\__| |_| \_\___|\__,_|\__,_|\__, (_)
											|___/
	*/
	attron(A_BOLD | COLOR_PAIR(6));
    2773:	48 8b 05 96 28 00 00 	mov    0x2896(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    277a:	ba 00 00 00 00       	mov    $0x0,%edx
    277f:	be 00 06 20 00       	mov    $0x200600,%esi
    2784:	48 89 c7             	mov    %rax,%rdi
    2787:	e8 24 eb ff ff       	callq  12b0 <wattr_on@plt>
	mvprintw(row / 2 - 10, (col - 48) / 2,
    278c:	8b 45 e8             	mov    -0x18(%rbp),%eax
    278f:	83 e8 30             	sub    $0x30,%eax
    2792:	89 c2                	mov    %eax,%edx
    2794:	c1 ea 1f             	shr    $0x1f,%edx
    2797:	01 d0                	add    %edx,%eax
    2799:	d1 f8                	sar    %eax
    279b:	89 c1                	mov    %eax,%ecx
    279d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    27a0:	89 c2                	mov    %eax,%edx
    27a2:	c1 ea 1f             	shr    $0x1f,%edx
    27a5:	01 d0                	add    %edx,%eax
    27a7:	d1 f8                	sar    %eax
    27a9:	83 e8 0a             	sub    $0xa,%eax
    27ac:	48 8d 15 1d 0d 00 00 	lea    0xd1d(%rip),%rdx        # 34d0 <_ZStL19piecewise_construct+0x4c8>
    27b3:	89 ce                	mov    %ecx,%esi
    27b5:	89 c7                	mov    %eax,%edi
    27b7:	b8 00 00 00 00       	mov    $0x0,%eax
    27bc:	e8 df eb ff ff       	callq  13a0 <mvprintw@plt>
			 "  ____      _     ____                _       _ ");
	mvprintw(row / 2 - 9, (col - 48) / 2,
    27c1:	8b 45 e8             	mov    -0x18(%rbp),%eax
    27c4:	83 e8 30             	sub    $0x30,%eax
    27c7:	89 c2                	mov    %eax,%edx
    27c9:	c1 ea 1f             	shr    $0x1f,%edx
    27cc:	01 d0                	add    %edx,%eax
    27ce:	d1 f8                	sar    %eax
    27d0:	89 c1                	mov    %eax,%ecx
    27d2:	8b 45 ec             	mov    -0x14(%rbp),%eax
    27d5:	89 c2                	mov    %eax,%edx
    27d7:	c1 ea 1f             	shr    $0x1f,%edx
    27da:	01 d0                	add    %edx,%eax
    27dc:	d1 f8                	sar    %eax
    27de:	83 e8 09             	sub    $0x9,%eax
    27e1:	48 8d 15 20 0d 00 00 	lea    0xd20(%rip),%rdx        # 3508 <_ZStL19piecewise_construct+0x500>
    27e8:	89 ce                	mov    %ecx,%esi
    27ea:	89 c7                	mov    %eax,%edi
    27ec:	b8 00 00 00 00       	mov    $0x0,%eax
    27f1:	e8 aa eb ff ff       	callq  13a0 <mvprintw@plt>
			 " / ___| ___| |_  |  _ \\ ___  __ _  __| |_   _| |");
	mvprintw(row / 2 - 8, (col - 48) / 2,
    27f6:	8b 45 e8             	mov    -0x18(%rbp),%eax
    27f9:	83 e8 30             	sub    $0x30,%eax
    27fc:	89 c2                	mov    %eax,%edx
    27fe:	c1 ea 1f             	shr    $0x1f,%edx
    2801:	01 d0                	add    %edx,%eax
    2803:	d1 f8                	sar    %eax
    2805:	89 c1                	mov    %eax,%ecx
    2807:	8b 45 ec             	mov    -0x14(%rbp),%eax
    280a:	89 c2                	mov    %eax,%edx
    280c:	c1 ea 1f             	shr    $0x1f,%edx
    280f:	01 d0                	add    %edx,%eax
    2811:	d1 f8                	sar    %eax
    2813:	83 e8 08             	sub    $0x8,%eax
    2816:	48 8d 15 23 0d 00 00 	lea    0xd23(%rip),%rdx        # 3540 <_ZStL19piecewise_construct+0x538>
    281d:	89 ce                	mov    %ecx,%esi
    281f:	89 c7                	mov    %eax,%edi
    2821:	b8 00 00 00 00       	mov    $0x0,%eax
    2826:	e8 75 eb ff ff       	callq  13a0 <mvprintw@plt>
			 "| |  _ / _ \\ __| | |_) / _ \\/ _` |/ _` | | | | |");
	mvprintw(row / 2 - 7, (col - 48) / 2,
    282b:	8b 45 e8             	mov    -0x18(%rbp),%eax
    282e:	83 e8 30             	sub    $0x30,%eax
    2831:	89 c2                	mov    %eax,%edx
    2833:	c1 ea 1f             	shr    $0x1f,%edx
    2836:	01 d0                	add    %edx,%eax
    2838:	d1 f8                	sar    %eax
    283a:	89 c1                	mov    %eax,%ecx
    283c:	8b 45 ec             	mov    -0x14(%rbp),%eax
    283f:	89 c2                	mov    %eax,%edx
    2841:	c1 ea 1f             	shr    $0x1f,%edx
    2844:	01 d0                	add    %edx,%eax
    2846:	d1 f8                	sar    %eax
    2848:	83 e8 07             	sub    $0x7,%eax
    284b:	48 8d 15 26 0d 00 00 	lea    0xd26(%rip),%rdx        # 3578 <_ZStL19piecewise_construct+0x570>
    2852:	89 ce                	mov    %ecx,%esi
    2854:	89 c7                	mov    %eax,%edi
    2856:	b8 00 00 00 00       	mov    $0x0,%eax
    285b:	e8 40 eb ff ff       	callq  13a0 <mvprintw@plt>
			 "| |_| |  __/ |_  |  _ <  __/ (_| | (_| | |_| |_|");
	mvprintw(row / 2 - 6, (col - 48) / 2,
    2860:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2863:	83 e8 30             	sub    $0x30,%eax
    2866:	89 c2                	mov    %eax,%edx
    2868:	c1 ea 1f             	shr    $0x1f,%edx
    286b:	01 d0                	add    %edx,%eax
    286d:	d1 f8                	sar    %eax
    286f:	89 c1                	mov    %eax,%ecx
    2871:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2874:	89 c2                	mov    %eax,%edx
    2876:	c1 ea 1f             	shr    $0x1f,%edx
    2879:	01 d0                	add    %edx,%eax
    287b:	d1 f8                	sar    %eax
    287d:	83 e8 06             	sub    $0x6,%eax
    2880:	48 8d 15 29 0d 00 00 	lea    0xd29(%rip),%rdx        # 35b0 <_ZStL19piecewise_construct+0x5a8>
    2887:	89 ce                	mov    %ecx,%esi
    2889:	89 c7                	mov    %eax,%edi
    288b:	b8 00 00 00 00       	mov    $0x0,%eax
    2890:	e8 0b eb ff ff       	callq  13a0 <mvprintw@plt>
			 " \\____|\\___|\\__| |_| \\_\\___|\\__,_|\\__,_|\\__, (_)");
	mvprintw(row / 2 - 5, (col - 48) / 2,
    2895:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2898:	83 e8 30             	sub    $0x30,%eax
    289b:	89 c2                	mov    %eax,%edx
    289d:	c1 ea 1f             	shr    $0x1f,%edx
    28a0:	01 d0                	add    %edx,%eax
    28a2:	d1 f8                	sar    %eax
    28a4:	89 c1                	mov    %eax,%ecx
    28a6:	8b 45 ec             	mov    -0x14(%rbp),%eax
    28a9:	89 c2                	mov    %eax,%edx
    28ab:	c1 ea 1f             	shr    $0x1f,%edx
    28ae:	01 d0                	add    %edx,%eax
    28b0:	d1 f8                	sar    %eax
    28b2:	83 e8 05             	sub    $0x5,%eax
    28b5:	48 8d 15 2c 0d 00 00 	lea    0xd2c(%rip),%rdx        # 35e8 <_ZStL19piecewise_construct+0x5e0>
    28bc:	89 ce                	mov    %ecx,%esi
    28be:	89 c7                	mov    %eax,%edi
    28c0:	b8 00 00 00 00       	mov    $0x0,%eax
    28c5:	e8 d6 ea ff ff       	callq  13a0 <mvprintw@plt>
			 "                                        |___/   ");
	attroff(A_BOLD | COLOR_PAIR(6));
    28ca:	48 8b 05 3f 27 00 00 	mov    0x273f(%rip),%rax        # 5010 <stdscr@@NCURSES6_TINFO_5.0.19991023>
    28d1:	ba 00 00 00 00       	mov    $0x0,%edx
    28d6:	be 00 06 20 00       	mov    $0x200600,%esi
    28db:	48 89 c7             	mov    %rax,%rdi
    28de:	e8 ad ea ff ff       	callq  1390 <wattr_off@plt>
	mvprintw(row / 2 + 1, (col - 5) / 2 + 3, "]");
    28e3:	8b 45 e8             	mov    -0x18(%rbp),%eax
    28e6:	83 e8 05             	sub    $0x5,%eax
    28e9:	89 c2                	mov    %eax,%edx
    28eb:	c1 ea 1f             	shr    $0x1f,%edx
    28ee:	01 d0                	add    %edx,%eax
    28f0:	d1 f8                	sar    %eax
    28f2:	8d 48 03             	lea    0x3(%rax),%ecx
    28f5:	8b 45 ec             	mov    -0x14(%rbp),%eax
    28f8:	89 c2                	mov    %eax,%edx
    28fa:	c1 ea 1f             	shr    $0x1f,%edx
    28fd:	01 d0                	add    %edx,%eax
    28ff:	d1 f8                	sar    %eax
    2901:	83 c0 01             	add    $0x1,%eax
    2904:	48 8d 15 0e 0d 00 00 	lea    0xd0e(%rip),%rdx        # 3619 <_ZStL19piecewise_construct+0x611>
    290b:	89 ce                	mov    %ecx,%esi
    290d:	89 c7                	mov    %eax,%edi
    290f:	b8 00 00 00 00       	mov    $0x0,%eax
    2914:	e8 87 ea ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 1, (col - 5) / 2 - 1, "[");
    2919:	8b 45 e8             	mov    -0x18(%rbp),%eax
    291c:	83 e8 05             	sub    $0x5,%eax
    291f:	89 c2                	mov    %eax,%edx
    2921:	c1 ea 1f             	shr    $0x1f,%edx
    2924:	01 d0                	add    %edx,%eax
    2926:	d1 f8                	sar    %eax
    2928:	8d 48 ff             	lea    -0x1(%rax),%ecx
    292b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    292e:	89 c2                	mov    %eax,%edx
    2930:	c1 ea 1f             	shr    $0x1f,%edx
    2933:	01 d0                	add    %edx,%eax
    2935:	d1 f8                	sar    %eax
    2937:	83 c0 01             	add    $0x1,%eax
    293a:	48 8d 15 da 0c 00 00 	lea    0xcda(%rip),%rdx        # 361b <_ZStL19piecewise_construct+0x613>
    2941:	89 ce                	mov    %ecx,%esi
    2943:	89 c7                	mov    %eax,%edi
    2945:	b8 00 00 00 00       	mov    $0x0,%eax
    294a:	e8 51 ea ff ff       	callq  13a0 <mvprintw@plt>
	mvprintw(row / 2 + 3, (col - 34) / 2,
    294f:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2952:	83 e8 22             	sub    $0x22,%eax
    2955:	89 c2                	mov    %eax,%edx
    2957:	c1 ea 1f             	shr    $0x1f,%edx
    295a:	01 d0                	add    %edx,%eax
    295c:	d1 f8                	sar    %eax
    295e:	89 c1                	mov    %eax,%ecx
    2960:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2963:	89 c2                	mov    %eax,%edx
    2965:	c1 ea 1f             	shr    $0x1f,%edx
    2968:	01 d0                	add    %edx,%eax
    296a:	d1 f8                	sar    %eax
    296c:	83 c0 03             	add    $0x3,%eax
    296f:	48 8d 15 aa 0c 00 00 	lea    0xcaa(%rip),%rdx        # 3620 <_ZStL19piecewise_construct+0x618>
    2976:	89 ce                	mov    %ecx,%esi
    2978:	89 c7                	mov    %eax,%edi
    297a:	b8 00 00 00 00       	mov    $0x0,%eax
    297f:	e8 1c ea ff ff       	callq  13a0 <mvprintw@plt>
			 "Press \"SPACE BAR\" to flap the bird");

	for (int j = 1; j < 4; j++) {
    2984:	c7 45 f8 01 00 00 00 	movl   $0x1,-0x8(%rbp)
    298b:	83 7d f8 03          	cmpl   $0x3,-0x8(%rbp)
    298f:	7f 66                	jg     29f7 <_Z12drawStartingii+0x29b>
		for (int i = 0; i < j; i++) {
    2991:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2998:	8b 45 fc             	mov    -0x4(%rbp),%eax
    299b:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    299e:	7d 47                	jge    29e7 <_Z12drawStartingii+0x28b>
			mvprintw(row / 2 + 1, (col - 5) / 2 - 1 + j, "#");
    29a0:	8b 45 e8             	mov    -0x18(%rbp),%eax
    29a3:	83 e8 05             	sub    $0x5,%eax
    29a6:	89 c2                	mov    %eax,%edx
    29a8:	c1 ea 1f             	shr    $0x1f,%edx
    29ab:	01 d0                	add    %edx,%eax
    29ad:	d1 f8                	sar    %eax
    29af:	8d 50 ff             	lea    -0x1(%rax),%edx
    29b2:	8b 45 f8             	mov    -0x8(%rbp),%eax
    29b5:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
    29b8:	8b 45 ec             	mov    -0x14(%rbp),%eax
    29bb:	89 c2                	mov    %eax,%edx
    29bd:	c1 ea 1f             	shr    $0x1f,%edx
    29c0:	01 d0                	add    %edx,%eax
    29c2:	d1 f8                	sar    %eax
    29c4:	83 c0 01             	add    $0x1,%eax
    29c7:	48 8d 15 53 06 00 00 	lea    0x653(%rip),%rdx        # 3021 <_ZStL19piecewise_construct+0x19>
    29ce:	89 ce                	mov    %ecx,%esi
    29d0:	89 c7                	mov    %eax,%edi
    29d2:	b8 00 00 00 00       	mov    $0x0,%eax
    29d7:	e8 c4 e9 ff ff       	callq  13a0 <mvprintw@plt>
			refresh();
    29dc:	e8 2f ea ff ff       	callq  1410 <refresh@plt>
		for (int i = 0; i < j; i++) {
    29e1:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    29e5:	eb b1                	jmp    2998 <_Z12drawStartingii+0x23c>
		}
		sleep(1);
    29e7:	bf 01 00 00 00       	mov    $0x1,%edi
    29ec:	e8 cf e8 ff ff       	callq  12c0 <sleep@plt>
	for (int j = 1; j < 4; j++) {
    29f1:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    29f5:	eb 94                	jmp    298b <_Z12drawStartingii+0x22f>
	}
}
    29f7:	90                   	nop
    29f8:	c9                   	leaveq 
    29f9:	c3                   	retq   

00000000000029fa <_Z8readBestPiPc>:

void readBest(int * bestScore, char bestPlayerName[]) {
    29fa:	f3 0f 1e fa          	endbr64 
    29fe:	55                   	push   %rbp
    29ff:	48 89 e5             	mov    %rsp,%rbp
    2a02:	48 83 ec 20          	sub    $0x20,%rsp
    2a06:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    2a0a:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
	FILE * bestFilePtr;

	bestFilePtr = fopen(FILE_NAME, "rb");
    2a0e:	48 8d 35 2e 0c 00 00 	lea    0xc2e(%rip),%rsi        # 3643 <_ZStL19piecewise_construct+0x63b>
    2a15:	48 8d 3d 20 07 00 00 	lea    0x720(%rip),%rdi        # 313c <_ZStL19piecewise_construct+0x134>
    2a1c:	e8 5f e9 ff ff       	callq  1380 <fopen@plt>
    2a21:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	if (bestFilePtr != NULL) {
    2a25:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    2a2a:	74 46                	je     2a72 <_Z8readBestPiPc+0x78>
		fread(bestScore, sizeof(int), 1, bestFilePtr);
    2a2c:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2a30:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a34:	48 89 d1             	mov    %rdx,%rcx
    2a37:	ba 01 00 00 00       	mov    $0x1,%edx
    2a3c:	be 04 00 00 00       	mov    $0x4,%esi
    2a41:	48 89 c7             	mov    %rax,%rdi
    2a44:	e8 a7 e9 ff ff       	callq  13f0 <fread@plt>
		fread(bestPlayerName, sizeof(char) * NAME_SIZE, 1, bestFilePtr);
    2a49:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2a4d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2a51:	48 89 d1             	mov    %rdx,%rcx
    2a54:	ba 01 00 00 00       	mov    $0x1,%edx
    2a59:	be 64 00 00 00       	mov    $0x64,%esi
    2a5e:	48 89 c7             	mov    %rax,%rdi
    2a61:	e8 8a e9 ff ff       	callq  13f0 <fread@plt>
		fclose(bestFilePtr);
    2a66:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2a6a:	48 89 c7             	mov    %rax,%rdi
    2a6d:	e8 ae e8 ff ff       	callq  1320 <fclose@plt>
	}
}
    2a72:	90                   	nop
    2a73:	c9                   	leaveq 
    2a74:	c3                   	retq   

0000000000002a75 <_Z9writeBestiPKc>:

void writeBest(int bestScore, const char bestPlayerName[]) {
    2a75:	f3 0f 1e fa          	endbr64 
    2a79:	55                   	push   %rbp
    2a7a:	48 89 e5             	mov    %rsp,%rbp
    2a7d:	48 83 ec 20          	sub    $0x20,%rsp
    2a81:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2a84:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
	FILE * bestFilePtr;

	bestFilePtr = fopen(FILE_NAME, "wb");
    2a88:	48 8d 35 b7 0b 00 00 	lea    0xbb7(%rip),%rsi        # 3646 <_ZStL19piecewise_construct+0x63e>
    2a8f:	48 8d 3d a6 06 00 00 	lea    0x6a6(%rip),%rdi        # 313c <_ZStL19piecewise_construct+0x134>
    2a96:	e8 e5 e8 ff ff       	callq  1380 <fopen@plt>
    2a9b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	fwrite(&bestScore, sizeof(int), 1, bestFilePtr);
    2a9f:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2aa3:	48 8d 45 ec          	lea    -0x14(%rbp),%rax
    2aa7:	48 89 d1             	mov    %rdx,%rcx
    2aaa:	ba 01 00 00 00       	mov    $0x1,%edx
    2aaf:	be 04 00 00 00       	mov    $0x4,%esi
    2ab4:	48 89 c7             	mov    %rax,%rdi
    2ab7:	e8 74 e9 ff ff       	callq  1430 <fwrite@plt>
	fwrite(bestPlayerName, sizeof(char) * NAME_SIZE, 1, bestFilePtr);
    2abc:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2ac0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2ac4:	48 89 d1             	mov    %rdx,%rcx
    2ac7:	ba 01 00 00 00       	mov    $0x1,%edx
    2acc:	be 64 00 00 00       	mov    $0x64,%esi
    2ad1:	48 89 c7             	mov    %rax,%rdi
    2ad4:	e8 57 e9 ff ff       	callq  1430 <fwrite@plt>

	fclose(bestFilePtr);
    2ad9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2add:	48 89 c7             	mov    %rax,%rdi
    2ae0:	e8 3b e8 ff ff       	callq  1320 <fclose@plt>
}
    2ae5:	90                   	nop
    2ae6:	c9                   	leaveq 
    2ae7:	c3                   	retq   

0000000000002ae8 <_Z15getNewPipeValuePiS_i>:

void getNewPipeValue(int * crackStart, int * crackFinish, int row) {
    2ae8:	f3 0f 1e fa          	endbr64 
    2aec:	55                   	push   %rbp
    2aed:	48 89 e5             	mov    %rsp,%rbp
    2af0:	48 83 ec 20          	sub    $0x20,%rsp
    2af4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2af8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    2afc:	89 55 ec             	mov    %edx,-0x14(%rbp)
	*crackStart = rand() % row / 2 + 3;
    2aff:	e8 5c e7 ff ff       	callq  1260 <rand@plt>
    2b04:	99                   	cltd   
    2b05:	f7 7d ec             	idivl  -0x14(%rbp)
    2b08:	89 d0                	mov    %edx,%eax
    2b0a:	89 c2                	mov    %eax,%edx
    2b0c:	c1 ea 1f             	shr    $0x1f,%edx
    2b0f:	01 d0                	add    %edx,%eax
    2b11:	d1 f8                	sar    %eax
    2b13:	8d 50 03             	lea    0x3(%rax),%edx
    2b16:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b1a:	89 10                	mov    %edx,(%rax)
	*crackFinish = *crackStart + CRACK_SIZE;
    2b1c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b20:	8b 00                	mov    (%rax),%eax
    2b22:	8d 50 04             	lea    0x4(%rax),%edx
    2b25:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2b29:	89 10                	mov    %edx,(%rax)
}
    2b2b:	90                   	nop
    2b2c:	c9                   	leaveq 
    2b2d:	c3                   	retq   

0000000000002b2e <_Z41__static_initialization_and_destruction_0ii>:
    2b2e:	f3 0f 1e fa          	endbr64 
    2b32:	55                   	push   %rbp
    2b33:	48 89 e5             	mov    %rsp,%rbp
    2b36:	48 83 ec 10          	sub    $0x10,%rsp
    2b3a:	89 7d fc             	mov    %edi,-0x4(%rbp)
    2b3d:	89 75 f8             	mov    %esi,-0x8(%rbp)
    2b40:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    2b44:	75 32                	jne    2b78 <_Z41__static_initialization_and_destruction_0ii+0x4a>
    2b46:	81 7d f8 ff ff 00 00 	cmpl   $0xffff,-0x8(%rbp)
    2b4d:	75 29                	jne    2b78 <_Z41__static_initialization_and_destruction_0ii+0x4a>
  extern wostream wclog;	/// Linked to standard error (buffered)
#endif
  ///@}

  // For construction of filebuffers for cout, cin, cerr, clog et. al.
  static ios_base::Init __ioinit;
    2b4f:	48 8d 3d c3 24 00 00 	lea    0x24c3(%rip),%rdi        # 5019 <_ZStL8__ioinit>
    2b56:	e8 a5 e8 ff ff       	callq  1400 <_ZNSt8ios_base4InitC1Ev@plt>
    2b5b:	48 8d 15 a6 24 00 00 	lea    0x24a6(%rip),%rdx        # 5008 <__dso_handle>
    2b62:	48 8d 35 b0 24 00 00 	lea    0x24b0(%rip),%rsi        # 5019 <_ZStL8__ioinit>
    2b69:	48 8b 05 88 24 00 00 	mov    0x2488(%rip),%rax        # 4ff8 <_ZNSt8ios_base4InitD1Ev@GLIBCXX_3.4>
    2b70:	48 89 c7             	mov    %rax,%rdi
    2b73:	e8 68 e7 ff ff       	callq  12e0 <__cxa_atexit@plt>
    2b78:	90                   	nop
    2b79:	c9                   	leaveq 
    2b7a:	c3                   	retq   

0000000000002b7b <_GLOBAL__sub_I_main>:
    2b7b:	f3 0f 1e fa          	endbr64 
    2b7f:	55                   	push   %rbp
    2b80:	48 89 e5             	mov    %rsp,%rbp
    2b83:	be ff ff 00 00       	mov    $0xffff,%esi
    2b88:	bf 01 00 00 00       	mov    $0x1,%edi
    2b8d:	e8 9c ff ff ff       	callq  2b2e <_Z41__static_initialization_and_destruction_0ii>
    2b92:	5d                   	pop    %rbp
    2b93:	c3                   	retq   
    2b94:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    2b9b:	00 00 00 
    2b9e:	66 90                	xchg   %ax,%ax

0000000000002ba0 <__libc_csu_init>:
    2ba0:	f3 0f 1e fa          	endbr64 
    2ba4:	41 57                	push   %r15
    2ba6:	4c 8d 3d d3 20 00 00 	lea    0x20d3(%rip),%r15        # 4c80 <__frame_dummy_init_array_entry>
    2bad:	41 56                	push   %r14
    2baf:	49 89 d6             	mov    %rdx,%r14
    2bb2:	41 55                	push   %r13
    2bb4:	49 89 f5             	mov    %rsi,%r13
    2bb7:	41 54                	push   %r12
    2bb9:	41 89 fc             	mov    %edi,%r12d
    2bbc:	55                   	push   %rbp
    2bbd:	48 8d 2d cc 20 00 00 	lea    0x20cc(%rip),%rbp        # 4c90 <__do_global_dtors_aux_fini_array_entry>
    2bc4:	53                   	push   %rbx
    2bc5:	4c 29 fd             	sub    %r15,%rbp
    2bc8:	48 83 ec 08          	sub    $0x8,%rsp
    2bcc:	e8 2f e4 ff ff       	callq  1000 <_init>
    2bd1:	48 c1 fd 03          	sar    $0x3,%rbp
    2bd5:	74 1f                	je     2bf6 <__libc_csu_init+0x56>
    2bd7:	31 db                	xor    %ebx,%ebx
    2bd9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    2be0:	4c 89 f2             	mov    %r14,%rdx
    2be3:	4c 89 ee             	mov    %r13,%rsi
    2be6:	44 89 e7             	mov    %r12d,%edi
    2be9:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    2bed:	48 83 c3 01          	add    $0x1,%rbx
    2bf1:	48 39 dd             	cmp    %rbx,%rbp
    2bf4:	75 ea                	jne    2be0 <__libc_csu_init+0x40>
    2bf6:	48 83 c4 08          	add    $0x8,%rsp
    2bfa:	5b                   	pop    %rbx
    2bfb:	5d                   	pop    %rbp
    2bfc:	41 5c                	pop    %r12
    2bfe:	41 5d                	pop    %r13
    2c00:	41 5e                	pop    %r14
    2c02:	41 5f                	pop    %r15
    2c04:	c3                   	retq   
    2c05:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    2c0c:	00 00 00 00 

0000000000002c10 <__libc_csu_fini>:
    2c10:	f3 0f 1e fa          	endbr64 
    2c14:	c3                   	retq   

Disassembly of section .fini:

0000000000002c18 <_fini>:
    2c18:	f3 0f 1e fa          	endbr64 
    2c1c:	48 83 ec 08          	sub    $0x8,%rsp
    2c20:	48 83 c4 08          	add    $0x8,%rsp
    2c24:	c3                   	retq   
