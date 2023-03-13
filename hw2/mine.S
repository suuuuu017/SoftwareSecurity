
mine:     file format elf64-x86-64


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
    1020:	ff 35 42 3f 00 00    	pushq  0x3f42(%rip)        # 4f68 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 43 3f 00 00 	bnd jmpq *0x3f43(%rip)        # 4f70 <_GLOBAL_OFFSET_TABLE_+0x10>
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

Disassembly of section .plt.got:

00000000000010f0 <__cxa_finalize@plt>:
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	f2 ff 25 fd 3e 00 00 	bnd jmpq *0x3efd(%rip)        # 4ff8 <__cxa_finalize@GLIBC_2.2.5>
    10fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001100 <free@plt>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	f2 ff 25 6d 3e 00 00 	bnd jmpq *0x3e6d(%rip)        # 4f78 <free@GLIBC_2.2.5>
    110b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001110 <putchar@plt>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	f2 ff 25 65 3e 00 00 	bnd jmpq *0x3e65(%rip)        # 4f80 <putchar@GLIBC_2.2.5>
    111b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001120 <puts@plt>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	f2 ff 25 5d 3e 00 00 	bnd jmpq *0x3e5d(%rip)        # 4f88 <puts@GLIBC_2.2.5>
    112b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001130 <__stack_chk_fail@plt>:
    1130:	f3 0f 1e fa          	endbr64 
    1134:	f2 ff 25 55 3e 00 00 	bnd jmpq *0x3e55(%rip)        # 4f90 <__stack_chk_fail@GLIBC_2.4>
    113b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001140 <system@plt>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	f2 ff 25 4d 3e 00 00 	bnd jmpq *0x3e4d(%rip)        # 4f98 <system@GLIBC_2.2.5>
    114b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001150 <printf@plt>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	f2 ff 25 45 3e 00 00 	bnd jmpq *0x3e45(%rip)        # 4fa0 <printf@GLIBC_2.2.5>
    115b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001160 <srand@plt>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	f2 ff 25 3d 3e 00 00 	bnd jmpq *0x3e3d(%rip)        # 4fa8 <srand@GLIBC_2.2.5>
    116b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001170 <time@plt>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	f2 ff 25 35 3e 00 00 	bnd jmpq *0x3e35(%rip)        # 4fb0 <time@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001180 <malloc@plt>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	f2 ff 25 2d 3e 00 00 	bnd jmpq *0x3e2d(%rip)        # 4fb8 <malloc@GLIBC_2.2.5>
    118b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001190 <atoi@plt>:
    1190:	f3 0f 1e fa          	endbr64 
    1194:	f2 ff 25 25 3e 00 00 	bnd jmpq *0x3e25(%rip)        # 4fc0 <atoi@GLIBC_2.2.5>
    119b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011a0 <__isoc99_scanf@plt>:
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	f2 ff 25 1d 3e 00 00 	bnd jmpq *0x3e1d(%rip)        # 4fc8 <__isoc99_scanf@GLIBC_2.7>
    11ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011b0 <rand@plt>:
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	f2 ff 25 15 3e 00 00 	bnd jmpq *0x3e15(%rip)        # 4fd0 <rand@GLIBC_2.2.5>
    11bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000011c0 <_start>:
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	31 ed                	xor    %ebp,%ebp
    11c6:	49 89 d1             	mov    %rdx,%r9
    11c9:	5e                   	pop    %rsi
    11ca:	48 89 e2             	mov    %rsp,%rdx
    11cd:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    11d1:	50                   	push   %rax
    11d2:	54                   	push   %rsp
    11d3:	4c 8d 05 76 10 00 00 	lea    0x1076(%rip),%r8        # 2250 <__libc_csu_fini>
    11da:	48 8d 0d ff 0f 00 00 	lea    0xfff(%rip),%rcx        # 21e0 <__libc_csu_init>
    11e1:	48 8d 3d d8 00 00 00 	lea    0xd8(%rip),%rdi        # 12c0 <main>
    11e8:	ff 15 f2 3d 00 00    	callq  *0x3df2(%rip)        # 4fe0 <__libc_start_main@GLIBC_2.2.5>
    11ee:	f4                   	hlt    
    11ef:	90                   	nop

00000000000011f0 <deregister_tm_clones>:
    11f0:	48 8d 3d 19 3e 00 00 	lea    0x3e19(%rip),%rdi        # 5010 <__TMC_END__>
    11f7:	48 8d 05 12 3e 00 00 	lea    0x3e12(%rip),%rax        # 5010 <__TMC_END__>
    11fe:	48 39 f8             	cmp    %rdi,%rax
    1201:	74 15                	je     1218 <deregister_tm_clones+0x28>
    1203:	48 8b 05 ce 3d 00 00 	mov    0x3dce(%rip),%rax        # 4fd8 <_ITM_deregisterTMCloneTable>
    120a:	48 85 c0             	test   %rax,%rax
    120d:	74 09                	je     1218 <deregister_tm_clones+0x28>
    120f:	ff e0                	jmpq   *%rax
    1211:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1218:	c3                   	retq   
    1219:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001220 <register_tm_clones>:
    1220:	48 8d 3d e9 3d 00 00 	lea    0x3de9(%rip),%rdi        # 5010 <__TMC_END__>
    1227:	48 8d 35 e2 3d 00 00 	lea    0x3de2(%rip),%rsi        # 5010 <__TMC_END__>
    122e:	48 29 fe             	sub    %rdi,%rsi
    1231:	48 89 f0             	mov    %rsi,%rax
    1234:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1238:	48 c1 f8 03          	sar    $0x3,%rax
    123c:	48 01 c6             	add    %rax,%rsi
    123f:	48 d1 fe             	sar    %rsi
    1242:	74 14                	je     1258 <register_tm_clones+0x38>
    1244:	48 8b 05 a5 3d 00 00 	mov    0x3da5(%rip),%rax        # 4ff0 <_ITM_registerTMCloneTable>
    124b:	48 85 c0             	test   %rax,%rax
    124e:	74 08                	je     1258 <register_tm_clones+0x38>
    1250:	ff e0                	jmpq   *%rax
    1252:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1258:	c3                   	retq   
    1259:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001260 <__do_global_dtors_aux>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	80 3d a5 3d 00 00 00 	cmpb   $0x0,0x3da5(%rip)        # 5010 <__TMC_END__>
    126b:	75 2b                	jne    1298 <__do_global_dtors_aux+0x38>
    126d:	55                   	push   %rbp
    126e:	48 83 3d 82 3d 00 00 	cmpq   $0x0,0x3d82(%rip)        # 4ff8 <__cxa_finalize@GLIBC_2.2.5>
    1275:	00 
    1276:	48 89 e5             	mov    %rsp,%rbp
    1279:	74 0c                	je     1287 <__do_global_dtors_aux+0x27>
    127b:	48 8b 3d 86 3d 00 00 	mov    0x3d86(%rip),%rdi        # 5008 <__dso_handle>
    1282:	e8 69 fe ff ff       	callq  10f0 <__cxa_finalize@plt>
    1287:	e8 64 ff ff ff       	callq  11f0 <deregister_tm_clones>
    128c:	c6 05 7d 3d 00 00 01 	movb   $0x1,0x3d7d(%rip)        # 5010 <__TMC_END__>
    1293:	5d                   	pop    %rbp
    1294:	c3                   	retq   
    1295:	0f 1f 00             	nopl   (%rax)
    1298:	c3                   	retq   
    1299:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000012a0 <frame_dummy>:
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	e9 77 ff ff ff       	jmpq   1220 <register_tm_clones>

00000000000012a9 <clear>:
    12a9:	f3 0f 1e fa          	endbr64 
    12ad:	55                   	push   %rbp
    12ae:	48 89 e5             	mov    %rsp,%rbp
    12b1:	48 8d 3d 50 1d 00 00 	lea    0x1d50(%rip),%rdi        # 3008 <_IO_stdin_used+0x8>
    12b8:	e8 83 fe ff ff       	callq  1140 <system@plt>
    12bd:	90                   	nop
    12be:	5d                   	pop    %rbp
    12bf:	c3                   	retq   

00000000000012c0 <main>:
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	55                   	push   %rbp
    12c5:	48 89 e5             	mov    %rsp,%rbp
    12c8:	48 83 ec 50          	sub    $0x50,%rsp
    12cc:	89 7d bc             	mov    %edi,-0x44(%rbp)
    12cf:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    12d3:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    12da:	00 00 
    12dc:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    12e0:	31 c0                	xor    %eax,%eax
    12e2:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    12e9:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
    12f0:	b8 00 00 00 00       	mov    $0x0,%eax
    12f5:	e8 af ff ff ff       	callq  12a9 <clear>
    12fa:	48 8d 3d 0f 1d 00 00 	lea    0x1d0f(%rip),%rdi        # 3010 <_IO_stdin_used+0x10>
    1301:	e8 1a fe ff ff       	callq  1120 <puts@plt>
    1306:	83 7d bc 02          	cmpl   $0x2,-0x44(%rbp)
    130a:	7e 2e                	jle    133a <main+0x7a>
    130c:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    1310:	48 83 c0 08          	add    $0x8,%rax
    1314:	48 8b 00             	mov    (%rax),%rax
    1317:	48 89 c7             	mov    %rax,%rdi
    131a:	e8 71 fe ff ff       	callq  1190 <atoi@plt>
    131f:	89 45 d8             	mov    %eax,-0x28(%rbp)
    1322:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    1326:	48 83 c0 10          	add    $0x10,%rax
    132a:	48 8b 00             	mov    (%rax),%rax
    132d:	48 89 c7             	mov    %rax,%rdi
    1330:	e8 5b fe ff ff       	callq  1190 <atoi@plt>
    1335:	89 45 dc             	mov    %eax,-0x24(%rbp)
    1338:	eb 0e                	jmp    1348 <main+0x88>
    133a:	c7 45 d8 05 00 00 00 	movl   $0x5,-0x28(%rbp)
    1341:	c7 45 dc 05 00 00 00 	movl   $0x5,-0x24(%rbp)
    1348:	c7 45 e8 01 00 00 00 	movl   $0x1,-0x18(%rbp)
    134f:	c7 45 ec 0f 00 00 00 	movl   $0xf,-0x14(%rbp)
    1356:	83 7d d8 00          	cmpl   $0x0,-0x28(%rbp)
    135a:	7e 12                	jle    136e <main+0xae>
    135c:	83 7d dc 00          	cmpl   $0x0,-0x24(%rbp)
    1360:	7e 0c                	jle    136e <main+0xae>
    1362:	83 7d e8 01          	cmpl   $0x1,-0x18(%rbp)
    1366:	75 06                	jne    136e <main+0xae>
    1368:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    136c:	7f 0c                	jg     137a <main+0xba>
    136e:	b8 00 00 00 00       	mov    $0x0,%eax
    1373:	e8 31 ff ff ff       	callq  12a9 <clear>
    1378:	eb 8c                	jmp    1306 <main+0x46>
    137a:	8b 55 ec             	mov    -0x14(%rbp),%edx
    137d:	8b 4d dc             	mov    -0x24(%rbp),%ecx
    1380:	8b 45 d8             	mov    -0x28(%rbp),%eax
    1383:	89 ce                	mov    %ecx,%esi
    1385:	89 c7                	mov    %eax,%edi
    1387:	e8 16 01 00 00       	callq  14a2 <create_field>
    138c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1390:	b8 00 00 00 00       	mov    $0x0,%eax
    1395:	e8 0f ff ff ff       	callq  12a9 <clear>
    139a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    139e:	48 89 c7             	mov    %rax,%rdi
    13a1:	e8 4c 03 00 00       	callq  16f2 <print_field>
    13a6:	48 8d 3d 89 1c 00 00 	lea    0x1c89(%rip),%rdi        # 3036 <_IO_stdin_used+0x36>
    13ad:	b8 00 00 00 00       	mov    $0x0,%eax
    13b2:	e8 99 fd ff ff       	callq  1150 <printf@plt>
    13b7:	48 8d 4d cf          	lea    -0x31(%rbp),%rcx
    13bb:	48 8d 55 d4          	lea    -0x2c(%rbp),%rdx
    13bf:	48 8d 45 d0          	lea    -0x30(%rbp),%rax
    13c3:	48 89 c6             	mov    %rax,%rsi
    13c6:	48 8d 3d 79 1c 00 00 	lea    0x1c79(%rip),%rdi        # 3046 <_IO_stdin_used+0x46>
    13cd:	b8 00 00 00 00       	mov    $0x0,%eax
    13d2:	e8 c9 fd ff ff       	callq  11a0 <__isoc99_scanf@plt>
    13d7:	0f b6 45 cf          	movzbl -0x31(%rbp),%eax
    13db:	0f be c8             	movsbl %al,%ecx
    13de:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    13e1:	8b 75 d0             	mov    -0x30(%rbp),%esi
    13e4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    13e8:	48 89 c7             	mov    %rax,%rdi
    13eb:	e8 af 05 00 00       	callq  199f <inter_cell>
    13f0:	89 45 e0             	mov    %eax,-0x20(%rbp)
    13f3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    13f7:	48 89 c7             	mov    %rax,%rdi
    13fa:	e8 e5 0b 00 00       	callq  1fe4 <check_win>
    13ff:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    1402:	b8 00 00 00 00       	mov    $0x0,%eax
    1407:	e8 9d fe ff ff       	callq  12a9 <clear>
    140c:	83 7d e0 01          	cmpl   $0x1,-0x20(%rbp)
    1410:	74 08                	je     141a <main+0x15a>
    1412:	83 7d e4 01          	cmpl   $0x1,-0x1c(%rbp)
    1416:	74 02                	je     141a <main+0x15a>
    1418:	eb 80                	jmp    139a <main+0xda>
    141a:	90                   	nop
    141b:	f3 0f 1e fa          	endbr64 
    141f:	83 7d e4 01          	cmpl   $0x1,-0x1c(%rbp)
    1423:	75 26                	jne    144b <main+0x18b>
    1425:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1429:	48 89 c7             	mov    %rax,%rdi
    142c:	e8 2f 0a 00 00       	callq  1e60 <open_all>
    1431:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1435:	48 89 c7             	mov    %rax,%rdi
    1438:	e8 b5 02 00 00       	callq  16f2 <print_field>
    143d:	48 8d 3d 0b 1c 00 00 	lea    0x1c0b(%rip),%rdi        # 304f <_IO_stdin_used+0x4f>
    1444:	e8 d7 fc ff ff       	callq  1120 <puts@plt>
    1449:	eb 24                	jmp    146f <main+0x1af>
    144b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    144f:	48 89 c7             	mov    %rax,%rdi
    1452:	e8 b3 0a 00 00       	callq  1f0a <open_all_mines>
    1457:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    145b:	48 89 c7             	mov    %rax,%rdi
    145e:	e8 8f 02 00 00       	callq  16f2 <print_field>
    1463:	48 8d 3d f1 1b 00 00 	lea    0x1bf1(%rip),%rdi        # 305b <_IO_stdin_used+0x5b>
    146a:	e8 b1 fc ff ff       	callq  1120 <puts@plt>
    146f:	48 8d 3d f2 1b 00 00 	lea    0x1bf2(%rip),%rdi        # 3068 <_IO_stdin_used+0x68>
    1476:	e8 a5 fc ff ff       	callq  1120 <puts@plt>
    147b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    147f:	48 89 c7             	mov    %rax,%rdi
    1482:	e8 79 fc ff ff       	callq  1100 <free@plt>
    1487:	b8 00 00 00 00       	mov    $0x0,%eax
    148c:	48 8b 75 f8          	mov    -0x8(%rbp),%rsi
    1490:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
    1497:	00 00 
    1499:	74 05                	je     14a0 <main+0x1e0>
    149b:	e8 90 fc ff ff       	callq  1130 <__stack_chk_fail@plt>
    14a0:	c9                   	leaveq 
    14a1:	c3                   	retq   

00000000000014a2 <create_field>:
    14a2:	f3 0f 1e fa          	endbr64 
    14a6:	55                   	push   %rbp
    14a7:	48 89 e5             	mov    %rsp,%rbp
    14aa:	48 83 ec 30          	sub    $0x30,%rsp
    14ae:	89 7d dc             	mov    %edi,-0x24(%rbp)
    14b1:	89 75 d8             	mov    %esi,-0x28(%rbp)
    14b4:	89 55 d4             	mov    %edx,-0x2c(%rbp)
    14b7:	bf 00 00 00 00       	mov    $0x0,%edi
    14bc:	e8 af fc ff ff       	callq  1170 <time@plt>
    14c1:	89 c7                	mov    %eax,%edi
    14c3:	e8 98 fc ff ff       	callq  1160 <srand@plt>
    14c8:	bf 10 00 00 00       	mov    $0x10,%edi
    14cd:	e8 ae fc ff ff       	callq  1180 <malloc@plt>
    14d2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    14d6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    14da:	8b 55 dc             	mov    -0x24(%rbp),%edx
    14dd:	89 10                	mov    %edx,(%rax)
    14df:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    14e3:	8b 55 d8             	mov    -0x28(%rbp),%edx
    14e6:	89 50 04             	mov    %edx,0x4(%rax)
    14e9:	8b 45 dc             	mov    -0x24(%rbp),%eax
    14ec:	0f af 45 d8          	imul   -0x28(%rbp),%eax
    14f0:	48 63 d0             	movslq %eax,%rdx
    14f3:	48 89 d0             	mov    %rdx,%rax
    14f6:	48 01 c0             	add    %rax,%rax
    14f9:	48 01 d0             	add    %rdx,%rax
    14fc:	48 c1 e0 03          	shl    $0x3,%rax
    1500:	48 89 c7             	mov    %rax,%rdi
    1503:	e8 78 fc ff ff       	callq  1180 <malloc@plt>
    1508:	48 89 c2             	mov    %rax,%rdx
    150b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    150f:	48 89 50 08          	mov    %rdx,0x8(%rax)
    1513:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    151a:	e9 44 01 00 00       	jmpq   1663 <create_field+0x1c1>
    151f:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
    1526:	e9 28 01 00 00       	jmpq   1653 <create_field+0x1b1>
    152b:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    152e:	8b 4d e0             	mov    -0x20(%rbp),%ecx
    1531:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1535:	89 ce                	mov    %ecx,%esi
    1537:	48 89 c7             	mov    %rax,%rdi
    153a:	e8 5c 0b 00 00       	callq  209b <get_index>
    153f:	89 45 f0             	mov    %eax,-0x10(%rbp)
    1542:	e8 69 fc ff ff       	callq  11b0 <rand@plt>
    1547:	48 63 d0             	movslq %eax,%rdx
    154a:	48 69 d2 1f 85 eb 51 	imul   $0x51eb851f,%rdx,%rdx
    1551:	48 c1 ea 20          	shr    $0x20,%rdx
    1555:	89 d1                	mov    %edx,%ecx
    1557:	c1 f9 05             	sar    $0x5,%ecx
    155a:	99                   	cltd   
    155b:	29 d1                	sub    %edx,%ecx
    155d:	89 ca                	mov    %ecx,%edx
    155f:	6b d2 64             	imul   $0x64,%edx,%edx
    1562:	29 d0                	sub    %edx,%eax
    1564:	89 c2                	mov    %eax,%edx
    1566:	39 55 d4             	cmp    %edx,-0x2c(%rbp)
    1569:	0f 9f c0             	setg   %al
    156c:	0f b6 c0             	movzbl %al,%eax
    156f:	89 45 f4             	mov    %eax,-0xc(%rbp)
    1572:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1576:	48 8b 48 08          	mov    0x8(%rax),%rcx
    157a:	8b 45 f0             	mov    -0x10(%rbp),%eax
    157d:	48 63 d0             	movslq %eax,%rdx
    1580:	48 89 d0             	mov    %rdx,%rax
    1583:	48 01 c0             	add    %rax,%rax
    1586:	48 01 d0             	add    %rdx,%rax
    1589:	48 c1 e0 03          	shl    $0x3,%rax
    158d:	48 8d 14 01          	lea    (%rcx,%rax,1),%rdx
    1591:	8b 45 e0             	mov    -0x20(%rbp),%eax
    1594:	89 02                	mov    %eax,(%rdx)
    1596:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    159a:	48 8b 48 08          	mov    0x8(%rax),%rcx
    159e:	8b 45 f0             	mov    -0x10(%rbp),%eax
    15a1:	48 63 d0             	movslq %eax,%rdx
    15a4:	48 89 d0             	mov    %rdx,%rax
    15a7:	48 01 c0             	add    %rax,%rax
    15aa:	48 01 d0             	add    %rdx,%rax
    15ad:	48 c1 e0 03          	shl    $0x3,%rax
    15b1:	48 8d 14 01          	lea    (%rcx,%rax,1),%rdx
    15b5:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    15b8:	89 42 04             	mov    %eax,0x4(%rdx)
    15bb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    15bf:	48 8b 48 08          	mov    0x8(%rax),%rcx
    15c3:	8b 45 f0             	mov    -0x10(%rbp),%eax
    15c6:	48 63 d0             	movslq %eax,%rdx
    15c9:	48 89 d0             	mov    %rdx,%rax
    15cc:	48 01 c0             	add    %rax,%rax
    15cf:	48 01 d0             	add    %rdx,%rax
    15d2:	48 c1 e0 03          	shl    $0x3,%rax
    15d6:	48 01 c8             	add    %rcx,%rax
    15d9:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%rax)
    15e0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    15e4:	48 8b 48 08          	mov    0x8(%rax),%rcx
    15e8:	8b 45 f0             	mov    -0x10(%rbp),%eax
    15eb:	48 63 d0             	movslq %eax,%rdx
    15ee:	48 89 d0             	mov    %rdx,%rax
    15f1:	48 01 c0             	add    %rax,%rax
    15f4:	48 01 d0             	add    %rdx,%rax
    15f7:	48 c1 e0 03          	shl    $0x3,%rax
    15fb:	48 8d 14 01          	lea    (%rcx,%rax,1),%rdx
    15ff:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1602:	89 42 08             	mov    %eax,0x8(%rdx)
    1605:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1609:	48 8b 48 08          	mov    0x8(%rax),%rcx
    160d:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1610:	48 63 d0             	movslq %eax,%rdx
    1613:	48 89 d0             	mov    %rdx,%rax
    1616:	48 01 c0             	add    %rax,%rax
    1619:	48 01 d0             	add    %rdx,%rax
    161c:	48 c1 e0 03          	shl    $0x3,%rax
    1620:	48 01 c8             	add    %rcx,%rax
    1623:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%rax)
    162a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    162e:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1632:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1635:	48 63 d0             	movslq %eax,%rdx
    1638:	48 89 d0             	mov    %rdx,%rax
    163b:	48 01 c0             	add    %rax,%rax
    163e:	48 01 d0             	add    %rdx,%rax
    1641:	48 c1 e0 03          	shl    $0x3,%rax
    1645:	48 01 c8             	add    %rcx,%rax
    1648:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%rax)
    164f:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
    1653:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    1656:	3b 45 d8             	cmp    -0x28(%rbp),%eax
    1659:	0f 8c cc fe ff ff    	jl     152b <create_field+0x89>
    165f:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    1663:	8b 45 e0             	mov    -0x20(%rbp),%eax
    1666:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    1669:	0f 8c b0 fe ff ff    	jl     151f <create_field+0x7d>
    166f:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    1676:	eb 6c                	jmp    16e4 <create_field+0x242>
    1678:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
    167f:	eb 57                	jmp    16d8 <create_field+0x236>
    1681:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    1684:	8b 4d e0             	mov    -0x20(%rbp),%ecx
    1687:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    168b:	89 ce                	mov    %ecx,%esi
    168d:	48 89 c7             	mov    %rax,%rdi
    1690:	e8 06 0a 00 00       	callq  209b <get_index>
    1695:	89 45 e8             	mov    %eax,-0x18(%rbp)
    1698:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    169b:	8b 4d e0             	mov    -0x20(%rbp),%ecx
    169e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    16a2:	89 ce                	mov    %ecx,%esi
    16a4:	48 89 c7             	mov    %rax,%rdi
    16a7:	e8 3f 0a 00 00       	callq  20eb <neighbour_mines>
    16ac:	89 45 ec             	mov    %eax,-0x14(%rbp)
    16af:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    16b3:	48 8b 48 08          	mov    0x8(%rax),%rcx
    16b7:	8b 45 e8             	mov    -0x18(%rbp),%eax
    16ba:	48 63 d0             	movslq %eax,%rdx
    16bd:	48 89 d0             	mov    %rdx,%rax
    16c0:	48 01 c0             	add    %rax,%rax
    16c3:	48 01 d0             	add    %rdx,%rax
    16c6:	48 c1 e0 03          	shl    $0x3,%rax
    16ca:	48 8d 14 01          	lea    (%rcx,%rax,1),%rdx
    16ce:	8b 45 ec             	mov    -0x14(%rbp),%eax
    16d1:	89 42 0c             	mov    %eax,0xc(%rdx)
    16d4:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
    16d8:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    16db:	3b 45 d8             	cmp    -0x28(%rbp),%eax
    16de:	7c a1                	jl     1681 <create_field+0x1df>
    16e0:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    16e4:	8b 45 e0             	mov    -0x20(%rbp),%eax
    16e7:	3b 45 dc             	cmp    -0x24(%rbp),%eax
    16ea:	7c 8c                	jl     1678 <create_field+0x1d6>
    16ec:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    16f0:	c9                   	leaveq 
    16f1:	c3                   	retq   

00000000000016f2 <print_field>:
    16f2:	f3 0f 1e fa          	endbr64 
    16f6:	55                   	push   %rbp
    16f7:	48 89 e5             	mov    %rsp,%rbp
    16fa:	48 83 ec 20          	sub    $0x20,%rsp
    16fe:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1702:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1709:	eb 56                	jmp    1761 <print_field+0x6f>
    170b:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    170f:	75 18                	jne    1729 <print_field+0x37>
    1711:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1714:	89 c6                	mov    %eax,%esi
    1716:	48 8d 3d 4f 19 00 00 	lea    0x194f(%rip),%rdi        # 306c <_IO_stdin_used+0x6c>
    171d:	b8 00 00 00 00       	mov    $0x0,%eax
    1722:	e8 29 fa ff ff       	callq  1150 <printf@plt>
    1727:	eb 34                	jmp    175d <print_field+0x6b>
    1729:	83 7d f4 09          	cmpl   $0x9,-0xc(%rbp)
    172d:	7f 18                	jg     1747 <print_field+0x55>
    172f:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1732:	89 c6                	mov    %eax,%esi
    1734:	48 8d 3d 3a 19 00 00 	lea    0x193a(%rip),%rdi        # 3075 <_IO_stdin_used+0x75>
    173b:	b8 00 00 00 00       	mov    $0x0,%eax
    1740:	e8 0b fa ff ff       	callq  1150 <printf@plt>
    1745:	eb 16                	jmp    175d <print_field+0x6b>
    1747:	8b 45 f4             	mov    -0xc(%rbp),%eax
    174a:	89 c6                	mov    %eax,%esi
    174c:	48 8d 3d 27 19 00 00 	lea    0x1927(%rip),%rdi        # 307a <_IO_stdin_used+0x7a>
    1753:	b8 00 00 00 00       	mov    $0x0,%eax
    1758:	e8 f3 f9 ff ff       	callq  1150 <printf@plt>
    175d:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1761:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1765:	8b 40 04             	mov    0x4(%rax),%eax
    1768:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    176b:	7c 9e                	jl     170b <print_field+0x19>
    176d:	48 8d 3d 0a 19 00 00 	lea    0x190a(%rip),%rdi        # 307e <_IO_stdin_used+0x7e>
    1774:	e8 a7 f9 ff ff       	callq  1120 <puts@plt>
    1779:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1780:	e9 a6 00 00 00       	jmpq   182b <print_field+0x139>
    1785:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    178c:	eb 7f                	jmp    180d <print_field+0x11b>
    178e:	83 7d f8 00          	cmpl   $0x0,-0x8(%rbp)
    1792:	75 16                	jne    17aa <print_field+0xb8>
    1794:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1797:	89 c6                	mov    %eax,%esi
    1799:	48 8d 3d e2 18 00 00 	lea    0x18e2(%rip),%rdi        # 3082 <_IO_stdin_used+0x82>
    17a0:	b8 00 00 00 00       	mov    $0x0,%eax
    17a5:	e8 a6 f9 ff ff       	callq  1150 <printf@plt>
    17aa:	8b 55 f8             	mov    -0x8(%rbp),%edx
    17ad:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    17b0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    17b4:	89 ce                	mov    %ecx,%esi
    17b6:	48 89 c7             	mov    %rax,%rdi
    17b9:	e8 dd 08 00 00       	callq  209b <get_index>
    17be:	89 45 fc             	mov    %eax,-0x4(%rbp)
    17c1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    17c5:	48 8b 48 08          	mov    0x8(%rax),%rcx
    17c9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    17cc:	48 63 d0             	movslq %eax,%rdx
    17cf:	48 89 d0             	mov    %rdx,%rax
    17d2:	48 01 c0             	add    %rax,%rax
    17d5:	48 01 d0             	add    %rdx,%rax
    17d8:	48 c1 e0 03          	shl    $0x3,%rax
    17dc:	48 01 c1             	add    %rax,%rcx
    17df:	48 83 ec 08          	sub    $0x8,%rsp
    17e3:	48 83 ec 18          	sub    $0x18,%rsp
    17e7:	48 89 e6             	mov    %rsp,%rsi
    17ea:	48 8b 01             	mov    (%rcx),%rax
    17ed:	48 8b 51 08          	mov    0x8(%rcx),%rdx
    17f1:	48 89 06             	mov    %rax,(%rsi)
    17f4:	48 89 56 08          	mov    %rdx,0x8(%rsi)
    17f8:	48 8b 41 10          	mov    0x10(%rcx),%rax
    17fc:	48 89 46 10          	mov    %rax,0x10(%rsi)
    1800:	e8 39 00 00 00       	callq  183e <print_cell>
    1805:	48 83 c4 20          	add    $0x20,%rsp
    1809:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    180d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1811:	8b 40 04             	mov    0x4(%rax),%eax
    1814:	39 45 f8             	cmp    %eax,-0x8(%rbp)
    1817:	0f 8c 71 ff ff ff    	jl     178e <print_field+0x9c>
    181d:	bf 0a 00 00 00       	mov    $0xa,%edi
    1822:	e8 e9 f8 ff ff       	callq  1110 <putchar@plt>
    1827:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    182b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    182f:	8b 00                	mov    (%rax),%eax
    1831:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1834:	0f 8c 4b ff ff ff    	jl     1785 <print_field+0x93>
    183a:	90                   	nop
    183b:	90                   	nop
    183c:	c9                   	leaveq 
    183d:	c3                   	retq   

000000000000183e <print_cell>:
    183e:	f3 0f 1e fa          	endbr64 
    1842:	55                   	push   %rbp
    1843:	48 89 e5             	mov    %rsp,%rbp
    1846:	8b 45 24             	mov    0x24(%rbp),%eax
    1849:	83 f8 01             	cmp    $0x1,%eax
    184c:	75 16                	jne    1864 <print_cell+0x26>
    184e:	48 8d 3d 32 18 00 00 	lea    0x1832(%rip),%rdi        # 3087 <_IO_stdin_used+0x87>
    1855:	b8 00 00 00 00       	mov    $0x0,%eax
    185a:	e8 f1 f8 ff ff       	callq  1150 <printf@plt>
    185f:	e9 39 01 00 00       	jmpq   199d <print_cell+0x15f>
    1864:	8b 45 20             	mov    0x20(%rbp),%eax
    1867:	83 f8 01             	cmp    $0x1,%eax
    186a:	0f 85 1c 01 00 00    	jne    198c <print_cell+0x14e>
    1870:	8b 45 18             	mov    0x18(%rbp),%eax
    1873:	83 f8 01             	cmp    $0x1,%eax
    1876:	75 16                	jne    188e <print_cell+0x50>
    1878:	48 8d 3d 1a 18 00 00 	lea    0x181a(%rip),%rdi        # 3099 <_IO_stdin_used+0x99>
    187f:	b8 00 00 00 00       	mov    $0x0,%eax
    1884:	e8 c7 f8 ff ff       	callq  1150 <printf@plt>
    1889:	e9 0f 01 00 00       	jmpq   199d <print_cell+0x15f>
    188e:	8b 45 1c             	mov    0x1c(%rbp),%eax
    1891:	85 c0                	test   %eax,%eax
    1893:	75 16                	jne    18ab <print_cell+0x6d>
    1895:	48 8d 3d 0f 18 00 00 	lea    0x180f(%rip),%rdi        # 30ab <_IO_stdin_used+0xab>
    189c:	b8 00 00 00 00       	mov    $0x0,%eax
    18a1:	e8 aa f8 ff ff       	callq  1150 <printf@plt>
    18a6:	e9 f2 00 00 00       	jmpq   199d <print_cell+0x15f>
    18ab:	8b 45 1c             	mov    0x1c(%rbp),%eax
    18ae:	83 f8 08             	cmp    $0x8,%eax
    18b1:	0f 87 bd 00 00 00    	ja     1974 <print_cell+0x136>
    18b7:	89 c0                	mov    %eax,%eax
    18b9:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    18c0:	00 
    18c1:	48 8d 05 50 18 00 00 	lea    0x1850(%rip),%rax        # 3118 <_IO_stdin_used+0x118>
    18c8:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    18cb:	48 98                	cltq   
    18cd:	48 8d 15 44 18 00 00 	lea    0x1844(%rip),%rdx        # 3118 <_IO_stdin_used+0x118>
    18d4:	48 01 d0             	add    %rdx,%rax
    18d7:	3e ff e0             	notrack jmpq *%rax
    18da:	48 8d 3d d9 17 00 00 	lea    0x17d9(%rip),%rdi        # 30ba <_IO_stdin_used+0xba>
    18e1:	b8 00 00 00 00       	mov    $0x0,%eax
    18e6:	e8 65 f8 ff ff       	callq  1150 <printf@plt>
    18eb:	e9 84 00 00 00       	jmpq   1974 <print_cell+0x136>
    18f0:	48 8d 3d cb 17 00 00 	lea    0x17cb(%rip),%rdi        # 30c2 <_IO_stdin_used+0xc2>
    18f7:	b8 00 00 00 00       	mov    $0x0,%eax
    18fc:	e8 4f f8 ff ff       	callq  1150 <printf@plt>
    1901:	eb 71                	jmp    1974 <print_cell+0x136>
    1903:	48 8d 3d c0 17 00 00 	lea    0x17c0(%rip),%rdi        # 30ca <_IO_stdin_used+0xca>
    190a:	b8 00 00 00 00       	mov    $0x0,%eax
    190f:	e8 3c f8 ff ff       	callq  1150 <printf@plt>
    1914:	eb 5e                	jmp    1974 <print_cell+0x136>
    1916:	48 8d 3d b5 17 00 00 	lea    0x17b5(%rip),%rdi        # 30d2 <_IO_stdin_used+0xd2>
    191d:	b8 00 00 00 00       	mov    $0x0,%eax
    1922:	e8 29 f8 ff ff       	callq  1150 <printf@plt>
    1927:	eb 4b                	jmp    1974 <print_cell+0x136>
    1929:	48 8d 3d aa 17 00 00 	lea    0x17aa(%rip),%rdi        # 30da <_IO_stdin_used+0xda>
    1930:	b8 00 00 00 00       	mov    $0x0,%eax
    1935:	e8 16 f8 ff ff       	callq  1150 <printf@plt>
    193a:	eb 38                	jmp    1974 <print_cell+0x136>
    193c:	48 8d 3d 9f 17 00 00 	lea    0x179f(%rip),%rdi        # 30e2 <_IO_stdin_used+0xe2>
    1943:	b8 00 00 00 00       	mov    $0x0,%eax
    1948:	e8 03 f8 ff ff       	callq  1150 <printf@plt>
    194d:	eb 25                	jmp    1974 <print_cell+0x136>
    194f:	48 8d 3d 94 17 00 00 	lea    0x1794(%rip),%rdi        # 30ea <_IO_stdin_used+0xea>
    1956:	b8 00 00 00 00       	mov    $0x0,%eax
    195b:	e8 f0 f7 ff ff       	callq  1150 <printf@plt>
    1960:	eb 12                	jmp    1974 <print_cell+0x136>
    1962:	48 8d 3d 89 17 00 00 	lea    0x1789(%rip),%rdi        # 30f2 <_IO_stdin_used+0xf2>
    1969:	b8 00 00 00 00       	mov    $0x0,%eax
    196e:	e8 dd f7 ff ff       	callq  1150 <printf@plt>
    1973:	90                   	nop
    1974:	8b 45 1c             	mov    0x1c(%rbp),%eax
    1977:	89 c6                	mov    %eax,%esi
    1979:	48 8d 3d 7a 17 00 00 	lea    0x177a(%rip),%rdi        # 30fa <_IO_stdin_used+0xfa>
    1980:	b8 00 00 00 00       	mov    $0x0,%eax
    1985:	e8 c6 f7 ff ff       	callq  1150 <printf@plt>
    198a:	eb 11                	jmp    199d <print_cell+0x15f>
    198c:	48 8d 3d 70 17 00 00 	lea    0x1770(%rip),%rdi        # 3103 <_IO_stdin_used+0x103>
    1993:	b8 00 00 00 00       	mov    $0x0,%eax
    1998:	e8 b3 f7 ff ff       	callq  1150 <printf@plt>
    199d:	5d                   	pop    %rbp
    199e:	c3                   	retq   

000000000000199f <inter_cell>:
    199f:	f3 0f 1e fa          	endbr64 
    19a3:	55                   	push   %rbp
    19a4:	48 89 e5             	mov    %rsp,%rbp
    19a7:	48 83 ec 20          	sub    $0x20,%rsp
    19ab:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    19af:	89 75 f4             	mov    %esi,-0xc(%rbp)
    19b2:	89 55 f0             	mov    %edx,-0x10(%rbp)
    19b5:	89 c8                	mov    %ecx,%eax
    19b7:	88 45 ec             	mov    %al,-0x14(%rbp)
    19ba:	80 7d ec 6f          	cmpb   $0x6f,-0x14(%rbp)
    19be:	74 06                	je     19c6 <inter_cell+0x27>
    19c0:	80 7d ec 4f          	cmpb   $0x4f,-0x14(%rbp)
    19c4:	75 16                	jne    19dc <inter_cell+0x3d>
    19c6:	8b 55 f0             	mov    -0x10(%rbp),%edx
    19c9:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    19cc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    19d0:	89 ce                	mov    %ecx,%esi
    19d2:	48 89 c7             	mov    %rax,%rdi
    19d5:	e8 29 00 00 00       	callq  1a03 <open_cell>
    19da:	eb 25                	jmp    1a01 <inter_cell+0x62>
    19dc:	80 7d ec 66          	cmpb   $0x66,-0x14(%rbp)
    19e0:	74 06                	je     19e8 <inter_cell+0x49>
    19e2:	80 7d ec 46          	cmpb   $0x46,-0x14(%rbp)
    19e6:	75 14                	jne    19fc <inter_cell+0x5d>
    19e8:	8b 55 f0             	mov    -0x10(%rbp),%edx
    19eb:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    19ee:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    19f2:	89 ce                	mov    %ecx,%esi
    19f4:	48 89 c7             	mov    %rax,%rdi
    19f7:	e8 21 01 00 00       	callq  1b1d <flag_cell>
    19fc:	b8 00 00 00 00       	mov    $0x0,%eax
    1a01:	c9                   	leaveq 
    1a02:	c3                   	retq   

0000000000001a03 <open_cell>:
    1a03:	f3 0f 1e fa          	endbr64 
    1a07:	55                   	push   %rbp
    1a08:	48 89 e5             	mov    %rsp,%rbp
    1a0b:	48 83 ec 20          	sub    $0x20,%rsp
    1a0f:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1a13:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    1a16:	89 55 e0             	mov    %edx,-0x20(%rbp)
    1a19:	8b 55 e0             	mov    -0x20(%rbp),%edx
    1a1c:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    1a1f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a23:	89 ce                	mov    %ecx,%esi
    1a25:	48 89 c7             	mov    %rax,%rdi
    1a28:	e8 6e 06 00 00       	callq  209b <get_index>
    1a2d:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1a30:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a34:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1a38:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1a3b:	48 63 d0             	movslq %eax,%rdx
    1a3e:	48 89 d0             	mov    %rdx,%rax
    1a41:	48 01 c0             	add    %rax,%rax
    1a44:	48 01 d0             	add    %rdx,%rax
    1a47:	48 c1 e0 03          	shl    $0x3,%rax
    1a4b:	48 01 c8             	add    %rcx,%rax
    1a4e:	8b 40 14             	mov    0x14(%rax),%eax
    1a51:	83 f8 01             	cmp    $0x1,%eax
    1a54:	75 0a                	jne    1a60 <open_cell+0x5d>
    1a56:	b8 00 00 00 00       	mov    $0x0,%eax
    1a5b:	e9 bb 00 00 00       	jmpq   1b1b <open_cell+0x118>
    1a60:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a64:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1a68:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1a6b:	48 63 d0             	movslq %eax,%rdx
    1a6e:	48 89 d0             	mov    %rdx,%rax
    1a71:	48 01 c0             	add    %rax,%rax
    1a74:	48 01 d0             	add    %rdx,%rax
    1a77:	48 c1 e0 03          	shl    $0x3,%rax
    1a7b:	48 01 c8             	add    %rcx,%rax
    1a7e:	8b 40 10             	mov    0x10(%rax),%eax
    1a81:	83 f8 01             	cmp    $0x1,%eax
    1a84:	75 16                	jne    1a9c <open_cell+0x99>
    1a86:	8b 55 e0             	mov    -0x20(%rbp),%edx
    1a89:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    1a8c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a90:	89 ce                	mov    %ecx,%esi
    1a92:	48 89 c7             	mov    %rax,%rdi
    1a95:	e8 43 02 00 00       	callq  1cdd <open_neighbours>
    1a9a:	eb 7f                	jmp    1b1b <open_cell+0x118>
    1a9c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1aa0:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1aa4:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1aa7:	48 63 d0             	movslq %eax,%rdx
    1aaa:	48 89 d0             	mov    %rdx,%rax
    1aad:	48 01 c0             	add    %rax,%rax
    1ab0:	48 01 d0             	add    %rdx,%rax
    1ab3:	48 c1 e0 03          	shl    $0x3,%rax
    1ab7:	48 01 c8             	add    %rcx,%rax
    1aba:	c7 40 10 01 00 00 00 	movl   $0x1,0x10(%rax)
    1ac1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1ac5:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1ac9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1acc:	48 63 d0             	movslq %eax,%rdx
    1acf:	48 89 d0             	mov    %rdx,%rax
    1ad2:	48 01 c0             	add    %rax,%rax
    1ad5:	48 01 d0             	add    %rdx,%rax
    1ad8:	48 c1 e0 03          	shl    $0x3,%rax
    1adc:	48 01 c8             	add    %rcx,%rax
    1adf:	8b 40 0c             	mov    0xc(%rax),%eax
    1ae2:	85 c0                	test   %eax,%eax
    1ae4:	75 14                	jne    1afa <open_cell+0xf7>
    1ae6:	8b 55 e0             	mov    -0x20(%rbp),%edx
    1ae9:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    1aec:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1af0:	89 ce                	mov    %ecx,%esi
    1af2:	48 89 c7             	mov    %rax,%rdi
    1af5:	e8 ed 00 00 00       	callq  1be7 <open_zeros>
    1afa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1afe:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1b02:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1b05:	48 63 d0             	movslq %eax,%rdx
    1b08:	48 89 d0             	mov    %rdx,%rax
    1b0b:	48 01 c0             	add    %rax,%rax
    1b0e:	48 01 d0             	add    %rdx,%rax
    1b11:	48 c1 e0 03          	shl    $0x3,%rax
    1b15:	48 01 c8             	add    %rcx,%rax
    1b18:	8b 40 08             	mov    0x8(%rax),%eax
    1b1b:	c9                   	leaveq 
    1b1c:	c3                   	retq   

0000000000001b1d <flag_cell>:
    1b1d:	f3 0f 1e fa          	endbr64 
    1b21:	55                   	push   %rbp
    1b22:	48 89 e5             	mov    %rsp,%rbp
    1b25:	48 83 ec 20          	sub    $0x20,%rsp
    1b29:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1b2d:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    1b30:	89 55 e0             	mov    %edx,-0x20(%rbp)
    1b33:	8b 55 e0             	mov    -0x20(%rbp),%edx
    1b36:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    1b39:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1b3d:	89 ce                	mov    %ecx,%esi
    1b3f:	48 89 c7             	mov    %rax,%rdi
    1b42:	e8 54 05 00 00       	callq  209b <get_index>
    1b47:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1b4a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1b4e:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1b52:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1b55:	48 63 d0             	movslq %eax,%rdx
    1b58:	48 89 d0             	mov    %rdx,%rax
    1b5b:	48 01 c0             	add    %rax,%rax
    1b5e:	48 01 d0             	add    %rdx,%rax
    1b61:	48 c1 e0 03          	shl    $0x3,%rax
    1b65:	48 01 c8             	add    %rcx,%rax
    1b68:	8b 40 10             	mov    0x10(%rax),%eax
    1b6b:	83 f8 01             	cmp    $0x1,%eax
    1b6e:	74 74                	je     1be4 <flag_cell+0xc7>
    1b70:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1b74:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1b78:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1b7b:	48 63 d0             	movslq %eax,%rdx
    1b7e:	48 89 d0             	mov    %rdx,%rax
    1b81:	48 01 c0             	add    %rax,%rax
    1b84:	48 01 d0             	add    %rdx,%rax
    1b87:	48 c1 e0 03          	shl    $0x3,%rax
    1b8b:	48 01 c8             	add    %rcx,%rax
    1b8e:	8b 40 14             	mov    0x14(%rax),%eax
    1b91:	83 f8 01             	cmp    $0x1,%eax
    1b94:	75 27                	jne    1bbd <flag_cell+0xa0>
    1b96:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1b9a:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1b9e:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ba1:	48 63 d0             	movslq %eax,%rdx
    1ba4:	48 89 d0             	mov    %rdx,%rax
    1ba7:	48 01 c0             	add    %rax,%rax
    1baa:	48 01 d0             	add    %rdx,%rax
    1bad:	48 c1 e0 03          	shl    $0x3,%rax
    1bb1:	48 01 c8             	add    %rcx,%rax
    1bb4:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%rax)
    1bbb:	eb 28                	jmp    1be5 <flag_cell+0xc8>
    1bbd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1bc1:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1bc5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1bc8:	48 63 d0             	movslq %eax,%rdx
    1bcb:	48 89 d0             	mov    %rdx,%rax
    1bce:	48 01 c0             	add    %rax,%rax
    1bd1:	48 01 d0             	add    %rdx,%rax
    1bd4:	48 c1 e0 03          	shl    $0x3,%rax
    1bd8:	48 01 c8             	add    %rcx,%rax
    1bdb:	c7 40 14 01 00 00 00 	movl   $0x1,0x14(%rax)
    1be2:	eb 01                	jmp    1be5 <flag_cell+0xc8>
    1be4:	90                   	nop
    1be5:	c9                   	leaveq 
    1be6:	c3                   	retq   

0000000000001be7 <open_zeros>:
    1be7:	f3 0f 1e fa          	endbr64 
    1beb:	55                   	push   %rbp
    1bec:	48 89 e5             	mov    %rsp,%rbp
    1bef:	48 83 ec 20          	sub    $0x20,%rsp
    1bf3:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1bf7:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    1bfa:	89 55 e0             	mov    %edx,-0x20(%rbp)
    1bfd:	8b 55 e0             	mov    -0x20(%rbp),%edx
    1c00:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    1c03:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c07:	89 ce                	mov    %ecx,%esi
    1c09:	48 89 c7             	mov    %rax,%rdi
    1c0c:	e8 8a 04 00 00       	callq  209b <get_index>
    1c11:	89 45 f8             	mov    %eax,-0x8(%rbp)
    1c14:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    1c17:	83 e8 01             	sub    $0x1,%eax
    1c1a:	89 45 f0             	mov    %eax,-0x10(%rbp)
    1c1d:	e9 a8 00 00 00       	jmpq   1cca <open_zeros+0xe3>
    1c22:	8b 45 e0             	mov    -0x20(%rbp),%eax
    1c25:	83 e8 01             	sub    $0x1,%eax
    1c28:	89 45 f4             	mov    %eax,-0xc(%rbp)
    1c2b:	e9 87 00 00 00       	jmpq   1cb7 <open_zeros+0xd0>
    1c30:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1c33:	8b 4d f0             	mov    -0x10(%rbp),%ecx
    1c36:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c3a:	89 ce                	mov    %ecx,%esi
    1c3c:	48 89 c7             	mov    %rax,%rdi
    1c3f:	e8 57 04 00 00       	callq  209b <get_index>
    1c44:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1c47:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
    1c4b:	74 66                	je     1cb3 <open_zeros+0xcc>
    1c4d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1c50:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    1c53:	74 5e                	je     1cb3 <open_zeros+0xcc>
    1c55:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c59:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1c5d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1c60:	48 63 d0             	movslq %eax,%rdx
    1c63:	48 89 d0             	mov    %rdx,%rax
    1c66:	48 01 c0             	add    %rax,%rax
    1c69:	48 01 d0             	add    %rdx,%rax
    1c6c:	48 c1 e0 03          	shl    $0x3,%rax
    1c70:	48 01 c8             	add    %rcx,%rax
    1c73:	8b 40 10             	mov    0x10(%rax),%eax
    1c76:	85 c0                	test   %eax,%eax
    1c78:	75 39                	jne    1cb3 <open_zeros+0xcc>
    1c7a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c7e:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1c82:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1c85:	48 63 d0             	movslq %eax,%rdx
    1c88:	48 89 d0             	mov    %rdx,%rax
    1c8b:	48 01 c0             	add    %rax,%rax
    1c8e:	48 01 d0             	add    %rdx,%rax
    1c91:	48 c1 e0 03          	shl    $0x3,%rax
    1c95:	48 01 c8             	add    %rcx,%rax
    1c98:	8b 40 14             	mov    0x14(%rax),%eax
    1c9b:	85 c0                	test   %eax,%eax
    1c9d:	75 14                	jne    1cb3 <open_zeros+0xcc>
    1c9f:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1ca2:	8b 4d f0             	mov    -0x10(%rbp),%ecx
    1ca5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1ca9:	89 ce                	mov    %ecx,%esi
    1cab:	48 89 c7             	mov    %rax,%rdi
    1cae:	e8 50 fd ff ff       	callq  1a03 <open_cell>
    1cb3:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1cb7:	8b 45 e0             	mov    -0x20(%rbp),%eax
    1cba:	83 c0 01             	add    $0x1,%eax
    1cbd:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1cc0:	0f 8e 6a ff ff ff    	jle    1c30 <open_zeros+0x49>
    1cc6:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    1cca:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    1ccd:	83 c0 01             	add    $0x1,%eax
    1cd0:	39 45 f0             	cmp    %eax,-0x10(%rbp)
    1cd3:	0f 8e 49 ff ff ff    	jle    1c22 <open_zeros+0x3b>
    1cd9:	90                   	nop
    1cda:	90                   	nop
    1cdb:	c9                   	leaveq 
    1cdc:	c3                   	retq   

0000000000001cdd <open_neighbours>:
    1cdd:	f3 0f 1e fa          	endbr64 
    1ce1:	55                   	push   %rbp
    1ce2:	48 89 e5             	mov    %rsp,%rbp
    1ce5:	48 83 ec 20          	sub    $0x20,%rsp
    1ce9:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1ced:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    1cf0:	89 55 e0             	mov    %edx,-0x20(%rbp)
    1cf3:	8b 55 e0             	mov    -0x20(%rbp),%edx
    1cf6:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    1cf9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1cfd:	89 ce                	mov    %ecx,%esi
    1cff:	48 89 c7             	mov    %rax,%rdi
    1d02:	e8 94 03 00 00       	callq  209b <get_index>
    1d07:	89 45 f8             	mov    %eax,-0x8(%rbp)
    1d0a:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    1d0d:	83 e8 01             	sub    $0x1,%eax
    1d10:	89 45 f0             	mov    %eax,-0x10(%rbp)
    1d13:	e9 32 01 00 00       	jmpq   1e4a <open_neighbours+0x16d>
    1d18:	8b 45 e0             	mov    -0x20(%rbp),%eax
    1d1b:	83 e8 01             	sub    $0x1,%eax
    1d1e:	89 45 f4             	mov    %eax,-0xc(%rbp)
    1d21:	e9 11 01 00 00       	jmpq   1e37 <open_neighbours+0x15a>
    1d26:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1d29:	8b 4d f0             	mov    -0x10(%rbp),%ecx
    1d2c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1d30:	89 ce                	mov    %ecx,%esi
    1d32:	48 89 c7             	mov    %rax,%rdi
    1d35:	e8 61 03 00 00       	callq  209b <get_index>
    1d3a:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1d3d:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
    1d41:	0f 84 ec 00 00 00    	je     1e33 <open_neighbours+0x156>
    1d47:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1d4a:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    1d4d:	0f 84 e0 00 00 00    	je     1e33 <open_neighbours+0x156>
    1d53:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1d57:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1d5b:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1d5e:	48 63 d0             	movslq %eax,%rdx
    1d61:	48 89 d0             	mov    %rdx,%rax
    1d64:	48 01 c0             	add    %rax,%rax
    1d67:	48 01 d0             	add    %rdx,%rax
    1d6a:	48 c1 e0 03          	shl    $0x3,%rax
    1d6e:	48 01 c8             	add    %rcx,%rax
    1d71:	8b 40 10             	mov    0x10(%rax),%eax
    1d74:	85 c0                	test   %eax,%eax
    1d76:	0f 85 b7 00 00 00    	jne    1e33 <open_neighbours+0x156>
    1d7c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1d80:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1d84:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1d87:	48 63 d0             	movslq %eax,%rdx
    1d8a:	48 89 d0             	mov    %rdx,%rax
    1d8d:	48 01 c0             	add    %rax,%rax
    1d90:	48 01 d0             	add    %rdx,%rax
    1d93:	48 c1 e0 03          	shl    $0x3,%rax
    1d97:	48 01 c8             	add    %rcx,%rax
    1d9a:	8b 40 14             	mov    0x14(%rax),%eax
    1d9d:	85 c0                	test   %eax,%eax
    1d9f:	0f 85 8e 00 00 00    	jne    1e33 <open_neighbours+0x156>
    1da5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1da9:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1dad:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1db0:	48 63 d0             	movslq %eax,%rdx
    1db3:	48 89 d0             	mov    %rdx,%rax
    1db6:	48 01 c0             	add    %rax,%rax
    1db9:	48 01 d0             	add    %rdx,%rax
    1dbc:	48 c1 e0 03          	shl    $0x3,%rax
    1dc0:	48 01 c8             	add    %rcx,%rax
    1dc3:	8b 40 08             	mov    0x8(%rax),%eax
    1dc6:	83 f8 01             	cmp    $0x1,%eax
    1dc9:	75 0a                	jne    1dd5 <open_neighbours+0xf8>
    1dcb:	b8 01 00 00 00       	mov    $0x1,%eax
    1dd0:	e9 89 00 00 00       	jmpq   1e5e <open_neighbours+0x181>
    1dd5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1dd9:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1ddd:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1de0:	48 63 d0             	movslq %eax,%rdx
    1de3:	48 89 d0             	mov    %rdx,%rax
    1de6:	48 01 c0             	add    %rax,%rax
    1de9:	48 01 d0             	add    %rdx,%rax
    1dec:	48 c1 e0 03          	shl    $0x3,%rax
    1df0:	48 01 c8             	add    %rcx,%rax
    1df3:	c7 40 10 01 00 00 00 	movl   $0x1,0x10(%rax)
    1dfa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1dfe:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1e02:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1e05:	48 63 d0             	movslq %eax,%rdx
    1e08:	48 89 d0             	mov    %rdx,%rax
    1e0b:	48 01 c0             	add    %rax,%rax
    1e0e:	48 01 d0             	add    %rdx,%rax
    1e11:	48 c1 e0 03          	shl    $0x3,%rax
    1e15:	48 01 c8             	add    %rcx,%rax
    1e18:	8b 40 0c             	mov    0xc(%rax),%eax
    1e1b:	85 c0                	test   %eax,%eax
    1e1d:	75 14                	jne    1e33 <open_neighbours+0x156>
    1e1f:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1e22:	8b 4d f0             	mov    -0x10(%rbp),%ecx
    1e25:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e29:	89 ce                	mov    %ecx,%esi
    1e2b:	48 89 c7             	mov    %rax,%rdi
    1e2e:	e8 b4 fd ff ff       	callq  1be7 <open_zeros>
    1e33:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1e37:	8b 45 e0             	mov    -0x20(%rbp),%eax
    1e3a:	83 c0 01             	add    $0x1,%eax
    1e3d:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1e40:	0f 8e e0 fe ff ff    	jle    1d26 <open_neighbours+0x49>
    1e46:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    1e4a:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    1e4d:	83 c0 01             	add    $0x1,%eax
    1e50:	39 45 f0             	cmp    %eax,-0x10(%rbp)
    1e53:	0f 8e bf fe ff ff    	jle    1d18 <open_neighbours+0x3b>
    1e59:	b8 00 00 00 00       	mov    $0x0,%eax
    1e5e:	c9                   	leaveq 
    1e5f:	c3                   	retq   

0000000000001e60 <open_all>:
    1e60:	f3 0f 1e fa          	endbr64 
    1e64:	55                   	push   %rbp
    1e65:	48 89 e5             	mov    %rsp,%rbp
    1e68:	48 83 ec 20          	sub    $0x20,%rsp
    1e6c:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1e70:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1e77:	eb 7e                	jmp    1ef7 <open_all+0x97>
    1e79:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    1e80:	eb 65                	jmp    1ee7 <open_all+0x87>
    1e82:	8b 55 f8             	mov    -0x8(%rbp),%edx
    1e85:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    1e88:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e8c:	89 ce                	mov    %ecx,%esi
    1e8e:	48 89 c7             	mov    %rax,%rdi
    1e91:	e8 05 02 00 00       	callq  209b <get_index>
    1e96:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1e99:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e9d:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1ea1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ea4:	48 63 d0             	movslq %eax,%rdx
    1ea7:	48 89 d0             	mov    %rdx,%rax
    1eaa:	48 01 c0             	add    %rax,%rax
    1ead:	48 01 d0             	add    %rdx,%rax
    1eb0:	48 c1 e0 03          	shl    $0x3,%rax
    1eb4:	48 01 c8             	add    %rcx,%rax
    1eb7:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%rax)
    1ebe:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1ec2:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1ec6:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1ec9:	48 63 d0             	movslq %eax,%rdx
    1ecc:	48 89 d0             	mov    %rdx,%rax
    1ecf:	48 01 c0             	add    %rax,%rax
    1ed2:	48 01 d0             	add    %rdx,%rax
    1ed5:	48 c1 e0 03          	shl    $0x3,%rax
    1ed9:	48 01 c8             	add    %rcx,%rax
    1edc:	c7 40 10 01 00 00 00 	movl   $0x1,0x10(%rax)
    1ee3:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    1ee7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1eeb:	8b 40 04             	mov    0x4(%rax),%eax
    1eee:	39 45 f8             	cmp    %eax,-0x8(%rbp)
    1ef1:	7c 8f                	jl     1e82 <open_all+0x22>
    1ef3:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1ef7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1efb:	8b 00                	mov    (%rax),%eax
    1efd:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1f00:	0f 8c 73 ff ff ff    	jl     1e79 <open_all+0x19>
    1f06:	90                   	nop
    1f07:	90                   	nop
    1f08:	c9                   	leaveq 
    1f09:	c3                   	retq   

0000000000001f0a <open_all_mines>:
    1f0a:	f3 0f 1e fa          	endbr64 
    1f0e:	55                   	push   %rbp
    1f0f:	48 89 e5             	mov    %rsp,%rbp
    1f12:	48 83 ec 20          	sub    $0x20,%rsp
    1f16:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1f1a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1f21:	e9 ab 00 00 00       	jmpq   1fd1 <open_all_mines+0xc7>
    1f26:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    1f2d:	e9 8b 00 00 00       	jmpq   1fbd <open_all_mines+0xb3>
    1f32:	8b 55 f8             	mov    -0x8(%rbp),%edx
    1f35:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    1f38:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f3c:	89 ce                	mov    %ecx,%esi
    1f3e:	48 89 c7             	mov    %rax,%rdi
    1f41:	e8 55 01 00 00       	callq  209b <get_index>
    1f46:	89 45 fc             	mov    %eax,-0x4(%rbp)
    1f49:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f4d:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1f51:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1f54:	48 63 d0             	movslq %eax,%rdx
    1f57:	48 89 d0             	mov    %rdx,%rax
    1f5a:	48 01 c0             	add    %rax,%rax
    1f5d:	48 01 d0             	add    %rdx,%rax
    1f60:	48 c1 e0 03          	shl    $0x3,%rax
    1f64:	48 01 c8             	add    %rcx,%rax
    1f67:	8b 40 08             	mov    0x8(%rax),%eax
    1f6a:	83 f8 01             	cmp    $0x1,%eax
    1f6d:	75 4a                	jne    1fb9 <open_all_mines+0xaf>
    1f6f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f73:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1f77:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1f7a:	48 63 d0             	movslq %eax,%rdx
    1f7d:	48 89 d0             	mov    %rdx,%rax
    1f80:	48 01 c0             	add    %rax,%rax
    1f83:	48 01 d0             	add    %rdx,%rax
    1f86:	48 c1 e0 03          	shl    $0x3,%rax
    1f8a:	48 01 c8             	add    %rcx,%rax
    1f8d:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%rax)
    1f94:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f98:	48 8b 48 08          	mov    0x8(%rax),%rcx
    1f9c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1f9f:	48 63 d0             	movslq %eax,%rdx
    1fa2:	48 89 d0             	mov    %rdx,%rax
    1fa5:	48 01 c0             	add    %rax,%rax
    1fa8:	48 01 d0             	add    %rdx,%rax
    1fab:	48 c1 e0 03          	shl    $0x3,%rax
    1faf:	48 01 c8             	add    %rcx,%rax
    1fb2:	c7 40 10 01 00 00 00 	movl   $0x1,0x10(%rax)
    1fb9:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    1fbd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1fc1:	8b 40 04             	mov    0x4(%rax),%eax
    1fc4:	39 45 f8             	cmp    %eax,-0x8(%rbp)
    1fc7:	0f 8c 65 ff ff ff    	jl     1f32 <open_all_mines+0x28>
    1fcd:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1fd1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1fd5:	8b 00                	mov    (%rax),%eax
    1fd7:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1fda:	0f 8c 46 ff ff ff    	jl     1f26 <open_all_mines+0x1c>
    1fe0:	90                   	nop
    1fe1:	90                   	nop
    1fe2:	c9                   	leaveq 
    1fe3:	c3                   	retq   

0000000000001fe4 <check_win>:
    1fe4:	f3 0f 1e fa          	endbr64 
    1fe8:	55                   	push   %rbp
    1fe9:	48 89 e5             	mov    %rsp,%rbp
    1fec:	48 83 ec 20          	sub    $0x20,%rsp
    1ff0:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1ff4:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1ffb:	e9 85 00 00 00       	jmpq   2085 <check_win+0xa1>
    2000:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    2007:	eb 6c                	jmp    2075 <check_win+0x91>
    2009:	8b 55 f8             	mov    -0x8(%rbp),%edx
    200c:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    200f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2013:	89 ce                	mov    %ecx,%esi
    2015:	48 89 c7             	mov    %rax,%rdi
    2018:	e8 7e 00 00 00       	callq  209b <get_index>
    201d:	89 45 fc             	mov    %eax,-0x4(%rbp)
    2020:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2024:	48 8b 48 08          	mov    0x8(%rax),%rcx
    2028:	8b 45 fc             	mov    -0x4(%rbp),%eax
    202b:	48 63 d0             	movslq %eax,%rdx
    202e:	48 89 d0             	mov    %rdx,%rax
    2031:	48 01 c0             	add    %rax,%rax
    2034:	48 01 d0             	add    %rdx,%rax
    2037:	48 c1 e0 03          	shl    $0x3,%rax
    203b:	48 01 c8             	add    %rcx,%rax
    203e:	8b 40 08             	mov    0x8(%rax),%eax
    2041:	85 c0                	test   %eax,%eax
    2043:	75 2c                	jne    2071 <check_win+0x8d>
    2045:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2049:	48 8b 48 08          	mov    0x8(%rax),%rcx
    204d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2050:	48 63 d0             	movslq %eax,%rdx
    2053:	48 89 d0             	mov    %rdx,%rax
    2056:	48 01 c0             	add    %rax,%rax
    2059:	48 01 d0             	add    %rdx,%rax
    205c:	48 c1 e0 03          	shl    $0x3,%rax
    2060:	48 01 c8             	add    %rcx,%rax
    2063:	8b 40 10             	mov    0x10(%rax),%eax
    2066:	85 c0                	test   %eax,%eax
    2068:	75 07                	jne    2071 <check_win+0x8d>
    206a:	b8 00 00 00 00       	mov    $0x0,%eax
    206f:	eb 28                	jmp    2099 <check_win+0xb5>
    2071:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    2075:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2079:	8b 40 04             	mov    0x4(%rax),%eax
    207c:	39 45 f8             	cmp    %eax,-0x8(%rbp)
    207f:	7c 88                	jl     2009 <check_win+0x25>
    2081:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    2085:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2089:	8b 00                	mov    (%rax),%eax
    208b:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    208e:	0f 8c 6c ff ff ff    	jl     2000 <check_win+0x1c>
    2094:	b8 01 00 00 00       	mov    $0x1,%eax
    2099:	c9                   	leaveq 
    209a:	c3                   	retq   

000000000000209b <get_index>:
    209b:	f3 0f 1e fa          	endbr64 
    209f:	55                   	push   %rbp
    20a0:	48 89 e5             	mov    %rsp,%rbp
    20a3:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    20a7:	89 75 f4             	mov    %esi,-0xc(%rbp)
    20aa:	89 55 f0             	mov    %edx,-0x10(%rbp)
    20ad:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    20b1:	78 1d                	js     20d0 <get_index+0x35>
    20b3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    20b7:	8b 00                	mov    (%rax),%eax
    20b9:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    20bc:	7d 12                	jge    20d0 <get_index+0x35>
    20be:	83 7d f0 00          	cmpl   $0x0,-0x10(%rbp)
    20c2:	78 0c                	js     20d0 <get_index+0x35>
    20c4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    20c8:	8b 40 04             	mov    0x4(%rax),%eax
    20cb:	39 45 f0             	cmp    %eax,-0x10(%rbp)
    20ce:	7c 07                	jl     20d7 <get_index+0x3c>
    20d0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    20d5:	eb 12                	jmp    20e9 <get_index+0x4e>
    20d7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    20db:	8b 40 04             	mov    0x4(%rax),%eax
    20de:	0f af 45 f4          	imul   -0xc(%rbp),%eax
    20e2:	89 c2                	mov    %eax,%edx
    20e4:	8b 45 f0             	mov    -0x10(%rbp),%eax
    20e7:	01 d0                	add    %edx,%eax
    20e9:	5d                   	pop    %rbp
    20ea:	c3                   	retq   

00000000000020eb <neighbour_mines>:
    20eb:	f3 0f 1e fa          	endbr64 
    20ef:	55                   	push   %rbp
    20f0:	48 89 e5             	mov    %rsp,%rbp
    20f3:	48 83 ec 30          	sub    $0x30,%rsp
    20f7:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    20fb:	89 75 d4             	mov    %esi,-0x2c(%rbp)
    20fe:	89 55 d0             	mov    %edx,-0x30(%rbp)
    2101:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    2108:	8b 55 d0             	mov    -0x30(%rbp),%edx
    210b:	8b 4d d4             	mov    -0x2c(%rbp),%ecx
    210e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2112:	89 ce                	mov    %ecx,%esi
    2114:	48 89 c7             	mov    %rax,%rdi
    2117:	e8 7f ff ff ff       	callq  209b <get_index>
    211c:	89 45 f8             	mov    %eax,-0x8(%rbp)
    211f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2123:	48 8b 48 08          	mov    0x8(%rax),%rcx
    2127:	8b 45 f8             	mov    -0x8(%rbp),%eax
    212a:	48 63 d0             	movslq %eax,%rdx
    212d:	48 89 d0             	mov    %rdx,%rax
    2130:	48 01 c0             	add    %rax,%rax
    2133:	48 01 d0             	add    %rdx,%rax
    2136:	48 c1 e0 03          	shl    $0x3,%rax
    213a:	48 01 c8             	add    %rcx,%rax
    213d:	8b 40 08             	mov    0x8(%rax),%eax
    2140:	83 f8 01             	cmp    $0x1,%eax
    2143:	75 0a                	jne    214f <neighbour_mines+0x64>
    2145:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    214a:	e9 86 00 00 00       	jmpq   21d5 <neighbour_mines+0xea>
    214f:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    2152:	83 e8 01             	sub    $0x1,%eax
    2155:	89 45 ec             	mov    %eax,-0x14(%rbp)
    2158:	eb 6d                	jmp    21c7 <neighbour_mines+0xdc>
    215a:	8b 45 d0             	mov    -0x30(%rbp),%eax
    215d:	83 e8 01             	sub    $0x1,%eax
    2160:	89 45 f0             	mov    %eax,-0x10(%rbp)
    2163:	eb 53                	jmp    21b8 <neighbour_mines+0xcd>
    2165:	8b 55 f0             	mov    -0x10(%rbp),%edx
    2168:	8b 4d ec             	mov    -0x14(%rbp),%ecx
    216b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    216f:	89 ce                	mov    %ecx,%esi
    2171:	48 89 c7             	mov    %rax,%rdi
    2174:	e8 22 ff ff ff       	callq  209b <get_index>
    2179:	89 45 fc             	mov    %eax,-0x4(%rbp)
    217c:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
    2180:	74 32                	je     21b4 <neighbour_mines+0xc9>
    2182:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2185:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    2188:	74 2a                	je     21b4 <neighbour_mines+0xc9>
    218a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    218e:	48 8b 48 08          	mov    0x8(%rax),%rcx
    2192:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2195:	48 63 d0             	movslq %eax,%rdx
    2198:	48 89 d0             	mov    %rdx,%rax
    219b:	48 01 c0             	add    %rax,%rax
    219e:	48 01 d0             	add    %rdx,%rax
    21a1:	48 c1 e0 03          	shl    $0x3,%rax
    21a5:	48 01 c8             	add    %rcx,%rax
    21a8:	8b 40 08             	mov    0x8(%rax),%eax
    21ab:	83 f8 01             	cmp    $0x1,%eax
    21ae:	75 04                	jne    21b4 <neighbour_mines+0xc9>
    21b0:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    21b4:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    21b8:	8b 45 d0             	mov    -0x30(%rbp),%eax
    21bb:	83 c0 01             	add    $0x1,%eax
    21be:	39 45 f0             	cmp    %eax,-0x10(%rbp)
    21c1:	7e a2                	jle    2165 <neighbour_mines+0x7a>
    21c3:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    21c7:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    21ca:	83 c0 01             	add    $0x1,%eax
    21cd:	39 45 ec             	cmp    %eax,-0x14(%rbp)
    21d0:	7e 88                	jle    215a <neighbour_mines+0x6f>
    21d2:	8b 45 f4             	mov    -0xc(%rbp),%eax
    21d5:	c9                   	leaveq 
    21d6:	c3                   	retq   
    21d7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    21de:	00 00 

00000000000021e0 <__libc_csu_init>:
    21e0:	f3 0f 1e fa          	endbr64 
    21e4:	41 57                	push   %r15
    21e6:	4c 8d 3d 73 2b 00 00 	lea    0x2b73(%rip),%r15        # 4d60 <__frame_dummy_init_array_entry>
    21ed:	41 56                	push   %r14
    21ef:	49 89 d6             	mov    %rdx,%r14
    21f2:	41 55                	push   %r13
    21f4:	49 89 f5             	mov    %rsi,%r13
    21f7:	41 54                	push   %r12
    21f9:	41 89 fc             	mov    %edi,%r12d
    21fc:	55                   	push   %rbp
    21fd:	48 8d 2d 64 2b 00 00 	lea    0x2b64(%rip),%rbp        # 4d68 <__do_global_dtors_aux_fini_array_entry>
    2204:	53                   	push   %rbx
    2205:	4c 29 fd             	sub    %r15,%rbp
    2208:	48 83 ec 08          	sub    $0x8,%rsp
    220c:	e8 ef ed ff ff       	callq  1000 <_init>
    2211:	48 c1 fd 03          	sar    $0x3,%rbp
    2215:	74 1f                	je     2236 <__libc_csu_init+0x56>
    2217:	31 db                	xor    %ebx,%ebx
    2219:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    2220:	4c 89 f2             	mov    %r14,%rdx
    2223:	4c 89 ee             	mov    %r13,%rsi
    2226:	44 89 e7             	mov    %r12d,%edi
    2229:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    222d:	48 83 c3 01          	add    $0x1,%rbx
    2231:	48 39 dd             	cmp    %rbx,%rbp
    2234:	75 ea                	jne    2220 <__libc_csu_init+0x40>
    2236:	48 83 c4 08          	add    $0x8,%rsp
    223a:	5b                   	pop    %rbx
    223b:	5d                   	pop    %rbp
    223c:	41 5c                	pop    %r12
    223e:	41 5d                	pop    %r13
    2240:	41 5e                	pop    %r14
    2242:	41 5f                	pop    %r15
    2244:	c3                   	retq   
    2245:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    224c:	00 00 00 00 

0000000000002250 <__libc_csu_fini>:
    2250:	f3 0f 1e fa          	endbr64 
    2254:	c3                   	retq   

Disassembly of section .fini:

0000000000002258 <_fini>:
    2258:	f3 0f 1e fa          	endbr64 
    225c:	48 83 ec 08          	sub    $0x8,%rsp
    2260:	48 83 c4 08          	add    $0x8,%rsp
    2264:	c3                   	retq   
