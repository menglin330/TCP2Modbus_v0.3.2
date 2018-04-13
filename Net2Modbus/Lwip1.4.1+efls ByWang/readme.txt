


QQ:925295580
e-mail:925295580@qq.com
Time:201512
author:王均伟



       SW

   beta---(V0.1)


1、TCP/IP基础协议栈
.支持UDP
.支持TCP
.支持ICMP

2、超轻量级efs文件系统
.支持unix标准文件API
.支持SDHC标准。兼容V1.0和V2.0大容量SDK卡-16G卡无压力。（驱动部分参考开源 :-)）
.超低内存占用，仅用一个512字节的高速缓存来对文集遍历。

3、支持1-write DS18B20 	温度传感器
.支持单总线严格时序
.支持ROM搜索，遍历树叶子，允许一条总线挂接多个温度传感器
.数据自动转换为HTML文件

4、TCP/IP应用
.支持TFTP服务端，可以完成文件的下载任务。（此部分来自GITHUB，增加部分TIMEOUT 事件）tftp -i
.支持NETBIOS服务。
.支持一个TCP服务器，本地端口8080.	测试服务
.支持一个TCP客户端，本地端口40096	远端端口2301 远端IP192.168.0.163	用来做数据交互
.支持一个UDP广播，  本地端口02	    广播地址255.255.255.255	  用来把温度采集的数据发广播
.支持一个HTTP服务器 本地端口80  	http:ip  访问之	  关联2只18B20温度传感器显示在简单的SD卡的网页上

5、系统编译后
Program Size: Code=51264 RO-data=28056 RW-data=1712 ZI-data=55048  

6、网络配置

ipaddr：192, 168, 0, 253-209
netmask：255, 255, 0, 0
gw：192, 168, 0, 20
macaddress：xxxxxxxxxx


tks for GitHUB

	    HW

 stm32f107+DP83848CVV+ds18B20*2+SDHC card (4GB)

7、修改了一个SDcrad的BUG，有一个判断语句写错了，fix后可以支持2GB和4GB以上的两种卡片了。20160122
8、增加了一个宏在main.h中
#define MYSELFBOARD
如果定义了，那么表示使用李伟给我的开发板
如果不定义就选择我自己画的那块板子。
没有什么本质区别，框架一样，只是IO口稍有改动。20160122


 20160123
9、增加一个SMTP应用，可以通过定义USED_SMTP来使能 。
10、完成smtp.c的移植和测试。可以向我的邮箱发送邮件。邮箱需要设置关闭SSL。并且需要修改一下源码 的几个宏定义。
11、把采集的温度数据20分钟发一封邮件到我自己的邮箱中。完成。  必须用通过认真的IP否则过不去防火墙

12、调整了一下发邮箱的时间为5分钟一封邮件，@163邮箱的限制大约是300封邮件


20160402

13、测试中发现有内存泄露的情况,通过增加内存的信息通过TCP输出的 2301端口debug后发现
  异常的如下
 总内存数（字节）：6144
 已用内存（字节）：5816
 剩余内存数（字节）：328
 使用标示：1
 正常的如下
 总内存数（字节）：6144
 已用内存（字节）：20
 剩余内存数（字节）：6124
 使用标示：1
 显然memalloc使内存溢出查找代码因为除了SMTP应用程序使用malloc外其他不具有使用的情况。
 所以肯定是SMTP出问题
 进一步分析代码为SMTP的smtp_send_mail（）中
 smtp_send_mail_alloced(struct smtp_session *s)
 函数使用的
 s = (struct smtp_session *)SMTP_STATE_MALLOC((mem_size_t)mem_len);
 分配了一块内存没有事正常的释放。
 这样反复
 几次最终导致这块应用代码不能正常返回一块完整的 mem_le大小的内存块而一直保留了328字节的剩余内存。
 这最终导致了所有依赖mem的应用程序全部获取不到足够的内存块。而出现的内存溢出。
 继续分析 释放的内存句柄  (struct smtp_session *) s
 发现几处问题

 1）非正常中止	“风险”
   if (smtp_verify(s->to, s->to_len, 0) != ERR_OK) {
    return ERR_ARG;
  }
  if (smtp_verify(s->from, s->from_len, 0) != ERR_OK) {
    return ERR_ARG;
  }
  if (smtp_verify(s->subject, s->subject_len, 0) != ERR_OK) {
    return ERR_ARG;
  }
  由于没有对  smtp_send_mail_alloced 函数进行判断所以如果此处返回会造成函数不能正常中止
  也就会导致 (struct smtp_session *) s	没有机会释放（因为在不正常中止时是在后面处理的）
  但是考虑到源数据是固定的从片上flash中取得的，这种几率几乎没有。但是存在风险。所以统一改为
  if (smtp_verify(s->to, s->to_len, 0) != ERR_OK) {
    	 err = ERR_ARG;
     goto leave;
  }
  if (smtp_verify(s->from, s->from_len, 0) != ERR_OK) {
    	 err = ERR_ARG;
     goto leave;
  }
  if (smtp_verify(s->subject, s->subject_len, 0) != ERR_OK) {
    	 err = ERR_ARG;
     goto leave;
  }

  2）、非正常TCP连接，主要原因。
  原来的函数为：
  if(tcp_bind(pcb, IP_ADDR_ANY, SMTP_PORT)!=ERR_OK)
	{
	return	ERR_USEl;
  	   
	}
  显然还是同样的会造成malloc 分配了但是没有被调用，修改为
  if(tcp_bind(pcb, IP_ADDR_ANY,SMTP_PORT)!=ERR_OK)
  {
	err = ERR_USE;
    goto leave;		   
  }

   这样	  leave中就会自动处理释放掉这个非正常中止的而造成的内存的溢出问题。
   leave:
  smtp_free_struct(s);
  return err;

 归根结底是一个问题。那就是必须保证malloc 和free 成对出现。



 14、NETBIOS 名字服务增加在lwipopts.h中增加
 #define NETBIOS_LWIP_NAME "WJW-BOARD"
 正确的名称
 这样可以使用如下格式找到板子的IP地址
 ping 	wjw-board 
 而不用指定IP地址
 20160410



 /*测试中发现长时间运行后SMTP还有停止不发的情况，内存的问题上面已经解决，下面尝试修改进行解决，并继续测试-见17条*/
  20160427

 15、修改SNMTP的timout超时时间统一为2分钟，因为我的邮件重发时间为3分钟。默认的10分钟太长。先修改之。不是他影响的。fix

 /** TCP poll timeout while sending message body, reset after every
 * successful write. 3 minutes def:(3 * 60 * SMTP_POLL_INTERVAL / 2)*/
#define SMTP_TIMEOUT_DATABLOCK  ( 1 * 60 * SMTP_POLL_INTERVAL / 2)
/** TCP poll timeout while waiting for confirmation after sending the body.
 * 10 minutes def:(10 * 60 * SMTP_POLL_INTERVAL / 2)*/
#define SMTP_TIMEOUT_DATATERM   (1 * 60 * SMTP_POLL_INTERVAL / 2)
/** TCP poll timeout while not sending the body.
 * This is somewhat lower than the RFC states (5 minutes for initial, MAIL
 * and RCPT) but still OK for us here.
 * 2 minutes def:( 2 * 60 * SMTP_POLL_INTERVAL / 2)*/
#define SMTP_TIMEOUT            ( 1 * 60 * SMTP_POLL_INTERVAL / 2)
 20160427
 
  16、增加监控SMTP TCP 部分的变量数组
   smtp_Tcp_count[0]//tcp new count 
    smtp_Tcp_count[1]//bind count
	 smtp_Tcp_count[2]connect count 
	 smtp_Tcp_count[3]bind fail save the all pcb list index number
	 that all use debug long time running on smtp .
 20160427

17、发现不是SMTP的问题似乎邮箱出问题了，重新修改以上15条参数全部为2分钟 ，30*4*0.5S=1MIN *2=2min 

/** TCP poll interval. Unit is 0.5 sec. */
#define SMTP_POLL_INTERVAL      4
/** TCP poll timeout while sending message body, reset after every
 * successful write. 3 minutes def:(3 * 60 * SMTP_POLL_INTERVAL / 2)*/
#define SMTP_TIMEOUT_DATABLOCK  30*2
/** TCP poll timeout while waiting for confirmation after sending the body.
 * 10 minutes def:(10 * 60 * SMTP_POLL_INTERVAL / 2)*/
#define SMTP_TIMEOUT_DATATERM   30*2
/** TCP poll timeout while not sending the body.
 * This is somewhat lower than the RFC states (5 minutes for initial, MAIL
 * and RCPT) but still OK for us here.
 * 2 minutes def:( 2 * 60 * SMTP_POLL_INTERVAL / 2)*/
#define SMTP_TIMEOUT
20160429            30*2
18、加长了KEEPALIVBE时间为
	pcb->so_options |= SOF_KEEPALIVE;
   pcb->keep_idle = 1500+150;// ms
    pcb->keep_intvl = 1500+150;// ms
   pcb->keep_cnt = 2;// report error after 2 KA without response
 20160429


19、增加几个SMTP结果的变量	smtp_Tcp_count[10]	upsize 10 dword

20、增加监控SMTP TCP 部分的变量数组
   smtp_Tcp_count[0]//tcp new count 
    smtp_Tcp_count[1]//bind count
	 smtp_Tcp_count[2]connect count 
	 smtp_Tcp_count[3]bind fail save the all pcb list index number
add smtp send result 
              smtp_Tcp_count[4]|= (smtp_result);  
			  smtp_Tcp_count[4]|= (srv_err<<8);
			  smtp_Tcp_count[4]|= (err<<24);

			  if(err==ERR_OK){smtp_Tcp_count[5]++;}	//smtp成功次数统计

			   if(arg!=(void*)0)
			   {
				smtp_Tcp_count[6]=0xAAAAAAAA ;	 //有参数
			   }
			   else
			   {
			   
			   smtp_Tcp_count[6]=0x55555555 ;	//没有参数
			   }
20160430
21、

 以上测试中发现运行到9天左右就会不再执行SMTP代码返回数据如下： 低字节在前--高字节在后
 【Receive from 192.168.0.253 : 40096】：
5D 11 00 00     5D 11 00 00    58 11 00 00    00 00 00 00     04 00 00 F6  48 11 00 00  55 55 55 55 

上面的数据可知：
tcp new count=0x115d
bind count=0x115d
connect count=0x1158
bind fail  number=0
smtp_result=  4（SMTP_RESULT_ERR_CLOSED）
srv_err=00
tcp err=0xf6是负数需要NOT +1=(-10) 错误代码为  ERR_ABRT	  Connection aborted

以上数据定格，不在变化，说明这个和TCP baind 没有关系，是TCP new和之前的调用问题，所以继续锁定这个问题找。

20160513

22、把速度调快，10秒钟一次SMTP 连接。修改SMTP 应用程序的超时时间为8秒钟同时增加
smtp_Tcp_count[8]++;来计数总的调用SMTP的次数
smtp_Tcp_count[7]++;来计数SMTP 用的TCP new之前的次数。排除一下TCP new的问题！
如果这个变量一直变化而后面的没有变化这证明TCP —new出错。反之再向前推，直到调用它的地方一点点排除。

继续追踪这个停止TCP 连接的问题。
20160513


 /********为了接口陈新的485而做*******************/

23、增加modbus RTU 主机部分底层TXRX的代码，打算使用RTU 和TCP 做成透传485.这边不处理，只转发。
定义了一个宏

//定义了则使用MODBUS RTU TX/RX底层收发 (注意应用层没有使用。因为应用层打算交给服务器做，这边仅仅做RTU透传)
#define USED_MODBUS

18:52调试TX通过。更换了TIM3和USART2的Remap

20160613

24、更新STM32的固件库，使用2011版本的，原因是原来的2009版本的CL系列的串口驱动有问题。波特率不正常。换为2011的正常了，
    MODBUS RTU的流程做了修改。发送屏蔽掉CRC校验的产生，。直接透传。
	注意是MODBUS 这个串口从软件上看也是半双工的	。
20160614

25、上面的24条问题最终结果是晶振问题导致的，和固件库没有关系。


#if !defined  HSE_VALUE
 #ifdef STM32F10X_CL   
  #define HSE_VALUE    ((uint32_t)8000000) /*!< Value of the External oscillator in Hz */
 #else 
  #define HSE_VALUE    ((uint32_t)8000000) /*!< Value of the External oscillator in Hz */
 #endif /* STM32F10X_CL */
#endif /* HSE_VALUE */


  这里	 #define HSE_VALUE    ((uint32_t)8000000) /*!< Value of the External oscillator in Hz */
  要定义为你自己的外部晶振值。
20160615

26、增加了服务器接口和陈新，这一版要准备用在大鹏数据采集上做网管，所以定了简答的协议，这边直观转发。

 IP4_ADDR(&ip_addr,114,215,155,179 );//陈新服务器

 /*服务器发下的协议类型 
协议帧格式
帧头+类型+数据域+\r\n
帧头：
一帧网关和服务器交互的开始同时还担负判读数据上传还是下发的任务。
【XFF+0X55】：表示数据上传到服务器
【0XFF+0XAA】: 表示是数据下发到网关
类型：
0x01:表示土壤温湿度传感器
0x02表示光照传感器
0x03 表示PH 值传感器
0x04 表示氧气含量传感器
数据域
不同的类型的传感器数据域，数据域就是厂家提供的MODBUS-RTU的协议直接搭载上。

 服务器发送：FF AA + 类型 +【modbus RTU 数据域 】+\r\n
 网关回复  ：FF 55 + 类型 +【modbus RTU 数据域 】+\r\n

*/

 27、根据服务器要求修改网关的上报数据

 getid 命令改为

 AB +00 +[三字节ID]+CD +'$'+'\r'+'\n'   9个字节

 修改上报数据位

 FF 55 + 类型（1字节）+ID（3字节）+[modbus-RTU数据域] + '$'+'\r'+'\n'

20180710

28、开启DHCP 
20160710

29、修改了服务器接口和主要是修改了IP地址其他不变。
 IP4_ADDR(&ip_addr,60,211,192,14);//济宁大鹏客户的IP服务器地址。
20160920


30、在stm32f10x.h中增加UID的地址映射，以便直接获取ID号

 typedef struct
 {
 	uint32_t UID0_31;
 	uint32_t UID32_63;
	uint32_t UID64_96;
 }ID_TypeDef;
#define UID_BASE              ((uint32_t)0x1FFFF7E8) /*uid 96 by wang jun wei */
#define UID    ((ID_TypeDef*) UID_BASE)
20160920
31、修改ID从CPU的UID中运算获得
  uint32_t id;

  UID_STM32[0]=0xAB;//mark

  UID_STM32[1]=0x00;//备用

  id=(UID->UID0_31+UID->UID32_63+UID->UID64_95);//sum ID
  
  UID_STM32[2]=id;
  UID_STM32[3]=id>>8;//
  UID_STM32[4]=id>>16; // build ID 	lost The Hight 8bit data save the low 3 byte data as it ID

  UID_STM32[5]=0xCD; //mark

  UID_STM32[6]=0x24;
  UID_STM32[7]=0x0d;  //efl
  UID_STM32[8]=0x0a;
 20160920
32、增加MAC地址从芯片ID获取。
 void GetMacAddr(void)
{

uint32_t cid;
cid=(UID->UID0_31+UID->UID32_63+UID->UID64_95);//sum ID
macaddress[0]=0x00;
macaddress[1]=0x26;
macaddress[2]=cid;
macaddress[3]=cid>>8;
macaddress[4]=cid>>16;
macaddress[5]=cid>>24;

}
20160921
33、修复MODBUS上报的错误ID

	 Mb2TcpBuff[0]=0xFF;
	 Mb2TcpBuff[1]=0x55;
	 Mb2TcpBuff[2]=Statues_MB;
	 Mb2TcpBuff[3]=UID_STM32[2];
	 Mb2TcpBuff[4]=UID_STM32[3];
	 Mb2TcpBuff[5]=UID_STM32[4];
	 memcpy(&Mb2TcpBuff[6],ucMBFrame,Mb2TcpLenth);//数据复制进TCP发送buf中
	 Mb2TcpBuff[Mb2TcpLenth+6]=0x24;
	 Mb2TcpBuff[Mb2TcpLenth+6+1]=0x0d;
	 Mb2TcpBuff[Mb2TcpLenth+6+2]=0x0a;	
20160921 


34、因济宁需要6套网关，重新加入FLASH操作，
在falshif.c中增加2个函数操作fash，用最后一个程序Flash块来记录IP和端口号信息
void GetIpFromFlash(uint32_t *ptr)
void WriteIpToFlash(uint32_t *ptr,uint8_t len)

增加几个变量，用来记录sever IP
ipaddr_sever[0]=flash_net_buf[0]>>24;//取出最高IP位
			ipaddr_sever[1]=flash_net_buf[0]>>16;
			ipaddr_sever[2]=flash_net_buf[0]>>8;
			ipaddr_sever[3]=flash_net_buf[0]>>0;//取出最低IP位
			port_sever     =flash_net_buf[1];


操作步骤
1、使用PC的UDP协议发送广播，端口21228 发送 getid 
2、设备收到后回复网关芯片的ID号,
3、使用如下命令配置服务器的IP地址和端口号

			//[setconfig.1.2.3.4:56] ascii 字符
			//1.2.3.4分别表示IP地址的4个字节，用逗号隔开，高位在前地位在后
			//56，表示端口号，高位在前地位在后，用：引导
			//73 65 74 63 6F 6E 66 69 67 2E 31 2E 32 2E 33 2E 34 3A 35 36  HEX显示

			 例子：
			 我要配置服务器的IP为192.168.0.4，端口2301，
			 转换十六进制为
			 IP地址192.168.0.4，端口2301，-> HEX IP地址：0xc0,0xa8,0x00,0x04 端口：0x08fd
			 则就要发送如下命令
			 测试
			 {73 65 74 63 6F 6E 66 69 67 2E  C0  2E  A8  2E  00  2E  04  3A  08  FD } 
			 {[0][1][2][3][4][5][6][7][8][9][10][11][12][13][14][15][16][17][18][19]}
			
			  济宁：	60,211,192,14)
			 {73 65 74 63 6F 6E 66 69 67 2E  3c  2E  d3  2E  c0  2E  0e  3A  08  FD}

			 配置成功后返回:OK 
			 
4、使用getconfig,查询当前的服务器IP地址和端口号


20180304   

35、协议增加二氧化痰
济宁老刘买的传感器读取参数协议
把下面的数据搭载在FFAA +类型开头的数据发给网关
查询二氧化碳浓度
PC发送：
【20 03 00 02 00 01 23 7B】
20表示地址，转换为十进制是32
最后两位是CRC16的值，可以计算，其他固定不动。
传感器回复：
【20 03 02 04 96 86 ED】
20表示地址，转换为十进制是32，
0496分别代表二氧化碳浓度值的最高8位和最低8位，程序需要组合起来
就是0x0496,转换为十进制就是二氧化痰浓度，单位是ppm 也就是1174ppm
最后2位是CRC16值，
 /*服务器发下的协议类型 
协议帧格式
帧头+类型+数据域
帧头：
一帧网关和服务器交互的开始同时还担负判读数据上传还是下发的任务。
【XFF+0X55】：表示数据上传到服务器
【0XFF+0XAA】: 表示是数据下发到网关
类型：
0x01:表示土壤温湿度传感器
0x02表示光照传感器
0x03 表示PH 值传感器
0x04 表示氧气含量传感器
0x05 表示二氧化碳
数据域
不同的类型的传感器数据域，数据域就是厂家提供的MODBUS-RTU的协议直接搭载上。

 服务器发送：FF AA + 类型 +【modbus RTU 数据域 】
 网关回复  ：FF 55 + 类型 +【modbus RTU 数据域 】+0x24+0x0d+0x0a

36、开始增加SI4432 先移植驱动，后重新把底层测试一遍

增加si4432目录，并添加SI4432.C(SI4432的驱动)和SI4432_proto.C（协议）

在主程序初始化里面增加SI4432的初始化
initsi4432();
rx_data();
增加新的线程用来接收上传SI4432上来的数据
Si4432Thread(LocalTime);
另外在文件目录下增加一个Si4432-Register-Settings_RevV-v26的excel表格，这个表格今天完全弄明白了操作手法
使得SI4432取得重大突破，原来的延迟卡顿问题将不会再是问题了。
使用哪个表进行配置，配置完毕的数据直接copy进void Si4432RegisterSetV26()这个函数中即可

方法：
1：打开表格，第一个表里面灰色部分我们只需要修改TX/RX中心频率和通信波特率RB即可。其他的默认即可:	比如模式GFSK，AFC时能、状态机关闭等默认即可
2：PH+FIFO 和FIFO两个我们选一个，我们只选PH+FIFO即可，里面的参数可以默认，不需要修改即可
3：打开最后一个表，在上面灰色的select you work Mode 中选择PH+FIFO模式
4：最后在下面的表单中寄存器的数据拷贝到函数void Si4432RegisterSetV26()，这个函数位于SI4432.C中

这是重大进步，今天花很久才搞好。曲折不少，下一步是测试距离和稳定性


SI4432可以做240-960	 MHZ之内的任意频点，我们主要做433和315，主要保证数据实时性和距离。

天线材质需要用铜导体，433MHZ天线长度17cm 315MHZ天线长度23CM


 增加433发送和接受程序。数据还是只转发。

2018.4.10

37、增加433发送和接受程序。数据还是只转发。
2018.4.12

38、网络重大改动，底层原来的处理是以太网中断后读取一包数据然后退出中断，在主循环中检测这一包数据，然后调用LWIP的input,送入协议栈中
 在做无线的测试时我发现似乎有丢失的情况，并且TCP链接也不稳定，存在经常断开的情况。
 对这一现象进行分析，是因为我的故意丢包造成的。这种结构会造成在数据很多的情况下，中断来了读取了数据，但是主循环并没有时间处理，等
 LWIP在处理的时候，有来了一包数据，这个数据把原来的数据又覆盖了	，这样会造成失序，所以我修改了结构。
 我直接在主循环中检测以太网包，如果有包那么一次性全部读取完毕再去处理别的。这样从网卡读取的数据就都进入了LWIP协议栈中，不会丢包也
 不会出现失序问题，这个我今天晚上改完，需要长时间测试。如果OK那么这将是里程碑的意义。

 在中断函数屏蔽掉处理函数
 void ETH_IRQHandler(void)
{

#if 0
  /* Handles all the received frames */
  while(ETH_GetRxPktSize() != 0) 
  {		
   //LwIP_Pkt_Handle();
   Read_Eth_Packet();
  }
 #endif

在主程序轮训里面把数据一次性读取到LWIP中，因为Lwip有很大的BUFF，所以存储这些不是问题
 void ETH_Recive_Poll(void)
{

   
	 /* Handles all the received frames */
  while(ETH_GetRxPktSize() != 0) 
  {		
   //LwIP_Pkt_Handle();
   Read_Eth_Packet();
  


	if(frameds.length>0) //处理以太网数据
	{
     LwIP_Pkt_Handle();//处理早已经接收放入内存的数据。
	 memset(&frameds, 0, sizeof(FrameTypeDef));
	}	
  }


  
   #if 0
	if(frameds.length>0) //处理以太网数据
	{
     LwIP_Pkt_Handle();//处理早已经接收放入内存的数据。
	 memset(&frameds, 0, sizeof(FrameTypeDef));
	}	

   #endif




}


 我已经做过对比测试。
 1、如果把上面的#if 0 打开-也就是老程序	，然后UDP不断去网关获取getid，狂发，然后在开TCP，会发现TCP链接极其不稳定。并且发送应用层数据
 TCP也无法正常接收到，（这是因为大量的数据充斥在网卡里面，而我处理不过来就丢了。造成了大量数据丢失）

 2、使用新的结构测试，#if 0关闭，就是新的结构，发现UDP即使不断的去查询ID，网关在及时回复的情况下，依然可以从容的链接TCP并且毫无延迟的
 发送应用层数据。

 之前在测试中发现有时候网关频繁掉线，以为是网络问题，原来根在这里。也是当时埋下的一个坑。

 跟进测试。看看稳定不稳定。

继续测试
2018.4.13




