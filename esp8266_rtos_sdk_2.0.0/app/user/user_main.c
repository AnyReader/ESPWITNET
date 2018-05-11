/*
 * ESPRSSIF MIT License
 *
 * Copyright (c) 2015 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP8266 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "esp_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "uart.h"


#define DEBUG_ON 1

#define SSID	"ChinaMobile"//"Easycom"//"Easyjoy"//"Fantasy"
#define PASSWORD	"{85208520}"//"87654321"//"yizhi2017"
#define RECONECT_TIME   300

LOCAL os_timer_t test_timer;
void user_esp_check_ip(void);
void user_task1(void* arg);
void user_task2(void* arg);
void user_task3(void* arg);
void user_task4(void* arg);

const char *device_find_request = "Are You Easyfp Smart Device?";
const char *device_find_response_ok = "|HID8526|RID2576|";//HOTEL ID Repeater ID

#define	DEMO_AP_SSID	"ChinaNet"
#define	DEMO_AP_PASSWORD	"87654321"
#define	TCP_SERVER_PORT	12110

static xTaskHandle xTaskHandle1, xTaskHandle2,xTaskHandle3,xTaskHandle4;
extern xQueueHandle xQueueUart;

extern u8 uart0ReceivedBegin;		//
extern u8 uart0ReceivedFlag;		//
extern u32 uart0ReceiveNum ;		//the number of uart data

extern u8 uart0TxBuf[UART0_TBUFSIZE];//
extern u8 uart0RxBuf[UART0_RBUFSIZE];//

u8 data_buffer[100];
int sock_fd;                /* server socked */

#define SERVER_IP  "192.168.1.102"
#define REMOTE_PORT		12110
#define LOCAL_PORT		10002
//char msg[] = "hello, you are connected!\n";

/******************************************************************************
 * FunctionName : user_rf_cal_sector_set
 * Description  : SDK just reversed 4 sectors, used for rf init data and paramters.
 *                We add this function to force users to set rf cal sector, since
 *                we don't know which sector is free in user's application.
 *                sector map for last several sectors : ABCCC
 *                A : rf cal
 *                B : rf init data
 *                C : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
*******************************************************************************/
uint32 user_rf_cal_sector_set(void)
{
    flash_size_map size_map = system_get_flash_size_map();
    uint32 rf_cal_sec = 0;

    switch (size_map) {
        case FLASH_SIZE_4M_MAP_256_256:
            rf_cal_sec = 128 - 5;
            break;

        case FLASH_SIZE_8M_MAP_512_512:
            rf_cal_sec = 256 - 5;
            break;

        case FLASH_SIZE_16M_MAP_512_512:
        case FLASH_SIZE_16M_MAP_1024_1024:
            rf_cal_sec = 512 - 5;
            break;

        case FLASH_SIZE_32M_MAP_512_512:
        case FLASH_SIZE_32M_MAP_1024_1024:
            rf_cal_sec = 1024 - 5;
            break;
        case FLASH_SIZE_64M_MAP_1024_1024:
            rf_cal_sec = 2048 - 5;
            break;
        case FLASH_SIZE_128M_MAP_1024_1024:
            rf_cal_sec = 4096 - 5;
            break;
        default:
            rf_cal_sec = 0;
            break;
    }

    return rf_cal_sec;
}

/******************************************************************************
 * FunctionName : user_esp_platform_check_ip
 * Description  : check whether get ip addr or not
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
user_esp_check_ip(void)
{
    struct ip_info ipconfig;

   //disarm timer first
    os_timer_disarm(&test_timer);

   //get ip info of ESP8266 station
    wifi_get_ip_info(STATION_IF, &ipconfig);

    if (wifi_station_get_connect_status() == STATION_GOT_IP && ipconfig.ip.addr != 0) {

#if DEBUG_ON
 //   	os_printf("Connected to router and assigned IP!\r\n");
#endif
//      user_tcpclient_init(CLIENT_LOCAL_PORT);
    	xTaskCreate(user_task1, "user_start_task1", 256, NULL, 7, &xTaskHandle1);

    	xTaskCreate(user_task4, "user_start_task4", 256, NULL, 5, &xTaskHandle4);

    } else {

        if ((wifi_station_get_connect_status() == STATION_WRONG_PASSWORD ||
                wifi_station_get_connect_status() == STATION_NO_AP_FOUND ||
                wifi_station_get_connect_status() == STATION_CONNECT_FAIL)) {

 //        os_printf("connect fail !!! \r\n");

        } else {


        }
                   //restart arm-timer to check ip
        os_timer_disarm(&test_timer);
        os_timer_setfn(&test_timer, (os_timer_func_t *)user_esp_check_ip, NULL);
        os_timer_arm(&test_timer, RECONECT_TIME, 0);  //

    }
}


/******************************************************************************
 * FunctionName : user_set_station_config
 * Description  : set the router info which ESP8266 station will connect to
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
user_set_station_config(void)
{
   // Wifi configuration
   //char ssid[32];
   //char password[64];
   struct station_config stationConf;

   memset(stationConf.ssid, 0, 32);
   memset(stationConf.password, 0, 64);
   //need not mac address
   stationConf.bssid_set = 0;

   //Set ap settings
   sprintf(stationConf.ssid,"%s", SSID);
   sprintf(stationConf.password,"%s", PASSWORD);

   wifi_station_set_config(&stationConf);

   //set a timer to check whether got ip from router succeed or not.
	os_timer_disarm(&test_timer);
	os_timer_setfn(&test_timer, (os_timer_func_t *)user_esp_check_ip, NULL);
    os_timer_arm(&test_timer, RECONECT_TIME, 0); //300 ms

}


void init_done_cb(void)
{
    char buf[64] = { 0 };
    u8 ret;
    sprintf(buf, "compile time:%s %s", __DATE__, __TIME__);
    printf("uart init ok, %s\n", buf);
    printf("SDK version: %s \n", system_get_sdk_version());
    printf("ESP8266	chip	ID:0x%x\n",	system_get_chip_id());


#if DEBUG_ON
	ret=espconn_tcp_get_max_con();
	printf("tcp_get_max: %d \r\n", ret);
    ret=system_get_cpu_freq();
	printf("cpu_freq: %d \r\n", ret);
#endif
}

//tcp client
void user_task1(void* arg)
{
	int err;
	int length;
//	int sock_conn;

//	os_event_t xe;

	uint32 g_user_x=system_get_time();

	printf("task1...%d\%d...\r\n",system_get_time(),g_user_x);

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;//
	int sock_fd;

//	memset(data_buffer,0,sizeof(data_buffer));

	do
	{
		sock_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (sock_fd == -1)
		{
			close(sock_fd);
			printf("failed to create cli socket %d!\n",sock_fd);
			vTaskDelay(1000/portTICK_RATE_MS);
 //       continue;
        //RAW_ASSERT(0);
		}
	}while(sock_fd==-1);

	printf("cli create socket %d\n", sock_fd);

//    fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFL, 0) | O_NONBLOCK);//非阻塞


	int keepAlive = 1;////设定KeepAlive
//	err=setsockopt(sock_fd,SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(int));
	if(setsockopt(sock_fd,SOL_SOCKET,SO_KEEPALIVE,(void*)&keepAlive,sizeof(keepAlive)) == -1)
	{

	}

	int keepIdle = 60;//开始首次KeepAlive探测前的TCP空闭时间
	int keepInterval = 5;//两次KeepAlive探测间的时间间隔
	int keepCount = 3;//判定断开前的KeepAlive探测次数


	if(setsockopt(sock_fd,IPPROTO_TCP,TCP_KEEPIDLE,(void *)&keepIdle,sizeof(keepIdle)) == -1) //SOL_TCP
	{

	}

	if(setsockopt(sock_fd,IPPROTO_TCP,TCP_KEEPINTVL,(void *)&keepInterval,sizeof(keepInterval)) == -1)
	{

	}

	if(setsockopt(sock_fd,IPPROTO_TCP,TCP_KEEPCNT,(void *)&keepCount,sizeof(keepCount)) == -1)
	{

	}


    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);  /* 将目标服务器的IP写入一个结构体 */  //
    server_addr.sin_port = htons(REMOTE_PORT);

#if 0
    client_addr.sin_family=AF_INET;
    client_addr.sin_port=htons(LOCAL_PORT);

   err = bind(sock_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));//设置本地端口  set local port
   if (err < 0)
   {
       // RAW_ASSERT(0);
		printf(" TCP client ask bind error %d\n",err);
		vTaskDelay(1000/portTICK_RATE_MS);
   }

#endif
        //close(sock_fd);
       // printf("connect server fail....\r\n");
   do
   {
      err=connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));//if success is 0
      if(err!=0)
      {
    	  printf("cli connect fail %d....\r\n",err);
    	  close(sock_fd);
    	  vTaskDelay(1000/portTICK_RATE_MS);

    	  sock_fd = socket(AF_INET, SOCK_STREAM, 0);//logic problem

    	  vTaskDelay(1000/portTICK_RATE_MS);
      }
   }while(err!=0);

    printf("connect server success %d/%d....\r\n",err,sock_fd);//0 0

	while(1)
	{
		//raw_sleep(100);

		length = recv(sock_fd, data_buffer, sizeof(data_buffer), 0); //>0 返回收到的字节数目   =0断开连接  <0错误
		if(length)
		{
			uart0_tx_buffer(data_buffer, length);
		}
		//err=send(sock_fd, data_buffer, length, 0);
        //vTaskDelay(1000/portTICK_RATE_MS);

        if(length==0)
        {
    //		close(sock_fd);

    //		sock_fd = socket(AF_INET, SOCK_STREAM, 0);//logic problem
    		err=connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
            vTaskDelay(1000/portTICK_RATE_MS);
    		printf("TCP client rcv fail %d/%d!\n",sock_fd,err);//0 -1
    		if(err<0)
    			goto NEWSOCK;

        }

        if(length <0)
        {

NEWSOCK:
			close(sock_fd);
        	do
        	{
        		sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        		if (sock_fd == -1)
        		{
        			close(sock_fd);
        			printf("failed-to-create-cli-socket %d!\n",sock_fd);
        			vTaskDelay(1000/portTICK_RATE_MS);
        		}
        	}while(sock_fd==-1);

//        	do
//        	{
        	    err=connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));//if success is 0
        	    if(err!=0)
        	    {
        	    	printf("cli-connect-fail %d....\r\n",err);
        	    	close(sock_fd);
        	    	vTaskDelay(1000/portTICK_RATE_MS);

        	     }
//        	 }while(err!=0);

//        	sock_fd = socket(AF_INET, SOCK_STREAM, 0);//logic problem

//        	err=connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
//     		printf("cli new socket %d/%d!\n",sock_fd,err);//-1 -1

        }

#if 0
        //因为阻塞的问题  这个函数不会执行
        if(xQueueReceive(xQueueUart, (void *)&xe, (portTickType)portMAX_DELAY))
        {
            switch (xe.event) {
                case UART_EVENT_RX_CHAR:
                    //printf("get %d\r\n", xe.param);
                	uart_rx_handle();
                	err=send(sock_fd, uart0RxBuf, uart0ReceiveNum, 0);
                	uart0ReceiveNum    = 0;
                	/**
                	if(uart0ReceivedFlag==1)
                	{
                		err=send(sock_fd, uart0RxBuf, uart0ReceiveNum, 0);
                		uart0ReceiveNum    = 0;
                		uart0ReceivedBegin = 0;
                		uart0ReceivedFlag  = 0;

                	}
**/

                    break;

                default:
                    break;
            }
        }
#endif
	}
}
void user_task2(void* arg)
{

	uint32 g_user_x=system_get_time();

	struct sockaddr_in server_addr;
	struct sockaddr_in conn_addr;
//	int sock_fd;                /* server socked */
	int sock_conn;          /* request socked */
	socklen_t addr_len;
	int err;
	int length;
	int count = 0;

	    printf("task2...%d\%d...\r\n",system_get_time(),g_user_x);
		do
		{
			sock_fd = socket(AF_INET, SOCK_STREAM, 0);
			if (sock_fd == -1)
			{
				 printf("failed to create sock_fd!\n");
				vTaskDelay(1000/portTICK_RATE_MS);
			}
		}while(sock_fd	==	-1);

	    memset(&server_addr, 0, sizeof(server_addr));
	    server_addr.sin_family = AF_INET;
	    server_addr.sin_addr.s_addr =htonl(INADDR_ANY);
	    server_addr.sin_port = htons(TCP_SERVER_PORT);  //server port

	    err = bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	    if (err < 0) {
	       // RAW_ASSERT(0);
			printf("ESP8266	TCP	server ask bind error\n");
			vTaskDelay(1000/portTICK_RATE_MS);
	    }

	    err = listen(sock_fd, 1);
	    if (err < 0) {
	       // RAW_ASSERT(0);
			printf("ESP8266	TCP	server task failed	to	set	listen	queue!\n");
			vTaskDelay(1000/portTICK_RATE_MS);

	    }

	    addr_len = sizeof(struct sockaddr_in);

	    printf("before accept!\n");
	    sock_conn = accept(sock_fd, (struct sockaddr *)&conn_addr, &addr_len);
	    printf("after accept!\n");

	    while (1) {


	        memset(data_buffer, 0, sizeof(data_buffer));//char	*data_buffer	=	(char	*)zalloc(128);  //free(recv_buf);


	        length = recv(sock_conn, (unsigned int *)data_buffer, 20, 0);

	        printf("length received %d\n", length);
	        printf("received string: %s\n", data_buffer);
//	        printf("received count: %d\n", count);//0 get data

	        //send(sock_conn, "good", 5, 0);
	        send(sock_conn, data_buffer, length, 0);
	        if(length<=0)
	        {
	    		printf("TCP server task read data fail!\n");
	    		//close(sock_conn);
	    		sock_conn = accept(sock_fd, (struct sockaddr *)&conn_addr, &addr_len);
	    		vTaskDelay(1000/portTICK_RATE_MS);
	        }
	    }

	/**
	while(1){

		//printf("test2...%d...\r\n",system_get_time()-g_user_x);
		if(uart0ReceiveNum>10) uart0ReceivedFlag=1;
		if(uart0ReceivedFlag==1)
		{
			uart0_tx_buffer(uart0RxBuf,uart0ReceiveNum);
			uart0ReceiveNum=0;
		}
	}
	**/
}
void user_task3(void* arg)
{
	os_event_t xe;
	int err;
	uint32 g_user_x=system_get_time();

	printf("task3...%d\%d...\r\n",system_get_time(),g_user_x);
	while(1)
	{
        if(xQueueReceive(xQueueUart, (void *)&xe, (portTickType)portMAX_DELAY))
        {
            switch (xe.event) {
                case UART_EVENT_RX_CHAR:
                    //printf("get %d\r\n", xe.param);
                	uart_rx_handle();
              		err=send(sock_fd, uart0RxBuf, uart0ReceiveNum, 0);
                	if(err<=0)
                	{
                		printf("send err %d/%d\n",err,sock_fd);
                		vTaskDelay(1000/portTICK_RATE_MS);

                	}

                    break;

                default:
                    break;
            }
        }
#if 0
    	if(uart0ReceivedFlag==1)
    	{
    		err=send(sock_fd, uart0RxBuf, uart0ReceiveNum, 0);
    		if(err<=0)
    		{
    			vTaskDelay(1000/portTICK_RATE_MS);
    		}
    		uart0ReceiveNum    = 0;
    		uart0ReceivedBegin = 0;
    		uart0ReceivedFlag  = 0;

    	}
#endif

	}
}

void user_task4(void* arg)
{
	int ret;
	unsigned short length;
	char buf[30];
	char DeviceBuffer[100] = {0};
	char hwaddr[6];
	struct ip_info ipconfig;
	sint8 rssi=wifi_station_get_rssi();

	int udp_sockfd;
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	do
	{
		udp_sockfd=socket(AF_INET,SOCK_DGRAM,0);
		if(udp_sockfd==-1)
		{
			printf("failed to create udp socket %d\t\n",udp_sockfd);//-1
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	}while(udp_sockfd<0);

	printf("udp socket ok!\n");

	addr.sin_family =AF_INET;
	addr.sin_port =htons(1250);//UDP_LOCAL_PORT
	addr.sin_addr.s_addr=htonl(INADDR_ANY);//inet_addr("127.0.0.1");

	do
	{
		ret =bind(udp_sockfd,(struct sockaddr*)&addr,sizeof(addr));//if ok return 0 else -1
		if(ret!=0)
		{
			printf("udp bind error %d \n",ret);
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	}while(ret!=0);

	printf("udp bind ok!\n");

	struct sockaddr_in cli;
	socklen_t len=sizeof(cli);


    printf("task4...%d...\r\n",system_get_time());
	while(1)
	{
	    if (wifi_get_opmode() != STATION_MODE)
	    {
	        wifi_get_macaddr(SOFTAP_IF, hwaddr);
	        wifi_get_ip_info(SOFTAP_IF, &ipconfig);

	    }
	    else
	    {
	    	wifi_get_ip_info(STATION_IF, &ipconfig);
	        wifi_get_macaddr(STATION_IF, hwaddr);
	    }

//		setsockopt(sock_fd,	SOL_SOCKET,	SO_RCVTIMEO,	(char	*)&nNetTimeout,	sizeof(int));

		 length = recvfrom(udp_sockfd,buf,sizeof(buf),0,(struct sockaddr*)&cli,&len);
#if 0
		 if(length)
		 {
			 sendto(udp_sockfd,buf,sizeof(buf),0,(struct sockaddr*)&cli,len);

		 }
#endif
		 if (length == strlen(device_find_request) &&
		            strncmp(buf, device_find_request, strlen(device_find_request)) == 0)
		 {
		      sprintf(DeviceBuffer,"%s""%s"MACSTR"|RSSI%d|IP"IPSTR"|", device_find_response_ok,"MAC",
		                   MAC2STR(hwaddr), rssi, IP2STR(&ipconfig.ip));
			printf("recv =%s from %s,port %d\n",DeviceBuffer,inet_ntoa(cli.sin_addr),ntohs(cli.sin_port));

			//	 printf("PORT %d,IP IPSTR\n",ntohs(cli.sin_port),IP2STR(cli.sin_addr.s_addr));//error
			//printf("IP %s,PORT %d",inet_ntoa(cli.sin_addr),	ntohs(cli.sin_port));
			ret=sendto(udp_sockfd,DeviceBuffer,sizeof(DeviceBuffer),0,(struct sockaddr*)&cli,len);
			if(ret<0)
			{

			}

		 }
		 if(length<0)
		 {

		 }


	}
	close(udp_sockfd);
}


void	wifi_handle_event_cb(System_Event_t	*evt)
{
	printf("event	%x\n",	evt->event_id);
	switch	(evt->event_id)
	{
		case	EVENT_STAMODE_CONNECTED:
				printf("connect	to	ssid	%s,	channel	%d\n",
				evt->event_info.connected.ssid,
				evt->event_info.connected.channel);
								break;
		case	EVENT_STAMODE_DISCONNECTED:
				printf("disconnect	from	ssid	%s,	reason	%d\n",
				evt->event_info.disconnected.ssid,
				evt->event_info.disconnected.reason);
								break;
		case	EVENT_STAMODE_AUTHMODE_CHANGE:
				printf("mode:	%d	->	%d\n",
				evt->event_info.auth_change.old_mode,
				evt->event_info.auth_change.new_mode);	break;
		case	EVENT_STAMODE_GOT_IP:
				printf("ip:"	IPSTR	",mask:"	IPSTR	",gw:"	IPSTR,
				IP2STR(&evt->event_info.got_ip.ip),
				IP2STR(&evt->event_info.got_ip.mask),
				IP2STR(&evt->event_info.got_ip.gw));
				printf("\n");
								break;
		case	EVENT_SOFTAPMODE_STACONNECTED://6
				printf("station:	"	MACSTR	"join,	AID	=	%d\n",
				MAC2STR(evt->event_info.sta_connected.mac),
				evt->event_info.sta_connected.aid);
								break;
		case	EVENT_SOFTAPMODE_STADISCONNECTED:
				printf("station:	"	MACSTR	"leave,	AID	=	%d\n",
				MAC2STR(evt->event_info.sta_disconnected.mac),
				evt->event_info.sta_disconnected.aid);
				break;
		default:
				break;
				}
}

#if 0
void creat_tcp_server(void)
{
	int32	listenfd;
	int32	ret;
	struct	sockaddr_in	server_addr,remote_addr;
	int	stack_counter=0;

	/*	Construct	local	address	structure	*/
	memset(&server_addr,	0,	sizeof(server_addr));	/*	Zero	out	structure	*/
	server_addr.sin_family	=	AF_INET;												/*	Internet	address	family	*/
	server_addr.sin_addr.s_addr	=	INADDR_ANY;			/*	Any	incoming	interface	*/
	server_addr.sin_len	=	sizeof(server_addr);
	server_addr.sin_port	=	htons(TCP_SERVER_PORT);	/*	Local	port	*/

	/*	Create	socket	for	incoming	connections	*/
	do
	{
		listenfd	=	socket(AF_INET,	SOCK_STREAM,	0);
		if	(listenfd	==	-1)
		{
			printf("ESP8266	TCP	server	task socket	error\n");
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	}while(listenfd	==	-1);

		printf("ESP8266	TCP	server	task create	socket:	%d\n",	server_sock);

		/*	Bind	to	the	local	port	*/
		do{
			ret	=	bind(listenfd,	(struct	sockaddr	*)&server_addr,	sizeof(server_addr));
			if	(ret	!=	0)
			{
				printf("ESP8266	TCP	server	task bind	fail\n");
				vTaskDelay(1000/portTICK_RATE_MS);
			}
			}while(ret	!=	0);

		printf("ESP8266	TCP	server	task port:%d\n",ntohs(server_addr.sin_port));



		do{
										/*	Listen	to	the	local	connection	*/
			ret	=	listen(listenfd,	MAX_CONN);
			if	(ret	!=	0)	{
				printf("ESP8266	TCP	server	task failed	to	set	listen	queue!\n");
				vTaskDelay(1000/portTICK_RATE_MS);
			}
		}while(ret	!=	0);

		printf("ESP8266	TCP	server	task listen	");
}
#endif
#if 0
void tcp_client_in()
{
	int32	client_sock;
				int32	len	=	sizeof(struct	sockaddr_in);

	for	(;;)	{
								printf("ESP8266	TCP	server	task wait	client\n");
								/*block	here	waiting	remote	connect	request*/
								if	((client_sock	=	accept(listenfd,	(struct	sockaddr	*)&remote_addr,	(socklen_t	*)&len))	<	0)	{
												printf("ESP8266	TCP	server	task accept	fail\n");
												continue;
								}
								printf("ESP8266	TCP	server	task Client	from	%s	%d\n",	inet_ntoa(remote_addr.sin_addr),	htons(remote_addr.sin_port));

								char	*recv_buf	=	(char	*)zalloc(128);
								while	((recbytes	=	read(client_sock	,	recv_buf,	128))	>	0)	{
												recv_buf[recbytes]	=	0;
												printf("ESP8266	TCP	server	task read	data	success	%d!\nESP8266	TCP	server	task %s\n",	recbytes,	recv_buf);
								}
								free(recv_buf);

								if	(recbytes	<=	0)	{
												printf("ESP8266	TCP	server	task read	data	fail!\n");
												close(client_sock);
								}
				}
}
#endif


#include "gpio.h"
#include "spi_register.h"
#include "spi_interface.h"

void spi_initialize()
{
    //Initialze Pins on ESP8266
    PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDI_U, FUNC_HSPIQ_MISO);
    PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDO_U, FUNC_HSPI_CS0);
    PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTCK_U, FUNC_HSPID_MOSI);
    PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTMS_U, FUNC_HSPI_CLK);

    SpiAttr pAttr;   //Set as Master/Sub mode 0 and speed 10MHz
    pAttr.mode = SpiMode_Master;
    pAttr.subMode = SpiSubMode_0;
    pAttr.speed = SpiSpeed_10MHz;
    pAttr.bitOrder = SpiBitOrder_MSBFirst;
    SPIInit(SpiNum_HSPI, &pAttr);
}

void Send_cmd(uint8 command)
{
    SpiData pDat;
    pDat.cmd = command;	   ///< Command value
    pDat.cmdLen = 1;       ///< Command byte length
    pDat.addr = NULL;      ///< Point to address value
    pDat.addrLen = 0; 	   ///< Address byte length
    pDat.data = NULL; 	   ///< Point to data buffer
    pDat.dataLen = 0; 	   ///< Data byte length.
    SPIMasterSendData(SpiNum_HSPI, &pDat);
}



/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void user_init(void)
{
	uart_init_new();
	init_done_cb();


	wifi_set_opmode(STATION_MODE);

//	wifi_set_event_handler_cb(wifi_handle_event_cb);

	// ESP8266 connect to router.
	user_set_station_config();

	xQueueUart = xQueueCreate(32, sizeof(os_event_t));
//	xTaskCreate(user_task1, "user_start_task1", 256, NULL, 5, &xTaskHandle1);
//	xTaskCreate(user_task2, "user_start_task2", 512, NULL, 7, &xTaskHandle2);
	xTaskCreate(user_task3, "user_start_task3", 512, NULL, 6, &xTaskHandle3);
//	xTaskCreate(user_task4, "user_start_task4", 256, NULL, 5, &xTaskHandle4);

    uint8 cmd = 0xaa;
    uint32 addr = 0xbbcc;
    uint32 data[2] = { 0x11223344, 0x55667788 };
    spi_initialize();
    printf("Starting SPI Communication\n");

    while (1)
    {
        Send_cmd(0x34);
        SpiData pDat;
        pDat.cmd = cmd;			      ///< Command value
        pDat.cmdLen = 1;		      ///< Command byte length
        pDat.addr = &addr; 		      ///< Point to address value
        pDat.addrLen = 2; 	          ///< Address byte length
        pDat.data = data; 		      ///< Point to data buffer
        pDat.dataLen = sizeof(data);  ///< Data byte length.
        SPIMasterSendData(SpiNum_HSPI, &pDat); //SPIMasterRecvData
        vTaskDelay(1000);
    }
}

