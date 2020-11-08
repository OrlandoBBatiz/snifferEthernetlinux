#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip.h>
#include<linux/if_ether.h>
#include<pthread.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<unistd.h>

typedef struct datoHilo{
	char frase[20];
	int numero;
}datoHilo;


void mensaje(struct datoHilo *datos){

	printf("\n%s: %d\n",datos->frase, datos->numero);
	
	//pthread_exit(NULL);
}


int main(){
	
	pthread_t hiloP1;
	pthread_t hiloP2;
	datoHilo var1;
	datoHilo var2;
	
	printf("1.-Ingrese una frase: ");
	fgets(var1.frase, sizeof(var1.frase),stdin);
	printf("1.-Ingrese un numero: ");
	scanf("%d", &var1.numero);

	
	printf("2.-Ingrese una frase: ");
	fflush(stdin);
	while (getchar() != '\n');
	//fgets(var2.frase, sizeof(var2.frase),stdin);
	fgets(var2.frase, sizeof(var2.frase),stdin);
	printf("2.-Ingrese un numero: ");
	scanf("%d", &var2.numero);
		
		
	pthread_create(&hiloP1,NULL,(void*)mensaje,(void*)&var1);
	pthread_create(&hiloP2,NULL,(void*)mensaje,(void*)&var2);
	
	
	pthread_join(hiloP1,NULL);
	pthread_join(hiloP2,NULL);
	
	printf("Han finalizado los Hilos sus tareas\n");
	
	
	
	
	return 0;
}
