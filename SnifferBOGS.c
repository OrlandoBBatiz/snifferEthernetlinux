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

//Nombre de adaptador wlp2s0
#define MAXLINE 65536  //Tamaño maximo de trama


//Variable Global a la que accederan ambos Hilos

char buffer[2000][MAXLINE];
int tamanios[2000];
int lectura_buffer = 1;		//Simula semaforo de procesos
//Variables para conteo de protocolos
	int nipv4=0;
	int nipv6=0;
	int narp=0;
	int ncontrolf=0;
	int nseguridad=0;
	int ndesconocido=0;

//Archivo para guardar los datos
FILE *Archivo;

//Estructura para guardar los datos que mete el usuario
typedef struct datosUser{
	int	num_paquetes;
	char nom_de_adaptador[10];
}datosUser;

typedef struct cont_direcc{
	char direc[18];
	int n;
}cont_direcc;


//Funciones extra para el analizador
void IdProtocolo (uint16_t proto, int tipo){

	if(tipo == 0){
		switch(proto){
		
				case 2048:
					
					printf("(IPv4)\n\n");
					nipv4++;
					break;
					
				case 34525:
					
					printf("(IPv6)\n\n");
					nipv6++;
					break;
					
				case 2054:
					
					printf("(ARP)\n\n");
					narp++;
					break;
					
				case 34824:
					
					printf("(Control de Flujo)\n\n");
					ncontrolf++;
					break;
				
				case 35045:
					
					printf("(Seguridad MAC)\n\n");
					nseguridad++;
					break;
				

				default: 
					printf("(Desconocido)\n\n");
					ndesconocido++;
		}
	}
	else if(tipo == 1){
		switch(proto){
		
				case 2048:
					fprintf(Archivo,"(IPv4)\n\n");
					break;
					
				case 34525:
					fprintf(Archivo,"(IPv6)\n\n");
					break;
					
				case 2054:			
					fprintf(Archivo,"(ARP)\n\n");
					break;
					
				case 34824:
					fprintf(Archivo,"(Control de Flujo)\n\n");
					break;
				
				case 35045:
					fprintf(Archivo,"(Seguridad MAC)\n\n");
					break;
				

				default: 
					fprintf(Archivo,"(Desconocido)\n\n");
		}
	}
}



//Funcion que estara Capturando los Datos
void capturador(struct datosUser *datosP){
	
	//Variables para el modo prosmicuo y analizar trama
	struct ifreq ethreq;
	struct ethhdr trama; //Estructura donde tiene DD, DS, L/T, Payload
	//Variables para el socket crudo
	int idsocket; //Socket capturador
	 //Buffer para recibir datos de 1024 bytes
    int sizeB;
    int i=0;
    int saddr_size;
    struct sockaddr_in source_socket_address;
    struct sockaddr_in dest_socket_address;
	struct sockaddr saddr;
    
	idsocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	 if(idsocket == -1){
		printf("Error al generar el socket\n\n");
		exit(1);
	 }
	
	
	//Modo Prosmicuo ACTIVO
	strncpy (ethreq.ifr_name, datosP->nom_de_adaptador, IFNAMSIZ);
	ioctl (idsocket,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl (idsocket, SIOCSIFFLAGS, &ethreq);
	
	//Recibiendo paquetes
	while( i < (datosP->num_paquetes) ){
	
		saddr_size = sizeof saddr;
		sizeB = recvfrom(idsocket , (char *)buffer[i] , MAXLINE, 0 , &saddr , &saddr_size);

		tamanios[i]=sizeB;
      	buffer[i][sizeB]='\0';
		printf("%d.-El buffer trae: %s\nTamanio: %d \n\n",i+1,buffer[i],sizeB);
		
		i++;
	}
	lectura_buffer = 0;
	

	//pthread_exit(NULL);
}

//Función que analizara la trama

void analizador(struct datosUser *datosP){

	int j=0;
	struct ethhdr *ethernet_header;
	int size_trama=0;
	char direccion_dest[18];
	char aux_dest[9];
	char direccion_orig[18];
	char aux_orig[9];
	uint16_t protocolo;
	int num802=0;
	int ethernetII=datosP->num_paquetes;
	

	
	Archivo = fopen("sniffer.txt","a+");
	if(Archivo ==NULL){
		printf("No se creo el archivo");
	}
	else{
		while(lectura_buffer){
			//While que sirve de semaforo
		}
		printf("----------INICIANDO ANALIZADOR----------\n\n");
		
		//Escritura incial
		fprintf(Archivo,"-------------------REPORTE DE SNIFFER-------------------\n\n");
		fprintf(Archivo,"Tarjeta de adaptador de red: %s\n",datosP->nom_de_adaptador);
		fprintf(Archivo,"Num. de tramas leídas: %d\n\n",datosP->num_paquetes);
		fprintf(Archivo,"Tramas Ethernet 802.3: %d\n",num802);
		fprintf(Archivo,"Tramas Ethernet II: %d\n\n",ethernetII);
		
		//Analizador para conteo de Tramas
		while(j < (datosP->num_paquetes)){

			if(tamanios[j]>45){
			
				printf("\nTrama %d: %s\nPayload: %d\n",j+1,buffer[j],tamanios[j]);
				ethernet_header = (struct ethhdr *)buffer[j];
				
				sprintf(direccion_dest,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header->h_dest[0], ethernet_header->h_dest[1], ethernet_header->h_dest[2], ethernet_header->h_dest[3], ethernet_header->h_dest[4], ethernet_header->h_dest[5]);
				
				sprintf(aux_dest,"%02x:%02x:%02x",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2]);
				
				sprintf(direccion_orig,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header->h_source[0], ethernet_header->h_source[1], ethernet_header->h_source[2], ethernet_header->h_source[3], ethernet_header->h_source[4], ethernet_header->h_source[5]);
				
				sprintf(aux_orig,"%02x:%02x:%02x",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2]);
								
				printf("Direccion Destino: %s\n",direccion_dest);
				if(strcmp("ff:ff:ff:ff:ff:ff",direccion_dest)==0){
					printf("Direccion de Destino es de Difusion\n");
				}
				else if(strcmp("01:00:5e",aux_dest)==0){
					printf("Direccion de Destino es de Multidifusion\n");
				}
				else{
					printf("Direccion de Destino es de Unidifusion\n");
				}
				
				printf("\nDirección Origen: %s\n",direccion_orig);
				if(strcmp("ff:ff:ff:ff:ff:ff",direccion_orig)==0){
					printf("Direccion de Origen es de Difusion\n");
				}
				else if(strcmp("01:00:5e",aux_orig)==0){
					printf("Direccion de Origen es de Multidifusion\n");
				}
				else{
					printf("Direccion de Origen es de Unidifusion\n");
				}
				
				protocolo = htons(ethernet_header->h_proto);
				printf("Protocolo: 0x%04X ",protocolo);
				IdProtocolo(protocolo,0);
				
				
			}
			j++;
		}
		
		printf("Tramas de IPv4: %d\n",nipv4);
		fprintf(Archivo,"Tramas de IPv4: %d\n",nipv4);
		
		printf("Tramas de IPv6: %d\n",nipv6);
		fprintf(Archivo,"Tramas de IPv6: %d\n",nipv6);
		
		printf("Tramas de ARP: %d\n",narp);
		fprintf(Archivo,"Tramas de ARP: %d\n",narp);
		
		printf("Tramas de Control de Flujo: %d\n",ncontrolf);
		fprintf(Archivo,"Tramas de Control de Flujo: %d\n",ncontrolf);
		
		printf("Tramas de Seguridad MAC: %d\n",nseguridad);
		fprintf(Archivo,"Tramas de Seguridad MAC: %d\n",nseguridad);
		
		printf("Tramas Desconocidas: %d\n",ndesconocido);
		fprintf(Archivo,"Tramas Desconocidas: %d\n\n",ndesconocido);
		
		j=0;
		
		while(j < (datosP->num_paquetes)){
		
			if(tamanios[j]>45){
			
				fprintf(Archivo,"\nTrama %d: %s\nPayload: %d\n",j+1,buffer[j],tamanios[j]);
				ethernet_header = (struct ethhdr *)buffer[j];
				
				sprintf(direccion_dest,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header->h_dest[0], ethernet_header->h_dest[1], ethernet_header->h_dest[2], ethernet_header->h_dest[3], ethernet_header->h_dest[4], ethernet_header->h_dest[5]);
				sprintf(aux_dest,"%02x:%02x:%02x",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2]);
				
				sprintf(direccion_orig,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header->h_source[0], ethernet_header->h_source[1], ethernet_header->h_source[2], ethernet_header->h_source[3], ethernet_header->h_source[4], ethernet_header->h_source[5]);
				sprintf(aux_orig,"%02x:%02x:%02x",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2]);
								
				fprintf(Archivo,"Direccion Destino: %s\n",direccion_dest);
				if(strcmp("ff:ff:ff:ff:ff:ff",direccion_dest)==0){
					fprintf(Archivo,"Direccion de Destino es de Difusion\n");
				}
				else if(strcmp("01:00:5e",aux_dest)==0){
					fprintf(Archivo,"Direccion de Destino es de Multidifusion\n");
				}
				else{
					fprintf(Archivo,"Direccion de Destino es de Unidifusion\n");
				}
				
				fprintf(Archivo,"\nDireccion Origen: %s\n",direccion_orig);
				if(strcmp("ff:ff:ff:ff:ff:ff",direccion_orig)==0){
					fprintf(Archivo,"Direccion de Origen es de Difusion\n");
				}
				else if(strcmp("01:00:5e",aux_orig)==0){
					fprintf(Archivo,"Direccion de Origen es de Multidifusion\n");
				}
				else{
					fprintf(Archivo,"Direccion de Origen es de Unidifusion\n");
				}
				
				protocolo = htons(ethernet_header->h_proto);
				fprintf(Archivo,"Protocolo: 0x%04X ",protocolo);
				IdProtocolo(protocolo,1);
				
				
			}
			j++;
		}
		
		
	}
	

}



int main(){


	datosUser datosP;
    char cierre[50]="/sbin/ifconfig ";
    pthread_t hiloCapturador;
    pthread_t hiloAnalizador;
    //int aux=0;

	printf("Ingrese el num de paquetes a analizar: ");
	scanf("%d",&datosP.num_paquetes);
	printf("Ingrese el nombre de sus adaptador de red: ");
	while (getchar() != '\n');
	fgets(datosP.nom_de_adaptador,10,stdin);
	strtok(datosP.nom_de_adaptador, "\n");
	
	printf("\nLEIDO\n\nNum Paq: %d\nNombre de Adaptador: %s\n",datosP.num_paquetes,datosP.nom_de_adaptador);
	
	//Creamos el Hilo capturador, donde lo mandamos a la función capturador y las variables de los datos de usuarios con apuntador
	pthread_create(&hiloCapturador,NULL,(void*)capturador,(void*)&datosP);
	pthread_create(&hiloAnalizador,NULL,(void*)analizador,(void*)&datosP);
	pthread_join(hiloCapturador,NULL);
	pthread_join(hiloAnalizador,NULL);
	
	//Creamos el string donde se quita el modo prosmicuo
	strcat(cierre,datosP.nom_de_adaptador);
	strcat(cierre," -promisc");
	system(cierre);

	return 0;
}
