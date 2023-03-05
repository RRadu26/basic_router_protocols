#include "include/skel.h"

typedef struct cell *listp;
typedef struct qpacket {
	packet *m;
	uint32_t ip;
} qpacket;
struct cell{
  qpacket *element;
  listp next;
  listp prev;
};
listp consp(qpacket *element, listp l) {
	listp temp = malloc(sizeof(struct cell));
	temp->element = element;
	temp->next = l;
	temp->prev = NULL;
	return temp;
}

int interfaces[ROUTER_NUM_INTERFACES];
struct route_table_entry rtable[100000];
struct arp_entry arp_table[100];
int rtable_len;
int arp_table_len;

struct route_table_entry *get_best_route(struct in_addr dest_ip) {
    long idx = -1;	

    for (size_t i = 0; i < rtable_len; i++) {
        if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {
	    	if (idx == -1) 
				idx = i;
	    	else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) 
				idx = i;
		}

    }

    if (idx == -1)
        return NULL;

    else
        return &rtable[idx];
}
struct arp_entry *get_arp_entry(in_addr_t dest_ip) {
    for (size_t i = 0; i < arp_table_len; i++) {
        if (memcmp(&dest_ip, &arp_table[i].ip, sizeof(struct in_addr)) == 0)
	    	return &arp_table[i];
    }
    return NULL;
}
void arp_received(packet *m, struct ether_header *eth, listp *l) {
	struct arp_header *arpe;
	struct in_addr my_ip_addr;
	inet_aton(get_interface_ip(m->interface), &my_ip_addr);
	arpe = ((void *) eth) + sizeof(struct ether_header);
	if (my_ip_addr.s_addr != (arpe->tpa))
		return;
	//daca routerul primeste un arp-request cu adresa sa ca destinatar
	//returneaza un pachet arp cu adresa mac.

	if (arpe->op == htons(1)) {
		arpe->op = htons(2);
		memcpy(eth->ether_dhost, &arpe->sha , 6);
		get_interface_mac(m->interface, eth->ether_shost);
				
		memcpy(&arpe->tpa ,&arpe->spa , 4);
		memcpy(arpe->tha , arpe->sha , 6);
		get_interface_mac(m->interface, arpe->sha);
		arpe->spa = my_ip_addr.s_addr;
		send_packet(m);
		return;
	}
	//daca routerul primeste un arp-reply adauga in cache-ul arp intrarea primita
	arp_table[arp_table_len].ip = arpe->spa;
	memcpy(arp_table[arp_table_len].mac, arpe->sha, 6);
	arp_table_len++;
	//routerul parcurge lista de pachete care asteapta raspunsul arp, le 
	//trimite pe cele pentru care adresa urmatorului hop este acum cunoscuta
	listp c = *l;
	while(c != NULL) {
		if (c->element->ip == arpe->spa) {
			struct ether_header *ethh = (struct ether_header *) c->element->m->payload;
			memcpy(ethh->ether_dhost, arpe->sha, 6);
			send_packet(c->element->m);
			if (c->prev != NULL)
				c->prev->next = c->next;
			else
				*l = c->next;
			if (c->next != NULL)
					c->next->prev = c->prev;
			listp a = c;
			c=c->next;
			free(a->element->m);
			free(a->element);
			free(a);
			continue;
		}
		c = c->next;
	} 

}
//functie ce trimite un arp request pe toate interfetele sale, adauga intr-o lista
//pachetele icmp care vor fi trimise mai cand se va primi reply-ul
void arp_forward(packet m, listp l,int rinterface, uint32_t rnexthop) {
	packet *p = malloc(sizeof(packet));
	struct ether_header eh;
	struct arp_header ah;
				
	eh.ether_type = htons(0x806);
	char f[6];f[0]=0xff;f[1]=0xff;f[2]=0xff;f[3]=0xff;f[4]=0xff;f[5]=0xff;
	memcpy(eh.ether_dhost, f, 6);
	get_interface_mac(1, eh.ether_shost);
	p->interface = 1;
	p->len = sizeof(eh) + sizeof(ah);
	ah.htype = htons(1);
	ah.ptype = htons(2048);
	ah.hlen = 6;
	ah.plen = 4;
	ah.op = htons(1);
	get_interface_mac(1, ah.sha);
	struct in_addr mia;
	inet_aton(get_interface_ip(1), &mia);
	ah.spa = mia.s_addr;
	char *a = calloc(6, 1);
	memcpy(ah.tha, a, 6);
	free(a);
	ah.tpa = rnexthop;
	memcpy(p->payload, &eh, sizeof(eh));
	memcpy(p->payload+sizeof(eh), &ah, sizeof(ah));
	send_packet(p);

	inet_aton(get_interface_ip(2), &mia);
	ah.spa = mia.s_addr;
	get_interface_mac(2, ah.sha);
	get_interface_mac(2, eh.ether_shost);
	p->interface = 2;
	memcpy(p->payload+sizeof(eh), &ah, sizeof(ah));
	send_packet(p);

	inet_aton(get_interface_ip(0), &mia);
	ah.spa = mia.s_addr;
	get_interface_mac(0, ah.sha);
	get_interface_mac(0, eh.ether_shost);
	p->interface = 0;
	memcpy(p->payload+sizeof(eh), &ah, sizeof(ah));
	send_packet(p);
	
	free(p);
	m.interface = rinterface;
	qpacket *qp = (qpacket*)malloc(sizeof(qpacket));
	qp->ip = rnexthop;
	qp->m=malloc(sizeof(packet));
	memcpy(qp->m, &m, sizeof(packet));
	l = consp(qp, l); 
}

int main(int argc, char *argv[]) {

	packet m;
	int rc;
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);

	// Do not modify this line
	init(argc - 2, argv + 2);
	arp_table_len=0;
	listp l = NULL;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */
		struct ether_header *eth = (struct ether_header *) m.payload;
		//s-a primit un pachet e tip arp
		if (ntohs(eth->ether_type) == 0x806) {
			arp_received(&m, eth, &l);
			continue;
		}
		//s-a primit un pachet de tip ipv4
		if (ntohs(eth->ether_type) == 0x0800) {
			struct iphdr *iph;
			iph = ((void *) eth) + sizeof(struct ether_header);
			//verificare checksum
			if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0)
				continue;
			//verificare ttl
			if (iph->ttl==0 || iph->ttl==1 )
				continue;
		
			struct in_addr dest_ip;			
			dest_ip.s_addr = iph->daddr;
			//cautare in tabela de rutare
			struct route_table_entry *route = get_best_route(dest_ip);
			if (route == NULL)
				continue;
			struct arp_entry *arp = get_arp_entry(route->next_hop);
			//actualizare ttl si checksum
			iph->ttl--;
			iph->check = 0;
			iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));
			//cautare in cache-ul arp, daca nu esista se face forward cu un pachet
			//arp pentru a afla mac-ul
			get_interface_mac(route->interface, eth->ether_shost);
			if (arp == NULL) {
				arp_forward(m, l, route->interface, route->next_hop);
				continue;
			}
			m.interface = route->interface;
		
			memcpy(eth->ether_dhost, &arp->mac , 6);

		}
		send_packet(&m); 

	}

}
