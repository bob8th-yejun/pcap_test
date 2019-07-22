template <typename T>
void safeFree(T* ptr){
    if (ptr != nullptr) {
        delete ptr;
        ptr = nullptr;
    }
}

class OSILayer {
public:
    unsigned short getLayerCode() {
        return layerCode;
    }
    unsigned short getChildLayerCode() {
        return childLayerCode;
    }
    const u_char* getPacket() {
        return packet;
    }

    virtual int getLayerSize(void) = 0;
    virtual void print(void) = 0;
protected:
    void setLayerCode(int code) {
        if (true)
            this->layerCode = code;
    }
    void setChildLayerCode(int code) {
        if (true)
            this->childLayerCode = code;
    }
    void setPacket(const u_char* pack) {
        packet = pack;
    }
private:
    unsigned short layerCode{NULL};
    unsigned short childLayerCode{NULL};
    const u_char* packet{nullptr};
};

class L2 : public OSILayer{
public:
    const u_char* getDMac() {
        return DMac;
    }
    const u_char* getSMac() {
        return SMac;
    }
protected:
    void setDMac(const u_char* mac) {
        memcpy(DMac, mac, sizeof(u_char) * 6);
    }
    void setSMac(const u_char* mac) {
        memcpy(SMac, mac, sizeof(u_char) * 6);
    }
private:
    u_char SMac[6];
    u_char DMac[6];
};

class L3 : public OSILayer {
public:
    const u_char* getDIP() {
        return DIP;
    }
    const u_char* getSIP() {
        return SIP;
    }
protected:
    void setDIP(const u_char* ip) {
        memcpy(DIP, ip, sizeof(u_char) * 4);
    }
    void setSIP(const u_char* ip) {
        memcpy(SIP, ip, sizeof(u_char) * 4);
    }
private:
    u_char SIP[4];
    u_char DIP[4];
};

class L4 : public OSILayer {
public:
    unsigned short getDPort() {
        return DPort;
    }
    unsigned short getSPort() {
        return SPort;
    }
protected:
    void setDPort(unsigned short port) {
        DPort = port;
    }
    void setSPort(unsigned short port) {
        SPort = port;
    }
private:
    unsigned short DPort{NULL};
    unsigned short SPort{NULL};
};

class L7 : public OSILayer{
public:
    const u_char* getRawData(){
        return rawData;
    }
    unsigned int getLen(){
        return len;
    }
    void printRaw(int len) {
        for (int i = 0; i < len && i < this->len; i++) {
            if(i == 0) printf("\t");
            else if(i % 10 == 0) printf("\n\t");
            else if(i % 5 == 0) printf("   ");
            printf("%.2X ", rawData[i]);
        }
        if (len < this->len)
            printf("...");
    }
protected:
    void setRawData(const u_char* pack){
        rawData = pack;
    }
    void setLen(unsigned int len) {
        this->len = len;
    }
private:
    const u_char* rawData{nullptr};
    unsigned int len;
};

class Ethernet : L2{
public:
    Ethernet(const u_char* pack) {
        setPacket(pack);
        setDMac(pack + 0);
        setSMac(pack + 6);
        setChildLayerCode((pack[12] << 8) + pack[13]);
    }
    ~Ethernet() { }

    int getLayerSize() {
        if (0x0600 < getChildLayerCode() && getChildLayerCode() != 0x8100) // Ethernet II (RFC894)
            return 14;
        else // Unknown or 0x8100 (Option)
            return -1;
    }
    void print() {
        printf("[L2] ETHERNET Protocol\n");
        printf("\tDMAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", getDMac()[0], getDMac()[1], getDMac()[2], getDMac()[3], getDMac()[4], getDMac()[5]);
        printf("\tSMAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", getSMac()[0], getSMac()[1], getSMac()[2], getSMac()[3], getSMac()[4], getSMac()[5]);
    }
private:
    // Ethernet Data
};

class L2Unknown : L2{
public:
    L2Unknown(unsigned short layerCode) {
        setLayerCode(layerCode);
    }
    ~L2Unknown() { }

    int getLayerSize() { return -1; }
    void print() {
        switch(getLayerCode()) {
        default: printf("[L2] Unknown Protocol (%d)\n", getLayerCode()); break;
        }
    }
};

class IPv4 : L3{
public:
    IPv4(const u_char* pack){
        setPacket(pack);
        setSIP(pack + 12);
        setDIP(pack + 16);
        setChildLayerCode(pack[9]);
    }
   // ~IPv4() { }

    int getLayerSize() {
        return 20; //Default Size (No Option)
    }
    void print() {
        printf("[L3] IPv4 Protocol\n");
        printf("\tDIP: %d.%d.%d.%d\n", getDIP()[0], getDIP()[1], getDIP()[2], getDIP()[3]);
        printf("\tSIP: %d.%d.%d.%d\n", getSIP()[0], getSIP()[1], getSIP()[2], getSIP()[3]);
    }
private:
    // IPv4 Data
};

class L3Unknown : L3{
public:
    L3Unknown(unsigned short layerCode) {
        setLayerCode(layerCode);
    }
    ~L3Unknown() { }

    int getLayerSize() { return -1; }
    void print() {
        switch(getLayerCode()) {
        case 0x0800: printf("[L3] IPv4 Protocol (Unknown)\n"); break;
        case 0x0806: printf("[L3] ARP Protocol (Unknown)\n"); break;
        case 0x8035: printf("[L3] RARP Protocol (Unknown)\n"); break;
        case 0x8138: printf("[L3] IPX Protocol (Unknown)\n"); break;
        case 0x8100: printf("[L3] VLAN Tag (Unknown)\n"); break;
        case 0x8847: printf("[L3] MPLS Unicast Protocol (Unknown)\n"); break;
        default: printf("[L3] Unknown Protocol (%d)\n", getLayerCode()); break;
        }
    }
};

class TCP : L4{
public:
    TCP(const u_char* pack) {
        setPacket(pack);
        setSPort((pack[0] << 8) + pack[1]);
        setDPort((pack[2] << 8) + pack[3]);
        setChildLayerCode(getDPort() < getSPort() ? getDPort() : getSPort()); //낮은 포트번호가 지정 프로토콜이 있을 확률이 높으므로
    }
    ~TCP() { }

    int getLayerSize() {
        return 20; //Default size (No Option)
    }
    void print() {
        printf("[L4] TCP Protocol\n");
        printf("\tDPort: %u\n", getDPort());
        printf("\tSPort: %u\n", getSPort());
    }
private:
    // TCP Data
};

class L4Unknown : L4{
public:
    L4Unknown(unsigned short layerCode) {
        setLayerCode(layerCode);
    }
    ~L4Unknown() { }

    int getLayerSize() { return -1; }
    void print() {
        switch(getLayerCode()) {
        case 1: printf("[L4] ICMP Protocol (Unknown)"); break;
        case 2: printf("[L4] IGMP Protocol (Unknown)"); break;
        case 6: printf("[L4] TCP Protocol (Unknown)"); break;
        case 9: printf("[L4] IGRP Protocol (Unknown)"); break;
        case 17: printf("[L4] UDP Protocol (Unknown)"); break;
        case 47: printf("[L4] GRE Protocol (Unknown)"); break;
        case 50: printf("[L4] ESP Protocol (Unknown)"); break;
        default: printf("[L4] Unknown Protocol (%d)\n", getLayerCode()); break;
        }
    }
};

class HTTP : L7{
public:
    HTTP(const u_char* pack, unsigned int size) {
        setPacket(pack);
        setRawData(pack);
        setLen(size);
    }
    ~HTTP() { }

    int getLayerSize() {
        return getLen();
    }
    void print() {
        printf("[L7] HTTP Protocol\n");
        printf("\t%dbyte\n", getLen());
        printRaw(10);
    }
private:
    // HTTP Data
};

class L7Unknown : L7{
public:
    L7Unknown(const u_char* pack, unsigned short layerCode, unsigned int size) {
        setPacket(pack);
        setRawData(pack);
        setLayerCode(layerCode);
        setLen(size);
    }
    ~L7Unknown() { }

    int getLayerSize() { return -1; }
    void print() {
        switch(getLayerCode()) {
        case 1: printf("[L7] TCPMUX Protocol (Unknown)\n"); break;
        case 7: printf("[L7] ECHO Protocol (Unknown)\n"); break;
        case 9: printf("[L7] DISCARD Protocol (Unknown)\n"); break;
        case 13: printf("[L7] DAYTIME Protocol (Unknown)\n"); break;
        case 17: printf("[L7] QOTD Protocol (Unknown)\n"); break;
        case 20: printf("[L7] FTP Protocol (Unknown)\n"); break;
        case 21: printf("[L7] FTP Protocol (Unknown)\n"); break;
        case 22: printf("[L7] SSH Protocol (Unknown)\n"); break;
        case 23: printf("[L7] TELNET Protocol (Unknown)\n"); break;
        case 25: printf("[L7] SMTP Protocol (Unknown)\n"); break;
        case 37: printf("[L7] TIME Protocol (Unknown)\n"); break;
        case 53: printf("[L7] DNS Protocol (Unknown)\n"); break;
        case 80: printf("[L7] HTTP Protocol (Unknown)\n"); break;
        case 109: printf("[L7] POP2 Protocol (Unknown)\n"); break;
        case 110: printf("[L7] POP3 Protocol (Unknown)\n"); break;
        case 111: printf("[L7] RPC Protocol (Unknown)\n"); break;
        case 143: printf("[L7] IMAP4 Protocol (Unknown)\n"); break;
        case 443: printf("[L7] HTTPS Protocol (Unknown)\n"); break;
        default: printf("[L7] Unknown Protocol\n"); break;
        }
        printf("\t%dbyte\n", getLen());
        printRaw(10);
    }
};

class PACKET{
public:
    PACKET(pcap_pkthdr* head, const u_char* body){
        this->head = head;
        this->body = body;
        //L2 Parsing
        if(true){ // L2 프로토콜은 어떻게 구분해야하는지 몰라서 항상 이더넷으로 제한
            l2 = (L2*)new Ethernet(body);
        } else {
            l2 = (L2*)new L2Unknown(0);
        }
        //L3 Parsing
        if(l2 != nullptr) {
            if (l2->getLayerSize() != -1) {
                const u_char* pack = l2->getPacket() + l2->getLayerSize();
                switch(l2->getChildLayerCode()) {
                case 0x0800: // IPv4
                    l3 = (L3*)new IPv4(pack);
                    break;
                case 0x0806: // ARP
                    l3 = (L3*)new L3Unknown(0x0806);
                    break;
                default:
                    l3 = (L3*)new L3Unknown(l2->getChildLayerCode());
                    break;
                }
            }
        }
        //L4 Parsing
        if (l3 != nullptr) {
            if (l3->getLayerSize() != -1) {
                const u_char* pack = l3->getPacket() + l3->getLayerSize();
                switch(l3->getChildLayerCode()) {
                case 1: //ICMP
                    l4 = (L4*)new L4Unknown(1);
                    break;
                case 2: //IGMP
                    l4 = (L4*)new L4Unknown(2);
                    break;
                case 6: //TCP
                    l4 = (L4*)new TCP(pack);
                    break;
                case 17: //UDP
                    l4 = (L4*)new L4Unknown(17);
                    break;
                default:
                    l4 = (L4*)new L4Unknown(l3->getChildLayerCode());
                    break;
                }
            }
        }
        //L7 Parsing
        if (l4 != nullptr) {
            if (l4->getLayerSize() != -1) {
                const u_char* pack = l4->getPacket() + l4->getLayerSize();
                unsigned int len = head->caplen - (pack - body);
                switch(l4->getChildLayerCode()) {
                case 80:
                    l7 = (L7*)new HTTP(pack, len);
                    break;
                case 443:
                    l7 = (L7*)new L7Unknown(pack, 443, len);
                default:
                    l7 = (L7*)new L7Unknown(pack, l4->getChildLayerCode(), len);
                }
            }
        }
    }
    ~PACKET() {
        safeFree(l2);
        safeFree(l3);
        safeFree(l4);
        safeFree(l7);
        safeFree(head);
        safeFree(body);
    }

    void print() {
        if(l2 != nullptr) l2->print();
        if(l3 != nullptr) l3->print();
        if(l4 != nullptr) l4->print();
        if(l7 != nullptr) l7->print();
    }
private:
    L2* l2{nullptr};
    L3* l3{nullptr};
    L4* l4{nullptr};
    L7* l7{nullptr};
    pcap_pkthdr* head;
    const u_char* body;
};
