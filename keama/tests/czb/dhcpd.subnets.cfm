#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM62 
subnet 140.60.68.0 netmask 255.255.252.0 {
     option broadcast-address 140.60.71.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.60.69.1 140.60.69.254;
             range 140.60.70.1 140.60.70.254;
        }
     option domain-name "cfm.commerzbank.com";
     option routers 140.60.68.6;
     option ntp-servers 140.60.68.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE cfm Netz 140.60.68.0/255.255.252.0 _____*****");
   }
}
#
